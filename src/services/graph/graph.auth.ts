/**
 * Microsoft Graph authentication
 *
 * App-only (client-credentials) authentication with a certificate — never a
 * client secret. Phishy proves its identity to the Microsoft identity
 * platform with a short-lived JWT it signs with the certificate's private
 * key, and receives an access token for Microsoft Graph in return.
 *
 * Implemented on Node built-ins (`crypto`, `fetch`); no MSAL dependency.
 *
 * Assertion format, verified against
 * https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
 *   Header:  alg = PS256, typ = JWT,
 *            x5t#S256 = base64url(SHA-256(certificate DER))
 *   Claims:  aud = https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
 *            iss = sub = application (client) ID
 *            jti = unique per assertion, nbf/iat = now,
 *            exp = "5-10 minutes after nbf at most"
 *   Signature: RSASSA-PSS with SHA-256 ("Use PSS padding")
 *
 * Token request, verified against
 * https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
 * ("Second case: Access token request with a certificate").
 *
 * The private key, the assertion and the access token never appear in log
 * lines or error messages produced here.
 */

import {
  KeyObject,
  X509Certificate,
  constants,
  createHash,
  createPrivateKey,
  randomUUID,
  sign,
} from 'crypto';
import { z } from 'zod';
import { createLogger } from '../../utils/logger';
import { withRetry } from '../../utils/retry';
import { GraphAuthError } from './graph.errors';

const logger = createLogger('graph-auth');

export const GRAPH_LOGIN_ORIGIN = 'https://login.microsoftonline.com';
export const GRAPH_DEFAULT_SCOPE = 'https://graph.microsoft.com/.default';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** Assertion lifetime: the documented range is 5-10 minutes; use the short end */
const ASSERTION_LIFETIME_SECONDS = 300;
/** Refresh a cached token this long before it expires */
const DEFAULT_REFRESH_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_TOKEN_TIMEOUT_MS = 10000;
const DEFAULT_TOKEN_ATTEMPTS = 3;
const DEFAULT_TOKEN_BASE_DELAY_MS = 500;

export const GUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** A tenant is addressed by its directory (tenant) ID or a verified domain name */
export const TENANT_PATTERN =
  /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})$/;

/**
 * A parsed signing certificate: the private key that signs assertions and
 * the thumbprint that tells Entra which uploaded certificate to verify with
 */
export interface GraphCertificate {
  privateKey: KeyObject;
  /** base64url(SHA-256(certificate DER)) — the `x5t#S256` header value */
  thumbprintS256: string;
  /** Certificate expiry, so callers can warn before it lapses */
  notAfter: Date;
}

/**
 * One app registration's identity. A client is built from exactly one of
 * these, so read and write access can never share a token.
 */
export interface GraphCredential {
  /** Short name for logs and errors (e.g. `read`) */
  label: string;
  tenantId: string;
  clientId: string;
  certificate: GraphCertificate;
}

/** Supplies the credential on demand (lets secret retrieval stay lazy) */
export type GraphCredentialSource = () => Promise<GraphCredential>;

/** What the HTTP client needs from an authenticator */
export interface GraphAccessTokenProvider {
  readonly label: string;
  /** A currently valid access token */
  getToken(): Promise<string>;
  /** Drop the cached token (e.g. after Graph answered 401) */
  invalidate(): void;
}

export interface GraphTokenProviderOptions {
  /** Injected for tests; defaults to the global `fetch` */
  fetchImpl?: typeof fetch;
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
  refreshSkewMs?: number;
  timeoutMs?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
}

const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.coerce.number().positive(),
});

const TokenErrorSchema = z.object({
  error: z.string().optional(),
  error_codes: z.array(z.number()).optional(),
  trace_id: z.string().optional(),
  correlation_id: z.string().optional(),
});

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Parse certificate material into a signing key and thumbprint.
 *
 * Accepts either a PEM bundle containing an unencrypted private key and the
 * certificate, or a JSON object `{"privateKey": "<PEM>", "certificate": "<PEM>"}`.
 * PEM passed through an environment variable may use literal `\n` sequences
 * in place of newlines.
 *
 * Errors raised here describe what is wrong without echoing the material.
 */
export function parseCertificateBundle(material: string): GraphCertificate {
  let text = material.trim();

  if (text.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error('Graph certificate material looks like JSON but could not be parsed');
    }
    const fields = parsed as { privateKey?: unknown; certificate?: unknown };
    if (typeof fields.privateKey !== 'string' || typeof fields.certificate !== 'string') {
      throw new Error(
        'Graph certificate JSON must have string "privateKey" and "certificate" fields'
      );
    }
    text = `${fields.privateKey}\n${fields.certificate}`;
  }

  if (!text.includes('\n') && text.includes('\\n')) {
    text = text.replace(/\\r/g, '').replace(/\\n/g, '\n');
  }

  const blocks = [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g)];
  const certificateBlock = blocks.find(block => block[1] === 'CERTIFICATE');
  const keyBlock = blocks.find(block => block[1].endsWith('PRIVATE KEY'));

  if (!certificateBlock) {
    throw new Error('Graph certificate material has no CERTIFICATE block');
  }
  if (!keyBlock) {
    throw new Error('Graph certificate material has no PRIVATE KEY block');
  }
  if (keyBlock[1] === 'ENCRYPTED PRIVATE KEY') {
    throw new Error(
      'Graph private key is passphrase-protected; store it unencrypted in Secrets Manager'
    );
  }

  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certificateBlock[0]);
  } catch {
    throw new Error('Graph certificate could not be parsed as X.509');
  }

  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(keyBlock[0]);
  } catch {
    throw new Error('Graph private key could not be parsed');
  }

  if (privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Graph private key must be an RSA key (assertions are signed with PS256)');
  }
  if (!certificate.checkPrivateKey(privateKey)) {
    throw new Error('Graph private key does not match the certificate');
  }

  return {
    privateKey,
    thumbprintS256: createHash('sha256').update(certificate.raw).digest('base64url'),
    notAfter: new Date(certificate.validTo),
  };
}

/**
 * The token endpoint for a tenant. The tenant is validated because it is
 * placed in a URL path.
 */
export function tokenEndpoint(tenantId: string): string {
  if (!TENANT_PATTERN.test(tenantId)) {
    throw new Error('Graph tenantId must be a directory (tenant) GUID or a domain name');
  }
  return `${GRAPH_LOGIN_ORIGIN}/${tenantId}/oauth2/v2.0/token`;
}

/**
 * Build and sign the JWT client assertion for a credential
 * (format documented at the top of this file)
 */
export function buildClientAssertion(
  credential: Pick<GraphCredential, 'tenantId' | 'clientId' | 'certificate'>,
  nowMs: number = Date.now()
): string {
  const issuedAt = Math.floor(nowMs / 1000);

  const header = {
    alg: 'PS256',
    typ: 'JWT',
    'x5t#S256': credential.certificate.thumbprintS256,
  };
  const claims = {
    aud: tokenEndpoint(credential.tenantId),
    iss: credential.clientId,
    sub: credential.clientId,
    jti: randomUUID(),
    nbf: issuedAt,
    iat: issuedAt,
    exp: issuedAt + ASSERTION_LIFETIME_SECONDS,
  };

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = sign('sha256', Buffer.from(signingInput), {
    key: credential.certificate.privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  });

  return `${signingInput}.${base64url(signature)}`;
}

/**
 * Obtains and caches access tokens for one credential.
 *
 * The token is held in memory, refreshed a few minutes before it expires,
 * and concurrent callers share a single in-flight token request.
 */
export class GraphTokenProvider implements GraphAccessTokenProvider {
  readonly label: string;

  private readonly source: GraphCredentialSource;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly refreshSkewMs: number;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;

  private cached?: { token: string; expiresAtMs: number };
  private inFlight?: Promise<string>;

  constructor(
    label: string,
    source: GraphCredentialSource,
    options: GraphTokenProviderOptions = {}
  ) {
    this.label = label;
    this.source = source;
    this.fetchImpl = options.fetchImpl ?? ((input, init): Promise<Response> => fetch(input, init));
    this.now = options.now ?? Date.now;
    this.refreshSkewMs = options.refreshSkewMs ?? DEFAULT_REFRESH_SKEW_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TOKEN_TIMEOUT_MS;
    this.maxAttempts = options.maxAttempts ?? DEFAULT_TOKEN_ATTEMPTS;
    this.baseDelayMs = options.baseDelayMs ?? DEFAULT_TOKEN_BASE_DELAY_MS;
  }

  async getToken(): Promise<string> {
    if (this.cached && this.now() < this.cached.expiresAtMs - this.refreshSkewMs) {
      return this.cached.token;
    }

    this.inFlight ??= this.acquire().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  invalidate(): void {
    this.cached = undefined;
  }

  private async acquire(): Promise<string> {
    let credential: GraphCredential;
    try {
      credential = await this.source();
    } catch (error) {
      // Messages from credential loading are written to be free of secret
      // material (see parseCertificateBundle / graph.credential.ts)
      throw new GraphAuthError(
        `Graph ${this.label} credential could not be loaded: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
        { label: this.label }
      );
    }

    const endpoint = tokenEndpoint(credential.tenantId);

    const result = await withRetry(() => this.requestToken(endpoint, credential), {
      maxRetries: this.maxAttempts,
      baseDelayMs: this.baseDelayMs,
      maxDelayMs: 5000,
      shouldRetry: error =>
        !(error instanceof GraphAuthError) ||
        error.status === undefined ||
        error.status === 429 ||
        error.status >= 500,
    });

    this.cached = {
      token: result.access_token,
      expiresAtMs: this.now() + result.expires_in * 1000,
    };
    logger.info('Graph access token acquired', {
      label: this.label,
      expiresInSeconds: result.expires_in,
    });

    return result.access_token;
  }

  private async requestToken(
    endpoint: string,
    credential: GraphCredential
  ): Promise<z.infer<typeof TokenResponseSchema>> {
    // A fresh assertion per attempt: each carries a unique jti
    const body = new URLSearchParams({
      client_id: credential.clientId,
      scope: GRAPH_DEFAULT_SCOPE,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: buildClientAssertion(credential, this.now()),
      grant_type: 'client_credentials',
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let status: number;
    let payload: unknown;
    try {
      const response = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: body.toString(),
        redirect: 'error',
        signal: controller.signal,
      });
      status = response.status;
      payload = await response.json().catch(() => undefined);
    } catch {
      // The underlying error is deliberately dropped: it is not needed to
      // act on the failure, and nothing about the request may leak
      throw new GraphAuthError(
        controller.signal.aborted
          ? `Graph ${this.label} token request timed out after ${this.timeoutMs}ms`
          : `Graph ${this.label} token request failed: network error`,
        { label: this.label }
      );
    } finally {
      clearTimeout(timer);
    }

    if (status < 200 || status >= 300) {
      const failure = TokenErrorSchema.safeParse(payload);
      const details = failure.success ? failure.data : {};
      const codes = details.error_codes?.length ? ` AADSTS${details.error_codes.join(',')}` : '';
      throw new GraphAuthError(
        `Graph ${this.label} token request rejected: status ${status} ${
          details.error ?? 'unknown_error'
        }${codes}`,
        {
          label: this.label,
          status,
          code: details.error,
          errorCodes: details.error_codes,
          traceId: details.trace_id,
          correlationId: details.correlation_id,
        }
      );
    }

    const parsed = TokenResponseSchema.safeParse(payload);
    if (!parsed.success) {
      throw new GraphAuthError(
        `Graph ${this.label} token response was malformed: status ${status} invalid_response`,
        { label: this.label, status, code: 'invalid_response' }
      );
    }
    return parsed.data;
  }
}

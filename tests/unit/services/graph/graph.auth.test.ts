/**
 * Graph authentication tests: certificate parsing, client assertion, token cache
 *
 * All key material is generated in memory by the test; fetch is mocked.
 */

import { constants, createHash, generateKeyPairSync, verify } from 'crypto';
import {
  GraphAuthError,
  GraphCredential,
  GraphTokenProvider,
  buildClientAssertion,
  parseCertificateBundle,
  tokenEndpoint,
} from '../../../../src/services/graph';
import { TestCertificate, generateTestCertificate } from '../../../mocks/graph.testcert';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const ACCESS_TOKEN = 'test-access-token-7f3c9a';

let testCert: TestCertificate;
let credential: GraphCredential;

beforeAll(() => {
  testCert = generateTestCertificate();
  credential = {
    label: 'read',
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    certificate: parseCertificateBundle(testCert.bundlePem),
  };
});

function decodeSegment(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

function tokenResponse(
  body: unknown = { token_type: 'Bearer', expires_in: 3600, access_token: ACCESS_TOKEN },
  status = 200
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

type FetchCall = [string, RequestInit];
type FetchMock = jest.Mock<Promise<Response>, FetchCall>;

function fetchReturning(...responses: Array<() => Response | Promise<Response>>): FetchMock {
  const mock = jest.fn<Promise<Response>, FetchCall>();
  responses.forEach(make => mock.mockImplementationOnce(() => Promise.resolve(make())));
  mock.mockImplementation(() => Promise.reject(new Error('unexpected fetch call')));
  return mock;
}

function provider(
  fetchMock: FetchMock,
  options: { now?: () => number; timeoutMs?: number } = {}
): GraphTokenProvider {
  return new GraphTokenProvider('read', () => Promise.resolve(credential), {
    fetchImpl: fetchMock as unknown as typeof fetch,
    baseDelayMs: 1,
    ...options,
  });
}

describe('parseCertificateBundle', () => {
  it('derives the x5t#S256 thumbprint from the certificate DER', () => {
    const parsed = parseCertificateBundle(testCert.bundlePem);
    const expected = createHash('sha256').update(testCert.certificateDer).digest('base64url');
    expect(parsed.thumbprintS256).toBe(expected);
    expect(parsed.thumbprintS256).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(parsed.privateKey.type).toBe('private');
    expect(parsed.notAfter.getTime()).toBeGreaterThan(Date.now());
  });

  it('accepts the certificate before the key', () => {
    const parsed = parseCertificateBundle(`${testCert.certificatePem}${testCert.privateKeyPem}`);
    expect(parsed.thumbprintS256).toBe(credential.certificate.thumbprintS256);
  });

  it('accepts the JSON form', () => {
    const parsed = parseCertificateBundle(
      JSON.stringify({ privateKey: testCert.privateKeyPem, certificate: testCert.certificatePem })
    );
    expect(parsed.thumbprintS256).toBe(credential.certificate.thumbprintS256);
  });

  it('accepts PEM with literal \\n sequences (environment variable form)', () => {
    const flattened = testCert.bundlePem.replace(/\n/g, '\\n');
    expect(flattened).not.toContain('\n');
    const parsed = parseCertificateBundle(flattened);
    expect(parsed.thumbprintS256).toBe(credential.certificate.thumbprintS256);
  });

  it('rejects incomplete material', () => {
    expect(() => parseCertificateBundle(testCert.privateKeyPem)).toThrow('no CERTIFICATE block');
    expect(() => parseCertificateBundle(testCert.certificatePem)).toThrow('no PRIVATE KEY block');
    expect(() => parseCertificateBundle('{"privateKey": 1}')).toThrow('"privateKey" and');
    expect(() => parseCertificateBundle('{not json')).toThrow('could not be parsed');
  });

  it('rejects a passphrase-protected key', () => {
    const encrypted = testCert.privateKey
      .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pw' })
      .toString();
    expect(() => parseCertificateBundle(`${encrypted}${testCert.certificatePem}`)).toThrow(
      'passphrase-protected'
    );
  });

  it('rejects a key that does not belong to the certificate', () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const otherPem = other.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => parseCertificateBundle(`${otherPem}${testCert.certificatePem}`)).toThrow(
      'does not match'
    );
  });

  it('rejects a non-RSA key', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const ecPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => parseCertificateBundle(`${ecPem}${testCert.certificatePem}`)).toThrow('RSA');
  });

  it('never echoes the material in an error', () => {
    const keyBody = testCert.privateKeyPem.split('\n')[1];
    const corruptKey = testCert.privateKeyPem.replace(keyBody, `${keyBody.slice(0, 40)}!!!!`);
    const attempts = [
      `${corruptKey}${testCert.certificatePem}`,
      `${testCert.privateKeyPem}-----BEGIN CERTIFICATE-----\nAAAA${keyBody}\n-----END CERTIFICATE-----`,
      `{"privateKey": "${keyBody}"}`,
    ];
    for (const material of attempts) {
      let message = '';
      try {
        parseCertificateBundle(material);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).not.toBe('');
      expect(message).not.toContain(keyBody.slice(0, 24));
      expect(message).not.toContain('BEGIN');
    }
  });
});

describe('tokenEndpoint', () => {
  it('builds the v2.0 token endpoint for a tenant GUID or domain', () => {
    expect(tokenEndpoint(TENANT_ID)).toBe(
      `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`
    );
    expect(tokenEndpoint('tenant.example.com')).toBe(
      'https://login.microsoftonline.com/tenant.example.com/oauth2/v2.0/token'
    );
  });

  it('refuses tenant values that would alter the URL', () => {
    for (const bad of ['', 'common/../x', 'a/b', 'evil.example.com/x?', 'tenant id', '..']) {
      expect(() => tokenEndpoint(bad)).toThrow('tenantId');
    }
  });
});

describe('buildClientAssertion', () => {
  const NOW_MS = 1_800_000_000_000;

  it('has the documented header', () => {
    const [header] = buildClientAssertion(credential, NOW_MS).split('.');
    expect(decodeSegment(header)).toEqual({
      alg: 'PS256',
      typ: 'JWT',
      'x5t#S256': createHash('sha256').update(testCert.certificateDer).digest('base64url'),
    });
  });

  it('has the documented claims and a short lifetime', () => {
    const [, payload] = buildClientAssertion(credential, NOW_MS).split('.');
    const claims = decodeSegment(payload);
    expect(Object.keys(claims).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub']);
    expect(claims.aud).toBe(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`);
    expect(claims.iss).toBe(CLIENT_ID);
    expect(claims.sub).toBe(CLIENT_ID);
    expect(claims.nbf).toBe(NOW_MS / 1000);
    expect(claims.iat).toBe(NOW_MS / 1000);
    expect((claims.exp as number) - (claims.nbf as number)).toBe(300);
    expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('is signed with RSASSA-PSS / SHA-256 by the certificate key', () => {
    const assertion = buildClientAssertion(credential, NOW_MS);
    const [header, payload, signature] = assertion.split('.');
    expect(assertion.split('.')).toHaveLength(3);
    expect(assertion).not.toMatch(/[+/=]/);

    const pss = {
      key: testCert.publicKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    };
    const signed = Buffer.from(`${header}.${payload}`);
    const signatureBytes = Buffer.from(signature, 'base64url');
    expect(verify('sha256', signed, pss, signatureBytes)).toBe(true);
    // Not PKCS#1 v1.5 (which would be RS256), and bound to the content
    expect(verify('sha256', signed, testCert.publicKey, signatureBytes)).toBe(false);
    expect(verify('sha256', Buffer.from(`${header}.${payload}x`), pss, signatureBytes)).toBe(false);
  });

  it('uses a fresh jti every time', () => {
    const jtis = new Set(
      [1, 2, 3].map(() => decodeSegment(buildClientAssertion(credential, NOW_MS).split('.')[1]).jti)
    );
    expect(jtis.size).toBe(3);
  });
});

describe('GraphTokenProvider', () => {
  it('sends a client-credentials request with a signed assertion', async () => {
    const fetchMock = fetchReturning(() => tokenResponse());
    await expect(provider(fetchMock).getToken()).resolves.toBe(ACCESS_TOKEN);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`);
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('error');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe(
      'application/x-www-form-urlencoded'
    );

    const form = new URLSearchParams(init.body as string);
    expect([...form.keys()].sort()).toEqual([
      'client_assertion',
      'client_assertion_type',
      'client_id',
      'grant_type',
      'scope',
    ]);
    expect(form.get('grant_type')).toBe('client_credentials');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('scope')).toBe('https://graph.microsoft.com/.default');
    expect(form.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    );
    expect(decodeSegment(form.get('client_assertion')!.split('.')[0]).alg).toBe('PS256');
  });

  it('caches the token until shortly before expiry', async () => {
    let now = 1_800_000_000_000;
    const fetchMock = fetchReturning(
      () => tokenResponse({ expires_in: 3600, access_token: 'token-one' }),
      () => tokenResponse({ expires_in: 3600, access_token: 'token-two' })
    );
    const tokens = provider(fetchMock, { now: () => now });

    expect(await tokens.getToken()).toBe('token-one');
    now += 54 * 60 * 1000; // 6 minutes of life left: still outside the refresh window
    expect(await tokens.getToken()).toBe('token-one');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    now += 2 * 60 * 1000; // 4 minutes left: inside the 5-minute refresh window
    expect(await tokens.getToken()).toBe('token-two');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('shares one in-flight request between concurrent callers', async () => {
    let release!: (response: Response) => void;
    const fetchMock = fetchReturning(() => new Promise<Response>(resolve => (release = resolve)));
    const tokens = provider(fetchMock);

    const pending = [tokens.getToken(), tokens.getToken(), tokens.getToken()];
    await new Promise(resolve => setImmediate(resolve));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    release(tokenResponse());
    await expect(Promise.all(pending)).resolves.toEqual([ACCESS_TOKEN, ACCESS_TOKEN, ACCESS_TOKEN]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps separate caches for separate credentials', async () => {
    const readFetch = fetchReturning(() => tokenResponse({ expires_in: 3600, access_token: 'r' }));
    const otherFetch = fetchReturning(() => tokenResponse({ expires_in: 3600, access_token: 'o' }));
    const read = provider(readFetch);
    const other = new GraphTokenProvider('other', () => Promise.resolve(credential), {
      fetchImpl: otherFetch as unknown as typeof fetch,
    });
    expect(await read.getToken()).toBe('r');
    expect(await other.getToken()).toBe('o');
    expect(await read.getToken()).toBe('r');
  });

  it('requests a new token after invalidate()', async () => {
    const fetchMock = fetchReturning(
      () => tokenResponse({ expires_in: 3600, access_token: 'token-one' }),
      () => tokenResponse({ expires_in: 3600, access_token: 'token-two' })
    );
    const tokens = provider(fetchMock);
    expect(await tokens.getToken()).toBe('token-one');
    tokens.invalidate();
    expect(await tokens.getToken()).toBe('token-two');
  });

  it('throws a typed error for a rejected request, without retrying or leaking', async () => {
    const fetchMock = fetchReturning(() =>
      tokenResponse(
        {
          error: 'invalid_client',
          error_description: 'AADSTS700027: Client assertion failed signature validation.',
          error_codes: [700027],
          trace_id: '11111111-aaaa-4bbb-8ccc-222222222222',
          correlation_id: '33333333-dddd-4eee-8fff-444444444444',
        },
        401
      )
    );

    const error = await provider(fetchMock)
      .getToken()
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(GraphAuthError);
    const authError = error as GraphAuthError;
    expect(authError.status).toBe(401);
    expect(authError.code).toBe('invalid_client');
    expect(authError.errorCodes).toEqual([700027]);
    expect(authError.traceId).toBe('11111111-aaaa-4bbb-8ccc-222222222222');
    expect(authError.label).toBe('read');
    expect(authError.message).toBe(
      'Graph read token request rejected: status 401 invalid_client AADSTS700027'
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const assertion = new URLSearchParams(fetchMock.mock.calls[0][1].body as string).get(
      'client_assertion'
    )!;
    const everything = `${authError.message} ${authError.stack} ${JSON.stringify(authError)}`;
    expect(everything).not.toContain(assertion);
    expect(everything).not.toContain(assertion.split('.')[2]);
  });

  it('retries a server error and then succeeds', async () => {
    const fetchMock = fetchReturning(
      () => tokenResponse({ error: 'temporarily_unavailable' }, 503),
      () => tokenResponse()
    );
    await expect(provider(fetchMock).getToken()).resolves.toBe(ACCESS_TOKEN);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const jti = (call: FetchCall): unknown =>
      decodeSegment(
        new URLSearchParams(call[1].body as string).get('client_assertion')!.split('.')[1]
      ).jti;
    expect(jti(fetchMock.mock.calls[0])).not.toBe(jti(fetchMock.mock.calls[1]));
  });

  it('gives up after a bounded number of attempts', async () => {
    const fetchMock = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.resolve(tokenResponse({}, 500))
    );
    await expect(provider(fetchMock).getToken()).rejects.toMatchObject({
      name: 'GraphAuthError',
      status: 500,
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('reports a network failure without the underlying error text', async () => {
    const fetchMock = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.reject(new Error('connect ECONNREFUSED secret-bearing detail'))
    );
    const error = (await provider(fetchMock)
      .getToken()
      .catch((e: unknown) => e)) as GraphAuthError;
    expect(error).toBeInstanceOf(GraphAuthError);
    expect(error.message).toBe('Graph read token request failed: network error');
    expect(error.status).toBeUndefined();
  });

  it('times out a hung token request', async () => {
    const fetchMock = jest.fn<Promise<Response>, FetchCall>(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal!.addEventListener('abort', () => reject(new Error('aborted')));
        })
    );
    const tokens = new GraphTokenProvider('read', () => Promise.resolve(credential), {
      fetchImpl: fetchMock as unknown as typeof fetch,
      timeoutMs: 15,
      maxAttempts: 1,
    });
    await expect(tokens.getToken()).rejects.toThrow(
      'Graph read token request timed out after 15ms'
    );
  });

  it('rejects a malformed token response', async () => {
    const fetchMock = fetchReturning(() => tokenResponse({ token_type: 'Bearer' }));
    await expect(provider(fetchMock).getToken()).rejects.toMatchObject({
      name: 'GraphAuthError',
      code: 'invalid_response',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not cache a failure: the next call tries again', async () => {
    const fetchMock = fetchReturning(
      () => tokenResponse({ error: 'invalid_client' }, 400),
      () => tokenResponse()
    );
    const tokens = provider(fetchMock);
    await expect(tokens.getToken()).rejects.toBeInstanceOf(GraphAuthError);
    await expect(tokens.getToken()).resolves.toBe(ACCESS_TOKEN);
  });

  it('wraps a credential-loading failure and makes no request', async () => {
    const fetchMock = fetchReturning();
    const tokens = new GraphTokenProvider(
      'read',
      () => Promise.reject(new Error('certificate expired on 2020-01-01T00:00:00.000Z')),
      { fetchImpl: fetchMock as unknown as typeof fetch }
    );
    await expect(tokens.getToken()).rejects.toThrow(
      'Graph read credential could not be loaded: certificate expired on 2020-01-01T00:00:00.000Z'
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

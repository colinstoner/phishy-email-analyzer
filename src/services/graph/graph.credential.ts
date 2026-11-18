/**
 * Microsoft Graph credential loading and client construction
 *
 * The certificate setting follows the same convention as the database
 * connection string: it is either an AWS Secrets Manager ARN or the material
 * itself (inline PEM). Unlike the database secret it is resolved lazily, on
 * the first Graph call, so a deployment that never calls Graph never touches
 * the secret and a Secrets Manager failure cannot stop email analysis.
 *
 * Secret material is never logged and never placed in an error message.
 */

import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { GraphConfig } from '../../config/schema';
import { createLogger } from '../../utils/logger';
import {
  GUID_PATTERN,
  GraphCredential,
  GraphTokenProvider,
  GraphTokenProviderOptions,
  TENANT_PATTERN,
  parseCertificateBundle,
} from './graph.auth';
import { GraphClient, GraphClientOptions } from './graph.client';

const logger = createLogger('graph-credential');

const SECRETS_MANAGER_ARN_PREFIX = 'arn:aws:secretsmanager:';
/** Warn when the certificate is this close to expiry */
const EXPIRY_WARNING_MS = 30 * 24 * 60 * 60 * 1000;

/** Fetches a secret's string value by ARN */
export type SecretFetcher = (secretArn: string) => Promise<string>;

/** One app registration as it appears in configuration */
export interface GraphCredentialSettings {
  /** Short name for logs and errors (e.g. `read`) */
  label: string;
  tenantId: string;
  clientId: string;
  /** Secrets Manager ARN, or inline certificate material */
  certificate: string;
}

export interface GraphClientFactoryOptions {
  /** Injected for tests; defaults to AWS Secrets Manager */
  fetchSecret?: SecretFetcher;
  tokenOptions?: GraphTokenProviderOptions;
  clientOptions?: Omit<GraphClientOptions, 'tokenProvider'>;
}

async function fetchSecretFromSecretsManager(secretArn: string): Promise<string> {
  // The region is part of the ARN: arn:aws:secretsmanager:<region>:<account>:secret:<name>
  const arnRegion = secretArn.split(':')[3];
  const region = arnRegion ? arnRegion : (process.env.AWS_REGION ?? 'us-east-1');
  const client = new SecretsManagerClient({ region });
  const response = await client.send(new GetSecretValueCommand({ SecretId: secretArn }));
  if (!response.SecretString) {
    throw new Error('Secret has no string value');
  }
  return response.SecretString;
}

/**
 * Resolve the certificate setting to certificate material: fetched from
 * Secrets Manager when the setting is an ARN, otherwise the setting itself.
 */
export async function resolveCertificateMaterial(
  setting: string,
  fetchSecret: SecretFetcher = fetchSecretFromSecretsManager
): Promise<string> {
  if (!setting.startsWith(SECRETS_MANAGER_ARN_PREFIX)) {
    return setting;
  }
  try {
    return await fetchSecret(setting);
  } catch (error) {
    // Only the SDK's error class is reported; its message is not needed to
    // act on the failure and is kept out of anything that may be logged
    const reason = error instanceof Error ? error.name : 'unknown error';
    throw new Error(`certificate secret could not be read from Secrets Manager (${reason})`, {
      cause: error,
    });
  }
}

/**
 * Load a complete credential (identifiers validated, certificate parsed)
 */
export async function loadGraphCredential(
  settings: GraphCredentialSettings,
  fetchSecret?: SecretFetcher
): Promise<GraphCredential> {
  if (!TENANT_PATTERN.test(settings.tenantId)) {
    throw new Error('tenantId must be a directory (tenant) GUID or a domain name');
  }
  if (!GUID_PATTERN.test(settings.clientId)) {
    throw new Error('clientId must be an application (client) GUID');
  }

  const material = await resolveCertificateMaterial(settings.certificate, fetchSecret);
  const certificate = parseCertificateBundle(material);

  const remainingMs = certificate.notAfter.getTime() - Date.now();
  if (remainingMs <= 0) {
    throw new Error(`certificate expired on ${certificate.notAfter.toISOString()}`);
  }
  if (remainingMs < EXPIRY_WARNING_MS) {
    logger.warn('Graph certificate expires soon; rotate it', {
      label: settings.label,
      notAfter: certificate.notAfter.toISOString(),
    });
  }

  return {
    label: settings.label,
    tenantId: settings.tenantId,
    clientId: settings.clientId,
    certificate,
  };
}

/**
 * Build a Graph client for one app registration. The credential is loaded on
 * first use and then held for the life of the client; a failed load is
 * retried on the next call.
 */
export function createGraphClient(
  settings: GraphCredentialSettings,
  options: GraphClientFactoryOptions = {}
): GraphClient {
  let loading: Promise<GraphCredential> | undefined;
  const source = (): Promise<GraphCredential> => {
    loading ??= loadGraphCredential(settings, options.fetchSecret).catch((error: unknown) => {
      loading = undefined;
      throw error;
    });
    return loading;
  };

  const tokenProvider = new GraphTokenProvider(settings.label, source, options.tokenOptions);
  return new GraphClient({ ...options.clientOptions, tokenProvider });
}

/**
 * Build the read-only Graph client from configuration, or undefined when
 * Graph access is not enabled. Nothing is fetched until the first request.
 */
export function createGraphReadClient(
  config: GraphConfig | undefined,
  options: GraphClientFactoryOptions = {}
): GraphClient | undefined {
  if (!config?.enabled) {
    return undefined;
  }
  if (!config.tenantId || !config.read?.clientId || !config.read.certificate) {
    // The config schema rejects this combination; guard anyway for callers
    // that build a config object by hand
    throw new Error('Graph is enabled but tenantId, read.clientId or read.certificate is missing');
  }
  return createGraphClient(
    {
      label: 'read',
      tenantId: config.tenantId,
      clientId: config.read.clientId,
      certificate: config.read.certificate,
    },
    options
  );
}

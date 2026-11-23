/**
 * Microsoft Graph credential loading: certificate material from Secrets
 * Manager or inline PEM, parsed and checked. A leaf module: it imports no
 * Graph client, so the write broker can load its own credential without
 * bundling the read path's client (graph.credential.ts builds clients on top
 * of this).
 *
 * Secret material is never logged and never placed in an error message.
 */

import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { createLogger } from '../../utils/logger';
import {
  GUID_PATTERN,
  GraphCredential,
  TENANT_PATTERN,
  parseCertificateBundle,
} from './graph.auth';

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

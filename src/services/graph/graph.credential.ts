/**
 * Microsoft Graph credential loading and client construction
 *
 * The certificate setting follows the same convention as the database
 * connection string: it is either an AWS Secrets Manager ARN or the material
 * itself (inline PEM). Unlike the database secret it is resolved lazily, on
 * the first Graph call, so a deployment that never calls Graph never touches
 * the secret and a Secrets Manager failure cannot stop email analysis.
 * Loading itself lives in certificate.loader.ts (no client imports).
 *
 * Secret material is never logged and never placed in an error message.
 */

import { GraphConfig } from '../../config/schema';
import { GraphCredential, GraphTokenProvider, GraphTokenProviderOptions } from './graph.auth';
import { GraphClient, GraphClientOptions } from './graph.client';
import { GraphCredentialSettings, SecretFetcher, loadGraphCredential } from './certificate.loader';

export {
  GraphCredentialSettings,
  SecretFetcher,
  loadGraphCredential,
  resolveCertificateMaterial,
} from './certificate.loader';

export interface GraphClientFactoryOptions {
  /** Injected for tests; defaults to AWS Secrets Manager */
  fetchSecret?: SecretFetcher;
  tokenOptions?: GraphTokenProviderOptions;
  clientOptions?: Omit<GraphClientOptions, 'tokenProvider'>;
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

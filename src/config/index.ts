/**
 * Configuration Loader
 * Loads configuration from multiple sources with priority chain
 */

import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { Readable } from 'stream';
import {
  PhishyConfig,
  PartialPhishyConfig,
  safeValidateConfig,
} from './schema';
import { createLogger } from '../utils/logger';

const logger = createLogger('config');

/** Cache for secrets to avoid repeated API calls */
let cachedDbConnectionString: string | null = null;

/**
 * Configuration priority (highest to lowest):
 * 1. Environment variables (runtime overrides)
 * 2. S3 configuration file
 * 3. Local configuration file
 * 4. Default values
 */

/**
 * Environment variable mappings for backwards compatibility
 */
const ENV_MAPPINGS: Record<string, string> = {
  // AI
  ANTHROPIC_API_KEY: 'ai.anthropic.apiKey',
  CLAUDE_MODEL: 'ai.anthropic.model',
  PHISHY_AI_PROVIDER: 'ai.provider',
  PHISHY_BEDROCK_REGION: 'ai.bedrock.region',
  PHISHY_BEDROCK_MODEL: 'ai.bedrock.modelId',

  // Email
  SAFE_DOMAINS: 'email.safeDomains',
  SAFE_SENDERS: 'email.safeSenders',
  DELETE_EMAILS_AFTER_PROCESSING: 'email.deleteAfterProcessing',

  // Notification
  SENDER_EMAIL: 'notification.senderEmail',
  SECURITY_TEAM_DISTRIBUTION: 'notification.securityTeamDistribution',
  SAFE_SENDER_SECURITY: 'notification.safeSenderSecurity',
  SES_CONFIG_SET: 'notification.sesConfigSet',

  // Storage
  S3_BUCKET_NAME: 'storage.s3Bucket',
  S3_PREFIX: 'storage.s3Prefix',
  PHISHY_AWS_REGION: 'storage.region',
  AWS_REGION: 'storage.region',

  // Intelligence
  PHISHY_INTELLIGENCE_ENABLED: 'intelligence.enabled',
  PHISHY_DB_CONNECTION: 'intelligence.connectionString',

  // Campaign Alerts
  PHISHY_CAMPAIGN_ALERTS_ENABLED: 'campaignAlerts.enabled',
  PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION: 'campaignAlerts.distributionList',

  // Profile
  PHISHY_PROFILE: 'profile',

  // Logging
  LOG_LEVEL: 'logLevel',
};

/**
 * Load configuration from all sources
 */
export async function loadConfig(): Promise<PhishyConfig> {
  logger.info('Loading configuration');

  // Start with defaults
  let config = getDefaultConfig();

  // Try to load from S3 if configured
  const s3ConfigPath = process.env.PHISHY_CONFIG_S3;
  if (s3ConfigPath) {
    try {
      const s3Config = await loadConfigFromS3(s3ConfigPath);
      config = mergeConfigs(config, s3Config);
      logger.info('Loaded configuration from S3', { path: s3ConfigPath });
    } catch (error) {
      logger.warn('Failed to load S3 configuration', {
        path: s3ConfigPath,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Apply environment variable overrides
  config = applyEnvironmentOverrides(config);

  // Resolve secrets from AWS Secrets Manager if configured
  config = await resolveSecrets(config);

  // Validate final configuration
  const validation = safeValidateConfig(config);

  if (!validation.success) {
    logger.error('Configuration validation failed', {
      errors: validation.errors?.format(),
    });
    throw new Error(`Invalid configuration: ${validation.errors?.message}`);
  }

  logger.info('Configuration loaded successfully', {
    provider: validation.data!.ai.provider,
    safeDomains: validation.data!.email.safeDomains.length,
    intelligenceEnabled: validation.data!.intelligence?.enabled ?? false,
  });

  return validation.data!;
}

/**
 * Get default configuration
 */
function getDefaultConfig(): PartialPhishyConfig {
  return {
    ai: {
      provider: 'anthropic',
      anthropic: {
        apiKey: '',
        model: 'claude-sonnet-4-5-20250514',
        maxTokens: 4096,
        timeout: 60000,
      },
      bedrock: {
        region: 'us-east-1',
        modelId: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        maxTokens: 4096,
        timeout: 60000,
      },
    },
    email: {
      safeDomains: ['example.com'],
      safeSenders: [],
      deleteAfterProcessing: false,
    },
    notification: {
      senderEmail: 'noreply@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: [],
      safeSenderSecurity: [],
    },
    storage: {
      s3Bucket: 'phishy-emails',
      s3Prefix: 'emails',
      region: process.env.AWS_REGION ?? 'us-east-1',
    },
    intelligence: {
      enabled: false,
      type: 'postgres',
    },
    logLevel: 'info',
  };
}

/**
 * Resolve secrets from AWS Secrets Manager
 * If intelligence.connectionString starts with 'arn:aws:secretsmanager:',
 * fetch the actual value from Secrets Manager
 */
async function resolveSecrets(config: PartialPhishyConfig): Promise<PartialPhishyConfig> {
  const connectionString = config.intelligence?.connectionString;

  if (!connectionString?.startsWith('arn:aws:secretsmanager:')) {
    return config;
  }

  // Use cached value if available
  if (cachedDbConnectionString) {
    return {
      ...config,
      intelligence: {
        ...config.intelligence,
        connectionString: cachedDbConnectionString,
      },
    };
  }

  try {
    logger.info('Fetching database credentials from Secrets Manager');

    const region = process.env.AWS_REGION ?? 'us-east-1';
    const client = new SecretsManagerClient({ region });

    const response = await client.send(
      new GetSecretValueCommand({ SecretId: connectionString })
    );

    let resolvedConnectionString: string;

    if (response.SecretString) {
      // Try to parse as JSON (Secrets Manager often stores key-value pairs)
      try {
        const secret = JSON.parse(response.SecretString) as Record<string, string>;
        // Support common formats: { connectionString: "..." } or { url: "..." } or { password: "..." }
        if (secret.connectionString) {
          resolvedConnectionString = secret.connectionString;
        } else if (secret.url) {
          resolvedConnectionString = secret.url;
        } else if (secret.password && secret.username && secret.host) {
          // Build connection string from components
          const port = secret.port ?? '5432';
          const database = secret.database ?? secret.dbname ?? 'phishy';
          resolvedConnectionString = `postgresql://${secret.username}:${secret.password}@${secret.host}:${port}/${database}`;
        } else {
          // Use raw secret string
          resolvedConnectionString = response.SecretString;
        }
      } catch {
        // Not JSON, use raw string
        resolvedConnectionString = response.SecretString;
      }
    } else {
      throw new Error('Secret has no string value');
    }

    // Cache for subsequent calls
    cachedDbConnectionString = resolvedConnectionString;

    logger.info('Database credentials resolved from Secrets Manager');

    return {
      ...config,
      intelligence: {
        ...config.intelligence,
        connectionString: resolvedConnectionString,
      },
    };
  } catch (error) {
    logger.error('Failed to fetch secret from Secrets Manager', {
      error: error instanceof Error ? error.message : String(error),
    });
    throw new Error(`Failed to resolve database secret: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Load configuration from S3
 */
async function loadConfigFromS3(s3Path: string): Promise<PartialPhishyConfig> {
  // Parse S3 path: s3://bucket/key
  const match = s3Path.match(/^s3:\/\/([^/]+)\/(.+)$/);
  if (!match) {
    throw new Error(`Invalid S3 path: ${s3Path}`);
  }

  const [, bucket, key] = match;
  const region = process.env.AWS_REGION ?? 'us-east-1';
  const client = new S3Client({ region });

  const response = await client.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: key,
    })
  );

  if (!response.Body) {
    throw new Error('Empty response from S3');
  }

  const content = await streamToString(response.Body as Readable);
  return JSON.parse(content) as PartialPhishyConfig;
}

/**
 * Apply environment variable overrides to configuration
 */
function applyEnvironmentOverrides(config: PartialPhishyConfig): PartialPhishyConfig {
  const result = { ...config };

  for (const [envVar, configPath] of Object.entries(ENV_MAPPINGS)) {
    const value = process.env[envVar];
    if (value !== undefined) {
      setNestedValue(result, configPath, parseEnvValue(envVar, value));
    }
  }

  return result;
}

/**
 * Parse environment variable value to appropriate type
 */
function parseEnvValue(key: string, value: string): unknown {
  // Boolean values
  if (value.toLowerCase() === 'true') return true;
  if (value.toLowerCase() === 'false') return false;

  // Comma-separated arrays
  if (
    key.includes('DOMAINS') ||
    key.includes('SENDERS') ||
    key.includes('DISTRIBUTION') ||
    key.includes('SAFE_SENDER_SECURITY')
  ) {
    return value.split(',').map(s => s.trim()).filter(Boolean);
  }

  // Numbers
  if (/^\d+$/.test(value)) {
    return parseInt(value, 10);
  }

  return value;
}

/**
 * Set a nested value in an object using dot notation path
 */
function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (!(key in current) || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[keys[keys.length - 1]] = value;
}

/**
 * Deep merge two configuration objects
 */
function mergeConfigs(
  base: PartialPhishyConfig,
  override: PartialPhishyConfig
): PartialPhishyConfig {
  const result = { ...base } as Record<string, unknown>;

  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      typeof result[key] === 'object' &&
      result[key] !== null
    ) {
      result[key] = mergeConfigs(
        result[key] as PartialPhishyConfig,
        value as PartialPhishyConfig
      );
    } else if (value !== undefined) {
      result[key] = value;
    }
  }

  return result as PartialPhishyConfig;
}

/**
 * Convert stream to string
 */
async function streamToString(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];

  return new Promise((resolve, reject) => {
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

// Re-export types
export { PhishyConfig, PartialPhishyConfig } from './schema';

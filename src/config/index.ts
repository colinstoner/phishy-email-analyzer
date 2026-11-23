/**
 * Configuration Loader
 * Loads configuration from multiple sources with priority chain
 */

import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { Readable } from 'stream';
import { z } from 'zod';
import {
  GraphBrokerConfig,
  GraphBrokerConfigSchema,
  GraphWriteBrokerConfig,
  GraphWriteBrokerConfigSchema,
  PhishyConfig,
  PhishyConfigSchema,
  PartialPhishyConfig,
  safeValidateConfig,
} from './schema';
import { createLogger } from '../utils/logger';
import { partitionSecurityTeamMembers } from './security-team';

const logger = createLogger('config');

/** Cache for secrets to avoid repeated API calls */
let cachedDbConnectionString: string | null = null;

/**
 * Configuration priority (highest to lowest):
 * 1. Environment variables (runtime overrides)
 * 2. S3 configuration file (PHISHY_CONFIG_S3)
 * 3. Default values
 * No local configuration file is read: config/phishy.config.json is only a
 * place to keep a file before uploading it to S3.
 */

/**
 * Environment variable mappings for backwards compatibility
 */
export const ENV_MAPPINGS: Readonly<Record<string, string>> = {
  // AI
  ANTHROPIC_API_KEY: 'ai.anthropic.apiKey',
  CLAUDE_MODEL: 'ai.anthropic.model',
  PHISHY_AI_PROVIDER: 'ai.provider',
  PHISHY_BEDROCK_REGION: 'ai.bedrock.region',
  PHISHY_BEDROCK_MODEL: 'ai.bedrock.modelId',
  PHISHY_AI_EFFORT: 'ai.effort',
  PHISHY_AI_REFUSAL_FALLBACK_MODEL: 'ai.refusalFallbackModel',

  // Email
  SAFE_DOMAINS: 'email.safeDomains',
  SAFE_SENDERS: 'email.safeSenders',
  DELETE_EMAILS_AFTER_PROCESSING: 'email.deleteAfterProcessing',

  // Notification
  SENDER_EMAIL: 'notification.senderEmail',
  REPLY_TO_EMAIL: 'notification.replyToEmail',
  SECURITY_TEAM_DISTRIBUTION: 'notification.securityTeamDistribution',
  SECURITY_TEAM_MEMBERS: 'notification.securityTeamMembers',
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

  // Campaign response (incident email, targeted warning, approved actions)
  PHISHY_CAMPAIGN_RESPONSE_ENABLED: 'campaignResponse.enabled',
  PHISHY_CAMPAIGN_RESPONSE_AUDIENCE: 'campaignResponse.audience',
  PHISHY_CAMPAIGN_RESPONSE_EMPLOYEE_WARNING: 'campaignResponse.employeeWarning',
  PHISHY_CAMPAIGN_RESPONSE_LIST_WARNING: 'campaignResponse.distributionWarning',
  PHISHY_CAMPAIGN_RESPONSE_APPROVAL_TTL_HOURS: 'campaignResponse.approvalTtlHours',
  PHISHY_CAMPAIGN_RESPONSE_MAX_WARNINGS: 'campaignResponse.maxWarningsPerCampaign',
  PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MAILBOXES: 'campaignResponse.maxRemovalMailboxes',
  PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MESSAGES: 'campaignResponse.maxRemovalMessages',
  PHISHY_CAMPAIGN_RESPONSE_UPDATE_INTERVAL_MINUTES: 'campaignResponse.updateIntervalMinutes',
  PHISHY_CAMPAIGN_RESPONSE_REACH_THRESHOLD: 'campaignResponse.reachThreshold',
  PHISHY_CAMPAIGN_RESPONSE_CLICKED_INSTRUCTIONS: 'campaignResponse.alreadyClickedInstructions',
  PHISHY_CAMPAIGN_RESPONSE_TIME_ZONE: 'campaignResponse.timeZone',
  // Approved removals: dry_run (default) or live through the Graph write broker
  PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE: 'campaignResponse.removal.mode',
  PHISHY_GRAPH_WRITE_BROKER_FUNCTION: 'campaignResponse.removal.writeBrokerFunctionName',

  // Campaign verdict cache
  PHISHY_CAMPAIGN_CACHE_ENABLED: 'campaignCache.enabled',
  PHISHY_CAMPAIGN_CACHE_TTL_HOURS: 'campaignCache.ttlHours',

  // Email commands
  PHISHY_EMAIL_COMMANDS_ENABLED: 'commands.enabled',

  // Outlook Report-button intake
  PHISHY_REPORT_BUTTON_ENABLED: 'reportButton.enabled',

  // Agentic analysis
  PHISHY_AGENTIC_ENABLED: 'agentic.enabled',
  PHISHY_AGENTIC_MAX_TOOL_ROUNDS: 'agentic.maxToolRounds',

  // Risk-score mode (experimental): model | checklist
  PHISHY_SCORING_MODE: 'scoring.mode',

  // Static attachment analysis
  PHISHY_ATTACHMENT_ANALYSIS_ENABLED: 'attachments.analysis.enabled',
  PHISHY_ATTACHMENT_ANALYSIS_TIME_BUDGET_MS: 'attachments.analysis.timeBudgetMs',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_BYTES: 'attachments.analysis.maxAttachmentBytes',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_UNCOMPRESSED_BYTES: 'attachments.analysis.maxUncompressedBytes',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_ARCHIVE_ENTRIES: 'attachments.analysis.maxArchiveEntries',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_DEPTH: 'attachments.analysis.maxDepth',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_PER_ATTACHMENT: 'attachments.analysis.maxTextPerAttachment',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_TOTAL: 'attachments.analysis.maxTextTotal',

  // Microsoft Graph (optional; certificate is a Secrets Manager ARN or inline PEM)
  PHISHY_GRAPH_ENABLED: 'graph.enabled',
  PHISHY_GRAPH_MODE: 'graph.mode',
  PHISHY_GRAPH_BROKER_FUNCTION: 'graph.brokerFunctionName',
  PHISHY_GRAPH_TENANT_ID: 'graph.tenantId',
  PHISHY_GRAPH_READ_CLIENT_ID: 'graph.read.clientId',
  PHISHY_GRAPH_READ_CERTIFICATE: 'graph.read.certificate',
  PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED: 'graph.originalFetch.enabled',
  PHISHY_GRAPH_BLAST_RADIUS_ENABLED: 'graph.blastRadius.enabled',
  PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS: 'graph.blastRadius.timeBudgetMs',
  PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES: 'graph.blastRadius.maxMailboxes',

  // Graph: sender-relationship check (message trace)
  PHISHY_GRAPH_SENDER_HISTORY_ENABLED: 'graph.senderHistory.enabled',
  PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS: 'graph.senderHistory.lookbackDays',
  PHISHY_GRAPH_SENDER_HISTORY_BURST_WINDOW_HOURS: 'graph.senderHistory.burstWindowHours',
  PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS: 'graph.senderHistory.budgetMs',
  PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MIN_RECIPIENTS: 'graph.senderHistory.fanoutMinRecipients',
  PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER: 'graph.senderHistory.fanoutMultiplier',

  // Graph: scheduled fan-out scan (message trace, no model)
  PHISHY_GRAPH_FANOUT_SCAN_ENABLED: 'graph.fanoutScan.enabled',
  PHISHY_GRAPH_FANOUT_SCAN_OVERLAP_MINUTES: 'graph.fanoutScan.overlapMinutes',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_WINDOW_MINUTES: 'graph.fanoutScan.maxWindowMinutes',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_PAGES: 'graph.fanoutScan.maxPages',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_CANDIDATES: 'graph.fanoutScan.maxCandidates',
  PHISHY_GRAPH_FANOUT_SCAN_REQUEST_ALLOWANCE: 'graph.fanoutScan.requestAllowancePer5Min',
  PHISHY_GRAPH_FANOUT_SCAN_BUDGET_MS: 'graph.fanoutScan.budgetMs',
  PHISHY_GRAPH_FANOUT_SCAN_DEDUPE_HOURS: 'graph.fanoutScan.dedupeHours',

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

  warnAboutCredentialInBrokerMode(config);
  warnAboutWriteCredential(config);
  for (const warning of ignoredConfigKeyWarnings(config)) {
    logger.warn(warning);
  }

  // Validate final configuration
  const validation = safeValidateConfig(config);

  if (!validation.success) {
    logger.error('Configuration validation failed', {
      errors: validation.errors?.format(),
    });
    throw new Error(`Invalid configuration: ${validation.errors?.message}`);
  }

  // Command and approval authority only for member addresses on a safe
  // domain: a typo must not authorize an outside address. The count only,
  // never the addresses.
  const notification = validation.data!.notification;
  const members = partitionSecurityTeamMembers(
    notification.securityTeamMembers,
    validation.data!.email.safeDomains
  );
  if (members.ignored > 0) {
    logger.warn(
      `notification.securityTeamMembers (SECURITY_TEAM_MEMBERS): ${members.ignored} address(es) ` +
        'not on a safe domain (email.safeDomains) ignored; they cannot issue commands or approvals'
    );
  }
  notification.securityTeamMembers = members.accepted;

  logger.info('Configuration loaded successfully', {
    provider: validation.data!.ai.provider,
    safeDomains: validation.data!.email.safeDomains.length,
    intelligenceEnabled: validation.data!.intelligence?.enabled ?? false,
  });

  return validation.data!;
}

/**
 * In broker mode the main function must hold no Graph credential. The schema
 * drops `graph.tenantId` and `graph.read` either way; this says so when
 * certificate material itself (not a Secrets Manager ARN) was supplied,
 * because that material should not be in this function's environment at all.
 */
function warnAboutCredentialInBrokerMode(config: PartialPhishyConfig): void {
  const graph = config.graph;
  if (!graph?.enabled || graph.mode !== 'broker') {
    return;
  }
  const certificate = graph.read?.certificate?.trim();
  if (certificate && !certificate.startsWith('arn:aws:secretsmanager:')) {
    logger.warn(
      'graph.mode is broker but inline certificate material is configured for this function. ' +
        'It is ignored here; remove it so only the Graph broker holds the credential'
    );
  }
}

/**
 * The write credential belongs to the Graph write broker alone. The main
 * function's schema has no place for it (a `graph.write` key is dropped and
 * the write broker's variables have no mapping here), so it is never part of
 * this function's configuration; this says so when someone put it here
 * anyway, so it can be removed from the environment too. Names only, never
 * a value.
 */
function warnAboutWriteCredential(config: PartialPhishyConfig): void {
  const present = GRAPH_WRITE_CREDENTIAL_ENV.filter(name => process.env[name] !== undefined);
  const graph = (config.graph ?? {}) as Record<string, unknown>;
  if (present.length > 0 || graph.write !== undefined) {
    logger.warn(
      'A Graph write credential is configured for this function ' +
        `(${[...present, ...(graph.write !== undefined ? ['graph.write'] : [])].join(', ')}). ` +
        'It is ignored here; only the Graph write broker may hold it. Remove it'
    );
  }
}

/**
 * Environment variables of the Graph write broker function and the
 * configuration path each sets in `GraphWriteBrokerConfigSchema`. Read by
 * `loadGraphWriteBrokerConfig` only; deliberately not in `ENV_MAPPINGS`, so
 * setting them on the main function (or the read broker) does nothing.
 */
export const GRAPH_WRITE_ENV_MAPPINGS: Readonly<Record<string, string>> = {
  PHISHY_GRAPH_WRITE_ENABLED: 'enabled',
  PHISHY_GRAPH_TENANT_ID: 'tenantId',
  PHISHY_GRAPH_WRITE_CLIENT_ID: 'clientId',
  PHISHY_GRAPH_WRITE_CERTIFICATE: 'certificate',
  PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS: 'allowedMailboxIds',
  LOG_LEVEL: 'logLevel',
};

/** The write broker's credential variables, which no other function should have */
const GRAPH_WRITE_CREDENTIAL_ENV = [
  'PHISHY_GRAPH_WRITE_CLIENT_ID',
  'PHISHY_GRAPH_WRITE_CERTIFICATE',
];

/**
 * Load the Graph write broker's configuration from its own environment only.
 * No S3 file is read: the shared configuration file is written for the main
 * function, and nothing in it may enable or widen the write tier. Throws
 * (with paths and fixed messages only) when the settings are invalid.
 */
export function loadGraphWriteBrokerConfig(
  env: NodeJS.ProcessEnv = process.env
): GraphWriteBrokerConfig {
  const raw: Record<string, unknown> = {};
  for (const [name, key] of Object.entries(GRAPH_WRITE_ENV_MAPPINGS)) {
    const value = env[name];
    if (value === undefined) {
      continue;
    }
    if (key === 'enabled') {
      // Only an explicit "true" turns writes on; anything else is off
      raw.enabled = value.trim().toLowerCase() === 'true';
    } else if (key === 'allowedMailboxIds') {
      const ids = value
        .split(',')
        .map(id => id.trim().toLowerCase())
        .filter(id => id.length > 0);
      if (ids.length > 0) {
        raw.allowedMailboxIds = ids;
      }
    } else if (value.trim().length > 0) {
      raw[key] = value.trim();
    }
  }
  const validation = GraphWriteBrokerConfigSchema.safeParse(raw);
  if (!validation.success) {
    const issues = validation.error.issues.map(issue => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));
    logger.error('Graph write broker configuration validation failed', { issues });
    throw new Error('Invalid Graph write broker configuration');
  }
  return validation.data;
}

/**
 * Keys the schema still accepts, so existing configurations keep loading,
 * but that nothing reads. One fixed message per key that was set explicitly
 * (in the S3 file or the environment); values are never logged.
 */
export function ignoredConfigKeyWarnings(config: PartialPhishyConfig): string[] {
  const warnings: string[] = [];
  if (config.storage?.s3Prefix !== undefined) {
    warnings.push(
      'storage.s3Prefix (S3_PREFIX) is set but ignored: the object key comes from the SES ' +
        'receipt and the fallback key is always emails/<message-id>. Remove it'
    );
  }
  if (config.intelligence?.type === 'dynamodb') {
    warnings.push(
      'intelligence.type is dynamodb, which is not implemented and is ignored: the ' +
        'intelligence database is PostgreSQL (intelligence.connectionString). Remove it'
    );
  }
  if (config.intelligence?.tableName !== undefined) {
    warnings.push('intelligence.tableName is set but ignored (nothing reads it). Remove it');
  }
  return warnings;
}

/**
 * Load the Graph broker's configuration: the same sources and the same
 * `graph.*` names as the main function (optional S3 file, then environment
 * variables), validated against the broker's own schema. Nothing but
 * `graph.*` and the log level is read, so the broker needs no email, AI,
 * database or notification settings, and no database secret is resolved.
 */
export async function loadGraphBrokerConfig(): Promise<GraphBrokerConfig> {
  let config: PartialPhishyConfig = {} as PartialPhishyConfig;

  const s3ConfigPath = process.env.PHISHY_CONFIG_S3;
  if (s3ConfigPath) {
    try {
      config = mergeConfigs(config, await loadConfigFromS3(s3ConfigPath));
    } catch (error) {
      logger.warn('Failed to load S3 configuration', {
        path: s3ConfigPath,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  config = applyEnvironmentOverrides(config);

  const validation = GraphBrokerConfigSchema.safeParse({
    graph: config.graph ?? {},
    logLevel: config.logLevel,
  });
  if (!validation.success) {
    // Paths and fixed messages only: never a configured value
    const issues = validation.error.issues.map(issue => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));
    logger.error('Graph broker configuration validation failed', { issues });
    throw new Error('Invalid Graph broker configuration');
  }
  return validation.data;
}

/**
 * Get default configuration
 */
function getDefaultConfig(): PartialPhishyConfig {
  return {
    ai: {
      provider: 'anthropic',
      // Note: anthropic.apiKey is NOT set here - it must come from env or config
      // This allows bedrock provider to work without requiring an Anthropic key
      bedrock: {
        region: 'us-east-1',
        modelId: 'global.anthropic.claude-opus-5-5',
        maxTokens: 16000,
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
      securityTeamMembers: [],
      safeSenderSecurity: [],
    },
    storage: {
      s3Bucket: 'phishy-emails',
      // s3Prefix is left to the schema default so an explicit (ignored) value can be warned about
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

    const response = await client.send(new GetSecretValueCommand({ SecretId: connectionString }));

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
    throw new Error(
      `Failed to resolve database secret: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
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
      setNestedValue(result, configPath, parseEnvValue(configPath, value));
    }
  }

  return result;
}

/** The shape an environment variable's value takes, decided by its target in the schema */
export type EnvValueKind = 'boolean' | 'number' | 'list' | 'string';

interface SchemaDef {
  type: string;
  innerType?: z.ZodType;
  in?: z.ZodType;
  shape?: Record<string, z.ZodType>;
}

function schemaDef(schema: z.ZodType): SchemaDef {
  return schema._zod.def;
}

/** Strip optional / default / transform wrappers down to the schema that holds the value */
function unwrapSchema(schema: z.ZodType): z.ZodType {
  let current = schema;
  for (;;) {
    const def = schemaDef(current);
    if (def.innerType) {
      current = def.innerType;
    } else if (def.type === 'pipe' && def.in) {
      current = def.in;
    } else {
      return current;
    }
  }
}

/**
 * The kind of value the schema expects at a dotted configuration path. List
 * versus scalar (and number versus string) is decided by the target field, not
 * by the variable's name. Throws for a path the schema does not have, so a
 * mapping that drifts from the schema fails loudly in tests.
 */
export function envValueKind(configPath: string): EnvValueKind {
  let schema: z.ZodType = PhishyConfigSchema;
  for (const segment of configPath.split('.')) {
    const def = schemaDef(unwrapSchema(schema));
    const next = def.type === 'object' ? def.shape?.[segment] : undefined;
    if (!next) {
      throw new Error(`No configuration schema field at ${configPath}`);
    }
    schema = next;
  }
  switch (schemaDef(unwrapSchema(schema)).type) {
    case 'boolean':
      return 'boolean';
    case 'number':
      return 'number';
    case 'array':
      return 'list';
    default:
      return 'string';
  }
}

/** A plain decimal number: digits, optionally a fractional part, optionally negative */
const DECIMAL_NUMBER = /^-?\d+(?:\.\d+)?$/;

/**
 * Parse an environment variable's value into the type its target field
 * expects. Conversion is decided by the schema, so string fields (IDs,
 * account numbers, model IDs, GUIDs, values with leading zeros) are never
 * turned into numbers or booleans. A value that does not fit is passed on
 * unchanged and fails validation with the field's own message.
 */
export function parseEnvValue(configPath: string, value: string): unknown {
  switch (envValueKind(configPath)) {
    case 'list':
      return value
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
    case 'boolean':
      if (value.toLowerCase() === 'true') return true;
      if (value.toLowerCase() === 'false') return false;
      return value;
    case 'number':
      return DECIMAL_NUMBER.test(value.trim()) ? Number(value.trim()) : value;
    default:
      return value;
  }
}

/** Keys that reach the prototype chain instead of naming a config value */
const UNSAFE_PATH_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Set a nested value in an object using dot notation path. Throws on a
 * `__proto__`, `constructor` or `prototype` segment (every mapped path is
 * code-defined, so that is a programming error, never input to tolerate).
 */
export function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split('.');
  // A path segment that names the prototype chain would write onto
  // Object.prototype (or a constructor) instead of into the config. Checked
  // segment by segment, right where each one is used as a key.
  const safeKey = (key: string): string => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error(`Refusing config path with a reserved segment: ${path}`);
    }
    return key;
  };
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = safeKey(keys[i]);
    if (!Object.prototype.hasOwnProperty.call(current, key) || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[safeKey(keys[keys.length - 1])] = value;
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
    // JSON.parse makes "__proto__" an own key; assigning it would swap the
    // result's prototype rather than set a config value
    if (UNSAFE_PATH_KEYS.has(key)) continue;
    if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      typeof result[key] === 'object' &&
      result[key] !== null
    ) {
      result[key] = mergeConfigs(result[key] as PartialPhishyConfig, value as PartialPhishyConfig);
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

export { partitionSecurityTeamMembers, securityTeamCommandSenders } from './security-team';

// Re-export types
export {
  GraphBrokerConfig,
  GraphWriteBrokerConfig,
  PhishyConfig,
  PartialPhishyConfig,
} from './schema';

/**
 * Configuration Schema
 * Zod-based validation for Phishy configuration
 */

import { z } from 'zod';
import { EFFORT_LEVELS } from '../services/ai/model.capabilities';

/**
 * AI Provider configuration schemas
 */
const AnthropicConfigSchema = z.object({
  apiKey: z.string().min(1, 'Anthropic API key is required'),
  model: z.string().default('claude-opus-5-5'),
  // Thinking counts toward max_tokens on Opus 5.5 — leave room for it
  maxTokens: z.number().positive().default(16000),
  timeout: z.number().positive().default(60000),
});

const BedrockConfigSchema = z.object({
  region: z.string().default('us-east-1'),
  modelId: z.string().default('global.anthropic.claude-opus-5-5'),
  maxTokens: z.number().positive().default(16000),
  timeout: z.number().positive().default(60000),
});

const AIConfigSchema = z
  .object({
    provider: z.enum(['anthropic', 'bedrock']).default('anthropic'),
    anthropic: AnthropicConfigSchema.optional(),
    bedrock: BedrockConfigSchema.optional(),
    fallbackProvider: z.enum(['anthropic', 'bedrock']).optional(),
    /**
     * How much the model thinks, and so the main cost/latency control. Sent as
     * output_config.effort to models that accept it; omitted for the rest.
     */
    effort: z.enum(EFFORT_LEVELS).default('medium'),
    /**
     * Model a request is retried on, once, when the primary provider's model
     * declines it (stop_reason "refusal"). Must be a model ID for the primary
     * provider. Unset: that provider's built-in default (`claude-opus-4-8` /
     * `global.anthropic.claude-opus-4-8`). Empty string: no retry.
     */
    refusalFallbackModel: z.string().optional(),
  })
  .refine(
    data => {
      // Require anthropic config when provider is anthropic
      if (data.provider === 'anthropic') {
        return data.anthropic?.apiKey && data.anthropic.apiKey.length > 0;
      }
      // Bedrock doesn't require additional config (uses IAM)
      return true;
    },
    {
      message: 'Anthropic API key is required when using anthropic provider',
      path: ['anthropic', 'apiKey'],
    }
  );

/**
 * Email configuration schema
 */
const EmailConfigSchema = z.object({
  safeDomains: z.array(z.string()).default(['example.com']),
  safeSenders: z.array(z.string()).default([]),
  deleteAfterProcessing: z.boolean().default(false),
});

/**
 * Notification configuration schema
 */
const NotificationConfigSchema = z.object({
  senderEmail: z.string().email('Valid sender email required'),
  senderName: z.string().default('Phishy'),
  securityTeamDistribution: z.array(z.string().email()).default([]),
  safeSenderSecurity: z.array(z.string().email()).default([]),
  sesConfigSet: z.string().optional(),
});

/**
 * Storage configuration schema
 */
const StorageConfigSchema = z.object({
  s3Bucket: z.string().min(1, 'S3 bucket name is required'),
  s3Prefix: z.string().default('emails'),
  region: z.string().default('us-east-1'),
});

/**
 * Intelligence/Database configuration schema
 */
const IntelligenceConfigSchema = z.object({
  enabled: z.boolean().default(false),
  type: z.enum(['postgres', 'dynamodb']).default('postgres'),
  connectionString: z.string().optional(),
  tableName: z.string().optional(),
});

/**
 * Campaign alert configuration schema
 */
const CampaignAlertConfigSchema = z.object({
  enabled: z.boolean().default(false),
  distributionList: z.string().email().optional(),
});

/**
 * Email commands configuration schema
 * Lets the security team reply to Phishy's reports (or email Phishy
 * directly) to correct verdicts and trigger actions. Senders must be in
 * notification.securityTeamDistribution AND pass SES SPF/DKIM checks.
 * Requires the intelligence database and migration 002.
 */
const CommandsConfigSchema = z.object({
  enabled: z.boolean().default(false),
});

/**
 * Outlook Report-button intake configuration schema
 * When the organization's Microsoft 365 "user reported settings" deliver
 * Report-button submissions to Phishy, recognize them and handle them
 * silently: phishing reports are analyzed and recorded and only the security
 * team is told (when the verdict warrants it); junk / not-junk reports are
 * skipped. The reporter is never emailed. Off by default — without it a
 * button report is treated like any other forward.
 */
const ReportButtonConfigSchema = z.object({
  enabled: z.boolean().default(false),
});

/**
 * Agentic analysis configuration schema
 * Runs analysis as a bounded tool-use loop: Claude may consult Phishy's own
 * threat intelligence (known indicators, campaign history, URL inspection,
 * enterprise profile) before delivering its verdict. Also enables AI
 * interpretation of free-text security-team commands. Falls back to the
 * standard single-shot analysis on any failure.
 */
const AgenticConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** Maximum tool-use rounds before the model must deliver a verdict */
  maxToolRounds: z.number().int().min(1).max(10).default(5),
});

/**
 * Campaign verdict cache configuration schema
 * Reuses a recent analysis verdict for reports matching the same campaign
 * signature, instead of paying for a fresh AI analysis per duplicate report.
 * Requires the intelligence database and migration 003.
 */
const CampaignCacheConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** How long a verdict may be reused before the campaign is re-analyzed */
  ttlHours: z.number().positive().max(168).default(24),
});

/**
 * Microsoft Graph configuration schema
 * Optional, app-only access to the organization's own Microsoft 365 tenant.
 * One tenant; each kind of access has its own app registration, authenticated
 * with a certificate (never a client secret). Only the `read` registration
 * exists today — a `write` registration, when added, is a sibling key with
 * its own clientId and certificate so the two can never share a token.
 *
 * Formats are enforced only when enabled, so stray or empty values cannot
 * break a deployment that has Graph switched off.
 */
const GRAPH_GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const GRAPH_TENANT_DOMAIN = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

const GraphCredentialConfigSchema = z.object({
  /** Application (client) ID of the app registration */
  clientId: z.string().optional(),
  /** Secrets Manager ARN, or inline PEM (private key + certificate) */
  certificate: z.string().optional(),
});

/**
 * Original-message fetch: before analysis, look up the original of a
 * forwarded email in the reporter's own mailbox and read its Internet
 * headers. Has effect only when `graph.enabled` is also true.
 */
const GraphOriginalFetchConfigSchema = z.object({
  enabled: z.boolean().default(false),
});

/**
 * Blast radius: after a malicious verdict, look up who else in the
 * organization received the message and what they did with it, for the
 * security team's copy of the report. Read-only; effective only when
 * `graph.enabled` is true.
 */
const GraphBlastRadiusConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** Hard limit on the whole lookup, in milliseconds */
  timeBudgetMs: z.number().int().min(1000).max(150000).default(45000),
  /** Most mailboxes one lookup will read */
  maxMailboxes: z.number().int().min(1).max(20000).default(2000),
});

/**
 * Sender-relationship check: before analysis, read the organization's own
 * message trace for the claimed external sender and hand the model (and the
 * report) counts about that relationship. Only effective when `graph.enabled`
 * is true. Needs `ExchangeMessageTrace.Read.All` on the read registration.
 */
const GraphSenderHistoryConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** Days of mail-flow records to examine (message trace keeps 90) */
  lookbackDays: z.number().int().min(14).max(90).default(30),
  /** Hours before the email's time treated as the burst, not as history */
  burstWindowHours: z.number().int().min(1).max(72).default(24),
  /** Overall deadline for one lookup; on expiry analysis proceeds without it */
  budgetMs: z.number().int().min(1000).max(30000).default(8000),
  /** Also compute history for the sender's whole domain (never for free-mail domains) */
  includeDomain: z.boolean().default(true),
  /** Extra free-mail domains, added to the built-in list */
  freeMailDomains: z.array(z.string()).default([]),
  /** Fewest distinct burst recipients that can count as anomalous fan-out */
  fanoutMinRecipients: z.number().int().min(2).max(1000).default(10),
  /** Burst recipients must be at least this many times the history recipients */
  fanoutMultiplier: z.number().min(1).max(100).default(3),
});

const GraphConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Directory (tenant) ID, or a verified domain of the tenant */
    tenantId: z.string().optional(),
    /** App registration holding read-only application permissions */
    read: GraphCredentialConfigSchema.optional(),
    /** Fetch the original message's headers from the reporter's mailbox */
    originalFetch: GraphOriginalFetchConfigSchema.optional(),
    /** Who-else-received-it lookup for malicious verdicts */
    blastRadius: GraphBlastRadiusConfigSchema.optional(),
    senderHistory: GraphSenderHistoryConfigSchema.optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.enabled) {
      return;
    }
    if (!data.tenantId) {
      ctx.addIssue({
        code: 'custom',
        path: ['tenantId'],
        message: 'graph.tenantId is required when graph.enabled is true',
      });
    } else if (!GRAPH_GUID.test(data.tenantId) && !GRAPH_TENANT_DOMAIN.test(data.tenantId)) {
      ctx.addIssue({
        code: 'custom',
        path: ['tenantId'],
        message: 'graph.tenantId must be a directory (tenant) GUID or a domain name',
      });
    }
    if (!data.read?.clientId) {
      ctx.addIssue({
        code: 'custom',
        path: ['read', 'clientId'],
        message: 'graph.read.clientId is required when graph.enabled is true',
      });
    } else if (!GRAPH_GUID.test(data.read.clientId)) {
      ctx.addIssue({
        code: 'custom',
        path: ['read', 'clientId'],
        message: 'graph.read.clientId must be an application (client) GUID',
      });
    }
    if (!data.read?.certificate?.trim()) {
      ctx.addIssue({
        code: 'custom',
        path: ['read', 'certificate'],
        message: 'graph.read.certificate is required when graph.enabled is true',
      });
    }
  });

/**
 * Complete Phishy configuration schema
 */
export const PhishyConfigSchema = z.object({
  ai: AIConfigSchema,
  email: EmailConfigSchema,
  notification: NotificationConfigSchema,
  storage: StorageConfigSchema,
  profile: z.string().optional(), // Profile ID or S3 path
  intelligence: IntelligenceConfigSchema.optional(),
  campaignAlerts: CampaignAlertConfigSchema.optional(),
  campaignCache: CampaignCacheConfigSchema.optional(),
  commands: CommandsConfigSchema.optional(),
  reportButton: ReportButtonConfigSchema.optional(),
  agentic: AgenticConfigSchema.optional(),
  graph: GraphConfigSchema.optional(),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  version: z.string().optional(),
});

/**
 * Inferred TypeScript type from schema
 */
export type PhishyConfig = z.infer<typeof PhishyConfigSchema>;
export type AIConfig = z.infer<typeof AIConfigSchema>;
export type AnthropicConfig = z.infer<typeof AnthropicConfigSchema>;
export type BedrockConfig = z.infer<typeof BedrockConfigSchema>;
export type EmailConfig = z.infer<typeof EmailConfigSchema>;
export type NotificationConfig = z.infer<typeof NotificationConfigSchema>;
export type StorageConfig = z.infer<typeof StorageConfigSchema>;
export type IntelligenceConfig = z.infer<typeof IntelligenceConfigSchema>;
export type CampaignAlertConfig = z.infer<typeof CampaignAlertConfigSchema>;
export type CampaignCacheConfig = z.infer<typeof CampaignCacheConfigSchema>;
export type CommandsConfig = z.infer<typeof CommandsConfigSchema>;
export type AgenticConfig = z.infer<typeof AgenticConfigSchema>;
export type GraphConfig = z.infer<typeof GraphConfigSchema>;
export type GraphCredentialConfig = z.infer<typeof GraphCredentialConfigSchema>;
export type GraphBlastRadiusConfig = z.infer<typeof GraphBlastRadiusConfigSchema>;
export type ReportButtonConfig = z.infer<typeof ReportButtonConfigSchema>;
export type GraphSenderHistoryConfig = z.infer<typeof GraphSenderHistoryConfigSchema>;

/**
 * Partial configuration for merging
 */
export type PartialPhishyConfig = z.input<typeof PhishyConfigSchema>;

/**
 * Validate configuration object
 */
export function validateConfig(config: unknown): PhishyConfig {
  return PhishyConfigSchema.parse(config);
}

/**
 * Safely validate configuration, returning errors
 */
export function safeValidateConfig(config: unknown): {
  success: boolean;
  data?: PhishyConfig;
  errors?: z.ZodError;
} {
  const result = PhishyConfigSchema.safeParse(config);

  if (result.success) {
    return { success: true, data: result.data };
  }

  return { success: false, errors: result.error };
}

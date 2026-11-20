/**
 * Configuration Schema
 * Zod-based validation for Phishy configuration
 */

import { z } from 'zod';
import { EFFORT_LEVELS } from '../services/ai/model.capabilities';
import { SCORING_MODES } from '../services/ai/scoring.mode';

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

/** Default "if you already clicked" text in the employee warning */
export const DEFAULT_ALREADY_CLICKED_INSTRUCTIONS =
  'If you clicked a link in it, opened an attachment, or entered your password, contact your IT or security team straight away and change your password. You will not be in trouble: reporting it quickly is what limits the damage.';

/**
 * Campaign response configuration schema
 * What Phishy does once a campaign crosses the alert threshold: an incident
 * email for the security team, a warning to the people who actually received
 * the attack (from blast radius) and proposed response actions approved over
 * the command channel. Off by default; off means the campaign alert behaves
 * exactly as before. Requires campaign alerts, the intelligence database and
 * migration 006.
 */
const CampaignResponseConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /**
   * Who is warned: the distribution list (`campaignAlerts.distributionList`,
   * the behaviour without campaign response), the recipients blast radius
   * found, or both.
   */
  audience: z.enum(['distribution', 'recipients', 'both']).default('distribution'),
  /** The targeted warning to recipients: approved by the security team first, sent at once, or never */
  employeeWarning: z.enum(['off', 'approve', 'auto']).default('approve'),
  /** The distribution-list broadcast: sent at once (as before), approved first, or never */
  distributionWarning: z.enum(['off', 'approve', 'auto']).default('auto'),
  /** How long a proposed action can be approved */
  approvalTtlHours: z.number().positive().max(72).default(4),
  /** Most employee emails (warnings and thank-you notes) one campaign may send */
  maxWarningsPerCampaign: z.number().int().min(1).max(1000).default(100),
  /** Most mailboxes and messages one removal action may name */
  maxRemovalMailboxes: z.number().int().min(1).max(5000).default(500),
  maxRemovalMessages: z.number().int().min(1).max(10000).default(1000),
  /** Shortest gap between incident updates to the security team */
  updateIntervalMinutes: z.number().int().min(1).max(1440).default(30),
  /** The organization's own "if you already clicked" instructions (plain text) */
  alreadyClickedInstructions: z
    .string()
    .min(1)
    .max(1000)
    .default(DEFAULT_ALREADY_CLICKED_INSTRUCTIONS),
  /** IANA time zone the warning's times are written in */
  timeZone: z
    .string()
    .default('UTC')
    .refine(
      zone => {
        try {
          new Intl.DateTimeFormat('en-US', { timeZone: zone });
          return true;
        } catch {
          return false;
        }
      },
      { message: 'campaignResponse.timeZone must be an IANA time zone such as Europe/London' }
    ),
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
 * Static attachment analysis: Phishy reads attachment bytes itself, in
 * process, never executing, rendering or fetching anything, and gives the
 * model computed facts plus bounded, fenced extracted text. Off by default;
 * with it off attachments are reduced to name, type, size and hash as before.
 */
const AttachmentAnalysisConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** Wall-clock budget for every attachment of one email together */
  timeBudgetMs: z.number().int().min(500).max(60000).default(10000),
  /** Attachments larger than this are not inspected (identified only) */
  maxAttachmentBytes: z
    .number()
    .int()
    .min(1024)
    .max(50 * 1024 * 1024)
    .default(25 * 1024 * 1024),
  /** Decompression budget for one email: archive entries, OOXML parts, PDF streams */
  maxUncompressedBytes: z
    .number()
    .int()
    .min(64 * 1024)
    .max(512 * 1024 * 1024)
    .default(64 * 1024 * 1024),
  /** Archive entries listed and examined per archive */
  maxArchiveEntries: z.number().int().min(1).max(5000).default(200),
  /** How deep archives and attached emails are followed */
  maxDepth: z.number().int().min(0).max(5).default(3),
  /** Characters of extracted text shown to the model per attachment (head and tail kept) */
  maxTextPerAttachment: z.number().int().min(0).max(50000).default(8000),
  /** Characters of extracted text shown for all attachments of one email */
  maxTextTotal: z.number().int().min(0).max(150000).default(24000),
});

const AttachmentsConfigSchema = z.object({
  analysis: AttachmentAnalysisConfigSchema.optional(),
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
 * Risk-score mode (experimental). `model` (default): the score shown starts
 * from the model's own free-form riskScore, exactly as before this setting
 * existed. `checklist`: code computes the score from a fixed checklist,
 * answered partly by Phishy itself and partly by the model
 * (services/intelligence/checklist.score.ts); the model's own score is kept
 * for comparison. A missing or malformed checklist falls back to `model`.
 */
const ScoringConfigSchema = z.object({
  mode: z.enum(SCORING_MODES).default('model'),
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
  /** Fewest distinct recipients of one subject in the burst that can count as anomalous fan-out */
  fanoutMinRecipients: z.number().int().min(2).max(1000).default(15),
  /** Those recipients must be at least this many times the history recipients */
  fanoutMultiplier: z.number().min(1).max(100).default(3),
});

/**
 * Scheduled fan-out scan: every few minutes, without waiting for a report,
 * look at recent inbound mail flow (message trace) and alert the security
 * team when an established external contact suddenly sends one subject to
 * many internal people (the sender-relationship rule, run proactively).
 * Code-driven and read-only; no model is involved. Effective only when
 * `graph.enabled` is true, and it needs the intelligence database for its
 * state (dedupe, the scan lock, the window). The thresholds are the
 * sender-relationship check's (`graph.senderHistory.*`).
 */
const GraphFanoutScanConfigSchema = z.object({
  enabled: z.boolean().default(false),
  /** Minutes each scan's window reaches back before the previous scan's end */
  overlapMinutes: z.number().int().min(1).max(30).default(10),
  /** Widest window one scan covers; after a longer gap the oldest part is skipped and said so */
  maxWindowMinutes: z.number().int().min(5).max(120).default(60),
  /** Message trace pages (of up to 5000 rows) one scan may read */
  maxPages: z.number().int().min(1).max(10).default(4),
  /** Candidates (most recipients first) whose sender history one scan checks */
  maxCandidates: z.number().int().min(1).max(10).default(3),
  /** Trace requests all scans together may spend in any 5 minutes (tenant limit: 100) */
  requestAllowancePer5Min: z.number().int().min(5).max(40).default(20),
  /** Hard limit on one scan's Graph work, in milliseconds */
  budgetMs: z.number().int().min(10000).max(120000).default(60000),
  /** A sender-and-subject wave quiet for this long is over; a new one alerts again */
  dedupeHours: z.number().int().min(1).max(168).default(24),
});

/**
 * Lambda function name, alias-qualified name or ARN: the only way the main
 * function addresses the Graph broker. Checked so a stray value cannot turn
 * the invocation into anything else.
 */
const LAMBDA_FUNCTION_REFERENCE = /^[A-Za-z0-9:_-]{1,170}$/;

const GraphConfigFields = z.object({
  enabled: z.boolean().default(false),
  /**
   * Where Graph requests are made. `direct` (the default when unset): by this function, which then
   * holds the read credential and needs a route to Microsoft. `broker`: by a
   * second function (the Graph broker) that this one invokes; this function
   * then holds no Graph credential and never contacts Microsoft.
   */
  mode: z.enum(['direct', 'broker']).optional(),
  /** Name or ARN of the Graph broker function (required when mode is `broker`) */
  brokerFunctionName: z.string().optional(),
  /** Directory (tenant) ID, or a verified domain of the tenant */
  tenantId: z.string().optional(),
  /** App registration holding read-only application permissions */
  read: GraphCredentialConfigSchema.optional(),
  /** Fetch the original message's headers from the reporter's mailbox */
  originalFetch: GraphOriginalFetchConfigSchema.optional(),
  /** Who-else-received-it lookup for malicious verdicts */
  blastRadius: GraphBlastRadiusConfigSchema.optional(),
  senderHistory: GraphSenderHistoryConfigSchema.optional(),
  /** Scheduled, proactive fan-out scan of recent inbound mail flow */
  fanoutScan: GraphFanoutScanConfigSchema.optional(),
});

type GraphConfigFieldValues = z.infer<typeof GraphConfigFields>;
type RefinementContext = z.core.$RefinementCtx<GraphConfigFieldValues>;

/** Whoever talks to Microsoft needs the tenant, the client ID and the certificate */
function requireGraphCredential(data: GraphConfigFieldValues, ctx: RefinementContext): void {
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
}

/**
 * The main function's view of `graph.*`. In `direct` mode it needs the
 * credential. In `broker` mode it needs only the broker's name, and any
 * tenant ID, client ID or certificate found in its configuration is dropped
 * here, so nothing downstream of configuration loading can hold or use it.
 */
const GraphConfigSchema = GraphConfigFields.superRefine((data, ctx) => {
  if (!data.enabled) {
    return;
  }
  if (data.mode === 'broker') {
    if (!data.brokerFunctionName) {
      ctx.addIssue({
        code: 'custom',
        path: ['brokerFunctionName'],
        message: 'graph.brokerFunctionName is required when graph.mode is broker',
      });
    } else if (!LAMBDA_FUNCTION_REFERENCE.test(data.brokerFunctionName)) {
      ctx.addIssue({
        code: 'custom',
        path: ['brokerFunctionName'],
        message: 'graph.brokerFunctionName must be a Lambda function name or ARN',
      });
    }
    return;
  }
  requireGraphCredential(data, ctx);
}).transform((data): GraphConfigFieldValues => {
  if (data.mode !== 'broker') {
    return data;
  }
  const withoutCredential = { ...data };
  delete withoutCredential.tenantId;
  delete withoutCredential.read;
  return withoutCredential;
});

/**
 * The Graph broker's own configuration: `graph.*` and the log level, nothing
 * else. The broker is the function that talks to Microsoft, so it always
 * needs the credential; `graph.mode` and `graph.brokerFunctionName` describe
 * the main function and are ignored here. It needs none of the email, AI,
 * database or notification settings and is not asked for them.
 */
export const GraphBrokerConfigSchema = z.object({
  graph: GraphConfigFields.superRefine((data, ctx) => {
    if (data.enabled) {
      requireGraphCredential(data, ctx);
    }
  }),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
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
  campaignResponse: CampaignResponseConfigSchema.optional(),
  campaignCache: CampaignCacheConfigSchema.optional(),
  commands: CommandsConfigSchema.optional(),
  reportButton: ReportButtonConfigSchema.optional(),
  agentic: AgenticConfigSchema.optional(),
  scoring: ScoringConfigSchema.optional(),
  attachments: AttachmentsConfigSchema.optional(),
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
export type CampaignResponseConfig = z.infer<typeof CampaignResponseConfigSchema>;
export type CommandsConfig = z.infer<typeof CommandsConfigSchema>;
export type AgenticConfig = z.infer<typeof AgenticConfigSchema>;
export type ScoringConfig = z.infer<typeof ScoringConfigSchema>;
export type AttachmentAnalysisConfig = z.infer<typeof AttachmentAnalysisConfigSchema>;
export type GraphConfig = z.infer<typeof GraphConfigSchema>;
export type GraphBrokerConfig = z.infer<typeof GraphBrokerConfigSchema>;
export type GraphCredentialConfig = z.infer<typeof GraphCredentialConfigSchema>;
export type GraphBlastRadiusConfig = z.infer<typeof GraphBlastRadiusConfigSchema>;
export type ReportButtonConfig = z.infer<typeof ReportButtonConfigSchema>;
export type GraphSenderHistoryConfig = z.infer<typeof GraphSenderHistoryConfigSchema>;
export type GraphFanoutScanConfig = z.infer<typeof GraphFanoutScanConfigSchema>;

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

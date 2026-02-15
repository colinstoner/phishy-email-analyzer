/**
 * Configuration Schema
 * Zod-based validation for Phishy configuration
 */

import { z } from 'zod';

/**
 * AI Provider configuration schemas
 */
const AnthropicConfigSchema = z.object({
  apiKey: z.string().min(1, 'Anthropic API key is required'),
  model: z.string().default('claude-sonnet-4-5-20250514'),
  maxTokens: z.number().positive().default(4096),
  timeout: z.number().positive().default(60000),
});

const BedrockConfigSchema = z.object({
  region: z.string().default('us-east-1'),
  modelId: z.string().default('us.anthropic.claude-sonnet-4-5-20250514-v1:0'),
  maxTokens: z.number().positive().default(4096),
  timeout: z.number().positive().default(60000),
});

const AIConfigSchema = z.object({
  provider: z.enum(['anthropic', 'bedrock']).default('anthropic'),
  anthropic: AnthropicConfigSchema.optional(),
  bedrock: BedrockConfigSchema.optional(),
  fallbackProvider: z.enum(['anthropic', 'bedrock']).optional(),
});

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

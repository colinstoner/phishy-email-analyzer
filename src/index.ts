/**
 * Phishy Email Analyzer v2
 *
 * An AI-powered phishing email analysis tool that uses Claude to
 * evaluate suspicious emails and provide detailed security reports.
 *
 * @license GPL-3.0
 */

// Export handlers
export { handler } from './handlers/unified.handler';
export { handler as sesHandler } from './handlers/lambda.handler';
export { handler as apiHandler } from './handlers/api.handler';

// Export types
export * from './types';

// Export services
export { EmailParserService } from './services/email/parser.service';
export { AnthropicProvider } from './services/ai/anthropic.provider';
export { BedrockProvider, BEDROCK_CLAUDE_MODELS } from './services/ai/bedrock.provider';
export { AnalysisService } from './services/ai/analysis.service';
export { S3Service } from './services/storage/s3.service';
export { SESNotifier } from './services/notification/ses.notifier';
export type { AIProvider, AnalysisOptions, ProviderHealth } from './services/ai/provider.interface';

// Export configuration
export { loadConfig } from './config';
export type { PhishyConfig } from './config/schema';

// Export models
export type { EnterpriseProfile } from './models/profile.model';
export { validateProfile, createMinimalProfile, EXAMPLE_PROFILE } from './models/profile.model';

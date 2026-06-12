/**
 * Lambda Handler
 * Main entry point for AWS Lambda function
 */

import { Context, SESEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, PhishyConfig } from '../config';
import { EmailParserService } from '../services/email/parser.service';
import { S3Service } from '../services/storage/s3.service';
import { SESNotifier } from '../services/notification/ses.notifier';
import { AnalysisService } from '../services/ai/analysis.service';
import { AnthropicProvider } from '../services/ai/anthropic.provider';
import { BedrockProvider } from '../services/ai/bedrock.provider';
import { AIProvider } from '../services/ai/provider.interface';
import { EnterpriseProfile, validateProfile } from '../models/profile.model';
import { LambdaResponse, ProcessingResult, EmailMessage, ExtractedEmailData } from '../types';
import { createLogger } from '../utils/logger';
import { extractEmailAddress, domainMatches } from '../utils/validation';
import { estimateCostUsd } from '../utils/pricing';
import { emitAIUsageMetric } from '../utils/metrics';
import { ReportOptions } from '../templates/report.html';
import { EmailCommandService } from '../services/commands/email.command.service';
import { IntelligenceDatabaseService, CampaignAlertService } from '../services/intelligence';
import { extractIOCs, IOCSourceContext } from '../services/intelligence/ioc.extractor';

const logger = createLogger('lambda-handler');

/**
 * Runtime cache for request deduplication
 */
const processedEmails = new Set<string>();
const CACHE_MAX_SIZE = 100;

/**
 * Cached configuration and services
 */
let cachedConfig: PhishyConfig | null = null;
let cachedProfile: EnterpriseProfile | undefined;
let cachedServices: {
  s3Service: S3Service;
  emailParser: EmailParserService;
  sesNotifier: SESNotifier;
  analysisService: AnalysisService;
  campaignService?: CampaignAlertService;
  intelligenceDb?: IntelligenceDatabaseService;
  commandService?: EmailCommandService;
} | null = null;

/**
 * Main Lambda handler function
 */
export async function handler(event: SESEvent, _context: Context): Promise<APIGatewayProxyResult> {
  logger.info('=== PHISHY STARTING ===');

  try {
    // Initialize services
    const { config, services } = await initializeServices();

    // Log event for debugging
    logger.debug('Received event', { event: JSON.stringify(event) });

    // Parse email events
    const emailEvents = await services.emailParser.parseEmailEvents(event);

    if (!emailEvents || emailEvents.length === 0) {
      logger.info('No email events to process');
      return createResponse(200, { success: true, message: 'No email events to process' });
    }

    logger.info('Processing email events', { count: emailEvents.length });

    // Process each email event
    const processingResults: ProcessingResult[] = [];

    for (const emailEvent of emailEvents) {
      if (!emailEvent?.msg) {
        logger.warn('Invalid email event format, missing msg property');
        processingResults.push({ status: 'error', error: 'Invalid email event format' });
        continue;
      }

      try {
        const result = await processEmailEvent(emailEvent.msg, config, services);
        processingResults.push(result);
      } catch (eventError) {
        logger.error('Error processing event', {
          error: eventError instanceof Error ? eventError.message : String(eventError),
        });
        processingResults.push({
          status: 'error',
          error: eventError instanceof Error ? eventError.message : String(eventError),
        });
      }
    }

    // Limit cache size
    maintainCacheSize();

    const successCount = processingResults.filter(r => r.status === 'processed').length;
    logger.info('Processing complete', {
      total: processingResults.length,
      successful: successCount,
    });

    return createResponse(200, { success: true, processed: processingResults.length });
  } catch (error) {
    logger.error('Error in handler', {
      error: error instanceof Error ? error.message : String(error),
    });
    return createResponse(200, { success: false, error: String(error) });
  }
}

/**
 * Initialize services from configuration
 */
async function initializeServices(): Promise<{
  config: PhishyConfig;
  services: NonNullable<typeof cachedServices>;
}> {
  // Use cached services if available
  if (cachedConfig && cachedServices) {
    return { config: cachedConfig, services: cachedServices };
  }

  // Load configuration
  const config = await loadConfig();
  cachedConfig = config;

  // Load enterprise profile if configured
  if (config.profile) {
    try {
      cachedProfile = await loadProfile(config.profile, config.storage.region);
    } catch (error) {
      logger.warn('Failed to load enterprise profile', {
        path: config.profile,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Create S3 service
  const s3Service = new S3Service(config.storage.region, config.storage.s3Bucket);

  // Create email parser
  const emailParser = new EmailParserService(
    s3Service,
    config.email.safeDomains,
    config.storage.s3Bucket
  );

  // Create AI provider(s)
  const primaryProvider = createAIProvider(config, emailParser, cachedProfile);
  let fallbackProvider: AIProvider | undefined;

  if (config.ai.fallbackProvider) {
    const fallbackConfig = {
      ...config,
      ai: { ...config.ai, provider: config.ai.fallbackProvider },
    };
    fallbackProvider = createAIProvider(fallbackConfig, emailParser, cachedProfile);
  }

  // Create analysis service
  const analysisService = new AnalysisService({
    primaryProvider,
    fallbackProvider,
  });

  // Create SES notifier
  const sesNotifier = new SESNotifier({
    region: config.storage.region,
    senderEmail: config.notification.senderEmail,
    senderName: config.notification.senderName,
    securityTeamDistribution: config.notification.securityTeamDistribution,
    configSet: config.notification.sesConfigSet,
  });

  // Initialize intelligence and campaign services if enabled
  let intelligenceDb: IntelligenceDatabaseService | undefined;
  let campaignService: CampaignAlertService | undefined;

  if (config.intelligence?.enabled && config.intelligence.connectionString) {
    intelligenceDb = new IntelligenceDatabaseService(config.intelligence.connectionString);
    await intelligenceDb.initialize();

    if (config.campaignAlerts?.enabled && config.campaignAlerts.distributionList) {
      campaignService = new CampaignAlertService(intelligenceDb, {
        enabled: true,
        distributionList: config.campaignAlerts.distributionList,
        senderEmail: config.notification.senderEmail,
        senderName: 'Phishy',
        region: config.storage.region,
      });
      logger.info('Campaign alert service initialized', {
        distributionList: config.campaignAlerts.distributionList,
      });
    }
  }

  // Email command channel: security team replies to reports to direct Phishy
  let commandService: EmailCommandService | undefined;
  if (config.commands?.enabled && intelligenceDb) {
    commandService = new EmailCommandService(
      intelligenceDb,
      sesNotifier,
      config.notification.securityTeamDistribution
    );
    logger.info('Email command service initialized', {
      authorizedSenders: config.notification.securityTeamDistribution.length,
    });
  }

  cachedServices = {
    s3Service,
    emailParser,
    sesNotifier,
    analysisService,
    intelligenceDb,
    campaignService,
    commandService,
  };

  logger.info('Services initialized', {
    provider: config.ai.provider,
    safeDomains: config.email.safeDomains.length,
    hasProfile: !!cachedProfile,
    intelligenceEnabled: !!intelligenceDb,
    campaignAlertsEnabled: !!campaignService,
  });

  return { config, services: cachedServices };
}

/**
 * Create AI provider based on configuration
 */
function createAIProvider(
  config: PhishyConfig,
  emailParser: EmailParserService,
  profile?: EnterpriseProfile
): AIProvider {
  const extractHeaders = (headers: Record<string, string>): Record<string, string> =>
    emailParser.extractEssentialHeaders(headers);

  if (config.ai.provider === 'bedrock') {
    if (!config.ai.bedrock) {
      throw new Error('Bedrock configuration required when provider is bedrock');
    }
    logger.info('Creating Bedrock provider', {
      region: config.ai.bedrock.region,
      modelId: config.ai.bedrock.modelId,
    });
    return new BedrockProvider(
      {
        region: config.ai.bedrock.region,
        modelId: config.ai.bedrock.modelId,
        maxTokens: config.ai.bedrock.maxTokens,
        timeout: config.ai.bedrock.timeout,
      },
      extractHeaders,
      profile
    );
  }

  // Default to Anthropic
  if (!config.ai.anthropic?.apiKey) {
    throw new Error('Anthropic API key required when provider is anthropic');
  }
  return new AnthropicProvider(
    {
      apiKey: config.ai.anthropic.apiKey,
      model: config.ai.anthropic.model,
      maxTokens: config.ai.anthropic.maxTokens,
      timeout: config.ai.anthropic.timeout,
    },
    extractHeaders,
    profile
  );
}

/**
 * Load enterprise profile from S3 or inline
 */
async function loadProfile(profilePath: string, region: string): Promise<EnterpriseProfile> {
  // Check if it's an S3 path
  if (profilePath.startsWith('s3://')) {
    const match = profilePath.match(/^s3:\/\/([^/]+)\/(.+)$/);
    if (!match) {
      throw new Error(`Invalid S3 profile path: ${profilePath}`);
    }

    const s3Service = new S3Service(region, match[1]);
    const content = await s3Service.getObject(match[1], match[2]);
    const profileData = JSON.parse(content) as unknown;
    return validateProfile(profileData);
  }

  // Try to parse as JSON
  try {
    const profileData = JSON.parse(profilePath) as unknown;
    return validateProfile(profileData);
  } catch {
    throw new Error(`Invalid profile: not a valid S3 path or JSON: ${profilePath}`);
  }
}

/**
 * Process a single email event
 */
async function processEmailEvent(
  msg: EmailMessage,
  config: PhishyConfig,
  services: NonNullable<typeof cachedServices>
): Promise<ProcessingResult> {
  // Extract and normalize email data
  const emailData = services.emailParser.extractEmailData(msg);

  logger.info('Extracted email data', {
    from: emailData.from_email,
    subject: emailData.subject.substring(0, 50),
  });

  // Check for duplicate
  const duplicateStatus = checkForDuplicate(msg, emailData);
  if (duplicateStatus) {
    return duplicateStatus;
  }

  // Security-team correspondence: replies to Phishy's reports are commands,
  // not new phishing reports — handle and stop before the analysis pipeline
  if (services.commandService?.looksLikeCommand(msg, emailData)) {
    const commandResult = await services.commandService.process(msg, emailData);
    if (commandResult.handled) {
      return {
        status: 'processed',
        recipient: emailData.from_email,
        reason: `command:${commandResult.action}`,
      };
    }
    // Not handled (e.g. failed SPF/DKIM) — fall through to the normal pipeline
  }

  // Validate email for processing
  const validationResult = validateEmail(emailData, config);
  if (validationResult.status !== 'processed') {
    return validationResult;
  }

  // Check if sender is a safelist user (not enterprise domain)
  // Safelist users bypass enterprise profile for basic analysis
  const isSafelistUser = config.email.safeSenders.some(
    s => s.toLowerCase() === emailData.from_email.toLowerCase()
  );

  if (isSafelistUser) {
    logger.info('Safelist user - bypassing enterprise profile', { from: emailData.from_email });
    services.analysisService.setProfile(undefined);
  } else if (cachedProfile) {
    services.analysisService.setProfile(cachedProfile);
  }

  // Analyze with AI
  const analysis = await services.analysisService.analyzeEmail(emailData);

  // Emit CloudWatch usage/cost metrics for every analysis, regardless of
  // whether the intelligence database is enabled
  const estimatedCostUsd = analysis.tokenUsage
    ? estimateCostUsd(
        analysis.model ?? 'unknown',
        analysis.tokenUsage.inputTokens,
        analysis.tokenUsage.outputTokens
      )
    : 0;
  if (analysis.tokenUsage) {
    emitAIUsageMetric({
      provider: analysis.provider ?? 'unknown',
      model: analysis.model ?? 'unknown',
      inputTokens: analysis.tokenUsage.inputTokens,
      outputTokens: analysis.tokenUsage.outputTokens,
      totalTokens: analysis.tokenUsage.totalTokens,
      estimatedCostUsd,
      processingTimeMs: analysis.processingTimeMs ?? 0,
      isPhishing: analysis.isPhishing,
    });
  }

  // Store analysis in intelligence database (only for enterprise users, not safelist)
  let storedAnalysisId: string | undefined;
  if (services.intelligenceDb && !isSafelistUser) {
    try {
      const senderDomain = emailData.from_email.split('@')[1] ?? 'unknown';
      const messageId = msg.messageId ?? `${Date.now()}-${Math.random().toString(36).substring(7)}`;

      const analysisId = await services.intelligenceDb.storeAnalysis({
        messageId,
        fromEmail: emailData.from_email,
        fromDomain: senderDomain,
        subject: emailData.subject,
        isPhishing: analysis.isPhishing,
        confidenceScore: normalizeConfidenceToNumber(analysis.confidence),
        riskLevel: mapConfidenceToRiskLevel(analysis.confidence),
        analysisResult: analysis,
        indicators: analysis.indicators ?? [],
        vipImpersonationDetected: false,
        aiProvider: analysis.provider ?? 'unknown',
        aiModel: analysis.model ?? 'unknown',
        processingTimeMs: analysis.processingTimeMs ?? 0,
      });
      storedAnalysisId = analysisId;
      logger.info('Stored analysis in intelligence database', { analysisId });

      // Store AI usage for cost tracking
      if (analysis.tokenUsage) {
        try {
          await services.intelligenceDb.storeAIUsage({
            analysisId,
            provider: analysis.provider ?? 'bedrock',
            model: analysis.model ?? 'unknown',
            inputTokens: analysis.tokenUsage.inputTokens,
            outputTokens: analysis.tokenUsage.outputTokens,
            totalTokens: analysis.tokenUsage.totalTokens,
            estimatedCostUsd,
          });
          logger.debug('Stored AI usage', {
            analysisId,
            totalTokens: analysis.tokenUsage.totalTokens,
            estimatedCostUsd,
          });
        } catch (usageError) {
          logger.warn('Failed to store AI usage', {
            error: usageError instanceof Error ? usageError.message : String(usageError),
          });
        }
      }

      // Extract and store IOCs if phishing detected
      if (analysis.isPhishing) {
        // Build source context for IOC provenance tracking
        const sourceContext: IOCSourceContext = {
          analysisId,
          messageId,
          fromEmail: emailData.from_email,
          fromDomain: senderDomain,
          subject: emailData.subject,
        };

        const iocs = extractIOCs(emailData, analysis, {}, sourceContext);
        logger.info('Extracted IOCs', { count: iocs.length, analysisId });

        for (const ioc of iocs) {
          try {
            await services.intelligenceDb.upsertIndicator(ioc);
          } catch (iocError) {
            logger.warn('Failed to store IOC', {
              type: ioc.indicatorType,
              error: iocError instanceof Error ? iocError.message : String(iocError),
            });
          }
        }
      }
    } catch (error) {
      logger.error('Failed to store analysis in intelligence database', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Track for campaign detection if phishing detected (skip for safelist users)
  if (analysis.isPhishing && services.campaignService && !isSafelistUser) {
    const senderDomain = emailData.from_email.split('@')[1] ?? 'unknown';
    const riskLevel = mapConfidenceToRiskLevel(analysis.confidence);

    try {
      const alertSent = await services.campaignService.processDetection(
        senderDomain,
        emailData.subject,
        emailData.originalForwarder ?? emailData.from_email,
        riskLevel,
        analysis.indicators
      );

      if (alertSent) {
        logger.info('Campaign alert sent', { senderDomain, subject: emailData.subject });
      }
    } catch (error) {
      logger.error('Campaign tracking failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Determine recipient
  const recipient = determineRecipient(emailData);

  // Send analysis if we have a valid recipient
  if (isValidEmailRecipient(recipient)) {
    // Use different CC list for safelist users vs enterprise users
    const ccOverride = isSafelistUser ? config.notification.safeSenderSecurity : undefined; // undefined uses default securityTeamDistribution

    // Include the Analysis ID in the report so security-team replies can be
    // matched back to this analysis (the email command channel)
    const reportOptions: ReportOptions | undefined = storedAnalysisId
      ? { analysisId: storedAnalysisId }
      : undefined;

    const emailResult = await services.sesNotifier.sendAnalysisReport(
      recipient,
      analysis,
      emailData,
      ccOverride,
      reportOptions
    );

    // Remember the outbound message ID so In-Reply-To matching works
    if (storedAnalysisId && emailResult.messageId && services.intelligenceDb) {
      try {
        await services.intelligenceDb.setReportMessageId(storedAnalysisId, emailResult.messageId);
      } catch (linkError) {
        logger.warn('Failed to store report message ID', {
          error: linkError instanceof Error ? linkError.message : String(linkError),
        });
      }
    }

    // Delete from S3 if configured
    if (config.email.deleteAfterProcessing && msg.s3Location) {
      logger.info('Cleaning up S3 object');
      await services.s3Service.deleteObject(msg.s3Location.bucket, msg.s3Location.key);
    }

    return {
      status: 'processed',
      recipient,
      messageId: emailResult.messageId,
    };
  }

  logger.warn('Cannot send analysis - invalid recipient', { recipient });
  return { status: 'incomplete', reason: 'invalid_recipient' };
}

/**
 * Check for duplicate email
 */
function checkForDuplicate(
  msg: EmailMessage,
  emailData: ExtractedEmailData
): ProcessingResult | null {
  const messageId = msg.messageId ?? emailData.headers['Message-ID'] ?? '';
  const fingerprint = `${emailData.from_email}:${emailData.subject}:${messageId}`.trim();

  if (fingerprint && processedEmails.has(fingerprint)) {
    logger.info('Skipping duplicate email', { fingerprint });
    return { status: 'duplicate' };
  }

  if (fingerprint) {
    processedEmails.add(fingerprint);
  }

  return null;
}

/**
 * Validate email for processing
 */
function validateEmail(emailData: ExtractedEmailData, config: PhishyConfig): ProcessingResult {
  // Skip if already an analysis email
  if (
    emailData.subject?.includes('Phishy Analysis') ||
    emailData.subject?.includes('Phishing Analysis')
  ) {
    logger.info('Skipping analysis email');
    return { status: 'skipped', reason: 'already_analyzed' };
  }

  // Check if from trusted source
  if (!isFromTrustedSource(emailData.from_email, config)) {
    logger.info('Skipping untrusted source', { from: emailData.from_email });
    return { status: 'skipped', reason: 'untrusted_source' };
  }

  return { status: 'processed' };
}

/**
 * Check if email is from a trusted source
 */
function isFromTrustedSource(email: string, config: PhishyConfig): boolean {
  if (!email) return false;

  const normalizedEmail = email.toLowerCase();

  // Check safe senders
  if (config.email.safeSenders.some(s => s.toLowerCase() === normalizedEmail)) {
    return true;
  }

  // Check safe domains
  const domain = normalizedEmail.split('@')[1];
  if (domain) {
    return config.email.safeDomains.some(safeDomain =>
      domainMatches(domain, safeDomain.toLowerCase())
    );
  }

  return false;
}

/**
 * Determine recipient for analysis report
 */
function determineRecipient(emailData: ExtractedEmailData): string {
  // Try original sender
  if (emailData.original_sender) {
    const email = extractEmailAddress(emailData.original_sender);
    if (email) {
      logger.debug('Using original sender as recipient', { email });
      return email;
    }
  }

  // Fall back to original forwarder
  if (emailData.originalForwarder) {
    logger.debug('Using original forwarder as recipient', {
      email: emailData.originalForwarder,
    });
    return emailData.originalForwarder;
  }

  logger.warn('No recipient found');
  return '';
}

/**
 * Check if email is valid for receiving reports
 */
function isValidEmailRecipient(email: string): boolean {
  return !!(
    email &&
    !email.includes('phishing') &&
    !email.includes('noreply') &&
    !email.includes('no-reply')
  );
}

/**
 * Map analysis confidence to risk level for campaign tracking
 */
function mapConfidenceToRiskLevel(confidence: string): 'critical' | 'high' | 'medium' | 'low' {
  const normalized = confidence.toLowerCase();
  if (normalized.includes('very high')) return 'critical';
  if (normalized.includes('high')) return 'high';
  if (normalized.includes('medium')) return 'medium';
  return 'low';
}

/**
 * Convert confidence string to numeric score (0-1 scale for database storage)
 */
function normalizeConfidenceToNumber(confidence: string): number {
  const normalized = confidence.toLowerCase();
  if (normalized.includes('very high')) return 0.95;
  if (normalized.includes('high')) return 0.85;
  if (normalized.includes('medium')) return 0.6;
  if (normalized.includes('low')) return 0.3;
  // Try to parse as number if it's already numeric (assume 0-100 scale)
  const parsed = parseInt(confidence, 10);
  if (!isNaN(parsed)) return Math.min(1, Math.max(0, parsed / 100));
  return 0.5; // Default to medium
}

/**
 * Maintain cache size to prevent memory leaks
 */
function maintainCacheSize(): void {
  if (processedEmails.size > CACHE_MAX_SIZE) {
    const toRemove = processedEmails.size - CACHE_MAX_SIZE;
    const iterator = processedEmails.values();
    for (let i = 0; i < toRemove; i++) {
      const value = iterator.next().value;
      if (value) {
        processedEmails.delete(value);
      }
    }
  }
}

/**
 * Create standardized API response
 */
function createResponse(statusCode: number, body: Record<string, unknown>): LambdaResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'OPTIONS,POST',
    },
    body: JSON.stringify(body),
  };
}

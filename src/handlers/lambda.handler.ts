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
import {
  LambdaResponse,
  ProcessingResult,
  EmailMessage,
  ExtractedEmailData,
  AnalysisResult,
  EmailSendResult,
} from '../types';
import { contentFacts, createLogger } from '../utils/logger';
import { extractEmailAddress, domainMatches } from '../utils/validation';
import { estimateCostUsd } from '../utils/pricing';
import {
  emitAIUsageMetric,
  emitAnalysisFailureMetric,
  emitCampaignCacheHitMetric,
  emitSecurityCopyFailureMetric,
  emitUserReportMetric,
} from '../utils/metrics';
import { shouldNotifySecurityTeam } from '../services/email/user.report';
import { ReportOptions } from '../templates/report.html';
import { EmailCommandService } from '../services/commands/email.command.service';
import { AgenticAnalyzer } from '../services/ai/agentic/agentic.analyzer';
import { AgenticToolExecutor } from '../services/ai/agentic/tool.executor';
import {
  IntelligenceDatabaseService,
  CampaignAlertService,
  computeCampaignSignature,
  buildCachedAnalysisResult,
  fuseRisk,
  modelVerdictOf,
  FusionSignals,
  RiskDecision,
} from '../services/intelligence';
import { decideIndicatorStorage, withProvenance } from '../services/intelligence/indicator.policy';
import { extractIOCs, IOCSourceContext } from '../services/intelligence/ioc.extractor';
import { ThreatIndicatorRecord, FeedbackRecord } from '../services/intelligence/database.service';
import type { BlastRadiusReport } from '../services/graph/blast-radius.service';
import { GraphGateway, createGraphGateway } from '../services/graph/graph.gateway';
import { attachmentRiskSignals } from '../services/attachments/risk';
import { CampaignResponseService } from '../services/response/campaign.response.service';
import { ResponseStore } from '../services/response/response.store';
import type { CampaignMatch, CampaignRecord } from '../services/intelligence/database.service';
import { isScheduledTaskCandidate } from './scheduled.event';

const logger = createLogger('lambda-handler');

/**
 * Runtime cache for request deduplication
 */
const processedEmails = new Set<string>();
const CACHE_MAX_SIZE = 100;

/**
 * Cost of the most recent real AI analysis in this Lambda instance — used to
 * estimate the spend avoided by a campaign verdict cache hit
 */
let lastAnalysisCostUsd = 0;

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
  /** Incident email, targeted warning and approved actions (campaignResponse.enabled) */
  campaignResponse?: CampaignResponseService;
  intelligenceDb?: IntelligenceDatabaseService;
  commandService?: EmailCommandService;
  /**
   * The three optional Microsoft Graph features (original-message lookup,
   * sender-relationship check, blast radius), run by this function
   * (`graph.mode: direct`) or by the Graph broker function (`broker`)
   */
  graph: GraphGateway;
} | null = null;

/**
 * Main Lambda handler function
 */
export async function handler(event: SESEvent, _context: Context): Promise<APIGatewayProxyResult> {
  logger.info('=== PHISHY STARTING ===');

  // A scheduled-task event is never email: the unified handler routes it
  // to `scheduled.handler.ts`; reaching this handler directly it is refused
  if (isScheduledTaskCandidate(event)) {
    logger.warn('Scheduled-task event reached the email handler; ignored');
    return createResponse(400, { success: false, error: 'not an email event' });
  }

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
        const result = await processEmailEvent(emailEvent.msg, config, services, () =>
          _context?.getRemainingTimeInMillis?.()
        );
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
 * The initialized services a scheduled task needs (`scheduled.handler.ts`):
 * the same configuration, notifier, database and Graph gateway the email
 * pipeline uses, built once per instance
 */
export async function scheduledTaskServices(): Promise<{
  config: PhishyConfig;
  sesNotifier: SESNotifier;
  intelligenceDb?: IntelligenceDatabaseService;
  graph: GraphGateway;
}> {
  const { config, services } = await initializeServices();
  return {
    config,
    sesNotifier: services.sesNotifier,
    intelligenceDb: services.intelligenceDb,
    graph: services.graph,
  };
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
    config.storage.s3Bucket,
    {
      detectUserReports: !!config.reportButton?.enabled,
      attachmentAnalysis: config.attachments?.analysis,
    }
  );

  // Create AI provider(s)
  const primaryProvider = createAIProvider(config, emailParser, cachedProfile);
  let fallbackProvider: AIProvider | undefined;

  if (config.ai.fallbackProvider) {
    // ai.refusalFallbackModel is a model ID in the PRIMARY provider's format,
    // so the fallback provider keeps its own built-in default instead
    const fallbackConfig = {
      ...config,
      ai: {
        ...config.ai,
        provider: config.ai.fallbackProvider,
        refusalFallbackModel: undefined,
      },
    };
    fallbackProvider = createAIProvider(fallbackConfig, emailParser, cachedProfile);
  }

  // Initialize intelligence and campaign services if enabled (before the
  // analysis service — the agentic tools query the intelligence database)
  let intelligenceDb: IntelligenceDatabaseService | undefined;
  let campaignService: CampaignAlertService | undefined;

  if (config.intelligence?.enabled && config.intelligence.connectionString) {
    intelligenceDb = new IntelligenceDatabaseService(config.intelligence.connectionString);
    await intelligenceDb.initialize();

    // Campaign response can run without a distribution list (audience
    // `recipients`); without campaign response the list is required, as before
    if (
      config.campaignAlerts?.enabled &&
      (config.campaignAlerts.distributionList || config.campaignResponse?.enabled)
    ) {
      campaignService = new CampaignAlertService(intelligenceDb, {
        enabled: true,
        distributionList: config.campaignAlerts.distributionList ?? '',
        senderEmail: config.notification.senderEmail,
        senderName: 'Phishy',
        region: config.storage.region,
      });
      logger.info('Campaign alert service initialized', {
        distributionList: config.campaignAlerts.distributionList,
      });
    }
  }

  // Agentic analysis: a bounded tool loop over Phishy's own data — known
  // indicators, campaign history, URL inspection, and the enterprise profile
  let agenticAnalyzer: AgenticAnalyzer | undefined;
  if (config.agentic?.enabled) {
    const toolExecutor = new AgenticToolExecutor({
      db: intelligenceDb,
      profile: cachedProfile,
    });
    agenticAnalyzer = new AgenticAnalyzer(toolExecutor, {
      maxToolRounds: config.agentic.maxToolRounds,
      essentialHeadersExtractor: (headers): Record<string, string> =>
        emailParser.extractEssentialHeaders(headers),
    });
    logger.info('Agentic analysis enabled', {
      maxToolRounds: config.agentic.maxToolRounds,
      tools: toolExecutor.getToolDefinitions().map(t => t.name),
    });
  }

  // Create analysis service
  const analysisService = new AnalysisService({
    primaryProvider,
    fallbackProvider,
    agenticAnalyzer,
  });

  // Create SES notifier
  const sesNotifier = new SESNotifier({
    region: config.storage.region,
    senderEmail: config.notification.senderEmail,
    senderName: config.notification.senderName,
    securityTeamDistribution: config.notification.securityTeamDistribution,
    configSet: config.notification.sesConfigSet,
  });

  // Campaign response (off by default): incident email, targeted warning,
  // approved actions. Needs campaign alerts (the trigger) and the database.
  let campaignResponse: CampaignResponseService | undefined;
  if (config.campaignResponse?.enabled) {
    if (campaignService && intelligenceDb) {
      const db = intelligenceDb;
      const alerts = campaignService;
      campaignResponse = new CampaignResponseService({
        store: new ResponseStore({
          query: (text, params): ReturnType<typeof db.runQuery> => db.runQuery(text, params),
        }),
        mailer: sesNotifier,
        config: config.campaignResponse,
        safeDomains: config.email.safeDomains,
        securityTeam: config.notification.securityTeamDistribution,
        distributionList: config.campaignAlerts?.distributionList,
        commandsEnabled: !!(config.commands?.enabled && intelligenceDb),
        legacyAlert: (match: CampaignMatch): Promise<boolean> => alerts.sendLegacyAlert(match),
        markCampaignAlerted: (campaignId: string): Promise<void> => alerts.markAlerted(campaignId),
      });
      logger.info('Campaign response enabled', {
        audience: config.campaignResponse.audience,
        employeeWarning: config.campaignResponse.employeeWarning,
        distributionWarning: config.campaignResponse.distributionWarning,
        commandsEnabled: !!config.commands?.enabled,
      });
      if (!config.commands?.enabled) {
        logger.warn(
          'Campaign response is on but the command channel is off: approvals cannot be received (PHISHY_EMAIL_COMMANDS_ENABLED)'
        );
      }
    } else {
      logger.warn(
        'campaignResponse.enabled has no effect without campaign alerts and the intelligence database'
      );
    }
  }

  // Email command channel: security team replies to reports to direct Phishy.
  // With agentic mode on, free-text verdicts are interpreted by the model;
  // approvals of response actions never are.
  let commandService: EmailCommandService | undefined;
  if (config.commands?.enabled && intelligenceDb) {
    commandService = new EmailCommandService(
      intelligenceDb,
      sesNotifier,
      config.notification.securityTeamDistribution,
      config.agentic?.enabled ? primaryProvider : undefined,
      campaignResponse
    );
    logger.info('Email command service initialized', {
      authorizedSenders: config.notification.securityTeamDistribution.length,
      aiCommandParsing: !!config.agentic?.enabled,
    });
  }

  // Microsoft Graph features (all optional, code-driven and read-only).
  // Nothing is contacted until the first lookup. In broker mode this builds
  // no Graph client and holds no Graph credential: the lookups are typed
  // invocations of the Graph broker function.
  const graph = createGraphGateway(config);

  cachedServices = {
    s3Service,
    emailParser,
    sesNotifier,
    analysisService,
    intelligenceDb,
    campaignService,
    ...(campaignResponse ? { campaignResponse } : {}),
    commandService,
    graph,
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
        effort: config.ai.effort,
        refusalFallbackModel: config.ai.refusalFallbackModel,
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
      effort: config.ai.effort,
      refusalFallbackModel: config.ai.refusalFallbackModel,
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
  services: NonNullable<typeof cachedServices>,
  getRemainingMs?: () => number | undefined
): Promise<ProcessingResult> {
  // Extract and normalize email data
  const emailData = services.emailParser.extractEmailData(msg);

  logger.info('Extracted email data', {
    from: emailData.from_email,
    subject: contentFacts(emailData.subject),
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

  // Outlook Report-button submissions: nobody is waiting for an answer, so
  // these are handled without emailing the reporter. Junk / not-junk reports
  // are mailbox hygiene, not a question for Phishy — count them and stop.
  const userReport = emailData.userReport;
  if (userReport) {
    emitUserReportMetric(userReport.reportedAs);
    if (userReport.reportedAs !== 'phishing') {
      logger.info('Report-button submission is not a phishing report — skipping analysis', {
        reporter: emailData.from_email,
        reportedAs: userReport.reportedAs,
      });
      await cleanupStoredEmail(msg, config, services);
      return { status: 'skipped', reason: `user_report_${userReport.reportedAs}` };
    }
    logger.info('Report-button phishing submission — analyzing silently', {
      reporter: emailData.from_email,
      networkMessageId: userReport.networkMessageId,
    });
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

  const senderDomain = emailData.from_email.split('@')[1] ?? 'unknown';
  const campaignSignature =
    services.intelligenceDb && !isSafelistUser
      ? computeCampaignSignature(senderDomain, emailData.subject)
      : undefined;

  // Campaign verdict cache: when a flood of the same email is reported, the
  // first report pays for a full AI analysis and the rest reuse its verdict.
  // A security-team ruling on any report in the campaign overrides the AI.
  let analysis: AnalysisResult | null = null;
  let fromCampaignCache = false;
  let securityVerdict: FeedbackRecord['verdict'] | undefined;
  if (config.campaignCache?.enabled && campaignSignature && services.intelligenceDb) {
    try {
      const cacheHit = await services.intelligenceDb.findCampaignVerdict(
        campaignSignature,
        config.campaignCache.ttlHours
      );
      if (cacheHit) {
        analysis = buildCachedAnalysisResult(cacheHit);
        fromCampaignCache = true;
        securityVerdict = cacheHit.feedbackVerdict;
        emitCampaignCacheHitMetric(lastAnalysisCostUsd);
        logger.info('Campaign verdict cache hit', {
          campaignSignature,
          sourceAnalysisId: cacheHit.analysisId,
          securityVerdict: cacheHit.feedbackVerdict,
        });
      }
    } catch (cacheError) {
      logger.warn('Campaign verdict cache lookup failed — running full analysis', {
        error: cacheError instanceof Error ? cacheError.message : String(cacheError),
      });
    }
  }

  // Analyze with AI (cache miss or cache disabled). When the original-message
  // lookup is on, first try to add the original's real headers to the email
  // facts; it never throws and any outcome but a unique match changes nothing.
  // Safelist users are outside the organization, so there is no mailbox to read.
  // A Report-button submission already carries the original with its headers.
  if (!analysis) {
    // Sender-relationship facts for the prompt, risk fusion and the report
    // (forwards and Report-button submissions alike). Never throws; undefined
    // on any failure, and analysis proceeds as usual.
    if (services.graph.senderHistory && !isSafelistUser) {
      emailData.senderHistory = await services.graph.lookupSenderHistory(emailData);
    }
    if (services.graph.originalFetch && !isSafelistUser && !userReport) {
      await services.graph.enrichWithOriginalMessage(
        services.emailParser,
        msg,
        emailData,
        config.email.safeDomains
      );
    }
    analysis = await services.analysisService.analyzeEmail(emailData);
  }

  // The model never produced a verdict (provider unreachable after retries).
  // The reporter still gets an honest "analysis unavailable" report below, but
  // this is an operational failure: surface it as a distinct, alarmable metric
  // so a provider outage is visible and isn't counted as a clean analysis.
  if (analysis.analysisFailed) {
    emitAnalysisFailureMetric(analysis.provider ?? 'unknown', analysis.model ?? 'unknown');
    logger.error('Analysis could not be completed — sending "analysis unavailable" report', {
      reporter: emailData.from_email,
      subject: contentFacts(emailData.subject),
      failureReason: analysis.failureReason,
    });
  }

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
    lastAnalysisCostUsd = estimatedCostUsd;
    emitAIUsageMetric({
      provider: analysis.provider ?? 'unknown',
      model: analysis.model ?? 'unknown',
      inputTokens: analysis.tokenUsage.inputTokens,
      outputTokens: analysis.tokenUsage.outputTokens,
      totalTokens: analysis.tokenUsage.totalTokens,
      estimatedCostUsd,
      processingTimeMs: analysis.processingTimeMs ?? 0,
      isPhishing: analysis.isPhishing,
      thinkingTokens: analysis.tokenUsage.thinkingTokens,
    });
  }

  // Fuse the model's verdict with Phishy's own intelligence (known
  // indicators, active campaigns, security-team rulings) into the final risk.
  const messageId = msg.messageId ?? `${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const iocSourceContext: IOCSourceContext = {
    messageId,
    reporterEmail: emailData.from_email,
    reporterDomain: senderDomain,
    subject: emailData.subject,
  };
  const extractedIOCs = services.intelligenceDb
    ? extractIOCs(
        emailData,
        analysis,
        { safeDomains: config.email.safeDomains, safeSenders: config.email.safeSenders },
        iocSourceContext
      )
    : [];

  const fusionSignals = services.intelligenceDb
    ? await gatherFusionSignals(
        services.intelligenceDb,
        extractedIOCs,
        campaignSignature,
        isSafelistUser
      )
    : {};
  // The model's own verdict, captured before fusion: it — not a score that
  // fusion raised — decides whether this email's indicators are stored.
  const modelVerdict = modelVerdictOf(analysis);
  const riskDecision = fuseRisk(analysis, {
    ...fusionSignals,
    senderHistory: emailData.senderHistory,
    // Decisive static-inspection findings; empty unless attachment analysis is on
    attachmentSignals: attachmentRiskSignals(emailData.attachments),
    // A security-team ruling on this campaign rides on the cache hit
    humanVerdict: securityVerdict,
  });
  if (riskDecision.reasons.length) {
    logger.info('Risk fusion applied', {
      verdict: riskDecision.verdict,
      riskScore: riskDecision.riskScore,
      riskLevel: riskDecision.riskLevel,
      confidenceBasis: riskDecision.confidenceBasis,
      modelVerdict,
      reasons: riskDecision.reasons,
    });
  }

  // The fused verdict is authoritative for downstream gating (IOC storage,
  // campaign detection) and the report.
  analysis.isPhishing = riskDecision.isPhishing;
  analysis.confidence = riskDecision.confidence;

  // Store analysis in intelligence database (only for enterprise users, not
  // safelist). A failed analysis is never stored: it carries no real verdict
  // and persisting it would seed the campaign verdict cache with a placeholder
  // that could be served as a verdict to future identical emails.
  let storedAnalysisId: string | undefined;
  if (services.intelligenceDb && !isSafelistUser && !analysis.analysisFailed) {
    try {
      const analysisId = await services.intelligenceDb.storeAnalysis({
        messageId,
        fromEmail: emailData.from_email,
        fromDomain: senderDomain,
        subject: emailData.subject,
        isPhishing: riskDecision.isPhishing,
        confidenceScore: riskDecision.riskScore / 100,
        riskLevel: riskDecision.riskLevel,
        verdict: riskDecision.verdict,
        riskScore: riskDecision.riskScore,
        analysisResult: analysis,
        indicators: analysis.indicators ?? [],
        vipImpersonationDetected: false,
        aiProvider: analysis.provider ?? 'unknown',
        aiModel: analysis.model ?? 'unknown',
        processingTimeMs: analysis.processingTimeMs ?? 0,
        campaignSignature,
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

      // Store the IOCs already extracted above only when the MODEL's own
      // verdict is malicious (fresh analysis) or the security team confirmed
      // the campaign — never because fusion raised the score, which is what
      // let indicators breed indicators. Each carries its provenance, and the
      // campaign signature as report key so repeat reports, thread replies
      // and campaign copies count once in times_seen.
      const storage = decideIndicatorStorage({
        modelVerdict,
        analysisFailed: analysis.analysisFailed,
        fromCampaignCache,
        humanVerdict: securityVerdict,
      });
      logger.info('Indicator storage decision', {
        store: storage.store,
        reason: storage.reason,
        count: extractedIOCs.length,
        analysisId,
      });
      if (storage.store && storage.provenance) {
        const provenance = storage.provenance;
        const reportKey = campaignSignature ?? messageId;
        for (const ioc of extractedIOCs) {
          try {
            await services.intelligenceDb.upsertIndicator(
              withProvenance(ioc, {
                provenance,
                sourceVerdict:
                  provenance === 'security_confirmed' ? 'confirmed_phishing' : modelVerdict,
                sourceAnalysisId: analysisId,
              }),
              { reportKey }
            );
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

  // Track for campaign detection if phishing detected (skip for safelist users).
  // With campaign response on, the detection is only counted here; what
  // happens next is decided after the reports (and blast radius) have gone.
  let trackedCampaign: { match: CampaignMatch; campaign: CampaignRecord } | undefined;
  if (
    riskDecision.isPhishing &&
    services.campaignService &&
    services.campaignResponse &&
    !isSafelistUser
  ) {
    trackedCampaign = await services.campaignService.trackDetection(
      senderDomain,
      emailData.subject,
      emailData.originalForwarder ?? emailData.from_email,
      riskDecision.riskLevel === 'safe' ? 'low' : riskDecision.riskLevel,
      analysis.indicators
    );
  } else if (riskDecision.isPhishing && services.campaignService && !isSafelistUser) {
    // Campaign tracking has no 'safe' tier; floor the fused level at 'low'.
    const riskLevel = riskDecision.riskLevel === 'safe' ? 'low' : riskDecision.riskLevel;

    try {
      const alertSent = await services.campaignService.processDetection(
        senderDomain,
        emailData.subject,
        emailData.originalForwarder ?? emailData.from_email,
        riskLevel,
        analysis.indicators
      );

      if (alertSent) {
        logger.info('Campaign alert sent', {
          senderDomain,
          subject: contentFacts(emailData.subject),
        });
      }
    } catch (error) {
      logger.error('Campaign tracking failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Blast radius: for a malicious verdict, who else received this and what
  // they did with it. Code-driven, after the verdict; the result goes only
  // into an email addressed to the security team and never to the model or
  // the reporter. Decided here, run just before that email is sent.
  const runBlastRadius =
    riskDecision.isPhishing &&
    !analysis.analysisFailed &&
    !isSafelistUser &&
    services.graph.blastRadius;
  // Campaign response reuses this report's lookup (the same result the
  // security team's copy carries): it is kept here, not re-run.
  let blastRadiusResult: BlastRadiusReport | undefined;
  const lookupBlastRadius = runBlastRadius
    ? async (reporterAddress?: string): Promise<BlastRadiusReport> => {
        const report = await services.graph.lookupBlastRadius(emailData, {
          remainingMs: getRemainingMs?.(),
          reporterAddress,
        });
        blastRadiusResult = report;
        return report;
      }
    : undefined;

  // After the reports have gone: open or update the campaign's incident
  const respondToCampaign = async (): Promise<void> => {
    if (!trackedCampaign || !services.campaignResponse) {
      return;
    }
    const outcome = await services.campaignResponse.handleCampaignReport({
      ...trackedCampaign,
      risk: reportRisk(riskDecision),
      analysis,
      emailData,
      ...(storedAnalysisId ? { analysisId: storedAnalysisId } : {}),
      ...(blastRadiusResult ? { blastRadius: blastRadiusResult } : {}),
      blastRadiusEnabled: services.graph.blastRadius,
      getRemainingMs,
    });
    logger.info('Campaign response', { outcome, campaignId: trackedCampaign.match.campaignId });
  };

  // Report-button submissions never produce a reply to the reporter. The
  // security team is told only when the outcome warrants their attention.
  if (userReport) {
    const silent = await finishSilentUserReport(msg, emailData, analysis, config, services, {
      storedAnalysisId,
      risk: reportRisk(riskDecision),
      isPhishing: riskDecision.isPhishing,
      lookupBlastRadius,
    });
    await respondToCampaign();
    return silent;
  }

  // Determine recipient
  const recipient = determineRecipient(emailData);

  // Send analysis if we have a valid recipient
  if (isValidEmailRecipient(recipient)) {
    // Use different CC list for safelist users vs enterprise users
    const ccOverride = isSafelistUser ? config.notification.safeSenderSecurity : undefined; // undefined uses default securityTeamDistribution

    // Include the Analysis ID in the report so security-team replies can be
    // matched back to this analysis (the email command channel)
    const reportOptions: ReportOptions = {
      ...(storedAnalysisId ? { analysisId: storedAnalysisId } : {}),
      risk: reportRisk(riskDecision),
      ...(services.commandService ? { replyCommands: true } : {}),
    };

    // With blast radius, the lookup runs inside sendReports, after the
    // reporter's copy has gone; its result is in the security team's copy only.
    const securityTeam = config.notification.securityTeamDistribution;
    const { reporterResult: emailResult, commandReplyMessageId } = await sendReports(
      services.sesNotifier,
      { recipient, analysis, emailData, ccOverride, reportOptions },
      lookupBlastRadius && securityTeam.length > 0
        ? {
            securityTeam,
            lookup: (): Promise<BlastRadiusReport> => lookupBlastRadius(recipient),
          }
        : undefined
    );

    // Remember the outbound message ID so In-Reply-To matching works (the
    // security team's copy when it was sent separately: they send commands)
    if (storedAnalysisId && commandReplyMessageId && services.intelligenceDb) {
      try {
        await services.intelligenceDb.setReportMessageId(storedAnalysisId, commandReplyMessageId);
      } catch (linkError) {
        logger.warn('Failed to store report message ID', {
          error: linkError instanceof Error ? linkError.message : String(linkError),
        });
      }
    }

    await cleanupStoredEmail(msg, config, services);
    await respondToCampaign();

    return {
      status: 'processed',
      recipient,
      messageId: emailResult.messageId,
    };
  }

  // An invalid recipient is not a verified reporter address: it can be any
  // text the email's headers supplied, so only its facts are logged above debug
  logger.warn('Cannot send analysis - invalid recipient', { recipient: contentFacts(recipient) });
  logger.debug('Invalid recipient value', { recipient });
  await respondToCampaign();
  return { status: 'incomplete', reason: 'invalid_recipient' };
}

/**
 * Run a blast-radius lookup for an email to the security team. `lookup()`
 * does not throw; if it ever does, the email still goes out, with a note.
 */
async function resolveBlastRadius(
  lookup: () => Promise<BlastRadiusReport>
): Promise<BlastRadiusReport> {
  try {
    return await lookup();
  } catch (error) {
    logger.error('Blast radius lookup threw', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    return {
      status: 'unavailable',
      note: 'Blast radius lookup could not be completed.',
      lookedUpAt: new Date().toISOString(),
    };
  }
}

/**
 * Send the analysis report.
 *
 * Without `blastRadius` (the feature is off, or the verdict is not
 * malicious): one email to the reporter with the security team in Cc.
 *
 * With it, two emails, in this order:
 * 1. the reporter's copy, at once and without the section — their warning
 *    never waits on the lookup;
 * 2. the lookup (bounded by its own budget and the remaining Lambda time);
 * 3. the security team's own copy, with the section, or with a one-line
 *    note when the lookup produced nothing. It is always sent.
 *
 * A reporter who is on the security team gets only the security copy. The
 * security copy's message ID is the one command replies are matched to.
 *
 * Each of the two emails is marked with its `audience`, which decides how
 * much sender-relationship detail it shows: none for the reporter, all of it
 * (sending IPs included) for the security team. The single combined email
 * carries no mark and shows counts only.
 */
export async function sendReports(
  notifier: SESNotifier,
  report: {
    recipient: string;
    analysis: AnalysisResult;
    emailData: ExtractedEmailData;
    ccOverride?: string[];
    reportOptions: ReportOptions;
  },
  blastRadius?: { securityTeam: string[]; lookup: () => Promise<BlastRadiusReport> }
): Promise<{ reporterResult: EmailSendResult; commandReplyMessageId?: string }> {
  const { recipient, analysis, emailData, ccOverride, reportOptions } = report;

  if (!blastRadius) {
    const reporterResult = await notifier.sendAnalysisReport(
      recipient,
      analysis,
      emailData,
      ccOverride,
      reportOptions
    );
    return { reporterResult, commandReplyMessageId: reporterResult.messageId };
  }

  const reporter = recipient.trim().toLowerCase();
  const reporterIsSecurityTeam = blastRadius.securityTeam.some(
    member => member.trim().toLowerCase() === reporter
  );
  const reporterResult = reporterIsSecurityTeam
    ? undefined
    : await notifier.sendAnalysisReport(recipient, analysis, emailData, [], {
        ...reportOptions,
        audience: 'reporter',
      });

  const section = await resolveBlastRadius(blastRadius.lookup);

  const [first, ...rest] = blastRadius.securityTeam;
  const securityResult = await notifier.sendAnalysisReport(first, analysis, emailData, rest, {
    ...reportOptions,
    audience: 'security',
    blastRadius: section,
  });
  if (!securityResult.success) {
    // The reporter already has theirs: nothing is re-sent, but this must be seen
    logger.error('Security-team copy of a malicious report was not sent', {
      error: securityResult.error,
    });
    emitSecurityCopyFailureMetric();
  }

  return {
    reporterResult: reporterResult ?? securityResult,
    commandReplyMessageId: securityResult.messageId,
  };
}

/**
 * Delete the raw email from S3 when configured to
 */
async function cleanupStoredEmail(
  msg: EmailMessage,
  config: PhishyConfig,
  services: NonNullable<typeof cachedServices>
): Promise<void> {
  if (config.email.deleteAfterProcessing && msg.s3Location) {
    logger.info('Cleaning up S3 object');
    await services.s3Service.deleteObject(msg.s3Location.bucket, msg.s3Location.key);
  }
}

/**
 * Finish an Outlook Report-button phishing submission. The reporter is never
 * emailed; the analysis has already been stored and counted toward campaign
 * detection. The security team — operator-configured addresses, never anything
 * derived from the message — gets the report when the verdict is malicious or
 * suspicious, or when the analysis could not be completed.
 *
 * With blast radius on and a malicious verdict (`lookupBlastRadius` is set),
 * the lookup runs first and that same single email carries its section, or
 * a one-line note when the lookup produced nothing. Nobody is waiting on
 * this path, so there is no second email and no ordering to preserve.
 */
async function finishSilentUserReport(
  msg: EmailMessage,
  emailData: ExtractedEmailData,
  analysis: AnalysisResult,
  config: PhishyConfig,
  services: NonNullable<typeof cachedServices>,
  outcome: {
    storedAnalysisId?: string;
    risk: NonNullable<ReportOptions['risk']>;
    isPhishing: boolean;
    lookupBlastRadius?: () => Promise<BlastRadiusReport>;
  }
): Promise<ProcessingResult> {
  const securityTeam = config.notification.securityTeamDistribution;
  const notify = shouldNotifySecurityTeam({
    isPhishing: outcome.isPhishing,
    verdict: outcome.risk.verdict,
    analysisFailed: analysis.analysisFailed,
  });

  if (!notify || securityTeam.length === 0) {
    logger.info('Report-button submission recorded — no notification sent', {
      reporter: emailData.from_email,
      verdict: outcome.risk.verdict,
      hasSecurityTeam: securityTeam.length > 0,
    });
    await cleanupStoredEmail(msg, config, services);
    return { status: 'processed', reason: 'user_report_recorded' };
  }

  const blastRadius = outcome.lookupBlastRadius
    ? await resolveBlastRadius(outcome.lookupBlastRadius)
    : undefined;

  const [primary, ...others] = securityTeam;
  const emailResult = await services.sesNotifier.sendAnalysisReport(
    primary,
    analysis,
    emailData,
    others,
    {
      ...(outcome.storedAnalysisId ? { analysisId: outcome.storedAnalysisId } : {}),
      risk: outcome.risk,
      silentReport: { reporter: emailData.from_email },
      // Addressed to the security team alone: full sender-relationship detail
      audience: 'security',
      ...(services.commandService ? { replyCommands: true } : {}),
      ...(blastRadius ? { blastRadius } : {}),
    }
  );
  if (blastRadius && !emailResult.success) {
    // Same signal as a failed security copy on the forward path
    logger.error('Security-team email for a malicious button report was not sent', {
      error: emailResult.error,
    });
    emitSecurityCopyFailureMetric();
  }

  // Remember the outbound message ID so security-team replies (commands)
  // can be matched back to this analysis
  if (outcome.storedAnalysisId && emailResult.messageId && services.intelligenceDb) {
    try {
      await services.intelligenceDb.setReportMessageId(
        outcome.storedAnalysisId,
        emailResult.messageId
      );
    } catch (linkError) {
      logger.warn('Failed to store report message ID', {
        error: linkError instanceof Error ? linkError.message : String(linkError),
      });
    }
  }

  await cleanupStoredEmail(msg, config, services);
  return {
    status: 'processed',
    recipient: primary,
    messageId: emailResult.messageId,
    reason: 'user_report_security_notified',
  };
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

/** Is this From address one of the configured security team's? (For skipping only, never for authorization.) */
function isSecurityTeamSender(from: string | undefined, config: PhishyConfig): boolean {
  const address = extractEmailAddress(from ?? '')?.toLowerCase();
  return (
    !!address &&
    config.notification.securityTeamDistribution.some(
      member => member.trim().toLowerCase() === address
    )
  );
}

/**
 * Validate email for processing
 */
function validateEmail(emailData: ExtractedEmailData, config: PhishyConfig): ProcessingResult {
  // Skip if already an analysis email
  if (
    emailData.subject?.includes('Phishy Analysis') ||
    emailData.subject?.includes('Phishing Analysis') ||
    // A reply in an incident thread. Only the security team receives those
    // emails, so the skip applies only to its members: anyone else's message
    // with this subject (a forwarded email that imitates it) is analyzed.
    (emailData.subject?.includes('[Phishy incident ') === true &&
      isSecurityTeamSender(emailData.from_email, config))
  ) {
    logger.info('Skipping analysis email');
    return { status: 'skipped', reason: 'already_analyzed' };
  }

  // Check if from trusted source
  if (!isFromTrustedSource(emailData.from_email, config)) {
    // Not a reporter: whoever sent this is outside the trusted domains
    logger.info('Skipping untrusted source', { from: contentFacts(emailData.from_email) });
    logger.debug('Untrusted source address', { from: emailData.from_email });
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

/** The fused decision as the report renders it */
function reportRisk(decision: RiskDecision): NonNullable<ReportOptions['risk']> {
  return {
    verdict: decision.verdict,
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    reasons: decision.reasons,
    confidence: decision.confidence,
    confidenceBasis: decision.confidenceBasis,
  };
}

/**
 * Gather the intelligence signals the risk-fusion layer needs: which of this
 * email's indicators are already known threats, and any active campaign it
 * matches. The security-team verdict, when present, rides on the campaign
 * cache hit, so it is not re-fetched here.
 */
async function gatherFusionSignals(
  db: IntelligenceDatabaseService,
  extractedIOCs: ThreatIndicatorRecord[],
  campaignSignature: string | undefined,
  isSafelistUser: boolean
): Promise<FusionSignals> {
  const matchedIndicators: ThreatIndicatorRecord[] = [];

  // Look up this email's candidate indicators against the store, by type.
  const byType = new Map<ThreatIndicatorRecord['indicatorType'], string[]>();
  for (const ioc of extractedIOCs) {
    const list = byType.get(ioc.indicatorType) ?? [];
    list.push(ioc.indicatorValue);
    byType.set(ioc.indicatorType, list);
  }
  for (const [type, values] of byType) {
    try {
      matchedIndicators.push(...(await db.lookupIndicators(type, values)));
    } catch (error) {
      logger.warn('Indicator lookup failed during risk fusion', {
        type,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  let campaign = null;
  if (campaignSignature) {
    try {
      campaign = await db.getCampaignBySignature(campaignSignature);
    } catch (error) {
      logger.warn('Campaign lookup failed during risk fusion', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { matchedIndicators, campaign, isSafeSender: isSafelistUser };
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

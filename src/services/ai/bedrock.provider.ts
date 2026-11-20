/**
 * AWS Bedrock Provider
 * Implements AI provider interface for AWS Bedrock Claude models
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { AIProvider, AnalysisOptions, ProviderHealth } from './provider.interface';
import { buildPhishingAnalysisPrompt } from './prompt.builder';
import { ScoringMode, attachChecklist } from './checklist';
import {
  ConversationMessage,
  ConversationRequest,
  ConversationResponse,
} from './conversation.types';
import { EffortLevel, effortForModel } from './model.capabilities';
import {
  ModelTurn,
  ProviderAuthError,
  analyzeSingleShot,
  completeSingleShot,
  normalizeModelResponse,
} from './model.response';
import { AnalysisResult, ExtractedEmailData } from '../../types';
import { contentFacts, createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';
import { EnterpriseProfile } from '../../models/profile.model';

const logger = createLogger('bedrock-provider');

/**
 * Supported Bedrock Claude models
 *
 * Primary recommendations:
 * - CLAUDE_OPUS_5_5: current Opus — best detection quality per dollar (default)
 * - CLAUDE_SONNET_5_5: balance of quality, speed, and cost
 * - CLAUDE_HAIKU_5_5: fastest and cheapest, for high-volume or quick-scan scenarios
 * - CLAUDE_FABLE_5_2: highest capability tier, at twice the Opus 5.5 price
 *
 * ID formats: on-demand invocation requires an INFERENCE PROFILE ID, not the
 * bare `anthropic.` model ID (Bedrock rejects the bare form with a
 * ValidationException — verified empirically). `global.` profiles route
 * dynamically at baseline pricing; swap to a regional prefix (`us.`, `eu.`,
 * ...) for data-residency requirements, at a 10% pricing premium. The 5.x
 * profiles below were confirmed ACTIVE in 2026-11; each also exists with a
 * `us.` prefix.
 */
export const BEDROCK_CLAUDE_MODELS = {
  // Current models (recommended)
  CLAUDE_OPUS_5_5: 'global.anthropic.claude-opus-5-5',
  CLAUDE_SONNET_5_5: 'global.anthropic.claude-sonnet-5-5',
  CLAUDE_HAIKU_5_5: 'global.anthropic.claude-haiku-5-5',
  CLAUDE_FABLE_5_2: 'global.anthropic.claude-fable-5-2',
  // Previous releases (still active)
  CLAUDE_OPUS_5: 'global.anthropic.claude-opus-5',
  CLAUDE_SONNET_5: 'global.anthropic.claude-sonnet-5',
  CLAUDE_FABLE_5_1: 'global.anthropic.claude-fable-5-1',
  CLAUDE_FABLE_5: 'global.anthropic.claude-fable-5',
  CLAUDE_OPUS_4_8: 'global.anthropic.claude-opus-4-8',
  CLAUDE_OPUS_4_6: 'global.anthropic.claude-opus-4-6-v1',
  CLAUDE_SONNET_4_6: 'global.anthropic.claude-sonnet-4-6',
  CLAUDE_HAIKU_4_5: 'us.anthropic.claude-haiku-4-5-20251001-v1:0',
  CLAUDE_SONNET_4_5: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
  // Deprecated on Bedrock (avoid for new deployments)
  CLAUDE_SONNET_4: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
} as const;

const DEFAULT_MODEL = BEDROCK_CLAUDE_MODELS.CLAUDE_OPUS_5_5;
/** Where a refused request is retried once. Opus 4.8 runs a narrower classifier set. */
const DEFAULT_REFUSAL_FALLBACK_MODEL = BEDROCK_CLAUDE_MODELS.CLAUDE_OPUS_4_8;

/** Routing prefix of an inference-profile ID: `us.anthropic.…` → `us` */
const INFERENCE_PROFILE_PREFIX = /^([a-z][a-z-]{1,15})\.anthropic\./;

/**
 * The default refusal-fallback model for a primary model. It keeps the
 * primary's routing prefix, so a deployment pinned to a geography (for
 * example `us.`) never sends the retry through a different one.
 */
export function defaultRefusalFallbackModel(primaryModel: string): string {
  const prefix = INFERENCE_PROFILE_PREFIX.exec(primaryModel)?.[1];
  if (!prefix || prefix === 'global') {
    return DEFAULT_REFUSAL_FALLBACK_MODEL;
  }
  return DEFAULT_REFUSAL_FALLBACK_MODEL.replace(/^global\./, `${prefix}.`);
}
/**
 * Thinking is always on for Opus 5.5 and counts toward max_tokens, so the
 * limit has to hold the thinking as well as the JSON verdict.
 */
const DEFAULT_MAX_TOKENS = 16000;
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_EFFORT: EffortLevel = 'medium';

/** Health probe budget: room to think briefly; any successful invoke counts as healthy. */
const HEALTH_CHECK_MAX_TOKENS = 1024;

/** System prompt for single-shot requests */
const SINGLE_SHOT_SYSTEM_PROMPT =
  'You are a security analyst helping to identify phishing emails. Always provide your analysis in the requested JSON format.';

/**
 * Retry budget for the email-analysis call. Phishy is an async, email-latency
 * workflow — a reporter waits seconds-to-minutes for a reply, not milliseconds —
 * and Bedrock's transient failures (InternalServerException / throttling) are
 * typically short windows. So we wait generously to ride them out rather than
 * give up and send an "analysis unavailable" report.
 *
 * 4 attempts back off ~15s / 30s / 60s between tries (≈105s of waiting worst
 * case). This is sized against the Lambda Timeout (180s) — keep them in sync:
 * waits + per-attempt latency must stay comfortably under the function timeout.
 */
const ANALYSIS_MAX_RETRIES = 4;
const ANALYSIS_BASE_DELAY_MS = 15000;
const ANALYSIS_MAX_DELAY_MS = 60000;

/**
 * Attempts for the one refusal-fallback call. It runs AFTER the primary call
 * has already spent its share of the Lambda timeout, so it gets a single retry
 * (one ~15s wait) rather than a second full ANALYSIS_* budget: worst-case
 * waiting is 105s + 15s = 120s, still inside the 180s function timeout.
 */
const REFUSAL_FALLBACK_MAX_RETRIES = 2;

interface RetryBudget {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs?: number;
}

const ANALYSIS_RETRY_BUDGET: RetryBudget = {
  maxRetries: ANALYSIS_MAX_RETRIES,
  baseDelayMs: ANALYSIS_BASE_DELAY_MS,
  maxDelayMs: ANALYSIS_MAX_DELAY_MS,
};
const REFUSAL_FALLBACK_RETRY_BUDGET: RetryBudget = {
  ...ANALYSIS_RETRY_BUDGET,
  maxRetries: REFUSAL_FALLBACK_MAX_RETRIES,
};
const CONVERSATION_RETRY_BUDGET: RetryBudget = { maxRetries: 3, baseDelayMs: 1000 };

/**
 * Pull the diagnostic detail out of an AWS SDK error. Bedrock surfaces a
 * generic "Bedrock is unable to process your request." message; the useful
 * triage data (exception name, HTTP status, request id) lives on the error
 * object's `name` and `$metadata`, which the bare message drops.
 */
function bedrockErrorDetail(error: unknown): {
  errorName: string;
  httpStatusCode?: number;
  requestId?: string;
} {
  const e = error as { name?: string; $metadata?: { httpStatusCode?: number; requestId?: string } };
  return {
    errorName: e?.name ?? 'UnknownError',
    httpStatusCode: e?.$metadata?.httpStatusCode,
    requestId: e?.$metadata?.requestId,
  };
}

/** SDK error names that mean Phishy's own AWS identity was rejected */
const AUTH_ERROR_NAMES = new Set([
  'CredentialsProviderError',
  'TokenProviderError',
  'ExpiredTokenException',
  'ExpiredToken',
  'UnrecognizedClientException',
  'InvalidClientTokenId',
  'AccessDeniedException',
  'InvalidSignatureException',
  'IncompleteSignatureException',
  'SignatureDoesNotMatch',
  'MissingAuthenticationTokenException',
]);

/** Messages the credential providers use when there is no usable identity */
const AUTH_ERROR_MESSAGE =
  /token is expired|security token included in the request is (?:expired|invalid)|could not load credentials|session (?:has )?expired/i;

/**
 * Whether an error from the Bedrock client is an authentication or
 * authorization failure: Phishy's credentials are missing, expired or
 * rejected, or its role may not invoke the model. These fail identically on
 * every retry. Throttling (429), timeouts and 5xx are not matched here.
 */
export function isBedrockAuthError(error: unknown): boolean {
  if (error instanceof ProviderAuthError) return true;
  const e = error as {
    name?: unknown;
    message?: unknown;
    $metadata?: { httpStatusCode?: unknown };
  };
  const status = e?.$metadata?.httpStatusCode;
  return (
    (typeof e?.name === 'string' && AUTH_ERROR_NAMES.has(e.name)) ||
    status === 401 ||
    status === 403 ||
    (typeof e?.message === 'string' && AUTH_ERROR_MESSAGE.test(e.message))
  );
}

export interface BedrockConfig {
  region: string;
  modelId?: string;
  maxTokens?: number;
  timeout?: number;
  /** Sent as output_config.effort to models that accept it */
  effort?: EffortLevel;
  /** Model a refused request is retried on once. Empty string disables the retry. */
  refusalFallbackModel?: string;
  /** `scoring.mode`: `checklist` asks for the scoring checklist and attaches it. Default `model`. */
  scoringMode?: ScoringMode;
}

interface InvokeRequest {
  model: string;
  messages: ConversationMessage[];
  maxTokens: number;
  effort: EffortLevel;
  retry: RetryBudget;
  system?: string;
  tools?: ConversationRequest['tools'];
}

export class BedrockProvider implements AIProvider {
  readonly name = 'bedrock';
  readonly model: string;

  private client: BedrockRuntimeClient;
  private maxTokens: number;
  private timeout: number;
  private effort: EffortLevel;
  private refusalFallbackModel: string;
  private scoringMode: ScoringMode;
  private profile?: EnterpriseProfile;
  private essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>;

  constructor(
    config: BedrockConfig,
    essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>,
    profile?: EnterpriseProfile
  ) {
    this.client = new BedrockRuntimeClient({ region: config.region });
    this.model = config.modelId ?? DEFAULT_MODEL;
    this.maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
    this.effort = config.effort ?? DEFAULT_EFFORT;
    this.refusalFallbackModel =
      config.refusalFallbackModel ?? defaultRefusalFallbackModel(this.model);
    this.scoringMode = config.scoringMode ?? 'model';
    this.profile = profile;
    this.essentialHeadersExtractor = essentialHeadersExtractor;
  }

  /**
   * Analyze email for phishing indicators
   */
  async analyzeEmail(
    emailData: ExtractedEmailData,
    options?: AnalysisOptions
  ): Promise<AnalysisResult> {
    logger.info('Starting email analysis with Bedrock', {
      model: this.model,
      subject: contentFacts(emailData.subject),
    });

    const essentialHeaders = this.essentialHeadersExtractor(emailData.headers);
    const prompt = buildPhishingAnalysisPrompt(emailData, essentialHeaders, this.profile, {
      scoringMode: this.scoringMode,
    });

    const result = await analyzeSingleShot({
      provider: this.name,
      model: this.model,
      refusalFallbackModel: this.refusalFallbackModel,
      invoke: (model, isRefusalFallback) =>
        this.sendSingleShot(model, prompt, options, isRefusalFallback),
    });

    attachChecklist(result, this.scoringMode, emailData);

    logger.info('Email analysis completed', {
      analysisFailed: result.analysisFailed ?? false,
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      model: result.model,
      processingTimeMs: result.processingTimeMs,
    });

    return result;
  }

  /**
   * Run one turn of a tool-capable conversation via InvokeModel. The request
   * body is the Anthropic Messages format, which Bedrock passes through.
   * A refusal or a truncated turn is returned (see `stopReason`), not thrown:
   * the caller decides what it means for the conversation.
   */
  async converse(
    request: ConversationRequest,
    options?: AnalysisOptions
  ): Promise<ConversationResponse> {
    logger.info('Bedrock conversation turn', {
      model: this.model,
      messages: request.messages.length,
      tools: request.tools?.length ?? 0,
    });

    const turn = await this.invokeModel({
      model: this.model,
      messages: request.messages,
      maxTokens: request.maxTokens ?? options?.maxTokens ?? this.maxTokens,
      effort: options?.effort ?? this.effort,
      retry: CONVERSATION_RETRY_BUDGET,
      system: request.system,
      tools: request.tools,
    });

    return {
      content: turn.content,
      rawContent: turn.rawContent,
      stopReason: turn.stopReason,
      refusalCategory: turn.refusalCategory,
      usage: turn.usage,
    };
  }

  /**
   * Send a raw prompt to Bedrock. Throws ModelRefusalError when the model
   * (and the refusal-fallback model) declines, and TruncatedResponseError
   * when the reply hits max_tokens.
   */
  async sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string> {
    const completion = await completeSingleShot({
      provider: this.name,
      model: this.model,
      refusalFallbackModel: this.refusalFallbackModel,
      invoke: (model, isRefusalFallback) =>
        this.sendSingleShot(model, prompt, options, isRefusalFallback),
    });
    return completion.text;
  }

  private sendSingleShot(
    model: string,
    prompt: string,
    options?: AnalysisOptions,
    isRefusalFallback = false
  ): Promise<ModelTurn> {
    const maxTokens = options?.maxTokens ?? this.maxTokens;
    // Note: timeout is handled by SDK defaults, not directly configurable per-request
    // Future enhancement: add AbortController support for per-request timeout
    void (options?.timeout ?? this.timeout);

    // Log at INFO level for visibility during debugging
    logger.info('Sending prompt to Bedrock', {
      model,
      promptLength: prompt.length,
      promptSizeKB: Math.round(prompt.length / 1024),
      maxTokens,
    });

    // Full prompt contains the reported email's content — debug level only,
    // so it never lands in CloudWatch logs at default log levels.
    logger.debug('Full prompt being sent', {
      prompt: prompt,
    });

    return this.invokeModel({
      model,
      messages: [{ role: 'user', content: prompt }],
      maxTokens,
      effort: options?.effort ?? this.effort,
      // Wait generously to ride out transient Bedrock blips — see the
      // ANALYSIS_* constants. Only retryable (transient) errors actually wait.
      retry: isRefusalFallback ? REFUSAL_FALLBACK_RETRY_BUDGET : ANALYSIS_RETRY_BUDGET,
      system: SINGLE_SHOT_SYSTEM_PROMPT,
    });
  }

  /**
   * Send one InvokeModel request, with retries for transient failures.
   *
   * No `thinking` field is sent: Opus 5.5 always thinks and rejects
   * `disabled` with a ValidationException, and omitting the field is valid on
   * every model. No sampling parameters and no `tool_choice` are sent either —
   * current models reject non-default values.
   */
  private invokeModel(request: InvokeRequest): Promise<ModelTurn> {
    const requestBody: Record<string, unknown> = {
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: request.maxTokens,
      messages: request.messages,
    };
    if (request.system) {
      requestBody.system = request.system;
    }
    if (request.tools?.length) {
      requestBody.tools = request.tools;
    }
    const effort = effortForModel(request.model, request.effort);
    if (effort) {
      requestBody.output_config = { effort };
    }
    const serializedBody = JSON.stringify(requestBody);

    return withRetry(
      async () => {
        const command = new InvokeModelCommand({
          modelId: request.model,
          contentType: 'application/json',
          accept: 'application/json',
          body: serializedBody,
        });

        let response;
        try {
          response = await this.client.send(command);
        } catch (sdkError) {
          // Enrich the log with the SDK's exception name / HTTP status / request
          // id — the message alone ("Bedrock is unable to process your request.")
          // is too generic to triage. Rethrow the original so retry semantics
          // are unchanged.
          logger.warn('Bedrock invocation error', {
            model: request.model,
            ...bedrockErrorDetail(sdkError),
            message: sdkError instanceof Error ? sdkError.message : String(sdkError),
          });
          if (isBedrockAuthError(sdkError)) {
            throw new ProviderAuthError(
              `Bedrock rejected Phishy's AWS credentials or permissions ` +
                `(${bedrockErrorDetail(sdkError).errorName}); not retried. Refresh the ` +
                `credentials or check bedrock:InvokeModel access for ${request.model}`,
              { cause: sdkError }
            );
          }
          throw sdkError;
        }

        if (!response.body) {
          throw new Error('Empty response from Bedrock');
        }

        const turn = normalizeModelResponse(
          parseBedrockBody(new TextDecoder().decode(response.body)),
          { provider: this.name, model: request.model }
        );
        if (turn.usage) {
          logger.info('Bedrock token usage', { ...turn.usage, model: request.model });
        }
        return turn;
      },
      {
        ...request.retry,
        shouldRetry: error => {
          // Credentials and permissions fail the same way every time; retrying
          // would burn the whole backoff budget (over 100s) before failing
          if (error instanceof ProviderAuthError) {
            return false;
          }
          // The SDK puts the exception type in `name`; the message is generic
          const detail = `${error.name} ${error.message}`;
          // Consistent failures — access denied, model not found, a rejected
          // request, a Bedrock API error, a malformed response — fail the same
          // way on a retry
          if (
            detail.includes('AccessDeniedException') ||
            detail.includes('ResourceNotFoundException') ||
            detail.includes('ValidationException') ||
            detail.includes('Bedrock error:') ||
            detail.includes('Invalid JSON response') ||
            detail.includes('Unexpected response format')
          ) {
            return false;
          }
          return isRetryableHttpError(error);
        },
      }
    );
  }

  /**
   * Check if provider is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.ping();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get provider health status
   */
  async healthCheck(): Promise<ProviderHealth> {
    const startTime = Date.now();

    try {
      await this.ping();

      return {
        available: true,
        latencyMs: Date.now() - startTime,
        lastChecked: new Date(),
      };
    } catch (error) {
      return {
        available: false,
        latencyMs: Date.now() - startTime,
        lastError: error instanceof Error ? error.message : String(error),
        lastChecked: new Date(),
      };
    }
  }

  /**
   * Minimal round trip. Any successful invoke means the provider is reachable
   * — the reply's text is not read, since a thinking model may spend a small
   * max_tokens budget before writing any.
   */
  private async ping(): Promise<void> {
    await this.invokeModel({
      model: this.model,
      messages: [{ role: 'user', content: 'Reply with "ok"' }],
      maxTokens: HEALTH_CHECK_MAX_TOKENS,
      effort: 'low',
      retry: CONVERSATION_RETRY_BUDGET,
    });
  }

  /**
   * Set or clear the enterprise profile
   */
  setProfile(profile?: EnterpriseProfile): void {
    this.profile = profile;
  }
}

/**
 * Decode an InvokeModel response body. Bedrock can return an `error` object
 * with HTTP 200; that is a failure, not a model reply.
 */
function parseBedrockBody(rawResponse: string): unknown {
  let parsed: { error?: { type?: string; message?: string } } | null;

  try {
    parsed = JSON.parse(rawResponse) as typeof parsed;
  } catch (parseError) {
    // Length only: the body can hold model output derived from the reported email
    logger.error('Failed to parse Bedrock response as JSON', {
      responseLength: rawResponse.length,
      error: parseError instanceof Error ? parseError.message : String(parseError),
    });
    // eslint-disable-next-line preserve-caught-error -- the SyntaxError message can quote the body (model output derived from the reported email); not attached as a cause
    throw new Error('Invalid JSON response from Bedrock');
  }

  if (parsed?.error) {
    logger.error('Bedrock returned an error', {
      errorType: parsed.error.type,
      errorMessage: parsed.error.message,
    });
    throw new Error(`Bedrock error: ${parsed.error.message ?? 'Unknown error'}`);
  }

  return parsed;
}

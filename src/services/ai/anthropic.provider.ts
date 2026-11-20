/**
 * Anthropic API Provider
 * Implements AI provider interface for direct Anthropic API calls
 */

import axios, { AxiosError } from 'axios';
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

const logger = createLogger('anthropic-provider');

const ANTHROPIC_API_ENDPOINT = 'https://api.anthropic.com/v1/messages';

/**
 * Supported Anthropic Claude models
 *
 * Primary recommendations:
 * - CLAUDE_OPUS_5_5: current Opus — best detection quality per dollar (default)
 * - CLAUDE_SONNET_5_5: balance of quality, speed, and cost
 * - CLAUDE_HAIKU_5_5: fastest and cheapest, for high-volume scenarios
 * - CLAUDE_FABLE_5_2: highest capability tier, at twice the Opus 5.5 price
 *
 * IDs are fixed aliases: never append a date suffix. Claude 3.x models are
 * retired and return 404 from the API.
 */
export const ANTHROPIC_CLAUDE_MODELS = {
  // Current models (recommended)
  CLAUDE_OPUS_5_5: 'claude-opus-5-5',
  CLAUDE_SONNET_5_5: 'claude-sonnet-5-5',
  CLAUDE_HAIKU_5_5: 'claude-haiku-5-5',
  CLAUDE_FABLE_5_2: 'claude-fable-5-2',
  // Previous releases (still active)
  CLAUDE_OPUS_5: 'claude-opus-5',
  CLAUDE_SONNET_5: 'claude-sonnet-5',
  CLAUDE_FABLE_5_1: 'claude-fable-5-1',
  CLAUDE_FABLE_5: 'claude-fable-5',
  CLAUDE_OPUS_4_8: 'claude-opus-4-8',
  CLAUDE_SONNET_4_6: 'claude-sonnet-4-6',
  CLAUDE_HAIKU_4_5: 'claude-haiku-4-5',
  CLAUDE_OPUS_4_5: 'claude-opus-4-5',
  // Deprecated (retires 2026-11-30)
  CLAUDE_SONNET_4_5: 'claude-sonnet-4-5',
} as const;

const DEFAULT_MODEL = ANTHROPIC_CLAUDE_MODELS.CLAUDE_OPUS_5_5;
/** Where a refused request is retried once. Opus 4.8 runs a narrower classifier set. */
const DEFAULT_REFUSAL_FALLBACK_MODEL = ANTHROPIC_CLAUDE_MODELS.CLAUDE_OPUS_4_8;
/**
 * Thinking is always on for Opus 5.5 and counts toward max_tokens, so the
 * limit has to hold the thinking as well as the JSON verdict.
 */
const DEFAULT_MAX_TOKENS = 16000;
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_EFFORT: EffortLevel = 'medium';

/** Health probe budget: room to think briefly; any HTTP 200 counts as healthy. */
const HEALTH_CHECK_MAX_TOKENS = 1024;

export interface AnthropicConfig {
  apiKey: string;
  model?: string;
  maxTokens?: number;
  timeout?: number;
  /** Sent as output_config.effort to models that accept it */
  effort?: EffortLevel;
  /** Model a refused request is retried on once. Empty string disables the retry. */
  refusalFallbackModel?: string;
  /** `scoring.mode`: `checklist` asks for the scoring checklist and attaches it. Default `model`. */
  scoringMode?: ScoringMode;
}

interface MessagesRequest {
  model: string;
  messages: ConversationMessage[];
  maxTokens: number;
  timeout: number;
  effort: EffortLevel;
  system?: string;
  tools?: ConversationRequest['tools'];
}

export class AnthropicProvider implements AIProvider {
  readonly name = 'anthropic';
  readonly model: string;

  private apiKey: string;
  private maxTokens: number;
  private timeout: number;
  private effort: EffortLevel;
  private refusalFallbackModel: string;
  private scoringMode: ScoringMode;
  private profile?: EnterpriseProfile;
  private essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>;

  constructor(
    config: AnthropicConfig,
    essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>,
    profile?: EnterpriseProfile
  ) {
    this.apiKey = config.apiKey;
    this.model = config.model ?? DEFAULT_MODEL;
    this.maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
    this.effort = config.effort ?? DEFAULT_EFFORT;
    this.refusalFallbackModel = config.refusalFallbackModel ?? DEFAULT_REFUSAL_FALLBACK_MODEL;
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
    logger.info('Starting email analysis with Anthropic', {
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
      invoke: model => this.sendSingleShot(model, prompt, options),
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
   * Run one turn of a tool-capable conversation against the Messages API.
   * A refusal or a truncated turn is returned (see `stopReason`), not thrown:
   * the caller decides what it means for the conversation.
   */
  async converse(
    request: ConversationRequest,
    options?: AnalysisOptions
  ): Promise<ConversationResponse> {
    logger.info('Anthropic conversation turn', {
      model: this.model,
      messages: request.messages.length,
      tools: request.tools?.length ?? 0,
    });

    const turn = await this.callMessagesApi({
      model: this.model,
      messages: request.messages,
      maxTokens: request.maxTokens ?? options?.maxTokens ?? this.maxTokens,
      timeout: options?.timeout ?? this.timeout,
      effort: options?.effort ?? this.effort,
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
   * Send a raw prompt to Anthropic API. Throws ModelRefusalError when the
   * model (and the refusal-fallback model) declines, and
   * TruncatedResponseError when the reply hits max_tokens.
   */
  async sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string> {
    const completion = await completeSingleShot({
      provider: this.name,
      model: this.model,
      refusalFallbackModel: this.refusalFallbackModel,
      invoke: model => this.sendSingleShot(model, prompt, options),
    });
    return completion.text;
  }

  private sendSingleShot(
    model: string,
    prompt: string,
    options?: AnalysisOptions
  ): Promise<ModelTurn> {
    const maxTokens = options?.maxTokens ?? this.maxTokens;

    logger.debug('Sending prompt to Anthropic API', {
      model,
      promptLength: prompt.length,
      maxTokens,
    });

    return this.callMessagesApi({
      model,
      messages: [{ role: 'user', content: prompt }],
      maxTokens,
      timeout: options?.timeout ?? this.timeout,
      effort: options?.effort ?? this.effort,
    });
  }

  /**
   * POST one Messages API request, with retries for transient failures.
   *
   * No `thinking` field is sent: Opus 5.5 always thinks and rejects
   * `disabled`, and omitting the field is valid on every model. No sampling
   * parameters and no `tool_choice` are sent either — current models reject
   * non-default values.
   */
  private callMessagesApi(request: MessagesRequest): Promise<ModelTurn> {
    const body: Record<string, unknown> = {
      model: request.model,
      messages: request.messages,
      max_tokens: request.maxTokens,
    };
    if (request.system) {
      body.system = request.system;
    }
    if (request.tools?.length) {
      body.tools = request.tools;
    }
    const effort = effortForModel(request.model, request.effort);
    if (effort) {
      body.output_config = { effort };
    }

    return withRetry(
      async () => {
        try {
          const response = await axios.post(ANTHROPIC_API_ENDPOINT, body, {
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': this.apiKey,
              'anthropic-version': '2023-06-01',
            },
            timeout: request.timeout,
          });

          const turn = normalizeModelResponse(response.data, {
            provider: this.name,
            model: request.model,
          });
          if (turn.usage) {
            logger.info('Anthropic token usage', { ...turn.usage, model: request.model });
          }
          return turn;
        } catch (error) {
          if (axios.isAxiosError(error)) {
            const axiosError = error as AxiosError;

            // Handle specific error codes
            if (axiosError.response?.status === 529) {
              logger.warn('Anthropic API is overloaded');
              // eslint-disable-next-line preserve-caught-error -- the AxiosError carries request headers (API key) and the email-derived body; it is deliberately not attached as a cause
              throw new Error('Anthropic API is currently overloaded (status 529)');
            }

            if (axiosError.response?.status === 401) {
              throw new ProviderAuthError('Invalid Anthropic API key (status 401); not retried');
            }
            if (axiosError.response?.status === 403) {
              throw new ProviderAuthError(
                'Anthropic API denied the request (status 403); not retried. Check the API key permissions'
              );
            }

            if (axiosError.response?.status === 400) {
              // eslint-disable-next-line preserve-caught-error -- the AxiosError carries request headers (API key) and the email-derived body; it is deliberately not attached as a cause
              throw new Error(
                `Anthropic API bad request: ${JSON.stringify(axiosError.response.data)}`
              );
            }

            // eslint-disable-next-line preserve-caught-error -- the AxiosError carries request headers (API key) and the email-derived body; it is deliberately not attached as a cause
            throw new Error(
              `Anthropic API error: ${axiosError.response?.status ?? 'unknown'} - ${axiosError.message}`
            );
          }

          throw error;
        }
      },
      {
        maxRetries: 3,
        baseDelayMs: 1000,
        shouldRetry: error => {
          // Don't retry auth errors, bad requests, or malformed responses
          if (
            error instanceof ProviderAuthError ||
            error.message.includes('bad request') ||
            error.message.includes('Unexpected response format')
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
    if (!this.apiKey) {
      return false;
    }

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
   * Minimal round trip. Any HTTP 200 means the provider is reachable — the
   * reply's text is not read, since a thinking model may spend a small
   * max_tokens budget before writing any.
   */
  private async ping(): Promise<void> {
    await this.sendSingleShot(this.model, 'Reply with "ok"', {
      maxTokens: HEALTH_CHECK_MAX_TOKENS,
      timeout: 10000,
      effort: 'low',
    });
  }

  /**
   * Set or clear the enterprise profile
   */
  setProfile(profile?: EnterpriseProfile): void {
    this.profile = profile;
  }
}

/**
 * Anthropic API Provider
 * Implements AI provider interface for direct Anthropic API calls
 */

import axios, { AxiosError } from 'axios';
import {
  AIProvider,
  AnalysisOptions,
  ProviderHealth,
  parseAnalysisResponse,
} from './provider.interface';
import { buildPhishingAnalysisPrompt } from './prompt.builder';
import { AnalysisResult, ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';
import { EnterpriseProfile } from '../../models/profile.model';

const logger = createLogger('anthropic-provider');

const ANTHROPIC_API_ENDPOINT = 'https://api.anthropic.com/v1/messages';

/**
 * Supported Anthropic Claude models
 *
 * Primary recommendations:
 * - claude-sonnet-4-5-20250514: Best balance of quality and speed (recommended)
 * - claude-haiku-4-5-20250514: Fastest option for high-volume scenarios
 */
export const ANTHROPIC_CLAUDE_MODELS = {
  // Claude 4.5 models (recommended)
  CLAUDE_SONNET_4_5: 'claude-sonnet-4-5-20250514',
  CLAUDE_HAIKU_4_5: 'claude-haiku-4-5-20250514',
  // Claude 4 models
  CLAUDE_OPUS_4: 'claude-opus-4-20250514',
  CLAUDE_SONNET_4: 'claude-sonnet-4-20250514',
  // Legacy models (for backwards compatibility)
  CLAUDE_3_5_SONNET: 'claude-3-5-sonnet-20241022',
  CLAUDE_3_SONNET: 'claude-3-sonnet-20240229',
  CLAUDE_3_HAIKU: 'claude-3-haiku-20240307',
} as const;

const DEFAULT_MODEL = ANTHROPIC_CLAUDE_MODELS.CLAUDE_SONNET_4_5;
const DEFAULT_MAX_TOKENS = 4096;
const DEFAULT_TIMEOUT_MS = 60000;

export interface AnthropicConfig {
  apiKey: string;
  model?: string;
  maxTokens?: number;
  timeout?: number;
}

export class AnthropicProvider implements AIProvider {
  readonly name = 'anthropic';
  readonly model: string;

  private apiKey: string;
  private maxTokens: number;
  private timeout: number;
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
    const startTime = Date.now();

    logger.info('Starting email analysis with Anthropic', {
      model: this.model,
      subject: emailData.subject.substring(0, 50),
    });

    const essentialHeaders = this.essentialHeadersExtractor(emailData.headers);
    const prompt = buildPhishingAnalysisPrompt(emailData, essentialHeaders, this.profile);

    const responseText = await this.sendPrompt(prompt, options);
    const processingTimeMs = Date.now() - startTime;

    const result = parseAnalysisResponse(responseText, this.name, this.model, processingTimeMs);

    logger.info('Email analysis completed', {
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      processingTimeMs,
    });

    return result;
  }

  /**
   * Send a raw prompt to Anthropic API
   */
  async sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string> {
    const maxTokens = options?.maxTokens ?? this.maxTokens;
    const timeout = options?.timeout ?? this.timeout;

    logger.debug('Sending prompt to Anthropic API', {
      model: this.model,
      promptLength: prompt.length,
      maxTokens,
    });

    return withRetry(
      async () => {
        try {
          const response = await axios.post(
            ANTHROPIC_API_ENDPOINT,
            {
              model: this.model,
              messages: [{ role: 'user', content: prompt }],
              max_tokens: maxTokens,
            },
            {
              headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey,
                'anthropic-version': '2023-06-01',
              },
              timeout,
            }
          );

          const content = response.data?.content?.[0]?.text;
          if (!content) {
            throw new Error('Unexpected response format from Anthropic API');
          }

          logger.debug('Received response from Anthropic API', {
            responseLength: content.length,
          });

          return content as string;
        } catch (error) {
          if (axios.isAxiosError(error)) {
            const axiosError = error as AxiosError;

            // Handle specific error codes
            if (axiosError.response?.status === 529) {
              logger.warn('Anthropic API is overloaded');
              throw new Error('Anthropic API is currently overloaded (status 529)');
            }

            if (axiosError.response?.status === 401) {
              throw new Error('Invalid Anthropic API key');
            }

            if (axiosError.response?.status === 400) {
              throw new Error(
                `Anthropic API bad request: ${JSON.stringify(axiosError.response.data)}`
              );
            }

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
          // Don't retry auth or bad request errors
          if (error.message.includes('401') || error.message.includes('400')) {
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
      // Quick health check with minimal prompt
      await this.sendPrompt('Reply with "ok"', { maxTokens: 10, timeout: 10000 });
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
      await this.sendPrompt('Reply with "ok"', { maxTokens: 10, timeout: 10000 });

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
   * Set or clear the enterprise profile
   */
  setProfile(profile?: EnterpriseProfile): void {
    this.profile = profile;
  }
}

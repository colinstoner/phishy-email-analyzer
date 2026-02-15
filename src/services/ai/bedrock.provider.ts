/**
 * AWS Bedrock Provider
 * Implements AI provider interface for AWS Bedrock Claude models
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from '@aws-sdk/client-bedrock-runtime';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import * as https from 'https';
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

const logger = createLogger('bedrock-provider');

/**
 * Supported Bedrock Claude models
 *
 * Primary recommendations:
 * - CLAUDE_SONNET_4_5: Best balance of quality and speed for phishing analysis (recommended)
 * - CLAUDE_HAIKU_4_5: Fastest option for high-volume or quick-scan scenarios
 */
export const BEDROCK_CLAUDE_MODELS = {
  // Claude 4.5 models (recommended)
  CLAUDE_SONNET_4_5: 'anthropic.claude-sonnet-4-5-20250929-v1:0',
  CLAUDE_HAIKU_4_5: 'anthropic.claude-haiku-4-5-20250929-v1:0',
  // Claude 4 models
  CLAUDE_OPUS_4: 'anthropic.claude-opus-4-20250514-v1:0',
  CLAUDE_SONNET_4: 'anthropic.claude-sonnet-4-20250514-v1:0',
  // Legacy models (for backwards compatibility)
  CLAUDE_3_5_SONNET: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
  CLAUDE_3_SONNET: 'anthropic.claude-3-sonnet-20240229-v1:0',
  CLAUDE_3_HAIKU: 'anthropic.claude-3-haiku-20240307-v1:0',
} as const;

const DEFAULT_MODEL = BEDROCK_CLAUDE_MODELS.CLAUDE_SONNET_4_5;
const DEFAULT_MAX_TOKENS = 4096;
const DEFAULT_TIMEOUT_MS = 60000;

export interface BedrockConfig {
  region: string;
  modelId?: string;
  maxTokens?: number;
  timeout?: number;
}

export class BedrockProvider implements AIProvider {
  readonly name = 'bedrock';
  readonly model: string;

  private client: BedrockRuntimeClient;
  private maxTokens: number;
  private timeout: number;
  private profile?: EnterpriseProfile;
  private essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>;

  constructor(
    config: BedrockConfig,
    essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>,
    profile?: EnterpriseProfile
  ) {
    // Configure HTTP handler with HTTP/1.1 and keepalive to avoid VPC endpoint HTTP/2 stream issues
    const requestHandler = new NodeHttpHandler({
      httpsAgent: new https.Agent({
        keepAlive: true,
        keepAliveMsecs: 10000,
        timeout: 120000,
        // Force HTTP/1.1 by disabling ALPN negotiation
        ALPNProtocols: ['http/1.1'],
      }),
      connectionTimeout: 10000,
      requestTimeout: 120000,
    });

    this.client = new BedrockRuntimeClient({
      region: config.region,
      requestHandler,
    });
    this.model = config.modelId ?? DEFAULT_MODEL;
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

    logger.info('Starting email analysis with Bedrock', {
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
   * Send a raw prompt to Bedrock
   */
  async sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string> {
    const maxTokens = options?.maxTokens ?? this.maxTokens;
    // Note: timeout is handled by SDK defaults, not directly configurable per-request
    // Future enhancement: add AbortController support for per-request timeout
    void (options?.timeout ?? this.timeout);

    logger.debug('Sending prompt to Bedrock', {
      model: this.model,
      promptLength: prompt.length,
      maxTokens,
    });

    return withRetry(
      async () => {
        const requestBody = {
          anthropic_version: 'bedrock-2023-05-31',
          max_tokens: maxTokens,
          messages: [
            {
              role: 'user',
              content: prompt,
            },
          ],
        };

        const command = new InvokeModelCommand({
          modelId: this.model,
          contentType: 'application/json',
          accept: 'application/json',
          body: JSON.stringify(requestBody),
        });

        const response = await this.client.send(command);

        if (!response.body) {
          throw new Error('Empty response from Bedrock');
        }

        const responseBody = JSON.parse(new TextDecoder().decode(response.body)) as {
          content?: Array<{ text?: string }>;
        };

        const content = responseBody.content?.[0]?.text;
        if (!content) {
          throw new Error('Unexpected response format from Bedrock');
        }

        logger.debug('Received response from Bedrock', {
          responseLength: content.length,
        });

        return content;
      },
      {
        maxRetries: 3,
        baseDelayMs: 1000,
        shouldRetry: error => {
          // Don't retry access denied errors
          if (error.message.includes('AccessDeniedException')) {
            return false;
          }
          // Don't retry model not found errors
          if (error.message.includes('ResourceNotFoundException')) {
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

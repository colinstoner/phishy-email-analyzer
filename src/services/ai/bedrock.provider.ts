/**
 * AWS Bedrock Provider
 * Implements AI provider interface for AWS Bedrock Claude models
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from '@aws-sdk/client-bedrock-runtime';
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
  CLAUDE_SONNET_4_5: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
  CLAUDE_HAIKU_4_5: 'us.anthropic.claude-haiku-4-5-20251001-v1:0',
  // Claude 4 models
  CLAUDE_SONNET_4: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
  CLAUDE_OPUS_4: 'us.anthropic.claude-opus-4-20250514-v1:0',
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
    this.client = new BedrockRuntimeClient({ region: config.region });
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

    // Log at INFO level for visibility during debugging
    logger.info('Sending prompt to Bedrock', {
      model: this.model,
      promptLength: prompt.length,
      promptSizeKB: Math.round(prompt.length / 1024),
      maxTokens,
    });

    // Log full prompt for debugging refusals
    logger.info('Full prompt being sent', {
      prompt: prompt,
    });

    return withRetry(
      async () => {
        const requestBody = {
          anthropic_version: 'bedrock-2023-05-31',
          max_tokens: maxTokens,
          system: 'You are a security analyst helping to identify phishing emails. Always provide your analysis in the requested JSON format.',
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

        const rawResponse = new TextDecoder().decode(response.body);
        const responseBody = parseBedrockResponse(rawResponse);

        logger.debug('Received response from Bedrock', {
          responseLength: responseBody.length,
        });

        return responseBody;
      },
      {
        maxRetries: 3,
        baseDelayMs: 1000,
        shouldRetry: error => {
          const message = error.message || '';
          // Don't retry access denied errors
          if (message.includes('AccessDeniedException')) {
            return false;
          }
          // Don't retry model not found errors
          if (message.includes('ResourceNotFoundException')) {
            return false;
          }
          // Don't retry Bedrock API errors (these are consistent failures)
          if (message.includes('Bedrock error:')) {
            return false;
          }
          // Don't retry invalid JSON (malformed response)
          if (message.includes('Invalid JSON response')) {
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

/**
 * Bedrock response structure
 */
interface BedrockResponse {
  id?: string;
  type?: string;
  role?: string;
  content?: Array<{
    type: string;
    text?: string;
  }>;
  model?: string;
  stop_reason?: string;
  stop_sequence?: string | null;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
  error?: {
    type?: string;
    message?: string;
  };
}

/**
 * Parse Bedrock response with robust error handling
 * Extracts text content from various response formats
 */
function parseBedrockResponse(rawResponse: string): string {
  let parsed: BedrockResponse;

  try {
    parsed = JSON.parse(rawResponse) as BedrockResponse;
  } catch (parseError) {
    logger.error('Failed to parse Bedrock response as JSON', {
      rawResponse: rawResponse.substring(0, 500),
      error: parseError instanceof Error ? parseError.message : String(parseError),
    });
    throw new Error('Invalid JSON response from Bedrock');
  }

  // Check for error response
  if (parsed.error) {
    logger.error('Bedrock returned an error', {
      errorType: parsed.error.type,
      errorMessage: parsed.error.message,
    });
    throw new Error(`Bedrock error: ${parsed.error.message ?? 'Unknown error'}`);
  }

  // Check for refusal - Claude declined to respond
  if (parsed.stop_reason === 'refusal') {
    logger.error('Claude refused to analyze - logging full response for debugging', {
      stopReason: parsed.stop_reason,
      fullResponse: JSON.stringify(parsed),
    });
    throw new Error('Claude refused to respond - check logs for full prompt');
  }

  // Extract text from content array
  if (parsed.content && Array.isArray(parsed.content)) {
    const textParts: string[] = [];

    for (const block of parsed.content) {
      if (block.type === 'text' && block.text) {
        textParts.push(block.text);
      }
    }

    if (textParts.length > 0) {
      return textParts.join('\n');
    }

    // Content array exists but no text blocks found
    logger.warn('Bedrock response has content but no text blocks', {
      contentTypes: parsed.content.map(b => b.type),
      stopReason: parsed.stop_reason,
    });
  }

  // Log detailed info for debugging
  logger.error('Could not extract text from Bedrock response', {
    rawResponse: rawResponse.substring(0, 1000),
    hasContent: !!parsed.content,
    contentLength: parsed.content?.length,
    stopReason: parsed.stop_reason,
    responseType: parsed.type,
  });

  throw new Error('No text content in Bedrock response');
}

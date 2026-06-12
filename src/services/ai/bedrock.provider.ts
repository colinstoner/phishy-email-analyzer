/**
 * AWS Bedrock Provider
 * Implements AI provider interface for AWS Bedrock Claude models
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import {
  AIProvider,
  AnalysisOptions,
  ProviderHealth,
  parseAnalysisResponse,
} from './provider.interface';
import { buildPhishingAnalysisPrompt } from './prompt.builder';
import { ConversationRequest, ConversationResponse, ContentBlock } from './conversation.types';
import { AnalysisResult, ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';
import { EnterpriseProfile } from '../../models/profile.model';

const logger = createLogger('bedrock-provider');

/**
 * Supported Bedrock Claude models
 *
 * Primary recommendations:
 * - CLAUDE_OPUS_4_8: Most capable model — best detection quality (default)
 * - CLAUDE_SONNET_4_6: Best balance of quality, speed, and cost
 * - CLAUDE_HAIKU_4_5: Fastest option for high-volume or quick-scan scenarios
 *
 * ID formats: on-demand invocation requires an INFERENCE PROFILE ID, not the
 * bare `anthropic.` model ID (Bedrock rejects the bare form with a
 * ValidationException — verified empirically). `global.` profiles route
 * dynamically at baseline pricing; swap to a regional prefix (`us.`, `eu.`,
 * ...) for data-residency requirements, at a 10% pricing premium.
 */
export const BEDROCK_CLAUDE_MODELS = {
  // Current models (recommended)
  CLAUDE_OPUS_4_8: 'global.anthropic.claude-opus-4-8',
  CLAUDE_OPUS_4_6: 'global.anthropic.claude-opus-4-6-v1',
  CLAUDE_SONNET_4_6: 'global.anthropic.claude-sonnet-4-6',
  CLAUDE_HAIKU_4_5: 'us.anthropic.claude-haiku-4-5-20251001-v1:0',
  // Previous generation (still active)
  CLAUDE_SONNET_4_5: 'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
  // Deprecated on Bedrock (avoid for new deployments)
  CLAUDE_SONNET_4: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
} as const;

const DEFAULT_MODEL = BEDROCK_CLAUDE_MODELS.CLAUDE_OPUS_4_8;
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

    const { text: responseText, usage } = await this.sendPromptWithUsage(prompt, options);
    const processingTimeMs = Date.now() - startTime;

    const result = parseAnalysisResponse(responseText, this.name, this.model, processingTimeMs);

    // Add token usage to result for cost tracking
    if (usage) {
      result.tokenUsage = usage;
    }

    logger.info('Email analysis completed', {
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      processingTimeMs,
    });

    return result;
  }

  /**
   * Run one turn of a tool-capable conversation via InvokeModel. The request
   * body is the Anthropic Messages format, which Bedrock passes through.
   */
  async converse(
    request: ConversationRequest,
    options?: AnalysisOptions
  ): Promise<ConversationResponse> {
    const maxTokens = request.maxTokens ?? options?.maxTokens ?? this.maxTokens;

    logger.info('Bedrock conversation turn', {
      model: this.model,
      messages: request.messages.length,
      tools: request.tools?.length ?? 0,
    });

    return withRetry(
      async () => {
        const requestBody: Record<string, unknown> = {
          anthropic_version: 'bedrock-2023-05-31',
          max_tokens: maxTokens,
          messages: request.messages,
        };
        if (request.system) {
          requestBody.system = request.system;
        }
        if (request.tools?.length) {
          requestBody.tools = request.tools;
        }

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

        const parsed = JSON.parse(new TextDecoder().decode(response.body)) as BedrockResponse;
        if (parsed.error) {
          throw new Error(`Bedrock error: ${parsed.error.message ?? 'Unknown error'}`);
        }
        if (parsed.stop_reason === 'refusal') {
          throw new Error('Claude refused to respond');
        }

        const content: ContentBlock[] = [];
        for (const block of parsed.content ?? []) {
          if (block.type === 'text' && block.text) {
            content.push({ type: 'text', text: block.text });
          } else if (block.type === 'tool_use' && block.id && block.name) {
            content.push({
              type: 'tool_use',
              id: block.id,
              name: block.name,
              input: block.input ?? {},
            });
          }
        }

        return {
          content,
          stopReason: parsed.stop_reason,
          usage: parsed.usage
            ? {
                inputTokens: parsed.usage.input_tokens,
                outputTokens: parsed.usage.output_tokens,
                totalTokens: parsed.usage.input_tokens + parsed.usage.output_tokens,
              }
            : undefined,
        };
      },
      {
        maxRetries: 3,
        baseDelayMs: 1000,
        shouldRetry: error => {
          const message = error.message || '';
          if (
            message.includes('AccessDeniedException') ||
            message.includes('ResourceNotFoundException') ||
            message.includes('Bedrock error:') ||
            message.includes('refused to respond')
          ) {
            return false;
          }
          return isRetryableHttpError(error);
        },
      }
    );
  }

  /**
   * Send a raw prompt to Bedrock
   */
  async sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string> {
    const result = await this.sendPromptWithUsage(prompt, options);
    return result.text;
  }

  /**
   * Send a raw prompt to Bedrock and return both text and usage data
   */
  private async sendPromptWithUsage(
    prompt: string,
    options?: AnalysisOptions
  ): Promise<{
    text: string;
    usage?: { inputTokens: number; outputTokens: number; totalTokens: number };
  }> {
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

    // Full prompt contains the reported email's content — debug level only,
    // so it never lands in CloudWatch logs at default log levels.
    logger.debug('Full prompt being sent', {
      prompt: prompt,
    });

    return withRetry(
      async () => {
        const requestBody = {
          anthropic_version: 'bedrock-2023-05-31',
          max_tokens: maxTokens,
          system:
            'You are a security analyst helping to identify phishing emails. Always provide your analysis in the requested JSON format.',
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
        const parsedResponse = parseBedrockResponse(rawResponse);

        // Log token usage for cost tracking
        let usage: { inputTokens: number; outputTokens: number; totalTokens: number } | undefined;
        if (parsedResponse.usage) {
          usage = {
            inputTokens: parsedResponse.usage.input_tokens,
            outputTokens: parsedResponse.usage.output_tokens,
            totalTokens: parsedResponse.usage.input_tokens + parsedResponse.usage.output_tokens,
          };
          logger.info('Bedrock token usage', {
            ...usage,
            model: this.model,
          });
        }

        logger.debug('Received response from Bedrock', {
          responseLength: parsedResponse.text.length,
        });

        return { text: parsedResponse.text, usage };
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
    id?: string;
    name?: string;
    input?: Record<string, unknown>;
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
 * Parsed response with text and usage data
 */
interface ParsedBedrockResponse {
  text: string;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

/**
 * Parse Bedrock response with robust error handling
 * Extracts text content and usage data from various response formats
 */
function parseBedrockResponse(rawResponse: string): ParsedBedrockResponse {
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
      return {
        text: textParts.join('\n'),
        usage: parsed.usage,
      };
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

/**
 * Model response handling
 * The provider-neutral half of a Messages API call: reading a response by
 * block type, and deciding what a refusal or a truncated reply means. Both
 * providers (raw HTTP and Bedrock InvokeModel) return the same response shape,
 * so both run every call path through here and behave identically.
 *
 * Fail-closed rules:
 * - `stop_reason: "refusal"` never yields text. It is retried once on the
 *   refusal-fallback model, then surfaces as a ModelRefusalError.
 * - `stop_reason: "max_tokens"` never yields text. Thinking counts toward
 *   max_tokens, so a truncated reply can be half a JSON object — or nothing.
 */

import { AnalysisResult, TokenUsage } from '../../types';
import { createLogger } from '../../utils/logger';
import { emitAnalysisRefusalMetric } from '../../utils/metrics';
import { ContentBlock, RawContentBlock, TextBlock } from './conversation.types';
import { createFailedAnalysisResult, parseAnalysisResponse } from './provider.interface';

const logger = createLogger('model-response');

/** A refusal in this category is a prompt problem; another model won't fix it. */
const NON_RETRYABLE_REFUSAL_CATEGORY = 'reasoning_extraction';

/** One normalized model reply */
export interface ModelTurn {
  /** Text blocks joined in order. Empty when the model returned none. */
  text: string;
  /** Typed text and tool_use blocks, in model order */
  content: ContentBlock[];
  /** Every block exactly as returned, thinking included */
  rawContent: RawContentBlock[];
  stopReason?: string;
  /** `stop_details.category` when the model refused. Informational only. */
  refusalCategory?: string | null;
  usage?: TokenUsage;
}

/** The model declined the request (`stop_reason: "refusal"`). */
export class ModelRefusalError extends Error {
  constructor(
    message: string,
    readonly category: string | null
  ) {
    super(message);
    this.name = 'ModelRefusalError';
  }
}

/** The reply was cut off at max_tokens and cannot be trusted as a verdict. */
export class TruncatedResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TruncatedResponseError';
  }
}

function readUsage(raw: unknown): TokenUsage | undefined {
  const usage = raw as
    | {
        input_tokens?: unknown;
        output_tokens?: unknown;
        output_tokens_details?: { thinking_tokens?: unknown };
      }
    | undefined;
  if (typeof usage?.input_tokens !== 'number' || typeof usage?.output_tokens !== 'number') {
    return undefined;
  }
  const thinkingTokens = usage.output_tokens_details?.thinking_tokens;
  return {
    inputTokens: usage.input_tokens,
    outputTokens: usage.output_tokens,
    totalTokens: usage.input_tokens + usage.output_tokens,
    ...(typeof thinkingTokens === 'number' ? { thinkingTokens } : {}),
  };
}

/**
 * Read a Messages API response body. Blocks are selected by `type`, never by
 * position: a reply from a thinking model starts with `thinking` blocks.
 *
 * A refusal is logged and counted here, once, so no call path can miss it.
 * Only the category is logged — a refused reply can hold partial output
 * derived from the suspicious email.
 */
export function normalizeModelResponse(
  data: unknown,
  context: { provider: string; model: string }
): ModelTurn {
  const body = (data ?? {}) as {
    content?: unknown;
    stop_reason?: unknown;
    stop_details?: { category?: unknown } | null;
    usage?: unknown;
  };
  const stopReason = typeof body.stop_reason === 'string' ? body.stop_reason : undefined;
  const refused = stopReason === 'refusal';

  // A refusal before any output has an empty (or absent) content array
  if (!Array.isArray(body.content) && !refused) {
    throw new Error(`Unexpected response format from ${context.provider}`);
  }
  const rawContent = (Array.isArray(body.content) ? body.content : []).filter(
    (block): block is RawContentBlock =>
      typeof block === 'object' &&
      block !== null &&
      typeof (block as { type?: unknown }).type === 'string'
  );

  const content: ContentBlock[] = [];
  for (const block of rawContent) {
    if (block.type === 'text' && typeof block.text === 'string' && block.text) {
      content.push({ type: 'text', text: block.text });
    } else if (
      block.type === 'tool_use' &&
      typeof block.id === 'string' &&
      typeof block.name === 'string'
    ) {
      content.push({
        type: 'tool_use',
        id: block.id,
        name: block.name,
        input: (block.input as Record<string, unknown> | undefined) ?? {},
      });
    }
  }

  const turn: ModelTurn = {
    text: content
      .filter((block): block is TextBlock => block.type === 'text')
      .map(block => block.text)
      .join('\n'),
    content,
    rawContent,
    stopReason,
    usage: readUsage(body.usage),
  };

  if (refused) {
    const category = body.stop_details?.category;
    turn.refusalCategory = typeof category === 'string' ? category : null;
    logger.warn('Model refused the request', {
      provider: context.provider,
      model: context.model,
      refusalCategory: turn.refusalCategory,
    });
    emitAnalysisRefusalMetric(context.provider, context.model, turn.refusalCategory);
  }

  return turn;
}

export interface SingleShotRequest {
  provider: string;
  model: string;
  /** Retried once on this model after a refusal. Empty or undefined disables the retry. */
  refusalFallbackModel?: string;
  /** Send the same request to the given model */
  invoke: (model: string, isRefusalFallback: boolean) => Promise<ModelTurn>;
}

export interface SingleShotCompletion {
  text: string;
  usage?: TokenUsage;
  /** The model that produced the text — the fallback model after a refusal */
  model: string;
}

function describeRefusal(model: string, category: string | null | undefined): string {
  return `${model} declined the request (category: ${category ?? 'unspecified'})`;
}

/**
 * Run one single-shot request and return its text, or throw.
 *
 * On a refusal the identical request is sent once to the refusal-fallback
 * model. It is a fresh request built from the prompt, so no thinking blocks
 * from the refusing model travel with it. `reasoning_extraction` refusals are
 * not retried: they mean the prompt asked for the model's reasoning, which a
 * different model does not change.
 */
export async function completeSingleShot(
  request: SingleShotRequest
): Promise<SingleShotCompletion> {
  const { provider, model, refusalFallbackModel, invoke } = request;
  let servedBy = model;
  let turn = await invoke(model, false);

  if (turn.stopReason === 'refusal') {
    const refusal = describeRefusal(model, turn.refusalCategory);

    if (turn.refusalCategory === NON_RETRYABLE_REFUSAL_CATEGORY) {
      throw new ModelRefusalError(
        `${refusal}; this category is not retried on another model`,
        turn.refusalCategory
      );
    }
    if (!refusalFallbackModel || refusalFallbackModel === model) {
      throw new ModelRefusalError(
        `${refusal}; no refusal-fallback model is configured`,
        turn.refusalCategory ?? null
      );
    }

    logger.info('Retrying refused request on the refusal-fallback model', {
      provider,
      refusedModel: model,
      fallbackModel: refusalFallbackModel,
      refusalCategory: turn.refusalCategory,
    });
    servedBy = refusalFallbackModel;
    turn = await invoke(refusalFallbackModel, true);

    if (turn.stopReason === 'refusal') {
      throw new ModelRefusalError(
        `${refusal}; fallback ${describeRefusal(refusalFallbackModel, turn.refusalCategory)}`,
        turn.refusalCategory ?? null
      );
    }
  }

  if (turn.stopReason === 'max_tokens') {
    throw new TruncatedResponseError(
      `${servedBy} hit the max_tokens limit before finishing its response`
    );
  }
  if (!turn.text) {
    throw new Error(`No text content in ${provider} response`);
  }

  return { text: turn.text, usage: turn.usage, model: servedBy };
}

/**
 * Single-shot email analysis. A refusal that the fallback could not recover,
 * or a truncated reply, comes back as an `analysisFailed` result — the report
 * then says the email was NOT checked. Transport errors still throw, so the
 * caller's provider fallback applies to them.
 */
export async function analyzeSingleShot(request: SingleShotRequest): Promise<AnalysisResult> {
  const startTime = Date.now();
  try {
    const completion = await completeSingleShot(request);
    const result = parseAnalysisResponse(
      completion.text,
      request.provider,
      completion.model,
      Date.now() - startTime
    );
    if (completion.usage) {
      result.tokenUsage = completion.usage;
    }
    return result;
  } catch (error) {
    if (error instanceof ModelRefusalError || error instanceof TruncatedResponseError) {
      logger.error('Analysis produced no verdict', {
        provider: request.provider,
        model: request.model,
        reason: error.message,
      });
      const reason =
        error instanceof ModelRefusalError
          ? `The model declined to analyze this email: ${error.message}`
          : `The model's response was incomplete: ${error.message}`;
      return createFailedAnalysisResult(reason, Date.now() - startTime);
    }
    throw error;
  }
}

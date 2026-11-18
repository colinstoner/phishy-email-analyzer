/**
 * AI Model Pricing
 * Per-model cost estimation for Anthropic API and AWS Bedrock usage
 */

import { createLogger } from './logger';

const logger = createLogger('pricing');

interface ModelPricing {
  match: string;
  inputPerMTok: number;
  outputPerMTok: number;
  /** Rates that apply to the whole request once its prompt exceeds a size */
  longPrompt?: { aboveInputTokens: number; inputPerMTok: number; outputPerMTok: number };
}

/**
 * Pricing in USD per million tokens. Output tokens include thinking tokens,
 * which are billed at the output rate.
 *
 * Matched by substring against the model ID, so one entry covers the bare
 * Anthropic ID, dated full IDs, and Bedrock variants with global./us./eu.
 * prefixes and -v1:0 suffixes. First match wins, so within a family the more
 * specific entry MUST come first: `opus-5-5` before `opus-5`, `fable-5-2`
 * before `fable-5`, `opus-4-8` before `opus-4`. Entries of different major
 * versions cannot shadow each other (`opus-5` is not a substring of
 * `opus-4-5`, nor `sonnet-5` of `sonnet-4-5`).
 *
 * Sources:
 * - 5.x models: Anthropic first-party list prices, verified 2026-11-17.
 *   Bedrock sets its own prices; the AWS Bedrock pricing page did not expose
 *   per-token rates for these models when checked on that date, so the
 *   first-party numbers are used for Bedrock IDs too. Re-check against
 *   https://aws.amazon.com/bedrock/pricing/ before relying on these for
 *   Bedrock billing.
 * - 4.x models: https://platform.claude.com/docs/en/pricing (verified 2026-06)
 */
const MODEL_PRICING: ModelPricing[] = [
  { match: 'opus-5-5', inputPerMTok: 4, outputPerMTok: 20 },
  { match: 'opus-5', inputPerMTok: 5, outputPerMTok: 25 },
  { match: 'sonnet-5-5', inputPerMTok: 2, outputPerMTok: 10 },
  { match: 'sonnet-5', inputPerMTok: 2, outputPerMTok: 10 },
  {
    match: 'haiku-5-5',
    inputPerMTok: 0.1,
    outputPerMTok: 0.5,
    longPrompt: { aboveInputTokens: 100_000, inputPerMTok: 0.5, outputPerMTok: 2.5 },
  },
  { match: 'fable-5-2', inputPerMTok: 8, outputPerMTok: 40 },
  { match: 'fable-5-1', inputPerMTok: 10, outputPerMTok: 50 },
  { match: 'fable-5', inputPerMTok: 10, outputPerMTok: 50 },
  { match: 'opus-4-8', inputPerMTok: 5, outputPerMTok: 25 },
  { match: 'opus-4-7', inputPerMTok: 5, outputPerMTok: 25 },
  { match: 'opus-4-6', inputPerMTok: 5, outputPerMTok: 25 },
  { match: 'opus-4-5', inputPerMTok: 5, outputPerMTok: 25 },
  { match: 'opus-4-1', inputPerMTok: 15, outputPerMTok: 75 },
  { match: 'opus-4', inputPerMTok: 15, outputPerMTok: 75 },
  { match: 'sonnet-4-6', inputPerMTok: 3, outputPerMTok: 15 },
  { match: 'sonnet-4-5', inputPerMTok: 3, outputPerMTok: 15 },
  { match: 'sonnet-4', inputPerMTok: 3, outputPerMTok: 15 },
  { match: 'haiku-4-5', inputPerMTok: 1, outputPerMTok: 5 },
];

/** Fallback when the model is unrecognized: Opus 4.8 / Opus 5 rates, so estimates err high. */
const FALLBACK_PRICING = { inputPerMTok: 5, outputPerMTok: 25 };

/**
 * Bedrock regional (CRIS) endpoints carry a 10% premium over global endpoints
 * for Sonnet 4.5 and newer models.
 */
const BEDROCK_REGIONAL_PREFIXES = ['us.', 'eu.', 'jp.', 'apac.'];

/**
 * Estimate the USD cost of a single AI request.
 * Unknown models log a warning and use Opus-tier rates rather than
 * silently under-reporting spend.
 */
export function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const pricing = MODEL_PRICING.find(p => model.includes(p.match));

  if (!pricing) {
    logger.warn('Unknown model for cost estimation, using Opus-tier fallback rates', { model });
  }

  const base = pricing ?? FALLBACK_PRICING;
  const { inputPerMTok, outputPerMTok } =
    pricing?.longPrompt && inputTokens > pricing.longPrompt.aboveInputTokens
      ? pricing.longPrompt
      : base;
  let cost = (inputTokens / 1_000_000) * inputPerMTok + (outputTokens / 1_000_000) * outputPerMTok;

  if (BEDROCK_REGIONAL_PREFIXES.some(prefix => model.startsWith(prefix))) {
    cost *= 1.1;
  }

  return cost;
}

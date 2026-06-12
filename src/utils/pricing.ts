/**
 * AI Model Pricing
 * Per-model cost estimation for Anthropic API and AWS Bedrock usage
 */

import { createLogger } from './logger';

const logger = createLogger('pricing');

/**
 * Pricing in USD per million tokens.
 * Matched by substring against the model ID, so one entry covers the bare
 * Anthropic ID, dated full IDs, and Bedrock variants with global./us./eu.
 * prefixes and -v1:0 suffixes. Ordered most-specific first; first match wins.
 *
 * Source: https://platform.claude.com/docs/en/pricing (verified 2026-06)
 */
const MODEL_PRICING: Array<{ match: string; inputPerMTok: number; outputPerMTok: number }> = [
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

/** Fallback when the model is unrecognized: current Opus-tier rates, so estimates err high. */
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

  const { inputPerMTok, outputPerMTok } = pricing ?? FALLBACK_PRICING;
  let cost = (inputTokens / 1_000_000) * inputPerMTok + (outputTokens / 1_000_000) * outputPerMTok;

  if (BEDROCK_REGIONAL_PREFIXES.some(prefix => model.startsWith(prefix))) {
    cost *= 1.1;
  }

  return cost;
}

/**
 * Pricing utility tests
 */

import { estimateCostUsd } from '../../../src/utils/pricing';

describe('estimateCostUsd', () => {
  it('prices Opus 4.8 at $5/$25 per MTok', () => {
    const cost = estimateCostUsd('claude-opus-4-8', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(30, 6);
  });

  it('prices Sonnet 4.6 at $3/$15 per MTok', () => {
    const cost = estimateCostUsd('claude-sonnet-4-6', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(18, 6);
  });

  it('prices Haiku 4.5 at $1/$5 per MTok', () => {
    const cost = estimateCostUsd('claude-haiku-4-5', 2_000_000, 0);
    expect(cost).toBeCloseTo(2, 6);
  });

  it('matches Bedrock model IDs with prefixes and version suffixes', () => {
    const cost = estimateCostUsd('global.anthropic.claude-sonnet-4-6', 1_000_000, 0);
    expect(cost).toBeCloseTo(3, 6);

    const bareOpus = estimateCostUsd('anthropic.claude-opus-4-8', 1_000_000, 0);
    expect(bareOpus).toBeCloseTo(5, 6);
  });

  it('applies the 10% regional premium for CRIS-prefixed Bedrock IDs', () => {
    const regional = estimateCostUsd('us.anthropic.claude-sonnet-4-5-20250929-v1:0', 1_000_000, 0);
    expect(regional).toBeCloseTo(3.3, 6);

    const global = estimateCostUsd('global.anthropic.claude-sonnet-4-6', 1_000_000, 0);
    expect(global).toBeCloseTo(3, 6);
  });

  it('distinguishes opus-4-1 (legacy pricing) from opus-4-5+ tiers', () => {
    expect(estimateCostUsd('claude-opus-4-1-20250805', 1_000_000, 0)).toBeCloseTo(15, 6);
    expect(estimateCostUsd('claude-opus-4-5', 1_000_000, 0)).toBeCloseTo(5, 6);
  });

  it('falls back to Opus-tier rates for unknown models', () => {
    const cost = estimateCostUsd('some-future-model', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(30, 6);
  });

  it('returns zero for zero tokens', () => {
    expect(estimateCostUsd('claude-opus-4-8', 0, 0)).toBe(0);
  });
});

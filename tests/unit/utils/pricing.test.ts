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

    const bareOpus = estimateCostUsd('global.anthropic.claude-opus-4-8', 1_000_000, 0);
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

  describe('5.x models', () => {
    const perMTok = (model: string): [number, number] => [
      estimateCostUsd(model, 1_000_000, 0),
      estimateCostUsd(model, 0, 1_000_000),
    ];

    it('prices each 5.x model at its own rate', () => {
      const expected: Array<[string, number, number]> = [
        ['claude-opus-5-5', 4, 20],
        ['claude-opus-5', 5, 25],
        ['claude-sonnet-5-5', 2, 10],
        ['claude-sonnet-5', 2, 10],
        ['claude-fable-5-2', 8, 40],
        ['claude-fable-5-1', 10, 50],
        ['claude-fable-5', 10, 50],
      ];
      for (const [model, input, output] of expected) {
        const [inputCost, outputCost] = perMTok(model);
        expect(inputCost).toBeCloseTo(input, 6);
        expect(outputCost).toBeCloseTo(output, 6);
      }
    });

    it('does not let opus-5 shadow opus-5-5, or fable-5 shadow fable-5-2', () => {
      // Each pair shares a prefix; the longer ID must reach its own entry
      expect(perMTok('claude-opus-5-5')).not.toEqual(perMTok('claude-opus-5'));
      expect(perMTok('claude-fable-5-2')).not.toEqual(perMTok('claude-fable-5'));
      expect(estimateCostUsd('global.anthropic.claude-opus-5-5', 1_000_000, 0)).toBeCloseTo(4, 6);
      expect(estimateCostUsd('global.anthropic.claude-opus-5', 1_000_000, 0)).toBeCloseTo(5, 6);
    });

    it('does not let 5.x entries capture 4.x IDs, or the reverse', () => {
      // opus-4-5 and sonnet-4-5 end in "-5" but are not 5.x models
      expect(perMTok('claude-opus-4-5')).toEqual([5, 25]);
      expect(perMTok('claude-opus-4-5-20251101')).toEqual([5, 25]);
      expect(perMTok('claude-sonnet-4-5')).toEqual([3, 15]);
      expect(perMTok('claude-haiku-4-5')).toEqual([1, 5]);
      // and the legacy catch-all "opus-4" / "sonnet-4" entries do not reach 5.x
      expect(perMTok('claude-opus-5')[0]).toBeCloseTo(5, 6);
      expect(perMTok('claude-sonnet-5')[0]).toBeCloseTo(2, 6);
      expect(perMTok('claude-opus-4-8')).toEqual([5, 25]);
    });

    it('prices Haiku 5.5 by prompt size', () => {
      // Up to 100K prompt tokens: $0.10 / $0.50
      expect(estimateCostUsd('claude-haiku-5-5', 100_000, 10_000)).toBeCloseTo(0.01 + 0.005, 6);
      // Above 100K: $0.50 / $2.50 for the whole request
      expect(estimateCostUsd('claude-haiku-5-5', 200_000, 10_000)).toBeCloseTo(0.1 + 0.025, 6);
    });

    it('applies the regional premium to us.-prefixed 5.x profiles', () => {
      expect(estimateCostUsd('us.anthropic.claude-opus-5-5', 1_000_000, 0)).toBeCloseTo(4.4, 6);
    });
  });

  it('falls back to Opus-tier rates for unknown models', () => {
    const cost = estimateCostUsd('some-future-model', 1_000_000, 1_000_000);
    expect(cost).toBeCloseTo(30, 6);
  });

  it('returns zero for zero tokens', () => {
    expect(estimateCostUsd('claude-opus-4-8', 0, 0)).toBe(0);
  });
});

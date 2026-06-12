/**
 * Campaign verdict cache tests — signature grouping and cached-result building
 */

import {
  buildCachedAnalysisResult,
  CACHE_PROVIDER,
  CACHE_MODEL,
} from '../../../../src/services/intelligence/campaign.cache';
import {
  computeCampaignSignature,
  CampaignVerdictCacheHit,
} from '../../../../src/services/intelligence/database.service';
import { AnalysisResult } from '../../../../src/types';

function makeAnalysisResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    summary: 'Credential-harvesting attempt impersonating a payroll provider.',
    isPhishing: true,
    confidence: 'High',
    indicators: ['Lookalike domain', 'Urgent language'],
    recommendations: ['Do not click any links', 'Delete the email'],
    provider: 'bedrock',
    model: 'anthropic.claude-opus-4-8',
    processingTimeMs: 4200,
    tokenUsage: { inputTokens: 1000, outputTokens: 500, totalTokens: 1500 },
    ...overrides,
  };
}

function makeHit(overrides: Partial<CampaignVerdictCacheHit> = {}): CampaignVerdictCacheHit {
  return {
    analysisId: '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
    analysisResult: makeAnalysisResult(),
    analyzedAt: new Date('2026-06-11T08:00:00Z'),
    ...overrides,
  };
}

describe('computeCampaignSignature', () => {
  it('groups numbered variants of the same subject', () => {
    expect(computeCampaignSignature('example.com', 'Invoice #4821 overdue')).toBe(
      computeCampaignSignature('example.com', 'Invoice #4822 overdue')
    );
  });

  it('ignores forward/reply prefixes and sender-domain case', () => {
    expect(computeCampaignSignature('Example.COM', 'FW: Invoice #4821 overdue')).toBe(
      computeCampaignSignature('example.com', 'Re: Invoice #99 overdue')
    );
  });

  it('separates different sender domains and different subjects', () => {
    const base = computeCampaignSignature('example.com', 'Invoice overdue');
    expect(computeCampaignSignature('example.org', 'Invoice overdue')).not.toBe(base);
    expect(computeCampaignSignature('example.com', 'Password reset required')).not.toBe(base);
  });

  it('produces the 16-char hex format used by flood detection', () => {
    expect(computeCampaignSignature('example.com', 'hello')).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('buildCachedAnalysisResult', () => {
  it('reuses the AI verdict and marks the result as cached', () => {
    const result = buildCachedAnalysisResult(makeHit());

    expect(result.isPhishing).toBe(true);
    expect(result.confidence).toBe('High');
    expect(result.provider).toBe(CACHE_PROVIDER);
    expect(result.model).toBe(CACHE_MODEL);
    expect(result.tokenUsage).toBeUndefined();
    expect(result.processingTimeMs).toBe(0);
    expect(result.summary).toContain('analyzed recently');
    expect(result.summary).toContain('Credential-harvesting attempt');
  });

  it('overrides the AI verdict when the security team ruled false positive', () => {
    const result = buildCachedAnalysisResult(
      makeHit({ feedbackVerdict: 'false_positive', feedbackBy: 'security@example.com' })
    );

    expect(result.isPhishing).toBe(false);
    expect(result.confidence).toBe('Very High');
    expect(result.summary).toContain('NOT phishing');
    expect(result.summary).toContain('Credential-harvesting attempt'); // original kept for context
    expect(result.recommendations).toEqual([
      'No action needed — this email was reviewed and cleared by your security team.',
    ]);
  });

  it('strengthens the verdict when the security team confirmed phishing', () => {
    const result = buildCachedAnalysisResult(
      makeHit({
        analysisResult: makeAnalysisResult({ isPhishing: true, confidence: 'Medium' }),
        feedbackVerdict: 'confirmed_phishing',
      })
    );

    expect(result.isPhishing).toBe(true);
    expect(result.confidence).toBe('Very High');
    expect(result.summary).toContain('security team has confirmed');
    expect(result.recommendations).toEqual(['Do not click any links', 'Delete the email']);
  });

  it('does not leak the raw AI response into cached reports', () => {
    const result = buildCachedAnalysisResult(
      makeHit({ analysisResult: makeAnalysisResult({ rawResponse: '{"full":"json"}' }) })
    );
    expect(result.rawResponse).toBeUndefined();
  });
});

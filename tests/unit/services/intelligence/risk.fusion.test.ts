/**
 * Risk fusion tests
 */

import { fuseRisk, scoreToLevel } from '../../../../src/services/intelligence/risk.fusion';
import { AnalysisResult, ThreatAssessment } from '../../../../src/types';
import {
  ThreatIndicatorRecord,
  CampaignRecord,
} from '../../../../src/services/intelligence/database.service';

function result(
  assessment?: Partial<ThreatAssessment>,
  overrides: Partial<AnalysisResult> = {}
): AnalysisResult {
  return {
    summary: 'test',
    isPhishing: false,
    confidence: 'Medium',
    indicators: [],
    recommendations: [],
    assessment: assessment
      ? {
          verdict: 'legitimate',
          riskScore: 5,
          verdictConfidence: 0.9,
          threatVectors: [],
          targeting: 'unknown',
          ...assessment,
        }
      : undefined,
    ...overrides,
  };
}

function indicator(timesSeen: number): ThreatIndicatorRecord {
  return {
    indicatorType: 'domain',
    indicatorValue: 'evil.test',
    indicatorHash: 'h',
    confidenceScore: 0.8,
    severity: 'high',
    timesSeen,
    firstSeenAt: new Date(),
    lastSeenAt: new Date(),
    isActive: true,
  };
}

describe('fuseRisk', () => {
  it('keeps a confidently-legitimate email at low risk (the core bug)', () => {
    const decision = fuseRisk(
      result({ verdict: 'legitimate', riskScore: 5, verdictConfidence: 0.95 })
    );
    expect(decision.riskLevel).toBe('safe');
    expect(decision.isPhishing).toBe(false);
    expect(decision.riskScore).toBe(5);
  });

  it('scores a high-risk BEC as critical and phishing', () => {
    const decision = fuseRisk(
      result({
        verdict: 'bec',
        riskScore: 88,
        threatVectors: ['wire_fraud'],
        targeting: 'targeted',
      })
    );
    expect(decision.riskLevel).toBe('critical');
    expect(decision.isPhishing).toBe(true);
    expect(decision.verdict).toBe('bec');
  });

  it('raises risk when a known indicator was seen in prior reports', () => {
    const decision = fuseRisk(result({ verdict: 'suspicious', riskScore: 40 }), {
      matchedIndicators: [indicator(3)],
    });
    expect(decision.riskScore).toBeGreaterThanOrEqual(60 + 3 * 8);
    expect(decision.reasons.join(' ')).toMatch(/prior reports/);
  });

  it('lets a security-team confirmation override to critical (and fixes the verdict)', () => {
    const decision = fuseRisk(result({ verdict: 'legitimate', riskScore: 5 }), {
      humanVerdict: 'confirmed_phishing',
    });
    expect(decision.riskLevel).toBe('critical');
    expect(decision.isPhishing).toBe(true);
    // verdict must not contradict the human ruling
    expect(decision.verdict).toBe('phishing');
  });

  it('keeps a specific malicious verdict when the team confirms phishing', () => {
    const decision = fuseRisk(result({ verdict: 'bec', riskScore: 70 }), {
      humanVerdict: 'confirmed_phishing',
    });
    expect(decision.verdict).toBe('bec'); // specificity preserved
    expect(decision.isPhishing).toBe(true);
  });

  it('lets a security-team false-positive override to safe (and clears the verdict)', () => {
    const decision = fuseRisk(result({ verdict: 'phishing', riskScore: 90 }), {
      humanVerdict: 'false_positive',
    });
    expect(decision.riskScore).toBe(0);
    expect(decision.isPhishing).toBe(false);
    expect(decision.verdict).toBe('legitimate');
  });

  it('raises risk to match an active critical campaign', () => {
    const campaign = {
      isActive: true,
      riskLevel: 'critical',
      detectionCount: 12,
      uniqueRecipients: ['a', 'b'],
    } as CampaignRecord;
    const decision = fuseRisk(result({ verdict: 'suspicious', riskScore: 30 }), { campaign });
    expect(decision.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('caps risk for a safe-sender allowlist match without intel', () => {
    const decision = fuseRisk(result({ verdict: 'spam', riskScore: 40 }), { isSafeSender: true });
    expect(decision.riskScore).toBeLessThanOrEqual(10);
  });

  it('does NOT let safe-sender override a known malicious indicator', () => {
    const decision = fuseRisk(result({ verdict: 'phishing', riskScore: 80 }), {
      isSafeSender: true,
      matchedIndicators: [indicator(2)],
    });
    expect(decision.riskScore).toBeGreaterThanOrEqual(70);
  });

  it('falls back to legacy isPhishing when no assessment is present', () => {
    const legacyPhish = fuseRisk(result(undefined, { isPhishing: true, confidence: 'High' }));
    expect(legacyPhish.isPhishing).toBe(true);
    expect(legacyPhish.riskLevel).not.toBe('safe');

    const legacyClean = fuseRisk(result(undefined, { isPhishing: false, confidence: 'High' }));
    expect(legacyClean.riskLevel).toBe('safe');
  });

  it('routes a failed analysis to undetermined, never legitimate/safe (the incident)', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }));
    expect(decision.verdict).toBe('undetermined');
    expect(decision.isPhishing).toBe(false);
    // The danger was the report calling an un-analyzed email "legitimate".
    expect(decision.verdict).not.toBe('legitimate');
    expect(decision.reasons.join(' ')).toMatch(/could not be completed/i);
  });

  it('does NOT let a safe-sender allowlist talk a failed analysis down to safe', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }), {
      isSafeSender: true,
    });
    expect(decision.verdict).toBe('undetermined');
    expect(decision.reasons.join(' ')).not.toMatch(/trusted-sender allowlist/i);
  });

  it('escalates a failed analysis when hard intel flags it, without claiming a clean verdict', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }), {
      matchedIndicators: [indicator(3)],
    });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBeGreaterThanOrEqual(60);
    expect(decision.isPhishing).toBe(true);
  });

  it('lets a security-team confirmation still override a failed analysis', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }), {
      humanVerdict: 'confirmed_phishing',
    });
    expect(decision.verdict).toBe('phishing');
    expect(decision.isPhishing).toBe(true);
  });
});

describe('scoreToLevel', () => {
  it('maps score bands to levels', () => {
    expect(scoreToLevel(90)).toBe('critical');
    expect(scoreToLevel(60)).toBe('high');
    expect(scoreToLevel(40)).toBe('medium');
    expect(scoreToLevel(12)).toBe('low');
    expect(scoreToLevel(3)).toBe('safe');
  });
});

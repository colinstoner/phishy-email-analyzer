/**
 * Risk fusion tests
 */

import {
  fuseRisk,
  scoreToLevel,
  modelVerdictOf,
  VERDICT_SCORE_BANDS,
  WEAK_INDICATOR_RISK_CEILING,
} from '../../../../src/services/intelligence/risk.fusion';
import { createFailedAnalysisResult } from '../../../../src/services/ai/provider.interface';
import { AnalysisResult, ThreatAssessment, ThreatVerdict } from '../../../../src/types';
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

/** A legacy indicator: stored before provenance was recorded (weak) */
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

/** A payload domain stored from a model-malicious report (strong) */
function strongIndicator(
  timesSeen: number,
  overrides: Partial<ThreatIndicatorRecord> = {},
  metadata: Record<string, unknown> = {}
): ThreatIndicatorRecord {
  return {
    ...indicator(timesSeen),
    metadata: {
      provenance: 'model_malicious',
      sourceVerdict: 'phishing',
      role: 'payload',
      ...metadata,
    },
    ...overrides,
  };
}

const ALL_VERDICTS: ThreatVerdict[] = [
  'bec',
  'phishing',
  'malware_delivery',
  'suspicious',
  'spam',
  'graymail',
  'legitimate',
];
const BENIGN: ThreatVerdict[] = ['legitimate', 'graymail', 'spam'];

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

  it('raises risk when a strong indicator was seen in prior reports', () => {
    const decision = fuseRisk(result({ verdict: 'suspicious', riskScore: 40 }), {
      matchedIndicators: [strongIndicator(1)],
    });
    expect(decision.riskScore).toBe(60 + 1 * 8);
    expect(decision.verdict).toBe('suspicious');
    expect(decision.isPhishing).toBe(true);
    expect(decision.confidenceBasis).toBe('threat_intel');
    expect(decision.reasons.join(' ')).toMatch(/earlier reports \(seen in 1 reported email\)/);
  });

  it('applies the full floor formula to a malicious verdict (inside its band)', () => {
    const decision = fuseRisk(result({ verdict: 'phishing', riskScore: 60 }), {
      matchedIndicators: [strongIndicator(3)],
    });
    expect(decision.riskScore).toBe(60 + 3 * 8);
    expect(decision.verdict).toBe('phishing');
    // The model already said phishing: its own confidence stands
    expect(decision.confidenceBasis).toBe('model');
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
    // The campaign floor (80) is applied, then the suspicious band caps it:
    // 'suspicious' is never shown as critical.
    expect(decision.riskScore).toBe(VERDICT_SCORE_BANDS.suspicious.max);
    expect(decision.riskLevel).toBe('high');
    expect(decision.isPhishing).toBe(true);
    expect(decision.reasons.join(' ')).toMatch(/active campaign/);
  });

  it('turns a benign verdict raised by an active campaign into suspicious, and says why', () => {
    const campaign = {
      isActive: true,
      riskLevel: 'high',
      detectionCount: 5,
      uniqueRecipients: ['a', 'b'],
    } as CampaignRecord;
    const decision = fuseRisk(result({ verdict: 'graymail', riskScore: 15 }), { campaign });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBe(60);
    expect(decision.reasons.join(' ')).toMatch(/looked like legitimate bulk email/);
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

  it('routes a model refusal to undetermined, never legitimate', () => {
    const refused = createFailedAnalysisResult(
      'The model declined to analyze this email: claude-opus-5-5 declined the request (category: cyber)'
    );

    const decision = fuseRisk(refused, { isSafeSender: true });

    expect(decision.verdict).toBe('undetermined');
    expect(decision.verdict).not.toBe('legitimate');
    expect(refused.summary).toMatch(/NOT checked/);
    // Operator detail stays out of the employee-facing summary
    expect(refused.summary).not.toContain('claude-opus-5-5');
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
      matchedIndicators: [strongIndicator(3)],
    });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBeGreaterThanOrEqual(60);
    expect(decision.isPhishing).toBe(true);
    expect(decision.confidenceBasis).toBe('threat_intel');
  });

  it('lets a weak match lift a failed analysis only to the weak ceiling, never phishing', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }), {
      matchedIndicators: [indicator(30)],
    });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBe(WEAK_INDICATOR_RISK_CEILING);
    expect(decision.isPhishing).toBe(false);
    expect(decision.confidenceBasis).toBe('unassessed');
  });

  it('lets a security-team confirmation still override a failed analysis', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }), {
      humanVerdict: 'confirmed_phishing',
    });
    expect(decision.verdict).toBe('phishing');
    expect(decision.isPhishing).toBe(true);
  });
});

describe('fuseRisk: strong and weak indicator matches', () => {
  it('treats a legacy indicator (no provenance) as weak: graymail stays graymail', () => {
    const decision = fuseRisk(result({ verdict: 'graymail', riskScore: 20 }), {
      matchedIndicators: [indicator(9)],
    });
    expect(decision.verdict).toBe('graymail');
    expect(decision.riskScore).toBe(20);
    expect(decision.isPhishing).toBe(false);
    expect(decision.reasons.join(' ')).toMatch(/not treated as evidence of an attack/);
  });

  it('treats an infrastructure-role indicator as weak even with provenance', () => {
    const decision = fuseRisk(result({ verdict: 'legitimate', riskScore: 5 }), {
      matchedIndicators: [strongIndicator(5, {}, { role: 'infrastructure' })],
    });
    expect(decision.verdict).toBe('legitimate');
    expect(decision.riskScore).toBe(5);
    expect(decision.isPhishing).toBe(false);
  });

  it('treats an expired indicator as weak', () => {
    const decision = fuseRisk(result({ verdict: 'legitimate', riskScore: 5 }), {
      matchedIndicators: [strongIndicator(5, { expiresAt: new Date('2026-10-01T00:00:00Z') })],
      now: new Date('2026-11-01T00:00:00Z'),
    });
    expect(decision.verdict).toBe('legitimate');
    expect(decision.isPhishing).toBe(false);
  });

  it('treats an indicator the security team cleared as weak', () => {
    const decision = fuseRisk(result({ verdict: 'spam', riskScore: 20 }), {
      matchedIndicators: [strongIndicator(5, {}, { securityCleared: true })],
    });
    expect(decision.verdict).toBe('spam');
    expect(decision.isPhishing).toBe(false);
  });

  it('counts a security-confirmed indicator as strong', () => {
    const confirmed = strongIndicator(2);
    confirmed.metadata = { role: 'sender', securityConfirmed: true };
    const decision = fuseRisk(result({ verdict: 'legitimate', riskScore: 5 }), {
      matchedIndicators: [confirmed],
    });
    expect(decision.verdict).toBe('suspicious');
  });

  it('turns a benign verdict raised by a strong match into suspicious, and says why', () => {
    for (const verdict of BENIGN) {
      const decision = fuseRisk(result({ verdict, riskScore: 5 }), {
        matchedIndicators: [strongIndicator(1)],
      });
      expect(decision.verdict).toBe('suspicious');
      expect(decision.riskScore).toBe(68);
      expect(decision.isPhishing).toBe(true);
      expect(decision.confidence).toBe('High');
      expect(decision.confidenceBasis).toBe('threat_intel');
      expect(decision.reasons.join(' ')).toMatch(/treating it as suspicious/);
    }
  });

  it('lifts a suspicious verdict to at most the weak ceiling on weak matches alone', () => {
    const decision = fuseRisk(result({ verdict: 'suspicious', riskScore: 30 }), {
      matchedIndicators: [indicator(50), strongIndicator(50, {}, { role: 'infrastructure' })],
    });
    expect(decision.riskScore).toBe(WEAK_INDICATOR_RISK_CEILING);
    expect(decision.isPhishing).toBe(false);
  });

  it('uses only strong matches for the floor when both kinds match', () => {
    const decision = fuseRisk(result({ verdict: 'phishing', riskScore: 55 }), {
      matchedIndicators: [indicator(40), strongIndicator(1)],
    });
    expect(decision.riskScore).toBe(68);
  });

  it('never lets weak matches make a benign verdict phishing, at any count or score', () => {
    for (const verdict of BENIGN) {
      for (const riskScore of [0, 10, 30, 55, 90]) {
        const decision = fuseRisk(result({ verdict, riskScore }), {
          matchedIndicators: [indicator(100), strongIndicator(100, {}, { role: 'infrastructure' })],
        });
        expect(decision.verdict).toBe(verdict);
        expect(decision.isPhishing).toBe(false);
      }
    }
  });

  it('does not let a weak match block the trusted-sender cap', () => {
    const decision = fuseRisk(result({ verdict: 'spam', riskScore: 30 }), {
      isSafeSender: true,
      matchedIndicators: [indicator(4)],
    });
    expect(decision.riskScore).toBe(10);
  });
});

describe('fuseRisk: score bands and the phishing flag', () => {
  it('keeps every final score inside the band for its final verdict', () => {
    const signalSets = [
      {},
      { matchedIndicators: [indicator(9)] },
      { matchedIndicators: [strongIndicator(4)] },
      {
        campaign: {
          isActive: true,
          riskLevel: 'critical',
          detectionCount: 3,
          uniqueRecipients: ['a'],
        } as CampaignRecord,
      },
      { isSafeSender: true },
    ];
    for (const verdict of ALL_VERDICTS) {
      for (const riskScore of [0, 5, 10, 20, 30, 45, 55, 70, 85, 100]) {
        for (const signals of signalSets) {
          const decision = fuseRisk(result({ verdict, riskScore }), signals);
          const band = VERDICT_SCORE_BANDS[decision.verdict as keyof typeof VERDICT_SCORE_BANDS];
          expect(decision.riskScore).toBeGreaterThanOrEqual(band.min);
          expect(decision.riskScore).toBeLessThanOrEqual(band.max);
          // The flag follows verdict and score together
          if (BENIGN.includes(decision.verdict)) {
            expect(decision.isPhishing).toBe(false);
          }
          if (['bec', 'phishing', 'malware_delivery'].includes(decision.verdict)) {
            expect(decision.isPhishing).toBe(true);
          }
        }
      }
    }
  });

  it('clamps a model score that disagrees with its own verdict', () => {
    expect(fuseRisk(result({ verdict: 'graymail', riskScore: 85 })).riskScore).toBe(29);
    expect(fuseRisk(result({ verdict: 'legitimate', riskScore: 40 })).riskScore).toBe(10);
    expect(fuseRisk(result({ verdict: 'phishing', riskScore: 20 })).riskScore).toBe(55);
    expect(fuseRisk(result({ verdict: 'suspicious', riskScore: 95 })).riskScore).toBe(79);
  });

  it('flags a suspicious verdict as phishing only at or above the threshold', () => {
    expect(fuseRisk(result({ verdict: 'suspicious', riskScore: 54 })).isPhishing).toBe(false);
    expect(fuseRisk(result({ verdict: 'suspicious', riskScore: 55 })).isPhishing).toBe(true);
  });

  it('never flags graymail as phishing, whatever score the model gave', () => {
    const decision = fuseRisk(result({ verdict: 'graymail', riskScore: 95 }));
    expect(decision.isPhishing).toBe(false);
    expect(decision.riskLevel).toBe('low');
  });
});

describe('fuseRisk: confidence', () => {
  it("shows the model's certainty, not a label derived from risk", () => {
    const decision = fuseRisk(
      result({ verdict: 'legitimate', riskScore: 10, verdictConfidence: 0.95 })
    );
    expect(decision.confidence).toBe('Very High');
    expect(decision.confidenceBasis).toBe('model');
  });

  it('maps verdictConfidence to the five labels', () => {
    const label = (verdictConfidence: number): string =>
      fuseRisk(result({ verdict: 'phishing', riskScore: 80, verdictConfidence })).confidence;
    expect(label(0.95)).toBe('Very High');
    expect(label(0.75)).toBe('High');
    expect(label(0.55)).toBe('Medium');
    expect(label(0.35)).toBe('Low');
    expect(label(0.1)).toBe('Very Low');
  });

  it('uses the legacy label when there is no structured assessment', () => {
    const decision = fuseRisk(result(undefined, { isPhishing: true, confidence: 'Medium' }));
    expect(decision.confidence).toBe('Medium');
    expect(decision.confidenceBasis).toBe('model');
  });

  it('says a security-team ruling decided the outcome', () => {
    for (const humanVerdict of ['confirmed_phishing', 'false_positive'] as const) {
      const decision = fuseRisk(result({ verdict: 'suspicious', riskScore: 50 }), {
        humanVerdict,
      });
      expect(decision.confidenceBasis).toBe('security_team');
      expect(decision.confidence).toBe('Very High');
    }
  });

  it('is not applicable for a failed analysis', () => {
    const decision = fuseRisk(result(undefined, { analysisFailed: true, isPhishing: false }));
    expect(decision.confidence).toBe('N/A');
    expect(decision.confidenceBasis).toBe('unassessed');
  });
});

describe('modelVerdictOf', () => {
  it("returns the model's own verdict, ignoring anything fusion would add", () => {
    expect(modelVerdictOf(result({ verdict: 'graymail', riskScore: 20 }))).toBe('graymail');
    expect(modelVerdictOf(result({ verdict: 'bec', riskScore: 90 }))).toBe('bec');
    expect(modelVerdictOf(result(undefined, { analysisFailed: true }))).toBe('undetermined');
    // Legacy results never count as malicious for storage
    expect(modelVerdictOf(result(undefined, { isPhishing: true, confidence: 'High' }))).toBe(
      'suspicious'
    );
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

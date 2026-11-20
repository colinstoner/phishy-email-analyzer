/**
 * Risk fusion in checklist scoring mode. The existing fusion tests run in
 * model mode untouched; these cover the checklist start and that every
 * floor, ceiling, cap and ruling still applies on top of it.
 */

import {
  ATTACHMENT_RISK_FLOOR,
  SENDER_FANOUT_RISK_FLOOR,
  WEAK_INDICATOR_RISK_CEILING,
  fuseRisk,
} from '../../../../src/services/intelligence/risk.fusion';
import {
  CHECKLIST_ITEMS,
  CHECKLIST_VERSION,
  ChecklistAnswers,
} from '../../../../src/services/ai/checklist';
import {
  CHECKLIST_REASONS,
  scoreChecklist,
} from '../../../../src/services/intelligence/checklist.score';
import { createFailedAnalysisResult } from '../../../../src/services/ai/provider.interface';
import {
  AnalysisResult,
  SenderHistoryFacts,
  ThreatAssessment,
  ThreatVerdict,
} from '../../../../src/types';
import { ThreatIndicatorRecord } from '../../../../src/services/intelligence/database.service';

function allClear(): ChecklistAnswers {
  return Object.fromEntries(
    CHECKLIST_ITEMS.map(item => [item.id, item.id === 'authentication_result' ? 'not_shown' : 'no'])
  ) as ChecklistAnswers;
}

function answers(overrides: Partial<ChecklistAnswers> = {}): ChecklistAnswers {
  return { ...allClear(), ...overrides };
}

function result(
  assessment: Partial<ThreatAssessment>,
  checklist: ChecklistAnswers | 'missing' | 'malformed' | 'none' = answers()
): AnalysisResult {
  return {
    summary: 'test',
    isPhishing: false,
    confidence: 'Medium',
    indicators: ['Model free-text indicator'],
    recommendations: [],
    assessment: {
      verdict: 'legitimate',
      riskScore: 5,
      verdictConfidence: 0.9,
      threatVectors: [],
      targeting: 'unknown',
      ...assessment,
    },
    ...(checklist === 'none'
      ? {}
      : typeof checklist === 'string'
        ? { checklist: { version: CHECKLIST_VERSION, status: checklist } }
        : { checklist: { version: CHECKLIST_VERSION, status: 'ok' as const, answers: checklist } }),
  };
}

function strongIndicator(timesSeen: number): ThreatIndicatorRecord {
  return {
    indicatorType: 'domain',
    indicatorValue: 'payload.example.net',
    indicatorHash: 'h',
    confidenceScore: 0.8,
    severity: 'high',
    timesSeen,
    firstSeenAt: new Date(),
    lastSeenAt: new Date(),
    isActive: true,
    metadata: { provenance: 'model_malicious', sourceVerdict: 'phishing', role: 'payload' },
  };
}

function weakIndicator(): ThreatIndicatorRecord {
  return { ...strongIndicator(1), metadata: undefined };
}

const CHECKLIST = { scoringMode: 'checklist' } as const;
const FANOUT = { classification: 'established_with_anomalous_fanout' } as SenderHistoryFacts;

describe('fuseRisk in model mode', () => {
  it('is identical with the option absent or set to model, checklist present or not', () => {
    const samples: AnalysisResult[] = [
      result({ verdict: 'suspicious', riskScore: 22 }, answers({ asks_for_credentials: 'yes' })),
      result({ verdict: 'phishing', riskScore: 91 }),
      result({ verdict: 'graymail', riskScore: 14 }, 'none'),
      createFailedAnalysisResult('provider down'),
    ];
    for (const sample of samples) {
      const plain = fuseRisk(sample, { senderHistory: FANOUT });
      expect(fuseRisk(sample, { senderHistory: FANOUT }, { scoringMode: 'model' })).toStrictEqual(
        plain
      );
      expect(plain).not.toHaveProperty('scoreBasis');
      expect(plain).not.toHaveProperty('modelRiskScore');
      expect(plain).not.toHaveProperty('checklistReasons');
    }
  });

  it('ignores a checklist entirely: the score is the model score', () => {
    const decision = fuseRisk(
      result({ verdict: 'suspicious', riskScore: 42 }, answers({ asks_for_payment: 'yes' }))
    );
    expect(decision.riskScore).toBe(42);
  });
});

describe('fuseRisk in checklist mode', () => {
  it('starts from the checklist score, keeping the model score for comparison', () => {
    const checklist = answers({ asks_for_credentials: 'yes', link_destination_mismatch: 'yes' });
    const decision = fuseRisk(
      result({ verdict: 'phishing', riskScore: 92 }, checklist),
      {},
      CHECKLIST
    );
    const expected = scoreChecklist(checklist, 'phishing');
    expect(decision).toMatchObject({
      verdict: 'phishing',
      riskScore: expected.score,
      scoreBasis: 'checklist',
      modelRiskScore: 92,
      checklistScore: expected.score,
      checklistRawScore: expected.rawScore,
      checklistReasons: expected.reasons,
      isPhishing: true,
      confidenceBasis: 'model',
    });
    expect(decision.riskScore).toBe(55);
    expect(decision.checklistReasons).toEqual([
      CHECKLIST_REASONS.asks_for_credentials,
      CHECKLIST_REASONS.link_destination_mismatch,
    ]);
  });

  it('gives the same score for the same answers whatever the model scored', () => {
    const checklist = answers({
      unexpected_for_recipient: 'unclear',
      document_or_share_lure: 'yes',
    });
    const scores = [8, 22, 30].map(
      modelScore =>
        fuseRisk(result({ verdict: 'legitimate', riskScore: modelScore }, checklist), {}, CHECKLIST)
          .riskScore
    );
    expect(new Set(scores).size).toBe(1);
  });

  it('keeps the label and the number in agreement (the model verdict band)', () => {
    const checklist = answers({ asks_for_credentials: 'yes', risky_attachment: 'yes' });
    const verdicts: ThreatVerdict[] = ['legitimate', 'graymail', 'spam', 'suspicious', 'bec'];
    const expected: Record<string, number> = {
      legitimate: 10,
      graymail: 29,
      spam: 29,
      suspicious: 70,
      bec: 70,
    };
    for (const verdict of verdicts) {
      expect(fuseRisk(result({ verdict }, checklist), {}, CHECKLIST).riskScore).toBe(
        expected[verdict]
      );
    }
  });

  it('decides the phishing flag of a suspicious verdict from the checklist score', () => {
    const low = fuseRisk(result({ verdict: 'suspicious', riskScore: 70 }), {}, CHECKLIST);
    expect(low).toMatchObject({ riskScore: 30, isPhishing: false });
    const high = fuseRisk(
      result(
        { verdict: 'suspicious', riskScore: 35 },
        answers({ asks_for_payment: 'yes', reply_to_diverts: 'yes', pressure_or_threat: 'yes' })
      ),
      {},
      CHECKLIST
    );
    expect(high).toMatchObject({ riskScore: 60, isPhishing: true });
  });

  it.each(['missing', 'malformed'] as const)(
    'falls back to the model score when the checklist is %s',
    status => {
      const decision = fuseRisk(
        result({ verdict: 'suspicious', riskScore: 44 }, status),
        {},
        CHECKLIST
      );
      expect(decision).toMatchObject({ riskScore: 44, scoreBasis: 'model', modelRiskScore: 44 });
      expect(decision).not.toHaveProperty('checklistReasons');
      expect(decision).not.toHaveProperty('checklistScore');
    }
  );

  it('falls back when no checklist was recorded (an analysis cached in model mode)', () => {
    const decision = fuseRisk(
      result({ verdict: 'graymail', riskScore: 18 }, 'none'),
      {},
      CHECKLIST
    );
    expect(decision).toMatchObject({ riskScore: 18, scoreBasis: 'model' });
  });

  it('falls back for answers from another checklist version', () => {
    const stale: AnalysisResult = {
      ...result({ verdict: 'suspicious', riskScore: 41 }),
      checklist: { version: CHECKLIST_VERSION + 1, status: 'ok', answers: answers() },
    };
    expect(fuseRisk(stale, {}, CHECKLIST)).toMatchObject({ riskScore: 41, scoreBasis: 'model' });
  });

  it('re-validates stored answers and falls back when they are not closed values', () => {
    const tampered = {
      ...result({ verdict: 'suspicious', riskScore: 47 }),
      checklist: {
        version: CHECKLIST_VERSION,
        status: 'ok',
        answers: { ...answers(), asks_for_payment: 'definitely' },
      },
    } as unknown as AnalysisResult;
    expect(fuseRisk(tampered, {}, CHECKLIST)).toMatchObject({ riskScore: 47, scoreBasis: 'model' });
  });

  it('never uses a checklist for a failed analysis', () => {
    const failed = { ...createFailedAnalysisResult('x'), checklist: undefined };
    const decision = fuseRisk(failed, {}, CHECKLIST);
    expect(decision).toMatchObject({ verdict: 'undetermined', riskScore: 0, scoreBasis: 'model' });
  });

  describe('every floor, ceiling, cap and ruling still applies on top', () => {
    it('security-team confirmation and clearance', () => {
      const confirmed = fuseRisk(
        result({ verdict: 'legitimate' }),
        { humanVerdict: 'confirmed_phishing' },
        CHECKLIST
      );
      expect(confirmed).toMatchObject({
        verdict: 'phishing',
        riskScore: 95,
        confidenceBasis: 'security_team',
      });
      const cleared = fuseRisk(
        result({ verdict: 'phishing' }, answers({ asks_for_credentials: 'yes' })),
        { humanVerdict: 'false_positive' },
        CHECKLIST
      );
      expect(cleared).toMatchObject({ verdict: 'legitimate', riskScore: 0, isPhishing: false });
    });

    it('the strong-indicator floor, with the benign verdict promoted', () => {
      const decision = fuseRisk(
        result({ verdict: 'legitimate' }),
        { matchedIndicators: [strongIndicator(3)] },
        CHECKLIST
      );
      expect(decision).toMatchObject({
        verdict: 'suspicious',
        riskScore: 79,
        confidenceBasis: 'threat_intel',
      });
    });

    it('the weak-indicator ceiling', () => {
      const decision = fuseRisk(
        result({ verdict: 'suspicious' }),
        { matchedIndicators: [weakIndicator()] },
        CHECKLIST
      );
      expect(decision.riskScore).toBe(WEAK_INDICATOR_RISK_CEILING);
    });

    it('the safe-sender cap', () => {
      const decision = fuseRisk(
        result({ verdict: 'suspicious' }, answers({ unexpected_for_recipient: 'yes' })),
        { isSafeSender: true },
        CHECKLIST
      );
      expect(decision.riskScore).toBeLessThanOrEqual(30);
      expect(decision.reasons).toContain('Reporter is on the trusted-sender allowlist.');
    });

    it('the sender fan-out floor', () => {
      const decision = fuseRisk(
        result({ verdict: 'legitimate' }),
        { senderHistory: FANOUT },
        CHECKLIST
      );
      expect(decision).toMatchObject({
        verdict: 'suspicious',
        riskScore: SENDER_FANOUT_RISK_FLOOR,
      });
    });

    it('the attachment floor', () => {
      const decision = fuseRisk(
        result({ verdict: 'graymail' }),
        { attachmentSignals: ['credential_form'] },
        CHECKLIST
      );
      expect(decision).toMatchObject({
        verdict: 'suspicious',
        riskScore: ATTACHMENT_RISK_FLOOR,
        confidenceBasis: 'attachment_inspection',
      });
    });

    it('an active campaign floor', () => {
      const decision = fuseRisk(
        result({ verdict: 'suspicious' }),
        {
          campaign: {
            id: 'c1',
            campaignSignature: 'sig',
            senderDomain: 'vendor.example.net',
            subjectPattern: 'invoice',
            isActive: true,
            riskLevel: 'critical',
            detectionCount: 12,
            uniqueRecipients: ['a@example.com', 'b@example.com'],
          } as never,
        },
        CHECKLIST
      );
      expect(decision.riskScore).toBe(79);
    });
  });
});

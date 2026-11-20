/**
 * Checklist scoring v2: the pure scoring function and its combination rule
 */

import {
  CHECKLIST_ITEMS,
  CHECKLIST_VERSION,
  ChecklistAnswers,
} from '../../../../src/services/ai/checklist';
import {
  ASK_WITHOUT_EVIDENCE_CAP,
  CHECKLIST_ASK_WITHOUT_EVIDENCE_REASON,
  CHECKLIST_BASE_SCORE,
  CHECKLIST_NO_WARNING_SIGNS_REASON,
  CHECKLIST_REASONS,
  CHECKLIST_WEIGHTS,
  checklistUnclearReason,
  scoreChecklist,
} from '../../../../src/services/intelligence/checklist.score';
import { VERDICT_SCORE_BANDS } from '../../../../src/services/intelligence/risk.fusion';
import { ThreatVerdict } from '../../../../src/types';

/** Every item answered with its "nothing applies" value */
function allClear(): ChecklistAnswers {
  return Object.fromEntries(
    CHECKLIST_ITEMS.map(item => [item.id, item.id === 'authentication_failed' ? 'unknown' : 'no'])
  ) as ChecklistAnswers;
}

function answers(overrides: Partial<ChecklistAnswers>): ChecklistAnswers {
  return { ...allClear(), ...overrides };
}

/**
 * The genuine supplier invoice from the live comparison: a PDF invoice with
 * a payment-portal link. The model answered payment, other channel and
 * document lure "yes"; nothing about the email itself is wrong. Code items
 * are what Phishy computes for such an email with the optional features
 * off (no Reply-To line in the forward, attachment not analyzed).
 */
const GENUINE_INVOICE: Partial<ChecklistAnswers> = {
  asks_for_payment: 'yes',
  moves_to_other_channel: 'yes',
  document_or_share_lure: 'yes',
  reply_to_diverts: 'unknown',
  risky_attachment: 'unknown',
  bcc_to_self: 'unknown',
  content_uninspectable: 'unknown',
  sender_fanout_anomalous: 'unknown',
};

const BANDED_VERDICTS = Object.keys(VERDICT_SCORE_BANDS) as Array<
  Exclude<ThreatVerdict, 'undetermined'>
>;

describe('checklist weights', () => {
  it('gives every answer of every item a weight, and every item a reason', () => {
    expect(Object.keys(CHECKLIST_WEIGHTS).sort()).toEqual(CHECKLIST_ITEMS.map(i => i.id).sort());
    expect(Object.keys(CHECKLIST_REASONS).sort()).toEqual(CHECKLIST_ITEMS.map(i => i.id).sort());
    for (const item of CHECKLIST_ITEMS) {
      expect(Object.keys(CHECKLIST_WEIGHTS[item.id]).sort()).toEqual([...item.answers].sort());
      for (const points of Object.values(CHECKLIST_WEIGHTS[item.id])) {
        expect(Number.isFinite(points)).toBe(true);
      }
      expect(CHECKLIST_REASONS[item.id].length).toBeGreaterThan(10);
    }
  });

  it('weights evidence, asks and context up and mitigations down, never the other way', () => {
    for (const item of CHECKLIST_ITEMS) {
      const weights = Object.values(CHECKLIST_WEIGHTS[item.id]);
      if (item.class === 'mitigating') expect(Math.max(...weights)).toBe(0);
      else expect(Math.min(...weights)).toBe(0);
    }
  });

  it('keeps mitigations small', () => {
    for (const item of CHECKLIST_ITEMS.filter(i => i.class === 'mitigating')) {
      expect(Math.min(...Object.values(CHECKLIST_WEIGHTS[item.id]))).toBeGreaterThanOrEqual(-10);
    }
  });

  it('scores unclear (model) at half, unknown (code) at nothing, and an unclear mitigation at nothing', () => {
    for (const item of CHECKLIST_ITEMS) {
      const w = CHECKLIST_WEIGHTS[item.id];
      if ('unclear' in w) expect(w.unclear).toBe(item.class === 'mitigating' ? 0 : w.yes / 2);
      if ('unknown' in w) expect(w.unknown).toBe(0);
    }
    // A pass never lowers risk and never raises it
    expect(CHECKLIST_WEIGHTS.authentication_failed).toEqual({ fail: 25, pass: 0, unknown: 0 });
  });
});

describe('scoreChecklist: the regressions the combination rule exists for', () => {
  it('scores a genuine invoice (payment ask, portal link, PDF, no evidence) below 30', () => {
    const result = scoreChecklist(answers(GENUINE_INVOICE), 'legitimate');
    expect(result.evidenceConfirmed).toBe(false);
    expect(result.rawScore).toBeLessThan(30);
    expect(result.rawScore).toBe(CHECKLIST_BASE_SCORE + ASK_WITHOUT_EVIDENCE_CAP);
    expect(result.reasons).toContain(CHECKLIST_ASK_WITHOUT_EVIDENCE_REASON);
    // Pressure counts only with evidence
    expect(
      scoreChecklist(answers({ ...GENUINE_INVOICE, pressure_or_threat: 'yes' }), 'legitimate')
        .rawScore
    ).toBe(result.rawScore);
    // ...and so does every other ask stacked on top
    expect(
      scoreChecklist(
        answers({
          ...GENUINE_INVOICE,
          asks_for_credentials: 'yes',
          asks_for_sensitive_data: 'yes',
        }),
        'legitimate'
      ).rawScore
    ).toBeLessThan(30);
  });

  it('scores a credential ask with a link mismatch, or with an unrelated file share, at least 60', () => {
    for (const evidence of [
      { link_text_mismatch: 'yes' },
      { file_share_unrelated_to_sender: 'yes' },
    ] as Array<Partial<ChecklistAnswers>>) {
      const result = scoreChecklist(
        answers({ asks_for_credentials: 'yes', ...evidence }),
        'phishing'
      );
      expect(result.evidenceConfirmed).toBe(true);
      expect(result.rawScore).toBeGreaterThanOrEqual(60);
    }
  });

  it('scores a risky attachment signal alone at least 50', () => {
    const result = scoreChecklist(answers({ risky_attachment: 'yes' }), 'malware_delivery');
    expect(result.rawScore).toBeGreaterThanOrEqual(50);
  });
});

describe('scoreChecklist', () => {
  it('is deterministic: the same answers and verdict give the same result every time', () => {
    const input = answers({
      asks_for_credentials: 'yes',
      link_destination_unrelated: 'unclear',
      reply_to_diverts: 'yes',
    });
    const first = scoreChecklist(input, 'phishing');
    for (let i = 0; i < 50; i++) {
      expect(scoreChecklist({ ...input }, 'phishing')).toEqual(first);
    }
  });

  it('does not depend on the order the answers arrive in', () => {
    const input = answers({ asks_for_payment: 'yes', pressure_or_threat: 'yes' });
    const reversed = Object.fromEntries(Object.entries(input).reverse()) as ChecklistAnswers;
    expect(scoreChecklist(reversed, 'bec')).toEqual(scoreChecklist(input, 'bec'));
  });

  it('starts at the base score with nothing applying, and says so', () => {
    const result = scoreChecklist(allClear(), 'suspicious');
    expect(result.rawScore).toBe(CHECKLIST_BASE_SCORE);
    expect(result.version).toBe(CHECKLIST_VERSION);
    expect(result.reasons).toEqual([CHECKLIST_NO_WARNING_SIGNS_REASON]);
    expect(result.contributions).toHaveLength(CHECKLIST_ITEMS.length);
    expect(result.contributions.every(c => c.points === 0)).toBe(true);
  });

  it("records each item's class and source with its points", () => {
    const result = scoreChecklist(answers({ reply_to_diverts: 'yes' }), 'suspicious');
    expect(result.contributions.find(c => c.id === 'reply_to_diverts')).toEqual({
      id: 'reply_to_diverts',
      class: 'evidence',
      source: 'code',
      answer: 'yes',
      points: 25,
    });
  });

  it('adds evidence, asks and context in full once evidence is confirmed', () => {
    const result = scoreChecklist(
      answers({
        asks_for_credentials: 'yes', // ask 35
        link_text_mismatch: 'yes', // evidence 25
        authentication_failed: 'fail', // evidence 25
        pressure_or_threat: 'yes', // context 10
      }),
      'phishing'
    );
    expect(result.totals).toEqual({ evidence: 50, ask: 35, context: 10, mitigating: 0 });
    expect(result.rawScore).toBe(CHECKLIST_BASE_SCORE + 50 + 35 + 10);
    expect(result.score).toBe(100);
  });

  it('scores evidence alone as moderate, and ignores context without evidence', () => {
    expect(scoreChecklist(answers({ reply_to_diverts: 'yes' }), 'suspicious').rawScore).toBe(30);
    expect(
      scoreChecklist(answers({ pressure_or_threat: 'yes', bcc_to_self: 'yes' }), 'suspicious')
        .rawScore
    ).toBe(CHECKLIST_BASE_SCORE);
  });

  it('never lets an unclear evidence item unlock the asks', () => {
    const result = scoreChecklist(
      answers({ ...GENUINE_INVOICE, sender_impersonation: 'unclear' }),
      'suspicious'
    );
    expect(result.evidenceConfirmed).toBe(false);
    // 5 + 12.5 (half of impersonation) + 15 (asks capped) = 32.5
    expect(result.rawScore).toBe(33);
  });

  it('counts unclear model items at half weight and names how many', () => {
    const result = scoreChecklist(
      answers({ asks_for_credentials: 'unclear', moves_to_other_channel: 'unclear' }),
      'suspicious'
    );
    // 5 + min(17.5 + 7.5, 15) = 20
    expect(result.rawScore).toBe(20);
    expect(result.reasons).toContain(checklistUnclearReason(2));
    expect(checklistUnclearReason(1)).toContain('1 check ');
  });

  it('scores unknown code answers as nothing and does not count them as unclear', () => {
    const unknown = Object.fromEntries(
      CHECKLIST_ITEMS.map(item => [item.id, item.source === 'code' ? 'unknown' : 'no'])
    ) as ChecklistAnswers;
    const result = scoreChecklist(unknown, 'suspicious');
    expect(result.rawScore).toBe(CHECKLIST_BASE_SCORE);
    expect(result.reasons).toEqual([CHECKLIST_NO_WARNING_SIGNS_REASON]);
  });

  it('never lowers risk for an unclear or unknown mitigation', () => {
    const base = scoreChecklist(allClear(), 'graymail');
    expect(
      scoreChecklist(answers({ bulk_marketing_with_unsubscribe: 'unclear' }), 'graymail').rawScore
    ).toBe(base.rawScore);
    expect(
      scoreChecklist(answers({ links_match_sender_domain: 'unknown' }), 'graymail').rawScore
    ).toBe(base.rawScore);
  });

  it('lets observed mitigations lower the raw score, not below 0', () => {
    const result = scoreChecklist(
      answers({ bulk_marketing_with_unsubscribe: 'yes', links_match_sender_domain: 'yes' }),
      'graymail'
    );
    expect(result.rawScore).toBe(0);
    // ...but the graymail band starts at 10
    expect(result.score).toBe(10);
    expect(result.reasons).toEqual([
      CHECKLIST_NO_WARNING_SIGNS_REASON,
      CHECKLIST_REASONS.bulk_marketing_with_unsubscribe,
      CHECKLIST_REASONS.links_match_sender_domain,
    ]);
  });

  it('saturates at 100', () => {
    const everything = Object.fromEntries(
      CHECKLIST_ITEMS.map(item => [
        item.id,
        item.class === 'mitigating' ? 'no' : item.id === 'authentication_failed' ? 'fail' : 'yes',
      ])
    ) as ChecklistAnswers;
    expect(scoreChecklist(everything, 'phishing')).toMatchObject({ rawScore: 100, score: 100 });
  });

  it("always lands inside the band of the model's verdict, and records the raw score", () => {
    const samples: ChecklistAnswers[] = [
      allClear(),
      answers({ bulk_marketing_with_unsubscribe: 'yes', links_match_sender_domain: 'yes' }),
      answers({
        asks_for_credentials: 'yes',
        sender_impersonation: 'yes',
        risky_attachment: 'yes',
      }),
      answers(GENUINE_INVOICE),
    ];
    for (const verdict of BANDED_VERDICTS) {
      const band = VERDICT_SCORE_BANDS[verdict];
      for (const sample of samples) {
        const { score, rawScore } = scoreChecklist(sample, verdict);
        expect(score).toBeGreaterThanOrEqual(band.min);
        expect(score).toBeLessThanOrEqual(band.max);
        expect(rawScore).toBe(scoreChecklist(sample, 'undetermined').rawScore);
      }
    }
    // A genuine invoice the model called phishing still shows a phishing score
    expect(scoreChecklist(answers(GENUINE_INVOICE), 'phishing')).toMatchObject({
      rawScore: 20,
      score: 55,
    });
  });

  it('gives fixed, code-written reasons in checklist order, for code and model items alike', () => {
    const result = scoreChecklist(
      answers({ reply_to_diverts: 'yes', asks_for_payment: 'yes', authentication_failed: 'fail' }),
      'bec'
    );
    expect(result.reasons).toEqual([
      CHECKLIST_REASONS.authentication_failed,
      CHECKLIST_REASONS.reply_to_diverts,
      CHECKLIST_REASONS.asks_for_payment,
    ]);
  });

  it('gives no reason for an authentication pass or unknown', () => {
    for (const value of ['pass', 'unknown'] as const) {
      const result = scoreChecklist(answers({ authentication_failed: value }), 'legitimate');
      expect(result.reasons).toEqual([CHECKLIST_NO_WARNING_SIGNS_REASON]);
    }
  });
});

/**
 * Checklist scoring: the pure scoring function
 */

import {
  CHECKLIST_ITEMS,
  CHECKLIST_VERSION,
  ChecklistAnswers,
} from '../../../../src/services/ai/checklist';
import {
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
    CHECKLIST_ITEMS.map(item => [item.id, item.id === 'authentication_result' ? 'not_shown' : 'no'])
  ) as ChecklistAnswers;
}

function answers(overrides: Partial<ChecklistAnswers>): ChecklistAnswers {
  return { ...allClear(), ...overrides };
}

const BANDED_VERDICTS = Object.keys(VERDICT_SCORE_BANDS) as Array<
  Exclude<ThreatVerdict, 'undetermined'>
>;

describe('checklist definition', () => {
  it('has a version and a fixed list of 15-25 uniquely named items', () => {
    expect(CHECKLIST_VERSION).toBe(1);
    expect(CHECKLIST_ITEMS.length).toBeGreaterThanOrEqual(15);
    expect(CHECKLIST_ITEMS.length).toBeLessThanOrEqual(25);
    const ids = CHECKLIST_ITEMS.map(item => item.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const item of CHECKLIST_ITEMS) {
      expect(item.id).toMatch(/^[a-z_]+$/);
      expect(item.answers.length).toBeGreaterThanOrEqual(2);
      expect(item.answers.length).toBeLessThanOrEqual(4);
    }
  });

  it('includes mitigating items as well as risk items', () => {
    expect(CHECKLIST_ITEMS.filter(i => i.kind === 'mitigating').length).toBeGreaterThan(0);
    expect(CHECKLIST_ITEMS.filter(i => i.kind === 'risk').length).toBeGreaterThan(0);
  });

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

  it('weights risk items up and mitigating items down, never the other way', () => {
    for (const item of CHECKLIST_ITEMS) {
      const weights = Object.values(CHECKLIST_WEIGHTS[item.id]);
      if (item.kind === 'risk') expect(Math.min(...weights)).toBe(0);
      else expect(Math.max(...weights)).toBe(0);
    }
  });

  it('scores unclear explicitly: half a risk item, nothing for a mitigation', () => {
    for (const item of CHECKLIST_ITEMS) {
      const w = CHECKLIST_WEIGHTS[item.id];
      if (!('unclear' in w)) continue;
      expect(w.unclear).toBe(item.kind === 'risk' ? w.yes / 2 : 0);
    }
    // Absent authentication results say nothing; a pass never lowers risk
    expect(CHECKLIST_WEIGHTS.authentication_result).toEqual({ fail: 20, pass: 0, not_shown: 0 });
  });
});

describe('scoreChecklist', () => {
  it('is deterministic: the same answers and verdict give the same result every time', () => {
    const input = answers({
      asks_for_credentials: 'yes',
      link_destination_mismatch: 'unclear',
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

  it('adds the documented points per item (a plain sum)', () => {
    const result = scoreChecklist(
      answers({
        asks_for_credentials: 'yes', // 30
        link_destination_mismatch: 'yes', // 20
        authentication_result: 'fail', // 20
      }),
      'phishing'
    );
    expect(result.rawScore).toBe(CHECKLIST_BASE_SCORE + 30 + 20 + 20);
    expect(result.score).toBe(75);
  });

  it('counts unclear risk items at half weight and names how many', () => {
    const result = scoreChecklist(
      answers({ asks_for_credentials: 'unclear', moves_to_other_channel: 'unclear' }),
      'suspicious'
    );
    // 5 + 15 + 7.5 = 27.5, rounded once at the end
    expect(result.rawScore).toBe(28);
    expect(result.reasons).toContain(checklistUnclearReason(2));
    expect(checklistUnclearReason(1)).toContain('1 check ');
  });

  it('never lowers risk for an unclear mitigation', () => {
    const base = scoreChecklist(allClear(), 'graymail');
    const unclear = scoreChecklist(
      answers({ bulk_marketing_with_unsubscribe: 'unclear' }),
      'graymail'
    );
    expect(unclear.rawScore).toBe(base.rawScore);
  });

  it('lets observed mitigations lower the raw score, not below 0', () => {
    const result = scoreChecklist(
      answers({
        bulk_marketing_with_unsubscribe: 'yes',
        routine_notice_no_action: 'yes',
        links_match_claimed_sender: 'yes',
      }),
      'graymail'
    );
    expect(result.rawScore).toBe(0);
    // ...but the graymail band starts at 10
    expect(result.score).toBe(10);
    expect(result.reasons).toEqual([
      CHECKLIST_NO_WARNING_SIGNS_REASON,
      CHECKLIST_REASONS.bulk_marketing_with_unsubscribe,
      CHECKLIST_REASONS.routine_notice_no_action,
      CHECKLIST_REASONS.links_match_claimed_sender,
    ]);
  });

  it('saturates at 100', () => {
    const everything = Object.fromEntries(
      CHECKLIST_ITEMS.map(item => [
        item.id,
        item.kind === 'mitigating' ? 'no' : item.id === 'authentication_result' ? 'fail' : 'yes',
      ])
    ) as ChecklistAnswers;
    expect(scoreChecklist(everything, 'phishing')).toMatchObject({ rawScore: 100, score: 100 });
  });

  it("always lands inside the band of the model's verdict", () => {
    const samples: ChecklistAnswers[] = [
      allClear(),
      answers({ bulk_marketing_with_unsubscribe: 'yes', routine_notice_no_action: 'yes' }),
      answers({
        asks_for_credentials: 'yes',
        sender_impersonation: 'yes',
        risky_attachment: 'yes',
      }),
      answers({ unexpected_for_recipient: 'unclear', document_or_share_lure: 'yes' }),
    ];
    for (const verdict of BANDED_VERDICTS) {
      const band = VERDICT_SCORE_BANDS[verdict];
      for (const sample of samples) {
        const { score } = scoreChecklist(sample, verdict);
        expect(score).toBeGreaterThanOrEqual(band.min);
        expect(score).toBeLessThanOrEqual(band.max);
      }
    }
  });

  it('gives fixed, code-written reasons in checklist order', () => {
    const result = scoreChecklist(
      answers({ reply_to_diverts: 'yes', asks_for_payment: 'yes', authentication_result: 'fail' }),
      'bec'
    );
    expect(result.reasons).toEqual([
      CHECKLIST_REASONS.asks_for_payment,
      CHECKLIST_REASONS.authentication_result,
      CHECKLIST_REASONS.reply_to_diverts,
    ]);
  });

  it('gives no reason for a pass or for authentication results not shown', () => {
    for (const value of ['pass', 'not_shown'] as const) {
      const result = scoreChecklist(answers({ authentication_result: value }), 'legitimate');
      expect(result.reasons).toEqual([CHECKLIST_NO_WARNING_SIGNS_REASON]);
    }
  });
});

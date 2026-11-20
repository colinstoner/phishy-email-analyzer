/**
 * Checklist scoring: the arithmetic (experimental, `scoring.mode: checklist`).
 *
 * Pure and deterministic: the same answers and verdict always give the same
 * score and the same reasons. The items live in services/ai/checklist.ts;
 * every weight and the whole combination rule live in this file, as
 * constants, so they can be read and changed in one place.
 *
 * Combination rule (version 2)
 *   E = points of the EVIDENCE items (something about the email is wrong)
 *   A = points of the ASK items (what the email wants the recipient to do)
 *   C = points of the CONTEXT items (pressure, circumstances)
 *   M = points of the MITIGATING items (zero or negative)
 *   confirmed = at least one evidence item answered `yes` (or `fail`)
 *
 *   raw   = BASE + E + (confirmed ? A + C : min(A, ASK_WITHOUT_EVIDENCE_CAP)) + M,
 *           rounded and clamped to 0-100
 *   score = raw clamped into the band of the model's verdict
 *           (VERDICT_SCORE_BANDS), so the label and the number never disagree
 *
 * Why: an ask is what ordinary business mail does too (an invoice asks for
 * payment, a supplier shares a document), so an ask on its own is worth
 * little; it becomes risk when something about the email is actually wrong.
 * Evidence on its own is moderate; evidence with an ask is high. Pressure
 * and context are common in benign mail and count only with evidence.
 * Mitigations always apply but are small, so they position an email within
 * its band and never outweigh evidence.
 *
 * `unclear` and `unknown` are explicit:
 * - a MODEL item answered `unclear` scores half its `yes` points (the
 *   briefing did not let the model tell; what cannot be checked cannot be
 *   called safe, but it is not a confirmed red flag either). An `unclear`
 *   evidence item never confirms evidence, so it cannot unlock the asks.
 * - a CODE item answered `unknown` scores 0: the fact it needs was absent
 *   (an optional feature off, nothing to check). Absence is never evidence
 *   either way: it cannot raise risk and, because no mitigation depends on
 *   it, cannot lower it.
 * - a MITIGATING item scores only when positively observed (`yes`);
 *   `unclear`/`unknown` score 0, so uncertainty never lowers risk.
 * - `authentication_failed: pass` scores 0: attackers pass authentication
 *   from their own and from compromised domains.
 *
 * The weights are a FIRST DRAFT, set by hand and NOT calibrated on real
 * mail; the maintainer will calibrate them separately on real data. How
 * they were chosen: a decisive attachment finding gets 50 (alone it must
 * reach the 'medium' band and match the attachment floor's intent); other
 * evidence gets 15-30 (alone, roughly the low/medium boundary); a
 * credential or payment ask gets 30-35 so that one ask plus one piece of
 * evidence reaches 'high' (60+); without evidence all asks together are
 * capped at 15; context gets 10; mitigations 5-10.
 */

import { ThreatVerdict } from '../../types';
import {
  CHECKLIST_ITEMS,
  CHECKLIST_VERSION,
  ChecklistAnswers,
  ChecklistClass,
  ChecklistItemId,
  ChecklistSource,
} from '../ai/checklist';
import { clampToBand } from './score.bands';

/** Points before any answer: no evidence is not proof of safety */
export const CHECKLIST_BASE_SCORE = 5;

/**
 * Most points all ask items together can add when no evidence item is
 * confirmed. A genuine invoice (payment ask plus a document to open) stays
 * low; the same asks with evidence count in full.
 */
export const ASK_WITHOUT_EVIDENCE_CAP = 15;

/**
 * Points for every answer of every item. Every answer an item allows has an
 * entry (a test asserts it), so no answer is scored by accident.
 */
export const CHECKLIST_WEIGHTS: Readonly<
  Record<ChecklistItemId, Readonly<Record<string, number>>>
> = {
  // Evidence
  link_text_mismatch: { yes: 25, no: 0, unknown: 0 },
  link_destination_unrelated: { yes: 20, unclear: 10, no: 0 },
  file_share_unrelated_to_sender: { yes: 25, no: 0, unknown: 0 },
  risky_attachment: { yes: 50, no: 0, unknown: 0 },
  sender_impersonation: { yes: 25, unclear: 12.5, no: 0 },
  authentication_failed: { fail: 25, pass: 0, unknown: 0 },
  reply_to_diverts: { yes: 25, no: 0, unknown: 0 },
  content_obfuscated: { yes: 15, no: 0, unknown: 0 },
  sender_fanout_anomalous: { yes: 30, no: 0, unknown: 0 },
  addresses_automated_review: { yes: 25, unclear: 12.5, no: 0 },
  // Asks
  asks_for_credentials: { yes: 35, unclear: 17.5, no: 0 },
  asks_for_payment: { yes: 30, unclear: 15, no: 0 },
  asks_for_sensitive_data: { yes: 25, unclear: 12.5, no: 0 },
  moves_to_other_channel: { yes: 15, unclear: 7.5, no: 0 },
  document_or_share_lure: { yes: 10, unclear: 5, no: 0 },
  // Context
  pressure_or_threat: { yes: 10, unclear: 5, no: 0 },
  bcc_to_self: { yes: 10, no: 0, unknown: 0 },
  content_uninspectable: { yes: 10, no: 0, unknown: 0 },
  // Mitigating
  bulk_marketing_with_unsubscribe: { yes: -10, unclear: 0, no: 0 },
  links_match_sender_domain: { yes: -5, no: 0, unknown: 0 },
};

/**
 * The reason shown to the employee when an item applies (`yes`, or `fail`
 * for authentication). Fixed wording written here, never model text.
 */
export const CHECKLIST_REASONS: Readonly<Record<ChecklistItemId, string>> = {
  link_text_mismatch:
    'Phishy found a link whose text shows a different address, or a file name, than where the link really goes.',
  link_destination_unrelated:
    'A link leads to a site unrelated to the sender and to the service the email names.',
  file_share_unrelated_to_sender:
    'Phishy found a shared-file link that does not appear to belong to the sender the email claims to come from.',
  risky_attachment:
    'Phishy found an attachment that could run a program, contains macros, or is a page that asks for a password.',
  sender_impersonation:
    'It presents itself as an organisation or person whose real address is not the one it was sent from.',
  authentication_failed:
    "Your mail system's authentication checks failed for the sender's domain when the email was delivered.",
  reply_to_diverts:
    'Replies would go to a different domain or person than the one it was sent from.',
  content_obfuscated: 'Phishy found hidden or reversed characters in its text.',
  sender_fanout_anomalous:
    'The sender suddenly emailed many people here it had never written to before, which is typical of a hacked account.',
  addresses_automated_review: 'It contains text that tries to influence automated security checks.',
  asks_for_credentials: 'It asks you to sign in, enter a password or code, or "verify" an account.',
  asks_for_payment:
    'It asks for a payment, a change to bank or payment details, gift cards or a money transfer.',
  asks_for_sensitive_data:
    'It asks for sensitive information such as personal, employee or financial details.',
  moves_to_other_channel:
    'It asks you to continue somewhere else, such as a phone number, another address or a chat app.',
  document_or_share_lure:
    'It mainly asks you to open a shared file, a document to sign, a voicemail or an invoice.',
  pressure_or_threat: 'It uses urgency, a deadline, a threat or secrecy to push you to act.',
  bcc_to_self:
    "It was addressed to the sender's own address with every real recipient hidden, the way a mass mailing from a hacked account is.",
  content_uninspectable:
    'Phishy could not see where a link really goes, or could not open a password-protected file.',
  bulk_marketing_with_unsubscribe:
    'It looks like bulk marketing or a newsletter with an unsubscribe link, and asks for nothing more.',
  links_match_sender_domain: "All of its links lead to the sender's own domain.",
};

/** Shown when no evidence, ask or context item applied */
export const CHECKLIST_NO_WARNING_SIGNS_REASON =
  "None of the warning signs on Phishy's checklist applied to this email.";

/** Shown when the email asks for something but no evidence item was confirmed */
export const CHECKLIST_ASK_WITHOUT_EVIDENCE_REASON =
  'Ordinary business email makes requests like this too. None of the checks found anything wrong with the email itself, so the request counted for little.';

/** Shown when some model items could not be told from the email */
export function checklistUnclearReason(count: number): string {
  return count === 1
    ? 'For 1 check the email did not show enough to tell; it counted at half weight.'
    : `For ${count} checks the email did not show enough to tell; each counted at half weight.`;
}

/** The answer that makes an item's reason apply */
function applies(id: ChecklistItemId, answer: string): boolean {
  return id === 'authentication_failed' ? answer === 'fail' : answer === 'yes';
}

export interface ChecklistContribution {
  id: ChecklistItemId;
  class: ChecklistClass;
  source: ChecklistSource;
  answer: string;
  /** The item's points before the combination rule */
  points: number;
}

export interface ChecklistScore {
  version: number;
  /** BASE + combined points, clamped to 0-100, before the verdict band */
  rawScore: number;
  /** rawScore clamped into the band of the model's verdict: the score shown */
  score: number;
  /** At least one evidence item was confirmed, so asks and context counted in full */
  evidenceConfirmed: boolean;
  /** Points per class before the combination rule */
  totals: Record<ChecklistClass, number>;
  /** Points per item, in checklist order */
  contributions: ChecklistContribution[];
  /** Fixed-wording reasons for the items that applied, in checklist order */
  reasons: string[];
}

/**
 * Score a complete set of checklist answers for the model's verdict.
 * Deterministic: no clock, no randomness, no state.
 */
export function scoreChecklist(answers: ChecklistAnswers, verdict: ThreatVerdict): ChecklistScore {
  const totals: Record<ChecklistClass, number> = { evidence: 0, ask: 0, context: 0, mitigating: 0 };
  let evidenceConfirmed = false;
  let unclear = 0;
  let warningApplied = false;
  let askApplied = false;
  const contributions: ChecklistContribution[] = [];
  const reasons: string[] = [];

  for (const item of CHECKLIST_ITEMS) {
    const answer = answers[item.id];
    const points = CHECKLIST_WEIGHTS[item.id][answer] ?? 0;
    totals[item.class] += points;
    contributions.push({ id: item.id, class: item.class, source: item.source, answer, points });
    if (answer === 'unclear' && item.class !== 'mitigating') unclear++;
    if (applies(item.id, answer)) {
      reasons.push(CHECKLIST_REASONS[item.id]);
      if (item.class === 'evidence') evidenceConfirmed = true;
      if (item.class === 'ask') askApplied = true;
      if (item.class !== 'mitigating') warningApplied = true;
    }
  }

  const askAndContext = evidenceConfirmed
    ? totals.ask + totals.context
    : Math.min(totals.ask, ASK_WITHOUT_EVIDENCE_CAP);
  const total = CHECKLIST_BASE_SCORE + totals.evidence + askAndContext + totals.mitigating;

  if (!warningApplied) reasons.unshift(CHECKLIST_NO_WARNING_SIGNS_REASON);
  if (!evidenceConfirmed && askApplied) reasons.push(CHECKLIST_ASK_WITHOUT_EVIDENCE_REASON);
  if (unclear > 0) reasons.push(checklistUnclearReason(unclear));

  const rawScore = Math.min(100, Math.max(0, Math.round(total)));
  return {
    version: CHECKLIST_VERSION,
    rawScore,
    score: clampToBand(verdict, rawScore),
    evidenceConfirmed,
    totals,
    contributions,
    reasons,
  };
}

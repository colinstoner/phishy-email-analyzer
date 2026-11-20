/**
 * Checklist scoring: the arithmetic (experimental, `scoring.mode: checklist`).
 *
 * Pure and deterministic: the same answers and verdict always give the same
 * score and the same reasons. The questions live in services/ai/checklist.ts.
 *
 * Combination rule
 *   raw   = BASE + sum of the points for each item's answer, clamped to 0-100
 *   score = raw clamped into the band of the model's verdict
 *           (VERDICT_SCORE_BANDS), so the label and the number never disagree
 *
 * A plain sum, not a weighted probability, because it is explainable item by
 * item ("a link goes somewhere else: +20") and order-independent. It
 * saturates at 100, which is fine: several strong signals together are
 * simply "as bad as it gets".
 *
 * `unclear` is handled explicitly, per item:
 * - a RISK item answered `unclear` scores half its `yes` points. The briefing
 *   did not let the model tell, and Phishy's rule is that what cannot be
 *   checked cannot be called safe; half keeps an unclear answer from
 *   counting as a confirmed red flag.
 * - a MITIGATING item answered `unclear` scores 0. A mitigation must be
 *   positively observed: uncertainty never lowers risk.
 * - `authentication_result: not_shown` scores 0. Authentication results are
 *   absent from every inline forward, so absence says nothing about the
 *   email; a pass also scores 0, because attackers pass authentication from
 *   their own and from compromised domains.
 *
 * The weights are a FIRST DRAFT, set by hand and not calibrated on real
 * mail. How they were chosen: the strongest single signals of harm if the
 * recipient acts (a credential or payment request, an attachment that runs
 * code) get 30-35; signals that frequently accompany an attack but also
 * occur in ordinary mail (impersonation, a link to an unrelated domain, an
 * authentication failure, text aimed at an automated reviewer) get 20-25;
 * context that is common in benign mail (urgency, a file-share lure,
 * unusual addressing) gets 5-15; mitigations are kept small (5-10) so they
 * can position an email within its band but never outweigh a strong risk
 * signal, and the verdict band bounds them anyway. They are deliberately
 * constants in code, not configuration, until they have been measured.
 */

import { ThreatVerdict } from '../../types';
import {
  CHECKLIST_ITEMS,
  CHECKLIST_VERSION,
  ChecklistAnswers,
  ChecklistItemId,
} from '../ai/checklist';
import { clampToBand } from './score.bands';

/** Points before any answer: no evidence is not proof of safety */
export const CHECKLIST_BASE_SCORE = 5;

/**
 * Points for every answer of every item. Every answer an item allows has an
 * entry (a test asserts it), so no answer is scored by accident.
 */
export const CHECKLIST_WEIGHTS: Readonly<
  Record<ChecklistItemId, Readonly<Record<string, number>>>
> = {
  asks_for_credentials: { yes: 30, unclear: 15, no: 0 },
  asks_for_payment: { yes: 30, unclear: 15, no: 0 },
  asks_for_sensitive_data: { yes: 20, unclear: 10, no: 0 },
  moves_to_other_channel: { yes: 15, unclear: 7.5, no: 0 },
  link_destination_mismatch: { yes: 20, unclear: 10, no: 0 },
  document_or_share_lure: { yes: 10, unclear: 5, no: 0 },
  file_share_unrelated_to_sender: { yes: 10, unclear: 5, no: 0 },
  risky_attachment: { yes: 35, unclear: 17.5, no: 0 },
  sender_impersonation: { yes: 25, unclear: 12.5, no: 0 },
  authentication_result: { fail: 20, pass: 0, not_shown: 0 },
  reply_to_diverts: { yes: 15, unclear: 7.5, no: 0 },
  pressure_or_threat: { yes: 10, unclear: 5, no: 0 },
  unexpected_for_recipient: { yes: 10, unclear: 5, no: 0 },
  content_obfuscated: { yes: 10, unclear: 5, no: 0 },
  unusual_addressing: { yes: 5, unclear: 2.5, no: 0 },
  addresses_automated_review: { yes: 25, unclear: 12.5, no: 0 },
  decisive_content_uninspectable: { yes: 10, unclear: 5, no: 0 },
  bulk_marketing_with_unsubscribe: { yes: -10, unclear: 0, no: 0 },
  routine_notice_no_action: { yes: -10, unclear: 0, no: 0 },
  links_match_claimed_sender: { yes: -5, unclear: 0, no: 0 },
};

/**
 * The reason shown to the employee when an item applies (`yes`, or `fail`
 * for authentication). Fixed wording written here, never model text.
 */
export const CHECKLIST_REASONS: Readonly<Record<ChecklistItemId, string>> = {
  asks_for_credentials: 'It asks you to sign in, enter a password or code, or "verify" an account.',
  asks_for_payment:
    'It asks for a payment, a change to bank or payment details, gift cards or a money transfer.',
  asks_for_sensitive_data:
    'It asks for sensitive information such as personal, employee or financial details.',
  moves_to_other_channel:
    'It tries to move the conversation somewhere else, such as a phone number, a personal address or a chat app.',
  link_destination_mismatch:
    'A link goes somewhere other than where the email says it goes, or to a site unrelated to the sender it claims to be.',
  document_or_share_lure:
    'It mainly asks you to open a shared file, a document to sign, a voicemail or an invoice.',
  file_share_unrelated_to_sender:
    'A shared-file link does not appear to belong to the sender the email claims to come from.',
  risky_attachment: 'An attachment could run a program, or asks for a password, when opened.',
  sender_impersonation:
    'It presents itself as an organisation or person whose real address is not the one it was sent from.',
  authentication_result:
    "The mail-authentication checks shown in the headers failed for the sender's domain.",
  reply_to_diverts: 'Replies would go to a different address than the one it was sent from.',
  pressure_or_threat: 'It uses urgency, a deadline, a threat or secrecy to push you to act.',
  unexpected_for_recipient: 'The request is unexpected for your role and for this kind of sender.',
  content_obfuscated: 'Parts of its content are hidden or disguised.',
  unusual_addressing:
    'It was addressed in an unusual way: to the sender itself, or not visibly to you.',
  addresses_automated_review: 'It contains text that tries to influence automated security checks.',
  decisive_content_uninspectable:
    'Phishy could not inspect content that would decide whether it is safe.',
  bulk_marketing_with_unsubscribe:
    'It looks like bulk marketing or a newsletter with an unsubscribe link, and asks for nothing more.',
  routine_notice_no_action:
    'It looks like a routine notice that asks for no sign-in, payment, reply or file opening.',
  links_match_claimed_sender: 'Its links lead to the organisation it says it is from.',
};

/** Shown when no risk item applied */
export const CHECKLIST_NO_WARNING_SIGNS_REASON =
  "None of the warning signs on Phishy's checklist applied to this email.";

/** Shown when some items could not be told from the email */
export function checklistUnclearReason(count: number): string {
  return count === 1
    ? 'For 1 check the email did not show enough to tell; it counted at half weight.'
    : `For ${count} checks the email did not show enough to tell; each counted at half weight.`;
}

/** The answer that makes an item's reason apply */
function applies(id: ChecklistItemId, answer: string): boolean {
  return id === 'authentication_result' ? answer === 'fail' : answer === 'yes';
}

export interface ChecklistScore {
  version: number;
  /** BASE + points, clamped to 0-100, before the verdict band */
  rawScore: number;
  /** rawScore clamped into the band of the model's verdict: the score shown */
  score: number;
  /** Points per item, in checklist order */
  contributions: Array<{ id: ChecklistItemId; answer: string; points: number }>;
  /** Fixed-wording reasons for the items that applied, in checklist order */
  reasons: string[];
}

/**
 * Score a complete set of checklist answers for the model's verdict.
 * Deterministic: no clock, no randomness, no state.
 */
export function scoreChecklist(answers: ChecklistAnswers, verdict: ThreatVerdict): ChecklistScore {
  let total = CHECKLIST_BASE_SCORE;
  let unclear = 0;
  let riskApplied = false;
  const contributions: ChecklistScore['contributions'] = [];
  const reasons: string[] = [];

  for (const item of CHECKLIST_ITEMS) {
    const answer = answers[item.id];
    const points = CHECKLIST_WEIGHTS[item.id][answer] ?? 0;
    total += points;
    contributions.push({ id: item.id, answer, points });
    if (answer === 'unclear' && item.kind === 'risk') unclear++;
    if (applies(item.id, answer)) {
      reasons.push(CHECKLIST_REASONS[item.id]);
      if (item.kind === 'risk') riskApplied = true;
    }
  }

  if (!riskApplied) reasons.unshift(CHECKLIST_NO_WARNING_SIGNS_REASON);
  if (unclear > 0) reasons.push(checklistUnclearReason(unclear));

  const rawScore = Math.min(100, Math.max(0, Math.round(total)));
  return {
    version: CHECKLIST_VERSION,
    rawScore,
    score: clampToBand(verdict, rawScore),
    contributions,
    reasons,
  };
}

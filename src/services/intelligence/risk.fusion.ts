/**
 * Risk Fusion
 *
 * The model produces a verdict and a first-pass risk score from the email
 * alone. This layer fuses that with hard signals from Phishy's own
 * intelligence — known indicators, active campaigns, and security-team
 * rulings — to produce the final risk, deterministically and with an
 * explanation trail the report can show. Pure function: the handler gathers
 * the signals, this decides.
 */

import {
  AnalysisResult,
  ThreatVerdict,
  ConfidenceLevel,
  MALICIOUS_VERDICTS,
  SenderHistoryFacts,
} from '../../types';
import { ThreatIndicatorRecord, CampaignRecord, FeedbackRecord } from './database.service';
import { partitionMatches } from './indicator.policy';
import { normalizeConfidence } from '../ai/provider.interface';
import type { AttachmentRiskSignal } from '../attachments/risk';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

/** Signals the handler collects before fusing */
export interface FusionSignals {
  /**
   * Known indicators from this email that already exist in the store. Each is
   * classified strong or weak (see indicator.policy.ts); only strong matches
   * can raise the score past the weak ceiling or change a verdict.
   */
  matchedIndicators?: ThreatIndicatorRecord[];
  /** An active campaign this email matches, if any */
  campaign?: CampaignRecord | null;
  /** A security-team ruling on this campaign, if any */
  humanVerdict?: FeedbackRecord['verdict'];
  /** The reporter is on the configured safe-sender / safe-domain allowlist */
  isSafeSender?: boolean;
  /**
   * Sender-relationship facts from the organization's mail-flow records.
   * One-directional by design: they can add a reason and raise the floor,
   * and are never read in a way that lowers a score or clears a verdict.
   */
  senderHistory?: SenderHistoryFacts;
  /**
   * Decisive findings of Phishy's static attachment inspection (see
   * services/attachments/risk.ts). One-directional: each adds a reason and
   * raises the floor; an inspected, inert attachment produces no signal and
   * so can never lower anything.
   */
  attachmentSignals?: AttachmentRiskSignal[];
  /** Clock for indicator expiry (tests) */
  now?: Date;
}

/**
 * Risk floor when an established sender shows anomalous fan-out (a known
 * contact suddenly mailing many people it never wrote to): 'medium'.
 */
export const SENDER_FANOUT_RISK_FLOOR = 35;

/**
 * Risk floor for a decisive attachment finding (a password form that posts
 * to a web host; an executable disguised as a document): 'high', above the
 * phishing threshold, so a suspicious verdict at the floor is flagged.
 */
export const ATTACHMENT_RISK_FLOOR = 60;

const ATTACHMENT_REASONS: Record<AttachmentRiskSignal, string> = {
  credential_form:
    'An attachment is a web page with a password field that sends what is typed into it to a web server. ' +
    'Opened from an email, such a page exists to collect your password.',
  disguised_executable:
    'An attachment is a program or script whose name is made to look like a document or picture. ' +
    'Opening it would run it.',
};

/**
 * Highest score weak indicator matches can lift an email to: 'medium', below
 * the phishing threshold. Weak matches (shared infrastructure, indicators
 * without provenance, expired ones) are context, never evidence on their own.
 */
export const WEAK_INDICATOR_RISK_CEILING = 40;

/**
 * Score at or above which a `suspicious` verdict is flagged as phishing for
 * downstream gating (campaign tracking, blast radius, isPhishing). Malicious
 * verdicts are always flagged; benign verdicts never are.
 */
export const PHISHING_SCORE_THRESHOLD = 55;

/**
 * Score band for each final verdict, applied after fusion so the number
 * shown always agrees with the label. `legitimate` (0-10) and the malicious
 * upper range follow the model's own rubric; `graymail`/`spam` follow its
 * 10-30 but stop at 29 so the level shown stays 'low' rather than 'medium';
 * `suspicious` spans 'medium' and 'high' but never 'critical' (critical is
 * reserved for a malicious verdict); a malicious verdict is never below
 * 'high'. `undetermined` has no band — its score is never shown.
 */
export const VERDICT_SCORE_BANDS: Readonly<
  Record<Exclude<ThreatVerdict, 'undetermined'>, { min: number; max: number }>
> = {
  legitimate: { min: 0, max: 10 },
  graymail: { min: 10, max: 29 },
  spam: { min: 10, max: 29 },
  suspicious: { min: 30, max: 79 },
  bec: { min: 55, max: 100 },
  phishing: { min: 55, max: 100 },
  malware_delivery: { min: 55, max: 100 },
};

/** Verdicts that say the email is not an attack */
const BENIGN_VERDICTS: readonly ThreatVerdict[] = ['legitimate', 'graymail', 'spam'];

/**
 * What the displayed confidence is based on:
 * - `model`: the model's own certainty in its verdict
 * - `security_team`: a security-team ruling decided the outcome
 * - `threat_intel`: a strong indicator match or an active campaign changed
 *   the outcome (verdict or phishing flag) the model reached
 * - `attachment_inspection`: a decisive finding of Phishy's own attachment
 *   inspection changed the outcome the model reached
 * - `unassessed`: the model never produced a verdict
 */
export type ConfidenceBasis =
  'model' | 'security_team' | 'threat_intel' | 'attachment_inspection' | 'unassessed';

export interface RiskDecision {
  verdict: ThreatVerdict;
  /** Fused 0-100 risk score, inside the band for `verdict` */
  riskScore: number;
  riskLevel: RiskLevel;
  isPhishing: boolean;
  /**
   * Confidence in the outcome. The model's `verdictConfidence` mapped to a
   * label when the model decided; 'Very High' for a security-team ruling;
   * 'High' when a strong signal decided; 'N/A' when unassessed.
   */
  confidence: ConfidenceLevel;
  confidenceBasis: ConfidenceBasis;
  /** Human-readable explanation of how intelligence moved the score */
  reasons: string[];
}

const CONFIDENCE_TO_SCORE: Record<string, number> = {
  'very high': 90,
  high: 75,
  medium: 50,
  low: 25,
  'very low': 10,
};

/** Map a fused 0-100 score to a discrete level */
export function scoreToLevel(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  if (score >= 10) return 'low';
  return 'safe';
}

/**
 * Derive a base risk score from a result, preferring the structured
 * assessment and falling back to the legacy isPhishing + confidence (quick
 * path, cache hits from older analyses).
 */
function baseScore(result: AnalysisResult): { score: number; verdict: ThreatVerdict } {
  // The model never produced a verdict — analysis could not be completed.
  // Start from 'undetermined' / 0 so this can never default to a "legitimate"
  // base. Hard intel below may still escalate it; nothing caps it to "safe".
  if (result.analysisFailed) {
    return { score: 0, verdict: 'undetermined' };
  }
  if (result.assessment) {
    return { score: result.assessment.riskScore, verdict: result.assessment.verdict };
  }
  if (!result.isPhishing) {
    return { score: 5, verdict: 'legitimate' };
  }
  const conf = (result.confidence ?? '').toLowerCase();
  return { score: CONFIDENCE_TO_SCORE[conf] ?? 50, verdict: 'suspicious' };
}

/**
 * The model's own verdict for a result, before any intelligence is fused in.
 * This — not the fused verdict — decides whether indicators are stored.
 */
export function modelVerdictOf(result: AnalysisResult): ThreatVerdict {
  return baseScore(result).verdict;
}

/** The model's confidence in its own verdict, as a display label */
function modelConfidence(result: AnalysisResult): ConfidenceLevel {
  if (result.analysisFailed) return 'N/A';
  if (result.assessment && typeof result.assessment.verdictConfidence === 'number') {
    return normalizeConfidence(result.assessment.verdictConfidence);
  }
  return normalizeConfidence(result.confidence);
}

const BENIGN_LABEL: Partial<Record<ThreatVerdict, string>> = {
  legitimate: 'a legitimate email',
  graymail: 'legitimate bulk email',
  spam: 'spam',
};

export function fuseRisk(result: AnalysisResult, signals: FusionSignals = {}): RiskDecision {
  const { score: initialScore, verdict: baseVerdict } = baseScore(result);
  let score = initialScore;
  let verdict = baseVerdict;
  const reasons: string[] = [];

  // 1. Security-team ruling is authoritative — it overrides everything,
  //    including the verdict (so the stored verdict and the report banner
  //    can't contradict the human ruling). A confirmed ruling keeps an
  //    already-malicious model verdict (preserving specificity like 'bec')
  //    but promotes a non-malicious one to 'phishing'; a clearance forces
  //    'legitimate'.
  if (signals.humanVerdict === 'confirmed_phishing') {
    score = Math.max(score, 95);
    const ruledVerdict = MALICIOUS_VERDICTS.includes(verdict) ? verdict : 'phishing';
    reasons.push('Your security team confirmed this campaign as phishing.');
    return decision(ruledVerdict, score, reasons, {
      isPhishing: true,
      confidence: 'Very High',
      confidenceBasis: 'security_team',
    });
  }
  if (signals.humanVerdict === 'false_positive') {
    reasons.push('Your security team reviewed this campaign and cleared it.');
    return decision('legitimate', 0, reasons, {
      isPhishing: false,
      confidence: 'Very High',
      confidenceBasis: 'security_team',
    });
  }

  // 2. Known indicators. Only STRONG matches (exact URL / address / sender or
  //    payload domain, from a model-malicious or security-confirmed report,
  //    unexpired) raise the floor, scaled by how many distinct reported
  //    emails the strongest was seen in.
  const { strong, weak } = partitionMatches(signals.matchedIndicators ?? [], signals.now);
  let intelRaised = false;
  if (strong.length > 0) {
    const strongest = strong.reduce((a, b) => (b.timesSeen > a.timesSeen ? b : a));
    const floor = Math.min(95, 60 + strongest.timesSeen * 8);
    if (floor > score) {
      score = floor;
      intelRaised = true;
    }
    reasons.push(
      `${countPhrase(strong.length, 'link, sender or domain', 'links, senders or domains')} in this email ` +
        `${strong.length === 1 ? 'matches a threat' : 'match threats'} confirmed in earlier reports ` +
        `(seen in ${strongest.timesSeen} reported ${strongest.timesSeen === 1 ? 'email' : 'emails'}).`
    );
  }

  // 3. WEAK matches are disclosed but are not evidence of an attack: they can
  //    lift an unconfirmed (suspicious) or unassessed email to the weak
  //    ceiling, never change a benign verdict, never reach the phishing
  //    threshold on their own.
  if (weak.length > 0) {
    reasons.push(
      `${countPhrase(weak.length, 'link or domain', 'links or domains')} in this email also appeared in ` +
        'earlier reports, but not as confirmed attack infrastructure, so ' +
        `${weak.length === 1 ? 'it was' : 'they were'} not treated as evidence of an attack.`
    );
    if (
      strong.length === 0 &&
      (verdict === 'suspicious' || verdict === 'undetermined') &&
      score < WEAK_INDICATOR_RISK_CEILING
    ) {
      score = WEAK_INDICATOR_RISK_CEILING;
    }
  }

  // 4. An active high/critical campaign raises the floor.
  if (signals.campaign?.isActive) {
    const campaignFloor =
      signals.campaign.riskLevel === 'critical'
        ? 80
        : signals.campaign.riskLevel === 'high'
          ? 60
          : 0;
    if (campaignFloor > score) {
      score = campaignFloor;
      intelRaised = true;
    }
    if (campaignFloor > 0) {
      reasons.push(
        `Part of an active campaign seen in ${signals.campaign.detectionCount} reports across ` +
          `${signals.campaign.uniqueRecipients.length} recipients.`
      );
    }
  }

  // 5. A safe-sender allowlist match caps risk — unless a strong match above
  //    already proved malice (in which case the floors above stand). Never
  //    caps an 'undetermined' result: a failed analysis must not be talked
  //    down to safe. Weak matches do not block the cap.
  if (
    signals.isSafeSender &&
    !MALICIOUS_VERDICTS.includes(verdict) &&
    verdict !== 'undetermined' &&
    strong.length === 0
  ) {
    score = Math.min(score, 10);
    intelRaised = false;
    reasons.push('Reporter is on the trusted-sender allowlist.');
  }

  // 6. Sender relationship. A relationship must never lower risk — trust is
  //    exactly what a mailbox takeover borrows — so only the anomalous
  //    classification is read, and only to raise: `established` (or any other
  //    class) contributes nothing, and nothing here can reduce the score or
  //    turn a verdict benign. It runs after the allowlist cap so the cap
  //    cannot undo it. When the floor lifts a 'legitimate' verdict the label
  //    becomes 'suspicious', so the banner cannot contradict the reason.
  if (signals.senderHistory?.classification === 'established_with_anomalous_fanout') {
    reasons.push(
      'This sender has emailed your organization before, but this time the same message went to far more ' +
        "people than usual, most of whom it had never written to. That pattern is typical of a known contact's mailbox being taken over."
    );
    if (score < SENDER_FANOUT_RISK_FLOOR) {
      score = SENDER_FANOUT_RISK_FLOOR;
      if (verdict === 'legitimate') {
        verdict = 'suspicious';
      }
    }
  }

  // 6b. Attachment inspection. Only findings with no innocent explanation
  //     are signals, and they only raise: a reason, a floor, and a benign
  //     label becomes 'suspicious' so the banner cannot contradict the
  //     reason. Like sender history it runs after the allowlist cap. There
  //     is no signal for an inert attachment, so a clean inspection cannot
  //     lower a score or clear a verdict.
  let attachmentRaised = false;
  let verdictChangedByAttachment = false;
  const attachmentSignals = [...new Set(signals.attachmentSignals ?? [])];
  if (attachmentSignals.length > 0) {
    for (const signal of attachmentSignals) reasons.push(ATTACHMENT_REASONS[signal]);
    if (score < ATTACHMENT_RISK_FLOOR) {
      score = ATTACHMENT_RISK_FLOOR;
      attachmentRaised = true;
    }
    if (isBenign(verdict)) {
      reasons.push(
        `On its content alone this looked like ${BENIGN_LABEL[verdict] ?? verdict}, but because of the ` +
          'attachment above Phishy is treating it as suspicious.'
      );
      verdict = 'suspicious';
      verdictChangedByAttachment = true;
    }
  }

  // 7. A failed analysis stays 'undetermined' unless hard intel above escalated
  //    it. Always disclose that the email could not be assessed so the report
  //    can't read as a clean bill of health.
  let unassessedEscalated = false;
  if (result.analysisFailed) {
    reasons.push(
      'Automated analysis could not be completed (the AI provider was temporarily unavailable), ' +
        'so Phishy could not assess this email — treat it with caution until you verify the sender another way.'
    );
    if (score > 0) {
      // Known indicators or an active campaign flagged it even without the
      // model. We can't name the threat type, but it isn't clean.
      verdict = 'suspicious';
      unassessedEscalated = true;
    }
  }

  // 8. Verdict and score must agree. When a strong match or campaign raised
  //    an email the model called benign past that verdict's band, the label
  //    becomes 'suspicious' and the reasons say why — otherwise the band
  //    would silently undo the raise, or the banner would read "legitimate"
  //    next to a high score.
  let verdictChangedByIntel = false;
  if (intelRaised && isBenign(verdict) && score > VERDICT_SCORE_BANDS[verdict].max) {
    reasons.push(
      `On its content alone this looked like ${BENIGN_LABEL[verdict] ?? verdict}, but because of the ` +
        'known threat above Phishy is treating it as suspicious.'
    );
    verdict = 'suspicious';
    verdictChangedByIntel = true;
  }

  const finalScore = clampToBand(verdict, score);
  const isPhishing = flagAsPhishing(verdict, finalScore);

  // 9. Confidence. The model's own certainty in its verdict — unless
  //    intelligence decided the outcome, in which case say so instead.
  const modelFlagged = flagAsPhishing(baseVerdict, clampToBand(baseVerdict, initialScore));
  const intelDecided =
    intelRaised && (verdictChangedByIntel || unassessedEscalated || (isPhishing && !modelFlagged));
  const attachmentDecided =
    !intelDecided &&
    (verdictChangedByAttachment ||
      (attachmentRaised && (unassessedEscalated || (isPhishing && !modelFlagged))));
  if (attachmentDecided) {
    return decision(verdict, finalScore, reasons, {
      isPhishing,
      confidence: 'High',
      confidenceBasis: 'attachment_inspection',
    });
  }
  if (intelDecided) {
    return decision(verdict, finalScore, reasons, {
      isPhishing,
      confidence: 'High',
      confidenceBasis: 'threat_intel',
    });
  }
  return decision(verdict, finalScore, reasons, {
    isPhishing,
    confidence: modelConfidence(result),
    confidenceBasis: result.analysisFailed ? 'unassessed' : 'model',
  });
}

function countPhrase(count: number, singular: string, plural: string): string {
  return count === 1 ? `1 ${singular}` : `${count} ${plural}`;
}

function isBenign(verdict: ThreatVerdict): verdict is 'legitimate' | 'graymail' | 'spam' {
  return BENIGN_VERDICTS.includes(verdict);
}

/** Clamp a score into its verdict's band (undetermined is left as-is) */
export function clampToBand(verdict: ThreatVerdict, score: number): number {
  const rounded = Math.min(100, Math.max(0, Math.round(score)));
  if (verdict === 'undetermined') return rounded;
  const band = VERDICT_SCORE_BANDS[verdict];
  return Math.min(band.max, Math.max(band.min, rounded));
}

/**
 * The phishing flag follows the final verdict and score together: malicious
 * verdicts always, a suspicious verdict at or above the threshold, a benign
 * or undetermined verdict never.
 */
function flagAsPhishing(verdict: ThreatVerdict, score: number): boolean {
  if (MALICIOUS_VERDICTS.includes(verdict)) return true;
  return verdict === 'suspicious' && score >= PHISHING_SCORE_THRESHOLD;
}

function decision(
  verdict: ThreatVerdict,
  score: number,
  reasons: string[],
  outcome: { isPhishing: boolean; confidence: ConfidenceLevel; confidenceBasis: ConfidenceBasis }
): RiskDecision {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));
  return {
    verdict,
    riskScore: clamped,
    riskLevel: scoreToLevel(clamped),
    isPhishing: outcome.isPhishing,
    confidence: outcome.confidence,
    confidenceBasis: outcome.confidenceBasis,
    reasons,
  };
}

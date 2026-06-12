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

import { AnalysisResult, ThreatVerdict, ConfidenceLevel, MALICIOUS_VERDICTS } from '../../types';
import { ThreatIndicatorRecord, CampaignRecord, FeedbackRecord } from './database.service';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

/** Signals the handler collects before fusing */
export interface FusionSignals {
  /** Known indicators from this email that already exist in the store */
  matchedIndicators?: ThreatIndicatorRecord[];
  /** An active campaign this email matches, if any */
  campaign?: CampaignRecord | null;
  /** A security-team ruling on this campaign, if any */
  humanVerdict?: FeedbackRecord['verdict'];
  /** The reporter is on the configured safe-sender / safe-domain allowlist */
  isSafeSender?: boolean;
}

export interface RiskDecision {
  verdict: ThreatVerdict;
  /** Fused 0-100 risk score */
  riskScore: number;
  riskLevel: RiskLevel;
  isPhishing: boolean;
  confidence: ConfidenceLevel;
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

function scoreToConfidence(score: number): ConfidenceLevel {
  if (score >= 85) return 'Very High';
  if (score >= 60) return 'High';
  if (score >= 35) return 'Medium';
  if (score >= 15) return 'Low';
  return 'Very Low';
}

/**
 * Derive a base risk score from a result, preferring the structured
 * assessment and falling back to the legacy isPhishing + confidence (quick
 * path, cache hits from older analyses).
 */
function baseScore(result: AnalysisResult): { score: number; verdict: ThreatVerdict } {
  if (result.assessment) {
    return { score: result.assessment.riskScore, verdict: result.assessment.verdict };
  }
  if (!result.isPhishing) {
    return { score: 5, verdict: 'legitimate' };
  }
  const conf = (result.confidence ?? '').toLowerCase();
  return { score: CONFIDENCE_TO_SCORE[conf] ?? 50, verdict: 'suspicious' };
}

export function fuseRisk(result: AnalysisResult, signals: FusionSignals = {}): RiskDecision {
  const { score: initialScore, verdict } = baseScore(result);
  let score = initialScore;
  const reasons: string[] = [];

  // 1. Security-team ruling is authoritative — it overrides everything.
  if (signals.humanVerdict === 'confirmed_phishing') {
    score = Math.max(score, 95);
    reasons.push('Your security team confirmed this campaign as phishing.');
    return finalize(verdict, score, reasons, true);
  }
  if (signals.humanVerdict === 'false_positive') {
    reasons.push('Your security team reviewed this campaign and cleared it.');
    return finalize(verdict, 0, reasons, false);
  }

  // 2. Known malicious indicators seen before raise the floor. Repeat
  //    sightings and higher stored confidence push harder.
  const matches = signals.matchedIndicators ?? [];
  if (matches.length > 0) {
    const strongest = matches.reduce((a, b) => (b.timesSeen > a.timesSeen ? b : a));
    const floor = Math.min(95, 60 + strongest.timesSeen * 8);
    if (floor > score) {
      score = floor;
    }
    const plural = matches.length === 1 ? 'indicator' : 'indicators';
    reasons.push(
      `${matches.length} ${plural} in this email ${matches.length === 1 ? 'was' : 'were'} flagged in prior reports ` +
        `(most-seen ${strongest.timesSeen}×).`
    );
  }

  // 3. An active high/critical campaign raises the floor.
  if (signals.campaign?.isActive) {
    const campaignFloor = signals.campaign.riskLevel === 'critical' ? 80 : signals.campaign.riskLevel === 'high' ? 60 : 0;
    if (campaignFloor > score) {
      score = campaignFloor;
    }
    if (campaignFloor > 0) {
      reasons.push(
        `Part of an active campaign seen in ${signals.campaign.detectionCount} reports across ` +
          `${signals.campaign.uniqueRecipients.length} recipients.`
      );
    }
  }

  // 4. A safe-sender allowlist match caps risk — unless intel above already
  //    proved malice (in which case the floors above stand).
  if (signals.isSafeSender && !MALICIOUS_VERDICTS.includes(verdict) && matches.length === 0) {
    score = Math.min(score, 10);
    reasons.push('Reporter is on the trusted-sender allowlist.');
  }

  return finalize(verdict, score, reasons, undefined);
}

function finalize(
  verdict: ThreatVerdict,
  score: number,
  reasons: string[],
  forcedPhishing: boolean | undefined
): RiskDecision {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));
  const isPhishing = forcedPhishing ?? (MALICIOUS_VERDICTS.includes(verdict) || clamped >= 55);
  return {
    verdict,
    riskScore: clamped,
    riskLevel: scoreToLevel(clamped),
    isPhishing,
    confidence: scoreToConfidence(clamped),
    reasons,
  };
}

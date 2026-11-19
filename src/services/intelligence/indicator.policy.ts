/**
 * Indicator Policy
 *
 * The rules that decide (a) when an email's indicators may be stored as
 * threat intelligence and (b) how much a stored indicator counts when a later
 * email matches it. Both live here so storage, risk fusion, the agentic
 * lookup tool and the audit CLI apply the same definitions.
 *
 * The failure this guards against is a feedback loop: indicators stored
 * because a *score* crossed a threshold, then matched by unrelated mail
 * (shared bulk-mail infrastructure), lifting that mail over the threshold and
 * storing its indicators in turn. So:
 *
 * - Storage follows the MODEL's own verdict (or a security-team ruling) —
 *   never a score that fusion raised.
 * - A match is "strong" only when the stored indicator is an exact URL, an
 *   exact address or a sender/payload domain, came from a model-malicious or
 *   security-confirmed report, and has not expired. Everything else is
 *   "weak": context worth disclosing, never evidence of an attack by itself.
 *
 * Indicator values are derived from hostile content. Nothing here interprets
 * them; it reads only the metadata Phishy itself wrote.
 */

import { MALICIOUS_VERDICTS, ThreatVerdict } from '../../types';
import type { FeedbackRecord, ThreatIndicatorRecord } from './database.service';

/** What part an indicator played in the email it came from */
export type IndicatorRole = 'sender' | 'payload' | 'infrastructure';

/** Why an indicator was stored */
export type IndicatorProvenance = 'model_malicious' | 'security_confirmed';

export type MatchStrength = 'strong' | 'weak';

/** Why a match was classified the way it was (audit output and tests) */
export type MatchReason =
  | 'strong'
  | 'inactive'
  | 'expired'
  | 'security_cleared'
  | 'no_provenance'
  | 'infrastructure_role'
  | 'unknown_role'
  | 'inexact_type';

/** Indicator types matched exactly by value (URL, address, domain) */
const STRONG_ELIGIBLE_TYPES: ReadonlySet<ThreatIndicatorRecord['indicatorType']> = new Set([
  'url',
  'email',
  'domain',
]);

const ROLES: ReadonlySet<string> = new Set(['sender', 'payload', 'infrastructure']);

/**
 * How many distinct report keys an indicator remembers for de-duplicating
 * `times_seen`. Older keys roll off; a report whose key rolled off counts
 * again, which only matters for indicators with very long histories.
 */
export const REPORT_KEY_HISTORY = 50;

/** Marker written into metadata by the audit CLI when it deactivates a row */
export const AUDIT_DEACTIVATION_MARKER = 'indicator-audit';

/**
 * Role recorded on the indicator, or derived from the extraction context for
 * indicators stored before roles were recorded. Undefined when unknown.
 */
export function indicatorRole(indicator: ThreatIndicatorRecord): IndicatorRole | undefined {
  const metadata = indicator.metadata ?? {};
  const recorded = metadata.role;
  if (typeof recorded === 'string' && ROLES.has(recorded)) {
    return recorded as IndicatorRole;
  }

  const context = typeof metadata.extractionContext === 'string' ? metadata.extractionContext : '';
  if (context.startsWith('ai_nominated:')) {
    const nominated = context.substring('ai_nominated:'.length);
    return ROLES.has(nominated) ? (nominated as IndicatorRole) : undefined;
  }
  switch (context) {
    case 'sender_domain':
    case 'original_sender_email':
      return 'sender';
    case 'final_url_domain':
    case 'final_url':
      return 'payload';
    case 'url_in_content':
      // A wrapped link (tracker, open redirector) is the hop, not the target
      return Array.isArray(metadata.redirectChain) ? 'infrastructure' : 'payload';
    case 'redirect_intermediary':
    case 'ip_in_content':
    case 'hash_in_content':
      return 'infrastructure';
    default:
      return undefined;
  }
}

/**
 * Why the indicator was stored, from metadata Phishy wrote. Indicators stored
 * before provenance was recorded have none. A security-team clearance
 * removes provenance even when the row is still active.
 */
export function indicatorProvenance(
  indicator: ThreatIndicatorRecord
): IndicatorProvenance | undefined {
  const metadata = indicator.metadata ?? {};
  if (metadata.securityCleared === true) return undefined;
  if (metadata.securityConfirmed === true || metadata.provenance === 'security_confirmed') {
    return 'security_confirmed';
  }
  if (
    metadata.provenance === 'model_malicious' &&
    typeof metadata.sourceVerdict === 'string' &&
    MALICIOUS_VERDICTS.includes(metadata.sourceVerdict as ThreatVerdict)
  ) {
    return 'model_malicious';
  }
  return undefined;
}

export function isIndicatorExpired(indicator: ThreatIndicatorRecord, now: Date): boolean {
  if (!indicator.expiresAt) return false;
  const expires = new Date(indicator.expiresAt);
  return !Number.isNaN(expires.getTime()) && expires.getTime() <= now.getTime();
}

/**
 * Strong ⇔ active, unexpired, stored from a model-malicious or
 * security-confirmed report, an exactly-matched type (URL, email address,
 * domain), and recorded in the role of sender or payload. Everything else is
 * weak — including every indicator stored before provenance was recorded.
 */
export function classifyIndicator(
  indicator: ThreatIndicatorRecord,
  now: Date = new Date()
): { strength: MatchStrength; reason: MatchReason } {
  const weak = (reason: MatchReason): { strength: MatchStrength; reason: MatchReason } => ({
    strength: 'weak',
    reason,
  });

  if (!indicator.isActive) return weak('inactive');
  if (isIndicatorExpired(indicator, now)) return weak('expired');
  if (indicator.metadata?.securityCleared === true) return weak('security_cleared');
  if (!indicatorProvenance(indicator)) return weak('no_provenance');
  if (!STRONG_ELIGIBLE_TYPES.has(indicator.indicatorType)) return weak('inexact_type');
  const role = indicatorRole(indicator);
  if (role === 'infrastructure') return weak('infrastructure_role');
  if (!role) return weak('unknown_role');
  return { strength: 'strong', reason: 'strong' };
}

/** Split matched indicators into strong and weak */
export function partitionMatches(
  matches: ThreatIndicatorRecord[],
  now: Date = new Date()
): { strong: ThreatIndicatorRecord[]; weak: ThreatIndicatorRecord[] } {
  const strong: ThreatIndicatorRecord[] = [];
  const weak: ThreatIndicatorRecord[] = [];
  for (const match of matches) {
    (classifyIndicator(match, now).strength === 'strong' ? strong : weak).push(match);
  }
  return { strong, weak };
}

/** Inputs to the storage decision, captured BEFORE risk fusion runs */
export interface IndicatorStorageInput {
  /** The model's own verdict (not the fused one) */
  modelVerdict: ThreatVerdict;
  /** The model never produced a verdict */
  analysisFailed?: boolean;
  /** This report reused a campaign-cache verdict instead of a fresh analysis */
  fromCampaignCache?: boolean;
  /** A security-team ruling that applies to this report */
  humanVerdict?: FeedbackRecord['verdict'];
}

export interface IndicatorStorageDecision {
  store: boolean;
  provenance?: IndicatorProvenance;
  /** Short machine-readable reason, logged */
  reason: string;
}

/**
 * Should this report's indicators be stored? Only for a model-malicious
 * verdict from a fresh analysis, or a security-team confirmation. Never
 * because fusion raised the score, never for a failed analysis, and never for
 * a plain campaign-cache hit (the source analysis already stored them).
 */
export function decideIndicatorStorage(input: IndicatorStorageInput): IndicatorStorageDecision {
  if (input.humanVerdict === 'false_positive') {
    return { store: false, reason: 'security_cleared' };
  }
  if (input.humanVerdict === 'confirmed_phishing') {
    return { store: true, provenance: 'security_confirmed', reason: 'security_confirmed' };
  }
  if (input.analysisFailed) {
    return { store: false, reason: 'analysis_failed' };
  }
  if (input.fromCampaignCache) {
    return { store: false, reason: 'campaign_cache_hit' };
  }
  if (MALICIOUS_VERDICTS.includes(input.modelVerdict)) {
    return { store: true, provenance: 'model_malicious', reason: 'model_malicious' };
  }
  return { store: false, reason: 'model_not_malicious' };
}

/**
 * Stamp provenance onto an indicator about to be stored. `sourceVerdict` is
 * the model's verdict, or the security team's ruling.
 */
export function withProvenance(
  indicator: ThreatIndicatorRecord,
  details: {
    provenance: IndicatorProvenance;
    sourceVerdict: string;
    sourceAnalysisId?: string;
  }
): ThreatIndicatorRecord {
  return {
    ...indicator,
    metadata: {
      ...indicator.metadata,
      provenance: details.provenance,
      sourceVerdict: details.sourceVerdict,
      ...(details.sourceAnalysisId ? { sourceAnalysisId: details.sourceAnalysisId } : {}),
      ...(details.provenance === 'security_confirmed' ? { securityConfirmed: true } : {}),
    },
  };
}

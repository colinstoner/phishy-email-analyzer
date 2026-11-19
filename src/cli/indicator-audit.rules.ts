/**
 * Indicator audit: the pure part. Classifies stored indicators with the same
 * strong/weak rule risk fusion uses, tallies them, and decides which match a
 * deactivation rule. No I/O; `indicator-audit.main.ts` does the reading,
 * printing and (with --apply) the updates.
 */

import { ThreatIndicatorRecord } from '../services/intelligence/database.service';
import {
  MatchReason,
  classifyIndicator,
  indicatorProvenance,
  indicatorRole,
  isIndicatorExpired,
} from '../services/intelligence/indicator.policy';

/**
 * Deactivation rules. Each is explicit and checkable from the row alone; a
 * row matching any selected rule is set `is_active = FALSE` (never deleted)
 * and marked with the rule's name so `--restore` can reverse it.
 */
export type DeactivationRule = 'expired' | 'unproven-infrastructure' | 'unproven';

export const DEACTIVATION_RULES: Record<DeactivationRule, string> = {
  expired: 'active, with expires_at in the past',
  'unproven-infrastructure':
    'active, no provenance (not stored from a model-malicious or security-confirmed report), ' +
    'and role infrastructure (redirectors, trackers, relays, IPs, hashes)',
  unproven:
    'active and no provenance, whatever the role (opt-in only: also removes legacy sender/payload indicators)',
};

/** Rules applied when --apply is given without --rule */
export const DEFAULT_RULES: readonly DeactivationRule[] = ['expired', 'unproven-infrastructure'];

export function isDeactivationRule(value: string): value is DeactivationRule {
  return Object.prototype.hasOwnProperty.call(DEACTIVATION_RULES, value);
}

/** The first selected rule an indicator matches, if any (active rows only) */
export function matchingRule(
  indicator: ThreatIndicatorRecord,
  rules: readonly DeactivationRule[],
  now: Date
): DeactivationRule | undefined {
  if (!indicator.isActive) return undefined;
  for (const rule of rules) {
    switch (rule) {
      case 'expired':
        if (isIndicatorExpired(indicator, now)) return rule;
        break;
      case 'unproven-infrastructure':
        if (!indicatorProvenance(indicator) && indicatorRole(indicator) === 'infrastructure') {
          return rule;
        }
        break;
      case 'unproven':
        if (!indicatorProvenance(indicator)) return rule;
        break;
    }
  }
  return undefined;
}

export interface WeakIndicatorRow {
  id?: string;
  type: ThreatIndicatorRecord['indicatorType'];
  role: string;
  timesSeen: number;
  reason: MatchReason;
  value: string;
}

export interface AuditSummary {
  total: number;
  active: number;
  inactive: number;
  /** Active indicators that would count as strong matches */
  strong: number;
  /** Active indicators that would count as weak matches (includes expired) */
  weak: number;
  /** Active indicators past expires_at */
  expired: number;
  weakByReason: Partial<Record<MatchReason, number>>;
  /** Active indicators matching each selected deactivation rule */
  matchedByRule: Partial<Record<DeactivationRule, number>>;
  /** The most-seen weak indicators */
  topWeak: WeakIndicatorRow[];
}

const MAX_VALUE_CHARS = 120;

/** C0/C1 controls, zero-width and bidi-override characters */
function isUnsafeChar(code: number): boolean {
  return (
    code < 0x20 ||
    (code >= 0x7f && code <= 0x9f) ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

function stripUnsafeChars(value: string): string {
  let out = '';
  for (const ch of value) {
    out += isUnsafeChar(ch.codePointAt(0) ?? 0) ? '?' : ch;
  }
  return out;
}

/**
 * Make a stored value safe to print. Values come from hostile email content:
 * strip control and bidi characters (no terminal escape injection), truncate,
 * and mask an email address's local part unless asked not to.
 */
export function displayValue(indicator: ThreatIndicatorRecord, showValues: boolean): string {
  let value = stripUnsafeChars(indicator.indicatorValue);
  if (indicator.indicatorType === 'email' && !showValues) {
    const at = value.lastIndexOf('@');
    value = at >= 0 ? `***${value.substring(at)}` : '***';
  }
  return value.length > MAX_VALUE_CHARS ? `${value.substring(0, MAX_VALUE_CHARS)}...` : value;
}

/**
 * Streaming tally: rows are added a page at a time, so the whole table is
 * never held in memory (only the ids to deactivate and the top-N list).
 */
export class IndicatorAudit {
  private readonly summaryState: AuditSummary = {
    total: 0,
    active: 0,
    inactive: 0,
    strong: 0,
    weak: 0,
    expired: 0,
    weakByReason: {},
    matchedByRule: {},
    topWeak: [],
  };
  private readonly idsByRule = new Map<DeactivationRule, string[]>();

  constructor(
    private readonly options: {
      rules: readonly DeactivationRule[];
      now: Date;
      top: number;
      showValues: boolean;
    }
  ) {}

  add(indicator: ThreatIndicatorRecord): void {
    const s = this.summaryState;
    s.total += 1;
    if (!indicator.isActive) {
      s.inactive += 1;
      return;
    }
    s.active += 1;

    const { strength, reason } = classifyIndicator(indicator, this.options.now);
    if (strength === 'strong') {
      s.strong += 1;
    } else {
      s.weak += 1;
      s.weakByReason[reason] = (s.weakByReason[reason] ?? 0) + 1;
      if (reason === 'expired') s.expired += 1;
      this.considerTop({
        id: indicator.id,
        type: indicator.indicatorType,
        role: indicatorRole(indicator) ?? 'unknown',
        timesSeen: indicator.timesSeen,
        reason,
        value: displayValue(indicator, this.options.showValues),
      });
    }

    const rule = matchingRule(indicator, this.options.rules, this.options.now);
    if (rule) {
      s.matchedByRule[rule] = (s.matchedByRule[rule] ?? 0) + 1;
      if (indicator.id) {
        const ids = this.idsByRule.get(rule) ?? [];
        ids.push(indicator.id);
        this.idsByRule.set(rule, ids);
      }
    }
  }

  summary(): AuditSummary {
    return { ...this.summaryState, topWeak: [...this.summaryState.topWeak] };
  }

  /** Ids to deactivate, grouped by the rule they matched */
  deactivations(): Map<DeactivationRule, string[]> {
    return new Map(this.idsByRule);
  }

  private considerTop(row: WeakIndicatorRow): void {
    const top = this.summaryState.topWeak;
    if (this.options.top <= 0) return;
    if (top.length >= this.options.top && row.timesSeen <= top[top.length - 1].timesSeen) return;
    top.push(row);
    top.sort((a, b) => b.timesSeen - a.timesSeen);
    if (top.length > this.options.top) top.pop();
  }
}

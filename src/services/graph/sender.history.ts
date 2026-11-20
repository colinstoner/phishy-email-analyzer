/**
 * Sender-relationship check (optional; `graph.senderHistory.enabled`).
 *
 * The case it exists for: a known external contact's mailbox is taken over
 * and the attacker mails everyone in its address book. SPF, DKIM and DMARC
 * pass because the account is real; what gives it away is behaviour — the
 * address has a history with the organization, but today's mail goes to far
 * more people than usual, many of whom never dealt with it. The
 * organization's own Exchange message trace holds that history and can be
 * read without opening any mailbox.
 *
 * Rules this file keeps:
 * - Code-driven, read-only, GET-only message trace (CLAUDE.md invariant 6).
 *   The model never sees a query and this is not an agentic tool.
 * - The sender address comes from the suspicious email and is hostile: its
 *   shape is validated before use, it reaches Graph only through
 *   `odataFilter`, and it is never logged (a hash prefix, at debug level).
 * - The result is numbers and an enum. No recipient or sender address
 *   leaves this file. The burst's sending IPs do (capped, shape-checked),
 *   for one consumer only: a report copy addressed to the security team
 *   alone. They never reach the prompt, the reporter or an info-level log.
 * - Rows are trusted only when they match the address that was asked for:
 *   the trace operations verify that, and a mismatch discards the lookup.
 * - Work is bounded: a fixed number of trace windows, a page cap per window,
 *   one overall deadline. A count cut short by a cap is reported as
 *   "at least N", never as exact (invariant 5).
 * - Any failure, timeout or 403 yields `undefined`: analysis proceeds exactly
 *   as it would with the feature off.
 * - A relationship never lowers risk. Nothing here produces a "trusted"
 *   signal; see `risk.fusion.ts` for where that is enforced.
 */

import { createHash } from 'crypto';
import { PhishyConfig } from '../../config/schema';
import {
  BoundedCount,
  ExtractedEmailData,
  SenderBurstIp,
  SenderHistoryFacts,
  SenderRelationshipClass,
} from '../../types';
import { createLogger } from '../../utils/logger';
import {
  emitSenderHistoryMetric,
  SenderHistoryMetric,
  SenderHistoryOutcome,
} from '../../utils/metrics';
import { domainMatches } from '../../utils/validation';
import { GraphClient } from './graph.client';
import { IP_SHAPE, MAX_REPORTED_BURST_IPS } from './graph.limits';
import { createGraphReadClient } from './graph.credential';
import { GraphError } from './graph.errors';
import { BoundedResult } from './operations.common';
import {
  MessageTrace,
  TRACE_MAX_AGE_MS,
  TRACE_MAX_WINDOW_MS,
  TraceOptions,
  TraceWindow,
  assertTraceRowsMatch,
  listMessageTracesByRecipient,
  listMessageTracesBySender,
} from './trace.operations';

const logger = createLogger('sender-history');

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// ── Classification thresholds (documented in docs/CONFIGURATION.md) ─────────

/** History messages from the address that make it `established` on their own */
export const ESTABLISHED_MIN_MESSAGES = 3;
/**
 * With two-way contact (someone in the organization wrote to the address in
 * the history period) this many history messages are enough for `established`
 */
export const ESTABLISHED_MIN_MESSAGES_WITH_TWO_WAY = 1;
/**
 * Anomalous fan-out is judged on the largest group of burst recipients that
 * received the SAME subject, and only for a sender with two-way contact.
 * The common false positives all fail one of those: one email to a project
 * team (too few recipients), a bulk sender nobody ever writes to (no two-way
 * contact), a transactional system sending many different messages in a day
 * (no single subject reaches many people).
 */
/** Messages the organization must have sent to the address in the history period */
export const FANOUT_MIN_TWO_WAY_MESSAGES = 1;
/** Default: fewest distinct recipients of one subject that can count as anomalous fan-out */
export const DEFAULT_FANOUT_MIN_RECIPIENTS = 15;
/** Default: those recipients must be at least this many times the history recipients */
export const DEFAULT_FANOUT_MULTIPLIER = 3;
/** Share of those recipients that must be new to the address */
export const FANOUT_MIN_NEW_RECIPIENT_SHARE = 0.5;

// ── Bounds ─────────────────────────────────────────────────────────────────

/** Rows kept per trace window per query; more than this is reported as "at least" */
export const TRACE_ROWS_PER_WINDOW = 2000;
/** Requests per trace window per query (the service pages at 1000 rows) */
export const TRACE_PAGES_PER_WINDOW = 2;
/**
 * Query types per window: mail from the address, and mail to it. Both filter
 * with `eq`, the only address predicate message trace applies; there is no
 * domain-level query because the service silently ignores `endswith` and
 * `contains` on addresses.
 */
const QUERY_TYPES = 2;
/** Trace requests in flight at once */
const MAX_CONCURRENT_REQUESTS = 6;
/**
 * Trace requests this instance may spend on sender history in any 5 minutes.
 * The tenant's limit is 100 per 5 minutes, shared with every other trace user.
 */
export const REQUEST_ALLOWANCE_PER_5_MIN = 60;
const REQUEST_ALLOWANCE_WINDOW_MS = 5 * 60 * 1000;
/**
 * Message trace can answer 403 intermittently (for hours after its service
 * principal is created, identical requests alternate between 200 and 403),
 * so one 403 says little. A request that gets one is retried this many
 * times, waiting `FORBIDDEN_RETRY_DELAY_MS` x the attempt number in between,
 * inside the lookup's deadline and the instance's request allowance.
 */
export const FORBIDDEN_RETRIES = 3;
export const FORBIDDEN_RETRY_DELAY_MS = 250;
/**
 * When a lookup ends on a 403 and no request in it ever succeeded, the
 * problem is permission or provisioning: the trace API is left alone for
 * this long
 */
export const FORBIDDEN_COOLDOWN_MS = 5 * 60 * 1000;
/** Results are reused per sender address for this long (a campaign produces many reports of one sender) */
export const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_MAX_ENTRIES = 200;
/**
 * The burst window starts `burstWindowHours` before the email's claimed date
 * and always ends now. The claimed date is hostile, so it can only move the
 * start back, and by at most this much.
 */
export const MAX_CLAIMED_AGE_MS = 7 * DAY_MS;
/** Margin inside the service's 90-day horizon */
const TRACE_AGE_MARGIN_MS = HOUR_MS;

export { MAX_REPORTED_BURST_IPS };

const MAX_HEADER_LENGTH = 1000;
const MAX_ADDRESS_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
/** A deliberately narrow, ASCII-only address shape: anything else is not looked up */
const ADDRESS_SHAPE =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const BARE_ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

export interface SenderHistorySettings {
  /** Days of mail-flow records to examine (14-90) */
  lookbackDays: number;
  /** Hours before the email's time that belong to the burst window */
  burstWindowHours: number;
  /** Overall deadline for one lookup */
  budgetMs: number;
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
  /** The organization's own domains: an address on one is not external */
  safeDomains: string[];
  safeSenders: string[];
  /**
   * Trace requests this service may spend in any 5 minutes (default
   * `REQUEST_ALLOWANCE_PER_5_MIN`). The fan-out scan gives its own instance a
   * smaller, separate allowance so it never spends the on-report check's.
   */
  requestAllowancePer5Min?: number;
}

/**
 * The claimed sender address from a forwarded `From:` value, or undefined
 * when there is not exactly one address of an ordinary shape. The value is
 * hostile text; nothing is normalized into shape — it either already is a
 * plain ASCII address or it is not looked up.
 */
export function claimedSenderAddress(headerValue: unknown): string | undefined {
  if (typeof headerValue !== 'string' || headerValue.length > MAX_HEADER_LENGTH) {
    return undefined;
  }

  // `Name <a@b>` and Outlook's `Name <a@b<mailto:a@b>>`: the bracketed
  // address is the real one; a display name may itself look like an address
  const bracketed = Array.from(headerValue.matchAll(/<([^<>\s]+)>/g), match =>
    match[1].replace(/^mailto:/i, '')
  ).filter(candidate => candidate.includes('@'));
  const candidates =
    bracketed.length > 0
      ? bracketed
      : (headerValue.match(BARE_ADDRESS) ?? []).map(candidate => candidate.replace(/\.+$/, ''));

  const distinct = new Set(candidates.map(candidate => candidate.toLowerCase()));
  if (distinct.size !== 1) {
    return undefined;
  }
  const [address] = distinct;
  if (
    address.length > MAX_ADDRESS_LENGTH ||
    address.indexOf('@') > MAX_LOCAL_PART_LENGTH ||
    !ADDRESS_SHAPE.test(address)
  ) {
    return undefined;
  }
  return address;
}

/** True unless the address is on one of the organization's own domains or is a safe sender */
export function isExternalSender(
  address: string,
  safeDomains: string[],
  safeSenders: string[]
): boolean {
  const domain = address.slice(address.indexOf('@') + 1);
  return (
    !safeDomains.some(safe => domainMatches(domain, safe)) &&
    !safeSenders.some(safe => safe.toLowerCase() === address)
  );
}

/**
 * The email's own time as far as it can be believed: the claimed date when
 * it parses and lies within the last `MAX_CLAIMED_AGE_MS`, otherwise now.
 * Only the resulting number is used; the text goes nowhere.
 */
export function resolveEmailTime(claimedDate: unknown, nowMs: number): number {
  if (typeof claimedDate !== 'string' || claimedDate.length > 100) {
    return nowMs;
  }
  const parsed = Date.parse(claimedDate);
  if (!Number.isFinite(parsed)) {
    return nowMs;
  }
  return Math.min(nowMs, Math.max(nowMs - MAX_CLAIMED_AGE_MS, parsed));
}

/** Split `[startMs, endMs]` into windows no wider than one trace query allows, newest first */
export function splitTraceWindows(startMs: number, endMs: number): TraceWindow[] {
  const windows: TraceWindow[] = [];
  for (let to = endMs; to > startMs; to -= TRACE_MAX_WINDOW_MS) {
    windows.push({
      receivedFrom: new Date(Math.max(startMs, to - TRACE_MAX_WINDOW_MS)),
      receivedTo: new Date(to),
    });
  }
  return windows;
}

/** Rows of one query type across all windows, with what a cap cut short */
export interface TraceRows {
  rows: MessageTrace[];
  /** A window that reaches into the history period was cut short */
  historyTruncated: boolean;
  /** A window that reaches into the burst window was cut short */
  burstTruncated: boolean;
}

export interface SenderHistoryInput {
  inbound: TraceRows;
  outbound: TraceRows;
  startMs: number;
  burstStartMs: number;
  nowMs: number;
  lookbackDays: number;
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
  /**
   * Judge fan-out on this one subject group (a `subjectGroupKey`) instead of
   * the widest one in the burst. The fan-out scan sets it: it has already
   * picked the subject, and the rule must be applied to that subject.
   */
  focusSubjectKey?: string;
}

interface PeriodTally {
  messages: Set<string>;
  recipients: Set<string>;
  /** Recipients per normalized subject. The subject is hostile text: a grouping key only */
  recipientsBySubject: Map<string, Set<string>>;
  senders: Set<string>;
  ips: Set<string>;
  firstMs?: number;
}

function emptyTally(): PeriodTally {
  return {
    messages: new Set(),
    recipients: new Set(),
    recipientsBySubject: new Map(),
    senders: new Set(),
    ips: new Set(),
  };
}

/**
 * A subject as a grouping key: trimmed, case-folded, whitespace collapsed.
 * It is hostile text and is used for nothing else — it stays in memory for
 * the length of one computation and is never logged, returned or shown.
 */
export function subjectGroupKey(subject: string | undefined): string {
  return (subject ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * The largest set of recipients that received one subject, and how many of
 * them are absent from `known`. Ties go to the group with more new recipients.
 */
function largestSubjectGroup(
  groups: Map<string, Set<string>>,
  known: Set<string>
): { recipients: number; fresh: number } {
  let best = { recipients: 0, fresh: 0 };
  for (const recipients of groups.values()) {
    let fresh = 0;
    for (const recipient of recipients) {
      if (!known.has(recipient)) {
        fresh++;
      }
    }
    if (
      recipients.size > best.recipients ||
      (recipients.size === best.recipients && fresh > best.fresh)
    ) {
      best = { recipients: recipients.size, fresh };
    }
  }
  return best;
}

/**
 * Tally rows into history and burst periods. One row is one message to one
 * recipient; `expanded` rows are a distribution list being expanded (its
 * members follow as their own rows), so they count as a message but not as a
 * recipient.
 */
function tally(
  rows: MessageTrace[],
  startMs: number,
  burstStartMs: number,
  nowMs: number
): { history: PeriodTally; burst: PeriodTally } {
  const history = emptyTally();
  const burst = emptyTally();
  const seen = new Set<string>();

  for (const row of rows) {
    const at = row.receivedDateTime ? Date.parse(row.receivedDateTime) : NaN;
    if (!Number.isFinite(at) || at < startMs || at > nowMs + 1000) {
      continue;
    }
    const recipient = row.recipientAddress?.toLowerCase() ?? '';
    const messageKey = row.messageId ?? row.id ?? `${row.receivedDateTime}`;
    // Adjacent windows share their boundary second, so a row can arrive twice.
    // A trace row's `id` is NOT unique per recipient: rows for different
    // recipients of one message can share it, so the recipient is always
    // part of the key (keying on `id` alone drops most of a wave's recipients).
    const rowKey = `${row.id ?? messageKey}\n${recipient}\n${row.receivedDateTime}`;
    if (seen.has(rowKey)) {
      continue;
    }
    seen.add(rowKey);

    const period = at >= burstStartMs ? burst : history;
    period.messages.add(messageKey);
    if (recipient && row.status?.toLowerCase() !== 'expanded') {
      period.recipients.add(recipient);
      const subjectKey = subjectGroupKey(row.subject);
      const group = period.recipientsBySubject.get(subjectKey) ?? new Set<string>();
      group.add(recipient);
      period.recipientsBySubject.set(subjectKey, group);
    }
    if (row.senderAddress) {
      period.senders.add(row.senderAddress.toLowerCase());
    }
    if (row.fromIP) {
      period.ips.add(row.fromIP);
    }
    if (period.firstMs === undefined || at < period.firstMs) {
      period.firstMs = at;
    }
  }
  return { history, burst };
}

function bounded(count: number, atLeast: boolean): BoundedCount {
  return { count, atLeast };
}

function utcDate(ms: number | undefined): string | undefined {
  return ms === undefined ? undefined : new Date(ms).toISOString().slice(0, 10);
}

/**
 * Decide the classification from counts. Fan-out is only judged against a
 * complete history (with a truncated one "new recipient" cannot be claimed),
 * only for a sender the organization has written to, and on the recipients
 * of a single subject rather than everything the sender sent in the burst.
 */
export function classifySenderRelationship(input: {
  historyMessages: number;
  historyRecipients: number;
  historyTruncated: boolean;
  twoWayMessages: number;
  /** Most distinct burst recipients that received one subject */
  sameSubjectRecipients: number;
  /** How many of those had no mail from the address in the history period */
  sameSubjectNewRecipients: number | null;
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
}): SenderRelationshipClass {
  if (input.historyMessages === 0 && input.twoWayMessages === 0) {
    return 'no_history';
  }
  const established =
    input.historyMessages >= ESTABLISHED_MIN_MESSAGES ||
    (input.twoWayMessages > 0 && input.historyMessages >= ESTABLISHED_MIN_MESSAGES_WITH_TWO_WAY);
  if (!established) {
    return 'limited_history';
  }
  const anomalous =
    !input.historyTruncated &&
    input.sameSubjectNewRecipients !== null &&
    input.twoWayMessages >= FANOUT_MIN_TWO_WAY_MESSAGES &&
    input.sameSubjectRecipients >= input.fanoutMinRecipients &&
    input.sameSubjectRecipients >= input.fanoutMultiplier * Math.max(input.historyRecipients, 1) &&
    input.sameSubjectNewRecipients >=
      Math.ceil(FANOUT_MIN_NEW_RECIPIENT_SHARE * input.sameSubjectRecipients);
  return anomalous ? 'established_with_anomalous_fanout' : 'established';
}

/**
 * Turn trace rows into the facts. Pure: no I/O, no clock.
 */
export function computeSenderHistoryFacts(input: SenderHistoryInput): SenderHistoryFacts {
  const { startMs, burstStartMs, nowMs } = input;
  const inbound = tally(input.inbound.rows, startMs, burstStartMs, nowMs);
  // Two-way contact is judged on the history period only: replies sent
  // during the burst ("is this real?") are a reaction to it, not a relationship
  const outbound = tally(input.outbound.rows, startMs, burstStartMs, nowMs).history;

  const historyTruncated = input.inbound.historyTruncated;
  const burstTruncated = input.inbound.burstTruncated;

  let newRecipients: BoundedCount | null = null;
  if (!historyTruncated) {
    let fresh = 0;
    for (const recipient of inbound.burst.recipients) {
      if (!inbound.history.recipients.has(recipient)) {
        fresh++;
      }
    }
    newRecipients = bounded(fresh, burstTruncated);
  }

  const subjectGroup = largestSubjectGroup(
    input.focusSubjectKey === undefined
      ? inbound.burst.recipientsBySubject
      : new Map(
          [...inbound.burst.recipientsBySubject].filter(([key]) => key === input.focusSubjectKey)
        ),
    inbound.history.recipients
  );

  let seenIps = 0;
  const reportableIps: SenderBurstIp[] = [];
  for (const ip of inbound.burst.ips) {
    const seenInHistory = inbound.history.ips.has(ip);
    if (seenInHistory) {
      seenIps++;
    }
    if (IP_SHAPE.test(ip)) {
      reportableIps.push({ ip, seenInHistory });
    }
  }
  // Unseen IPs first: they are what the security team will want to look at
  reportableIps.sort(
    (a, b) => Number(a.seenInHistory) - Number(b.seenInHistory) || a.ip.localeCompare(b.ip)
  );
  const burstIps = reportableIps.slice(0, MAX_REPORTED_BURST_IPS);

  const classification = classifySenderRelationship({
    historyMessages: inbound.history.messages.size,
    historyRecipients: inbound.history.recipients.size,
    historyTruncated,
    twoWayMessages: outbound.messages.size,
    sameSubjectRecipients: subjectGroup.recipients,
    sameSubjectNewRecipients: historyTruncated ? null : subjectGroup.fresh,
    fanoutMinRecipients: input.fanoutMinRecipients,
    fanoutMultiplier: input.fanoutMultiplier,
  });

  return {
    classification,
    lookbackDays: input.lookbackDays,
    burstWindowHours: Math.max(1, Math.ceil((nowMs - burstStartMs) / HOUR_MS)),
    history: {
      messages: bounded(inbound.history.messages.size, historyTruncated),
      recipients: bounded(inbound.history.recipients.size, historyTruncated),
      firstSeen: utcDate(inbound.history.firstMs),
    },
    twoWay: {
      messages: bounded(outbound.messages.size, input.outbound.historyTruncated),
      internalSenders: bounded(outbound.senders.size, input.outbound.historyTruncated),
    },
    burst: {
      messages: bounded(inbound.burst.messages.size, burstTruncated),
      recipients: bounded(inbound.burst.recipients.size, burstTruncated),
      newRecipients,
      sameSubject: {
        recipients: bounded(subjectGroup.recipients, burstTruncated),
        newRecipients: historyTruncated ? null : bounded(subjectGroup.fresh, burstTruncated),
      },
    },
    sendingIps: {
      burst: inbound.burst.ips.size,
      seenInHistory: seenIps,
      historyComplete: !historyTruncated,
      ...(burstIps.length > 0 ? { burstIps } : {}),
      ...(inbound.burst.ips.size > burstIps.length
        ? { burstIpsOmitted: inbound.burst.ips.size - burstIps.length }
        : {}),
    },
    truncated: historyTruncated || burstTruncated || input.outbound.historyTruncated,
  };
}

/** Run tasks with at most `limit` in flight; rejects on the first failure */
async function runLimited<T>(tasks: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results = new Array<T>(tasks.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await tasks[index]();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

class BudgetExceededError extends Error {
  constructor() {
    super('sender history lookup exceeded its time budget');
    this.name = 'BudgetExceededError';
  }
}

interface CacheEntry {
  facts: SenderHistoryFacts;
  expiresAt: number;
}

export interface SenderHistoryDeps {
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
  /** Injected for tests; defaults to a timer that ends early when the signal aborts */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

/** What one lookup's trace requests met, for classifying a failure and for the metric */
interface LookupStats {
  /** Trace operations that returned rows */
  succeeded: number;
  /** Retries made after a 403 */
  forbiddenRetries: number;
  /** A query returned rows its address filter did not select */
  filterMismatch?: boolean;
  /** The allowance refused a further page, so a window was cut short */
  allowanceCut?: boolean;
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });
}

/** The two claimed values one lookup reads. Both are hostile text. */
export interface SenderLookupInput {
  /** The forwarded block's `From:` value */
  claimedFrom: unknown;
  /** The forwarded block's date, when it has one */
  claimedDate: unknown;
  /** A tighter deadline than the configured one, when the caller has less time */
  budgetMs?: number;
  /**
   * Judge fan-out on this subject (hostile text, used only as a grouping
   * key) rather than on the widest subject in the burst
   */
  focusSubject?: string;
}

/** One lookup's facts, if any, and the metric line that describes it (not yet emitted) */
export interface SenderLookupResult {
  facts?: SenderHistoryFacts;
  metric: SenderHistoryMetric;
  /**
   * True when the request allowance refused a further page of a window, so
   * the facts (if any) are cut short by the allowance rather than by a row
   * cap. Kept off the metric (and so off the broker's wire format).
   */
  allowanceCut?: boolean;
}

export class SenderHistoryService {
  private readonly cache = new Map<string, CacheEntry>();
  /** Start times of recent trace requests, for the per-instance allowance */
  private requestLog: number[] = [];
  private forbiddenUntil = 0;
  private readonly now: () => number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;

  constructor(
    private readonly client: GraphClient,
    private readonly settings: SenderHistorySettings,
    deps: SenderHistoryDeps = {}
  ) {
    this.now = deps.now ?? Date.now;
    this.sleep = deps.sleep ?? abortableSleep;
  }

  /**
   * Look up the claimed sender of a forwarded email. Never throws: any
   * reason there are no facts is reported as a metric and `undefined`.
   */
  async lookupForEmail(emailData: ExtractedEmailData): Promise<SenderHistoryFacts | undefined> {
    const { facts, metric } = await this.lookupSender(() => ({
      claimedFrom: emailData.forwardedHeaders?.['Original-From'],
      claimedDate:
        emailData.forwardedHeaders?.['Original-Date'] ??
        emailData.forwardedHeaders?.['Original-Sent'],
    }));
    emitSenderHistoryMetric(metric);
    return facts;
  }

  /**
   * The lookup itself, without emitting its metric: the caller does that
   * (the Graph broker hands the metric back to the main function, which
   * emits it once). Never throws.
   */
  async lookupSender(read: () => SenderLookupInput): Promise<SenderLookupResult> {
    try {
      return await this.lookup(read());
    } catch (error) {
      // Nothing below is expected to throw; this keeps a defect here from
      // ever costing the reporter their analysis
      logger.warn('Sender history skipped: unexpected failure', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      return { metric: { outcome: 'error', durationMs: 0 } };
    }
  }

  private async lookup(input: SenderLookupInput): Promise<SenderLookupResult> {
    const startedAt = this.now();
    const stats: LookupStats = { succeeded: 0, forbiddenRetries: 0 };
    const budgetMs = Math.min(this.settings.budgetMs, input.budgetMs ?? Infinity);
    const finish = (
      outcome: SenderHistoryOutcome,
      facts?: SenderHistoryFacts
    ): SenderLookupResult => ({
      facts,
      ...(stats.allowanceCut ? { allowanceCut: true } : {}),
      metric: {
        outcome,
        durationMs: Math.max(0, this.now() - startedAt),
        classification: facts?.classification,
        truncated: facts?.truncated,
        forbiddenRetries: stats.forbiddenRetries,
        filterMismatch: stats.filterMismatch,
      },
    });

    const address = claimedSenderAddress(input.claimedFrom);
    if (!address || !this.isExternal(address)) {
      return finish('skipped');
    }
    const focusSubjectKey =
      input.focusSubject === undefined ? undefined : subjectGroupKey(input.focusSubject);
    const key = createHash('sha256')
      .update(focusSubjectKey === undefined ? address : `${address}\n${focusSubjectKey}`)
      .digest('hex');

    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > startedAt) {
      return finish('cache_hit', cached.facts);
    }
    if (startedAt < this.forbiddenUntil) {
      return finish('cooldown');
    }

    const nowMs = Math.floor(startedAt / 1000) * 1000;
    const lookbackMs = Math.min(
      this.settings.lookbackDays * DAY_MS,
      TRACE_MAX_AGE_MS - TRACE_AGE_MARGIN_MS
    );
    const startMs = nowMs - lookbackMs;
    const emailMs = resolveEmailTime(input.claimedDate, nowMs);
    const burstStartMs = Math.max(startMs, emailMs - this.settings.burstWindowHours * HOUR_MS);
    const windows = splitTraceWindows(startMs, nowMs);

    if (!this.reserveRequests(windows.length * QUERY_TYPES, startedAt)) {
      logger.warn('Sender history skipped: this instance has used its message trace allowance', {
        allowancePer5Min: this.allowance,
      });
      return finish('rate_limited');
    }

    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new BudgetExceededError());
      }, budgetMs);
    });

    try {
      const collected = this.collect(address, windows, {
        burstStartMs,
        nowMs,
        budgetMs,
        signal: controller.signal,
        stats,
      });
      // The deadline wins even if a request ignores cancellation
      collected.catch(() => undefined);
      const rows = await Promise.race([collected, deadline]);

      const facts = computeSenderHistoryFacts({
        ...rows,
        startMs,
        burstStartMs,
        nowMs,
        lookbackDays: Math.round(lookbackMs / DAY_MS),
        fanoutMinRecipients: this.settings.fanoutMinRecipients,
        fanoutMultiplier: this.settings.fanoutMultiplier,
        focusSubjectKey,
      });
      this.remember(key, facts, startedAt);

      logger.info('Sender history computed', {
        classification: facts.classification,
        historyMessages: facts.history.messages.count,
        historyRecipients: facts.history.recipients.count,
        burstRecipients: facts.burst.recipients.count,
        sameSubjectRecipients: facts.burst.sameSubject.recipients.count,
        truncated: facts.truncated,
        windows: windows.length,
        forbiddenRetries: stats.forbiddenRetries,
      });
      logger.debug('Sender history subject', { senderHash: key.slice(0, 12) });
      return finish('ok', facts);
    } catch (error) {
      controller.abort();
      return finish(this.classifyFailure(error, stats, budgetMs));
    } finally {
      clearTimeout(timer);
    }
  }

  /** Trace requests this service has counted in the last 5 minutes */
  requestsUsed(at: number = this.now()): number {
    return this.requestLog.filter(time => time > at - REQUEST_ALLOWANCE_WINDOW_MS).length;
  }

  private get allowance(): number {
    return this.settings.requestAllowancePer5Min ?? REQUEST_ALLOWANCE_PER_5_MIN;
  }

  private isExternal(address: string): boolean {
    return isExternalSender(address, this.settings.safeDomains, this.settings.safeSenders);
  }

  /** Count the lookup against this instance's allowance, or refuse it */
  private reserveRequests(count: number, at: number): boolean {
    this.requestLog = this.requestLog.filter(time => time > at - REQUEST_ALLOWANCE_WINDOW_MS);
    if (this.requestLog.length + count > this.allowance) {
      return false;
    }
    this.noteRequests(count, at);
    return true;
  }

  private noteRequests(count: number, at: number): void {
    for (let i = 0; i < count; i++) {
      this.requestLog.push(at);
    }
  }

  private remember(key: string, facts: SenderHistoryFacts, at: number): void {
    if (this.cache.size >= CACHE_MAX_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) {
        this.cache.delete(oldest);
      }
    }
    this.cache.set(key, { facts, expiresAt: at + CACHE_TTL_MS });
  }

  private async collect(
    address: string,
    windows: TraceWindow[],
    context: {
      burstStartMs: number;
      nowMs: number;
      budgetMs: number;
      signal: AbortSignal;
      stats: LookupStats;
    }
  ): Promise<Pick<SenderHistoryInput, 'inbound' | 'outbound'>> {
    const options: TraceOptions = {
      maxItems: TRACE_ROWS_PER_WINDOW,
      maxPages: TRACE_PAGES_PER_WINDOW,
      timeoutMs: context.budgetMs,
      signal: context.signal,
      now: new Date(context.nowMs),
      // A further page is one more request: it is counted against the
      // allowance before it is made, and refused (the window cut short and
      // reported as truncated) when the allowance has no room for it
      beforeNextPage: (): boolean => {
        if (this.reserveRequests(1, this.now())) {
          return true;
        }
        context.stats.allowanceCut = true;
        return false;
      },
    };
    const empty = (): TraceRows => ({ rows: [], historyTruncated: false, burstTruncated: false });
    const inbound = empty();
    const outbound = empty();

    const into =
      (
        target: TraceRows,
        window: TraceWindow,
        field: 'senderAddress' | 'recipientAddress',
        run: () => Promise<BoundedResult<MessageTrace>>
      ) =>
      async (): Promise<void> => {
        const result = await this.retryingForbidden(run, context.signal, context.stats);
        // Counts are only facts about this sender if every row is about this
        // sender. The operation already rejects rows naming another address;
        // here a row with no address at all is rejected too.
        assertTraceRowsMatch(this.client, result.items, field, address);
        context.stats.succeeded++;
        target.rows.push(...result.items);
        if (result.truncated) {
          target.historyTruncated ||= window.receivedFrom.getTime() < context.burstStartMs;
          target.burstTruncated ||= window.receivedTo.getTime() >= context.burstStartMs;
        }
      };

    const tasks: Array<() => Promise<void>> = [];
    for (const window of windows) {
      tasks.push(
        into(inbound, window, 'senderAddress', () =>
          listMessageTracesBySender(this.client, { ...options, ...window, senderAddress: address })
        ),
        into(outbound, window, 'recipientAddress', () =>
          listMessageTracesByRecipient(this.client, {
            ...options,
            ...window,
            recipientAddress: address,
          })
        )
      );
    }

    await runLimited(tasks, MAX_CONCURRENT_REQUESTS);
    return { inbound, outbound };
  }

  /**
   * Run one trace operation, retrying it when it answers 403. Each retry is
   * one more request against the instance's allowance; when the allowance or
   * the retries run out, or the deadline has passed, the 403 stands.
   */
  private async retryingForbidden<T>(
    run: () => Promise<T>,
    signal: AbortSignal,
    stats: LookupStats
  ): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await run();
      } catch (error) {
        const forbidden = error instanceof GraphError && error.status === 403;
        if (!forbidden || attempt > FORBIDDEN_RETRIES || signal.aborted) {
          throw error;
        }
        await this.sleep(FORBIDDEN_RETRY_DELAY_MS * attempt, signal);
        if (signal.aborted || !this.reserveRequests(1, this.now())) {
          throw error;
        }
        stats.forbiddenRetries++;
      }
    }
  }

  /** Map a failure to a metric outcome and log it without any request data */
  private classifyFailure(
    error: unknown,
    stats: LookupStats,
    budgetMs: number
  ): SenderHistoryOutcome {
    if (error instanceof BudgetExceededError) {
      logger.warn('Sender history skipped: time budget exceeded', { budgetMs });
      return 'timeout';
    }
    if (error instanceof GraphError) {
      if (error.kind === 'filter_not_applied') {
        // The rows are not about this sender at all. Nothing is computed
        // from them: counts from unfiltered mail flow must never be facts.
        stats.filterMismatch = true;
        logger.warn(
          'Sender history discarded: message trace returned rows that do not match the address ' +
            'filter that was sent (the service accepted the filter without applying it)'
        );
        return 'error';
      }
      if (error.status === 403 && stats.succeeded > 0) {
        // Other requests in this lookup worked: the service is flapping, not
        // refusing. No cooldown, so the next report tries again.
        logger.warn('Sender history skipped: message trace kept answering 403 intermittently', {
          code: error.code,
          requestId: error.requestId,
          forbiddenRetries: stats.forbiddenRetries,
        });
        return 'error';
      }
      if (error.status === 403) {
        this.forbiddenUntil = this.now() + FORBIDDEN_COOLDOWN_MS;
        logger.warn(
          'Sender history skipped: message trace returned 403. Check that the read app has ' +
            'ExchangeMessageTrace.Read.All with admin consent and that the message trace service ' +
            'principal exists in the tenant; not retrying for a few minutes',
          { code: error.code, requestId: error.requestId, forbiddenRetries: stats.forbiddenRetries }
        );
        return 'forbidden';
      }
      logger.warn('Sender history skipped: message trace request failed', {
        kind: error.kind,
        status: error.status,
        code: error.code,
        requestId: error.requestId,
      });
      return error.kind === 'timeout' ? 'timeout' : 'error';
    }
    logger.warn('Sender history skipped: lookup failed', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    return 'error';
  }
}

/**
 * Build the service from configuration, or undefined when the feature (or
 * Graph itself) is off. Nothing is fetched until the first lookup.
 */
export function createSenderHistoryService(
  config: Pick<PhishyConfig, 'graph' | 'email'>,
  client?: GraphClient
): SenderHistoryService | undefined {
  const settings = config.graph?.senderHistory;
  if (!settings?.enabled) {
    return undefined;
  }
  if (!config.graph?.enabled) {
    logger.warn('graph.senderHistory.enabled has no effect while graph.enabled is false');
    return undefined;
  }
  const readClient = client ?? createGraphReadClient(config.graph);
  if (!readClient) {
    return undefined;
  }
  return new SenderHistoryService(readClient, {
    lookbackDays: settings.lookbackDays,
    burstWindowHours: settings.burstWindowHours,
    budgetMs: settings.budgetMs,
    fanoutMinRecipients: settings.fanoutMinRecipients,
    fanoutMultiplier: settings.fanoutMultiplier,
    safeDomains: config.email.safeDomains,
    safeSenders: config.email.safeSenders,
  });
}

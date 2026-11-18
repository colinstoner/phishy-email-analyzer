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
 * - The result is numbers and an enum. No recipient address, sender address
 *   or IP leaves this file.
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
  SenderHistoryFacts,
  SenderRelationshipClass,
} from '../../types';
import { createLogger } from '../../utils/logger';
import { emitSenderHistoryMetric, SenderHistoryOutcome } from '../../utils/metrics';
import { domainMatches } from '../../utils/validation';
import { GraphClient } from './graph.client';
import { createGraphReadClient } from './graph.credential';
import { GraphError } from './graph.errors';
import { BoundedResult } from './operations.common';
import {
  MessageTrace,
  TRACE_MAX_AGE_MS,
  TRACE_MAX_WINDOW_MS,
  TraceOptions,
  TraceWindow,
  listMessageTracesByRecipient,
  listMessageTracesBySender,
  listMessageTracesBySenderDomain,
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
/** Default: fewest distinct burst recipients that can count as anomalous fan-out */
export const DEFAULT_FANOUT_MIN_RECIPIENTS = 10;
/** Default: burst recipients must be at least this many times the history recipients */
export const DEFAULT_FANOUT_MULTIPLIER = 3;
/** Share of burst recipients that must be new to the address */
export const FANOUT_MIN_NEW_RECIPIENT_SHARE = 0.5;

// ── Bounds ─────────────────────────────────────────────────────────────────

/** Rows kept per trace window per query; more than this is reported as "at least" */
export const TRACE_ROWS_PER_WINDOW = 2000;
/** Requests per trace window per query (the service pages at 1000 rows) */
export const TRACE_PAGES_PER_WINDOW = 2;
/** Trace requests in flight at once */
const MAX_CONCURRENT_REQUESTS = 6;
/**
 * Trace requests this instance may spend on sender history in any 5 minutes.
 * The tenant's limit is 100 per 5 minutes, shared with every other trace user.
 */
export const REQUEST_ALLOWANCE_PER_5_MIN = 60;
const REQUEST_ALLOWANCE_WINDOW_MS = 5 * 60 * 1000;
/** After a 403 the trace API is left alone for this long */
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

const MAX_HEADER_LENGTH = 1000;
const MAX_ADDRESS_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
/** A deliberately narrow, ASCII-only address shape: anything else is not looked up */
const ADDRESS_SHAPE =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const BARE_ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

/**
 * Mailbox providers anyone can sign up with: a domain-level history for
 * these says nothing about the sender. Extend with
 * `graph.senderHistory.freeMailDomains`.
 */
export const FREE_MAIL_DOMAINS: readonly string[] = [
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'ymail.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
  'gmx.com',
  'mail.com',
  'zoho.com',
  'yandex.com',
];

export interface SenderHistorySettings {
  /** Days of mail-flow records to examine (14-90) */
  lookbackDays: number;
  /** Hours before the email's time that belong to the burst window */
  burstWindowHours: number;
  /** Overall deadline for one lookup */
  budgetMs: number;
  /** Also compute history for the sender's whole domain (never for free-mail domains) */
  includeDomain: boolean;
  /** Extra free-mail domains, on top of `FREE_MAIL_DOMAINS` */
  freeMailDomains: string[];
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
  /** The organization's own domains: an address on one is not external */
  safeDomains: string[];
  safeSenders: string[];
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
  /** Absent when domain-level history was not queried */
  domain?: TraceRows;
  startMs: number;
  burstStartMs: number;
  nowMs: number;
  lookbackDays: number;
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
}

interface PeriodTally {
  messages: Set<string>;
  recipients: Set<string>;
  senders: Set<string>;
  ips: Set<string>;
  firstMs?: number;
}

function emptyTally(): PeriodTally {
  return { messages: new Set(), recipients: new Set(), senders: new Set(), ips: new Set() };
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
    // Adjacent windows share their boundary second, so a row can arrive twice
    const rowKey = row.id ?? `${messageKey}\n${recipient}\n${row.receivedDateTime}`;
    if (seen.has(rowKey)) {
      continue;
    }
    seen.add(rowKey);

    const period = at >= burstStartMs ? burst : history;
    period.messages.add(messageKey);
    if (recipient && row.status?.toLowerCase() !== 'expanded') {
      period.recipients.add(recipient);
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
 * complete history: with a truncated one "new recipient" cannot be claimed.
 */
export function classifySenderRelationship(input: {
  historyMessages: number;
  historyRecipients: number;
  historyTruncated: boolean;
  twoWayMessages: number;
  burstRecipients: number;
  newRecipients: number | null;
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
    input.newRecipients !== null &&
    input.burstRecipients >= input.fanoutMinRecipients &&
    input.burstRecipients >= input.fanoutMultiplier * Math.max(input.historyRecipients, 1) &&
    input.newRecipients >= Math.ceil(FANOUT_MIN_NEW_RECIPIENT_SHARE * input.burstRecipients);
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

  let seenIps = 0;
  for (const ip of inbound.burst.ips) {
    if (inbound.history.ips.has(ip)) {
      seenIps++;
    }
  }

  let domain: SenderHistoryFacts['domain'];
  if (input.domain) {
    const domainHistory = tally(input.domain.rows, startMs, burstStartMs, nowMs).history;
    domain = {
      messages: bounded(domainHistory.messages.size, input.domain.historyTruncated),
      recipients: bounded(domainHistory.recipients.size, input.domain.historyTruncated),
      firstSeen: utcDate(domainHistory.firstMs),
    };
  }

  const classification = classifySenderRelationship({
    historyMessages: inbound.history.messages.size,
    historyRecipients: inbound.history.recipients.size,
    historyTruncated,
    twoWayMessages: outbound.messages.size,
    burstRecipients: inbound.burst.recipients.size,
    newRecipients: newRecipients?.count ?? null,
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
    },
    sendingIps: {
      burst: inbound.burst.ips.size,
      seenInHistory: seenIps,
      historyComplete: !historyTruncated,
    },
    domain,
    truncated:
      historyTruncated ||
      burstTruncated ||
      input.outbound.historyTruncated ||
      (input.domain?.historyTruncated ?? false),
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
}

export class SenderHistoryService {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly freeMail: Set<string>;
  /** Start times of recent trace requests, for the per-instance allowance */
  private requestLog: number[] = [];
  private forbiddenUntil = 0;
  private readonly now: () => number;

  constructor(
    private readonly client: GraphClient,
    private readonly settings: SenderHistorySettings,
    deps: SenderHistoryDeps = {}
  ) {
    this.now = deps.now ?? Date.now;
    this.freeMail = new Set(
      [...FREE_MAIL_DOMAINS, ...settings.freeMailDomains].map(domain => domain.toLowerCase())
    );
  }

  /**
   * Look up the claimed sender of a forwarded email. Never throws: any
   * reason there are no facts is reported as a metric and `undefined`.
   */
  async lookupForEmail(emailData: ExtractedEmailData): Promise<SenderHistoryFacts | undefined> {
    try {
      return await this.lookup(emailData);
    } catch (error) {
      // Nothing below is expected to throw; this keeps a defect here from
      // ever costing the reporter their analysis
      logger.warn('Sender history skipped: unexpected failure', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      emitSenderHistoryMetric({ outcome: 'error', durationMs: 0 });
      return undefined;
    }
  }

  private async lookup(emailData: ExtractedEmailData): Promise<SenderHistoryFacts | undefined> {
    const startedAt = this.now();
    const finish = (
      outcome: SenderHistoryOutcome,
      facts?: SenderHistoryFacts
    ): SenderHistoryFacts | undefined => {
      emitSenderHistoryMetric({
        outcome,
        durationMs: Math.max(0, this.now() - startedAt),
        classification: facts?.classification,
        truncated: facts?.truncated,
      });
      return facts;
    };

    const address = claimedSenderAddress(emailData.forwardedHeaders?.['Original-From']);
    if (!address || !this.isExternal(address)) {
      return finish('skipped');
    }
    const key = createHash('sha256').update(address).digest('hex');

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
    const emailMs = resolveEmailTime(
      emailData.forwardedHeaders?.['Original-Date'] ??
        emailData.forwardedHeaders?.['Original-Sent'],
      nowMs
    );
    const burstStartMs = Math.max(startMs, emailMs - this.settings.burstWindowHours * HOUR_MS);
    const windows = splitTraceWindows(startMs, nowMs);

    const domain = address.slice(address.indexOf('@') + 1);
    const withDomain = this.settings.includeDomain && !this.freeMail.has(domain);
    const queryTypes = withDomain ? 3 : 2;

    if (!this.reserveRequests(windows.length * queryTypes, startedAt)) {
      logger.warn('Sender history skipped: this instance has used its message trace allowance', {
        allowancePer5Min: REQUEST_ALLOWANCE_PER_5_MIN,
      });
      return finish('rate_limited');
    }

    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new BudgetExceededError());
      }, this.settings.budgetMs);
    });

    try {
      const collected = this.collect(address, withDomain ? domain : undefined, windows, {
        burstStartMs,
        nowMs,
        signal: controller.signal,
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
      });
      this.remember(key, facts, startedAt);

      logger.info('Sender history computed', {
        classification: facts.classification,
        historyMessages: facts.history.messages.count,
        historyRecipients: facts.history.recipients.count,
        burstRecipients: facts.burst.recipients.count,
        truncated: facts.truncated,
        windows: windows.length,
        queryTypes,
      });
      logger.debug('Sender history subject', { senderHash: key.slice(0, 12) });
      return finish('ok', facts);
    } catch (error) {
      controller.abort();
      return finish(this.classifyFailure(error));
    } finally {
      clearTimeout(timer);
    }
  }

  private isExternal(address: string): boolean {
    const domain = address.slice(address.indexOf('@') + 1);
    return (
      !this.settings.safeDomains.some(safe => domainMatches(domain, safe)) &&
      !this.settings.safeSenders.some(safe => safe.toLowerCase() === address)
    );
  }

  /** Count the lookup against this instance's allowance, or refuse it */
  private reserveRequests(count: number, at: number): boolean {
    this.requestLog = this.requestLog.filter(time => time > at - REQUEST_ALLOWANCE_WINDOW_MS);
    if (this.requestLog.length + count > REQUEST_ALLOWANCE_PER_5_MIN) {
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
    domain: string | undefined,
    windows: TraceWindow[],
    context: { burstStartMs: number; nowMs: number; signal: AbortSignal }
  ): Promise<Pick<SenderHistoryInput, 'inbound' | 'outbound' | 'domain'>> {
    const options: TraceOptions = {
      maxItems: TRACE_ROWS_PER_WINDOW,
      maxPages: TRACE_PAGES_PER_WINDOW,
      timeoutMs: this.settings.budgetMs,
      signal: context.signal,
      now: new Date(context.nowMs),
    };
    const empty = (): TraceRows => ({ rows: [], historyTruncated: false, burstTruncated: false });
    const inbound = empty();
    const outbound = empty();
    const domainRows = domain === undefined ? undefined : empty();

    const into =
      (target: TraceRows, window: TraceWindow, run: () => Promise<BoundedResult<MessageTrace>>) =>
      async (): Promise<void> => {
        const result = await run();
        target.rows.push(...result.items);
        // A second page was requested when more than one page of rows came back
        if (result.truncated || result.items.length > TRACE_ROWS_PER_WINDOW / 2) {
          this.noteRequests(TRACE_PAGES_PER_WINDOW - 1, this.now());
        }
        if (result.truncated) {
          target.historyTruncated ||= window.receivedFrom.getTime() < context.burstStartMs;
          target.burstTruncated ||= window.receivedTo.getTime() >= context.burstStartMs;
        }
      };

    const tasks: Array<() => Promise<void>> = [];
    for (const window of windows) {
      tasks.push(
        into(inbound, window, () =>
          listMessageTracesBySender(this.client, { ...options, ...window, senderAddress: address })
        ),
        into(outbound, window, () =>
          listMessageTracesByRecipient(this.client, {
            ...options,
            ...window,
            recipientAddress: address,
          })
        )
      );
      if (domainRows && domain !== undefined) {
        tasks.push(
          into(domainRows, window, () =>
            listMessageTracesBySenderDomain(this.client, {
              ...options,
              ...window,
              senderDomain: domain,
            })
          )
        );
      }
    }

    await runLimited(tasks, MAX_CONCURRENT_REQUESTS);
    return { inbound, outbound, domain: domainRows };
  }

  /** Map a failure to a metric outcome and log it without any request data */
  private classifyFailure(error: unknown): SenderHistoryOutcome {
    if (error instanceof BudgetExceededError) {
      logger.warn('Sender history skipped: time budget exceeded', {
        budgetMs: this.settings.budgetMs,
      });
      return 'timeout';
    }
    if (error instanceof GraphError) {
      if (error.status === 403) {
        this.forbiddenUntil = this.now() + FORBIDDEN_COOLDOWN_MS;
        logger.warn(
          'Sender history skipped: message trace returned 403. Check that the read app has ' +
            'ExchangeMessageTrace.Read.All with admin consent and that the message trace service ' +
            'principal exists in the tenant; not retrying for a few minutes',
          { code: error.code, requestId: error.requestId }
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
    includeDomain: settings.includeDomain,
    freeMailDomains: settings.freeMailDomains,
    fanoutMinRecipients: settings.fanoutMinRecipients,
    fanoutMultiplier: settings.fanoutMultiplier,
    safeDomains: config.email.safeDomains,
    safeSenders: config.email.safeSenders,
  });
}

/**
 * Fan-out scan: the sender-relationship rule, run proactively over recent
 * inbound mail flow instead of on one reported email.
 *
 * A taken-over external mailbox typically reaches dozens of the
 * organization's mailboxes within a minute or two; the first employee report
 * arrives minutes later. This scan reads the tenant's Exchange message trace
 * for a short recent window, groups inbound rows by external sender and
 * subject, and for the few groups that reach many internal recipients runs
 * the existing sender-history computation to apply the full rule
 * (`established_with_anomalous_fanout`). It runs where the Graph client is:
 * in the Graph broker (`fanout_scan`) or, in direct mode, in the main
 * function. Deciding what to do with a flag (dedupe, alerting) is the main
 * function's job (`services/hunting/`).
 *
 * Rules this file keeps:
 * - Code-driven, read-only, GET-only (CLAUDE.md invariant 6). No model is
 *   involved anywhere in this feature; nothing here is an agentic tool.
 * - Mail-flow rows are hostile data: addresses and subjects are grouping
 *   keys and are returned only inside a flag, for an email addressed to the
 *   security team alone. Nothing from a row is logged at any level.
 * - Every request is counted. A scan has a request budget (from the caller,
 *   sized from a tenant-wide allowance) and this instance has its own rolling
 *   cap on top; neither touches the on-report check's allowance, which lives
 *   in a different `SenderHistoryService` instance.
 * - Every bound is disclosed: a page cap, a candidate cap, the request
 *   budget, the time budget or a failed history lookup makes the result
 *   `incomplete` with the reasons listed. Nothing is silently truncated.
 * - Never throws.
 */

import { createLogger } from '../../utils/logger';
import { domainMatches } from '../../utils/validation';
import { PhishyConfig } from '../../config/schema';
import { SenderHistoryFacts } from '../../types';
import { GraphClient, GraphPageCursor } from './graph.client';
import { createGraphReadClient } from './graph.credential';
import { GraphError } from './graph.errors';
import { MAX_LISTED_RECIPIENTS, MAX_SUBJECT_LENGTH } from './graph.limits';
import {
  DEFAULT_FANOUT_MIN_RECIPIENTS,
  DEFAULT_FANOUT_MULTIPLIER,
  FORBIDDEN_RETRIES,
  FORBIDDEN_RETRY_DELAY_MS,
  SenderHistoryService,
  claimedSenderAddress,
  subjectGroupKey,
} from './sender.history';
import { MessageTrace, listMessageTracePage } from './trace.operations';

const logger = createLogger('fanout-scan');

const FIVE_MINUTES_MS = 5 * 60 * 1000;

/** Most flags one scan returns (the wire format's bound too) */
export const FANOUT_MAX_FLAGS = 10;
/** Most candidates one scan may check, whatever the caller asks */
export const FANOUT_MAX_CANDIDATES = 10;
/** Most trace pages one scan may read, whatever the caller asks */
export const FANOUT_MAX_PAGES = 10;
/** Widest window one scan accepts */
export const FANOUT_MAX_WINDOW_MS = 2 * 60 * 60 * 1000;
/**
 * Trace requests this instance spends on scans in any 5 minutes, whatever
 * callers ask: a second guard under the caller's tenant-wide allowance, for
 * a caller that is wrong or not the scheduled job
 */
export const FANOUT_INSTANCE_ALLOWANCE_PER_5_MIN = 40;
/** A history lookup is not started with less time than this left */
const MIN_HISTORY_BUDGET_MS = 3000;
/** Longest a single history lookup may take inside a scan */
const MAX_HISTORY_BUDGET_MS = 20_000;

export type FanoutIncompleteReason =
  | 'page_limit' // the window had more rows than the page cap allowed
  | 'page_error' // a page after the first failed; earlier pages were used
  | 'candidate_limit' // more candidates than the cap; the smallest were not checked
  | 'request_allowance' // the request budget ran out before everything was checked
  | 'time_budget' // the time budget ran out before everything was checked
  | 'history_unavailable'; // a candidate's sender-history lookup failed

export const FANOUT_INCOMPLETE_REASONS: readonly FanoutIncompleteReason[] = [
  'page_limit',
  'page_error',
  'candidate_limit',
  'request_allowance',
  'time_budget',
  'history_unavailable',
];

export type FanoutScanOutcome = 'ok' | 'forbidden' | 'timeout' | 'rate_limited' | 'error';

/** Recipient delivery states as the alert counts them */
export interface FanoutStatusCounts {
  delivered: number;
  /** Filtered as spam: in the recipient's Junk Email folder */
  junk: number;
  quarantined: number;
  failed: number;
  other: number;
}

/** One flagged wave. Sender, subject and recipient addresses are hostile mail-flow data. */
export interface FanoutFlag {
  senderAddress: string;
  /** The subject as the first row in the window carried it (cut to 255 characters) */
  subject: string;
  /** First and last row of this wave in the scanned window */
  firstSeen: string;
  lastSeen: string;
  /** Distinct internal recipients of this sender and subject in the window */
  windowRecipients: number;
  /** Distinct messages (Message-IDs) behind them */
  windowMessages: number;
  /** Distinct recipients by their best delivery state (delivered beats junk beats quarantined beats failed) */
  statuses: FanoutStatusCounts;
  /** Up to 100 of the recipients, sorted; the rest are counted */
  recipients: Array<{ address: string; status: keyof FanoutStatusCounts }>;
  recipientsOmitted: number;
  /** The sender-relationship facts that make the wave anomalous */
  facts: SenderHistoryFacts;
}

export interface FanoutScanResult {
  outcome: FanoutScanOutcome;
  /** Every row the trace returned */
  rowsScanned: number;
  /** Rows from an external sender to an internal recipient */
  inboundRows: number;
  pages: number;
  /** Trace requests spent, retries and history lookups included */
  requestsUsed: number;
  forbiddenRetries: number;
  /** The trace returned rows outside the requested window: nothing was used */
  filterMismatch: boolean;
  /** Sender-and-subject groups that reached the recipient minimum in the window */
  candidates: number;
  /** Of those, how many had their sender history checked */
  candidatesChecked: number;
  incomplete: boolean;
  incompleteReasons: FanoutIncompleteReason[];
  flagged: FanoutFlag[];
}

/** What a scan is asked to do. Everything here is operator configuration or code. */
export interface FanoutScanRequest {
  receivedFrom: Date;
  receivedTo: Date;
  /** The organization's own domains: what "internal" means */
  internalDomains: string[];
  maxPages: number;
  maxCandidates: number;
  /** Trace requests this scan may spend in all */
  maxRequests: number;
  budgetMs: number;
}

/** The rule's thresholds and the history period: the sender-relationship check's settings */
export interface FanoutScanSettings {
  lookbackDays: number;
  burstWindowHours: number;
  fanoutMinRecipients: number;
  fanoutMultiplier: number;
}

export interface FanoutScanDeps {
  now?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}

// ── Grouping (pure) ─────────────────────────────────────────────────────────

/** True when the address's domain is (a subdomain of) one of the internal domains */
export function isInternalAddress(address: string, internalDomains: string[]): boolean {
  const at = address.lastIndexOf('@');
  if (at < 1) {
    return false;
  }
  const domain = address.slice(at + 1);
  return internalDomains.some(internal => domainMatches(domain, internal));
}

const STATUS_RANK: Record<keyof FanoutStatusCounts, number> = {
  delivered: 5,
  junk: 4,
  quarantined: 3,
  failed: 2,
  other: 1,
};

/** A trace status word as the alert counts it */
export function statusBucket(status: string | undefined): keyof FanoutStatusCounts {
  switch ((status ?? '').toLowerCase().replace(/\s+/g, '')) {
    case 'delivered':
      return 'delivered';
    case 'filteredasspam':
      return 'junk';
    case 'quarantined':
      return 'quarantined';
    case 'failed':
      return 'failed';
    default:
      return 'other';
  }
}

/** Rows of one external sender and one normalized subject in the window */
export interface FanoutGroup {
  senderAddress: string;
  subjectKey: string;
  subject: string;
  /** Recipient → best delivery state */
  recipients: Map<string, keyof FanoutStatusCounts>;
  messages: Set<string>;
  firstMs: number;
  lastMs: number;
}

/**
 * Group inbound rows (external sender, internal recipient) by sender and
 * normalized subject (`subjectGroupKey`, the same key the sender-history
 * rule groups by). Rows are counted the way the sender-relationship check
 * counts them: an `expanded` row (a distribution list being expanded; its
 * members have rows of their own) is not a recipient; failed, quarantined
 * and junked rows are recipients (they were targeted) and their state is
 * kept for the alert. A row repeated across overlapping pages or windows
 * counts once.
 */
export function groupInboundRows(
  rows: MessageTrace[],
  internalDomains: string[]
): { inboundRows: number; groups: Map<string, FanoutGroup> } {
  const groups = new Map<string, FanoutGroup>();
  const seen = new Set<string>();
  let inboundRows = 0;

  for (const row of rows) {
    const sender = row.senderAddress?.trim().toLowerCase();
    const recipient = row.recipientAddress?.trim().toLowerCase();
    const at = row.receivedDateTime ? Date.parse(row.receivedDateTime) : NaN;
    if (!sender || !recipient || !Number.isFinite(at)) {
      continue;
    }
    if (
      isInternalAddress(sender, internalDomains) ||
      !isInternalAddress(recipient, internalDomains)
    ) {
      continue;
    }
    const rowKey = row.id ?? `${row.messageId ?? ''}\n${recipient}\n${row.receivedDateTime}`;
    if (seen.has(rowKey)) {
      continue;
    }
    seen.add(rowKey);
    inboundRows++;
    if (row.status?.toLowerCase() === 'expanded') {
      continue;
    }

    const subjectKey = subjectGroupKey(row.subject);
    const groupKey = `${sender}\n${subjectKey}`;
    let group = groups.get(groupKey);
    if (!group) {
      group = {
        senderAddress: sender,
        subjectKey,
        subject: (row.subject ?? '').slice(0, MAX_SUBJECT_LENGTH),
        recipients: new Map(),
        messages: new Set(),
        firstMs: at,
        lastMs: at,
      };
      groups.set(groupKey, group);
    } else if (at < group.firstMs) {
      group.firstMs = at;
      group.subject = (row.subject ?? '').slice(0, MAX_SUBJECT_LENGTH);
    }
    group.lastMs = Math.max(group.lastMs, at);
    group.messages.add(row.messageId ?? rowKey);
    const bucket = statusBucket(row.status);
    const previous = group.recipients.get(recipient);
    if (previous === undefined || STATUS_RANK[bucket] > STATUS_RANK[previous]) {
      group.recipients.set(recipient, bucket);
    }
  }
  return { inboundRows, groups };
}

/** Groups that reach the minimum, most recipients first (ties: earliest, then sender) */
export function selectCandidates(
  groups: Map<string, FanoutGroup>,
  minRecipients: number
): FanoutGroup[] {
  return [...groups.values()]
    .filter(group => group.recipients.size >= minRecipients)
    .sort(
      (a, b) =>
        b.recipients.size - a.recipients.size ||
        a.firstMs - b.firstMs ||
        a.senderAddress.localeCompare(b.senderAddress)
    );
}

function toFlag(group: FanoutGroup, facts: SenderHistoryFacts): FanoutFlag {
  const statuses: FanoutStatusCounts = {
    delivered: 0,
    junk: 0,
    quarantined: 0,
    failed: 0,
    other: 0,
  };
  for (const status of group.recipients.values()) {
    statuses[status]++;
  }
  const sorted = [...group.recipients.entries()].sort(([a], [b]) => a.localeCompare(b));
  return {
    senderAddress: group.senderAddress,
    subject: group.subject,
    firstSeen: new Date(group.firstMs).toISOString(),
    lastSeen: new Date(group.lastMs).toISOString(),
    windowRecipients: group.recipients.size,
    windowMessages: group.messages.size,
    statuses,
    recipients: sorted
      .slice(0, MAX_LISTED_RECIPIENTS)
      .map(([address, status]) => ({ address, status })),
    recipientsOmitted: Math.max(0, sorted.length - MAX_LISTED_RECIPIENTS),
    facts,
  };
}

// ── The scan ────────────────────────────────────────────────────────────────

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

class ScanBudget {
  used = 0;
  forbiddenRetries = 0;
  constructor(readonly limit: number) {}
  get remaining(): number {
    return Math.max(0, this.limit - this.used);
  }
  take(): boolean {
    if (this.used >= this.limit) {
      return false;
    }
    this.used++;
    return true;
  }
}

export class FanoutScanService {
  private readonly now: () => number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Start times of this instance's scan requests, for its own rolling cap */
  private requestLog: number[] = [];

  constructor(
    private readonly client: GraphClient,
    private readonly settings: FanoutScanSettings,
    deps: FanoutScanDeps = {}
  ) {
    this.now = deps.now ?? Date.now;
    this.sleep = deps.sleep ?? abortableSleep;
  }

  /** Run one scan. Never throws. */
  async scan(request: FanoutScanRequest): Promise<FanoutScanResult> {
    try {
      return await this.run(request);
    } catch (error) {
      logger.warn('Fan-out scan failed unexpectedly', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      return emptyResult('error');
    }
  }

  private instanceRemaining(at: number): number {
    this.requestLog = this.requestLog.filter(time => time > at - FIVE_MINUTES_MS);
    return Math.max(0, FANOUT_INSTANCE_ALLOWANCE_PER_5_MIN - this.requestLog.length);
  }

  private async run(request: FanoutScanRequest): Promise<FanoutScanResult> {
    const startedAt = this.now();
    const deadline = startedAt + request.budgetMs;
    const budget = new ScanBudget(Math.min(request.maxRequests, this.instanceRemaining(startedAt)));
    if (budget.limit < 1) {
      logger.warn('Fan-out scan skipped: no message trace requests left in this scan allowance', {
        instanceAllowancePer5Min: FANOUT_INSTANCE_ALLOWANCE_PER_5_MIN,
      });
      return emptyResult('rate_limited');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1, request.budgetMs));
    const reasons = new Set<FanoutIncompleteReason>();
    try {
      const pages = await this.readWindow(request, budget, controller.signal, reasons);
      if ('failed' in pages) {
        return {
          ...emptyResult(pages.failed),
          requestsUsed: budget.used,
          forbiddenRetries: budget.forbiddenRetries,
          filterMismatch: pages.filterMismatch,
          pages: pages.pages,
        };
      }

      const minRecipients = this.settings.fanoutMinRecipients;
      const { inboundRows, groups } = groupInboundRows(pages.rows, request.internalDomains);
      const candidates = selectCandidates(groups, minRecipients);
      const maxCandidates = Math.min(request.maxCandidates, FANOUT_MAX_CANDIDATES);
      if (candidates.length > maxCandidates) {
        reasons.add('candidate_limit');
      }

      // A history service for this scan alone: its allowance is what is
      // left of this scan's budget, its cache lasts one scan, and it never
      // spends the on-report check's allowance
      const history = new SenderHistoryService(
        this.client,
        {
          lookbackDays: this.settings.lookbackDays,
          burstWindowHours: this.settings.burstWindowHours,
          budgetMs: MAX_HISTORY_BUDGET_MS,
          fanoutMinRecipients: minRecipients,
          fanoutMultiplier: this.settings.fanoutMultiplier,
          safeDomains: request.internalDomains,
          safeSenders: [],
          requestAllowancePer5Min: budget.remaining,
        },
        { now: this.now, sleep: this.sleep }
      );

      const flagged: FanoutFlag[] = [];
      let checked = 0;
      for (const candidate of candidates.slice(0, maxCandidates)) {
        const left = deadline - this.now();
        if (left < MIN_HISTORY_BUDGET_MS || controller.signal.aborted) {
          reasons.add('time_budget');
          break;
        }
        if (!claimedSenderAddress(candidate.senderAddress)) {
          // Not an address the history check will look up: nothing to judge
          continue;
        }
        const before = history.requestsUsed();
        const { facts, metric } = await history.lookupSender(() => ({
          claimedFrom: candidate.senderAddress,
          claimedDate: new Date(candidate.firstMs).toISOString(),
          budgetMs: Math.min(left, MAX_HISTORY_BUDGET_MS),
          focusSubject: candidate.subject,
        }));
        const spent = Math.max(0, history.requestsUsed() - before);
        budget.used += spent;
        budget.forbiddenRetries += metric.forbiddenRetries ?? 0;
        this.noteRequests(spent);

        if (metric.outcome === 'rate_limited') {
          reasons.add('request_allowance');
          break;
        }
        checked++;
        if (!facts) {
          reasons.add(metric.outcome === 'timeout' ? 'time_budget' : 'history_unavailable');
          continue;
        }
        if (
          facts.classification === 'established_with_anomalous_fanout' &&
          flagged.length < FANOUT_MAX_FLAGS
        ) {
          flagged.push(toFlag(candidate, facts));
        }
      }

      const incompleteReasons = FANOUT_INCOMPLETE_REASONS.filter(reason => reasons.has(reason));
      logger.info('Fan-out scan finished', {
        rowsScanned: pages.rows.length,
        inboundRows,
        pages: pages.pages,
        candidates: candidates.length,
        candidatesChecked: checked,
        flagged: flagged.length,
        requestsUsed: budget.used,
        incompleteReasons,
        durationMs: this.now() - startedAt,
      });
      return {
        outcome: 'ok',
        rowsScanned: pages.rows.length,
        inboundRows,
        pages: pages.pages,
        requestsUsed: budget.used,
        forbiddenRetries: budget.forbiddenRetries,
        filterMismatch: false,
        candidates: candidates.length,
        candidatesChecked: checked,
        incomplete: incompleteReasons.length > 0,
        incompleteReasons,
        flagged,
      };
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }

  private noteRequests(count: number): void {
    const at = this.now();
    for (let i = 0; i < count; i++) {
      this.requestLog.push(at);
    }
  }

  /** Spend one request from the scan budget and this instance's cap, or refuse */
  private takeRequest(budget: ScanBudget): boolean {
    if (this.instanceRemaining(this.now()) < 1 || !budget.take()) {
      return false;
    }
    this.noteRequests(1);
    return true;
  }

  /**
   * Read the window page by page. Each page is one request; a 403 on a page
   * is retried (the service answers 403 intermittently) inside the budgets.
   */
  private async readWindow(
    request: FanoutScanRequest,
    budget: ScanBudget,
    signal: AbortSignal,
    reasons: Set<FanoutIncompleteReason>
  ): Promise<
    | { rows: MessageTrace[]; pages: number }
    | { failed: FanoutScanOutcome; filterMismatch: boolean; pages: number }
  > {
    const rows: MessageTrace[] = [];
    const maxPages = Math.min(request.maxPages, FANOUT_MAX_PAGES);
    let cursor: GraphPageCursor | undefined;
    let pages = 0;

    while (pages < maxPages) {
      if (!this.takeRequest(budget)) {
        if (pages === 0) {
          return { failed: 'rate_limited', filterMismatch: false, pages };
        }
        reasons.add('request_allowance');
        return { rows, pages };
      }
      let page: { items: MessageTrace[]; next?: GraphPageCursor };
      try {
        page = await this.pageWithRetries(request, cursor, budget, signal);
      } catch (error) {
        const failure = this.describeFailure(error, signal);
        if (failure.filterMismatch) {
          // Rows the date filter did not select: none of them is used
          return { failed: 'error', filterMismatch: true, pages };
        }
        if (pages === 0) {
          return { failed: failure.outcome, filterMismatch: false, pages };
        }
        reasons.add(failure.outcome === 'timeout' ? 'time_budget' : 'page_error');
        return { rows, pages };
      }
      pages++;
      rows.push(...page.items);
      if (!page.next) {
        return { rows, pages };
      }
      cursor = page.next;
    }
    reasons.add('page_limit');
    return { rows, pages };
  }

  private async pageWithRetries(
    request: FanoutScanRequest,
    cursor: GraphPageCursor | undefined,
    budget: ScanBudget,
    signal: AbortSignal
  ): Promise<{ items: MessageTrace[]; next?: GraphPageCursor }> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await listMessageTracePage(this.client, {
          receivedFrom: request.receivedFrom,
          receivedTo: request.receivedTo,
          cursor,
          signal,
          now: new Date(this.now()),
        });
      } catch (error) {
        const forbidden = error instanceof GraphError && error.status === 403;
        if (!forbidden || attempt > FORBIDDEN_RETRIES || signal.aborted) {
          throw error;
        }
        await this.sleep(FORBIDDEN_RETRY_DELAY_MS * attempt, signal);
        if (signal.aborted || !this.takeRequest(budget)) {
          throw error;
        }
        budget.forbiddenRetries++;
      }
    }
  }

  private describeFailure(
    error: unknown,
    signal: AbortSignal
  ): { outcome: FanoutScanOutcome; filterMismatch: boolean } {
    if (error instanceof GraphError) {
      if (error.kind === 'filter_not_applied') {
        logger.warn(
          'Fan-out scan discarded: message trace returned rows outside the requested time window ' +
            '(the service accepted the filter without applying it)'
        );
        return { outcome: 'error', filterMismatch: true };
      }
      logger.warn('Fan-out scan: message trace request failed', {
        kind: error.kind,
        status: error.status,
        code: error.code,
        requestId: error.requestId,
      });
      if (error.status === 403) {
        return { outcome: 'forbidden', filterMismatch: false };
      }
      return {
        outcome: error.kind === 'timeout' || signal.aborted ? 'timeout' : 'error',
        filterMismatch: false,
      };
    }
    logger.warn('Fan-out scan: message trace request failed', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    return { outcome: signal.aborted ? 'timeout' : 'error', filterMismatch: false };
  }
}

export function emptyResult(outcome: FanoutScanOutcome): FanoutScanResult {
  return {
    outcome,
    rowsScanned: 0,
    inboundRows: 0,
    pages: 0,
    requestsUsed: 0,
    forbiddenRetries: 0,
    filterMismatch: false,
    candidates: 0,
    candidatesChecked: 0,
    incomplete: false,
    incompleteReasons: [],
    flagged: [],
  };
}

/** The rule's settings from configuration: the sender-relationship check's, or its defaults */
export function fanoutScanSettings(graph: PhishyConfig['graph']): FanoutScanSettings {
  const history = graph?.senderHistory;
  return {
    lookbackDays: history?.lookbackDays ?? 30,
    burstWindowHours: history?.burstWindowHours ?? 24,
    fanoutMinRecipients: history?.fanoutMinRecipients ?? DEFAULT_FANOUT_MIN_RECIPIENTS,
    fanoutMultiplier: history?.fanoutMultiplier ?? DEFAULT_FANOUT_MULTIPLIER,
  };
}

/**
 * Build the scan from configuration where the Graph client lives, or
 * undefined when the feature (or Graph) is off. Nothing is fetched until the
 * first scan.
 */
export function createFanoutScanService(
  graph: PhishyConfig['graph'],
  client?: GraphClient
): FanoutScanService | undefined {
  if (!graph?.fanoutScan?.enabled) {
    return undefined;
  }
  if (!graph.enabled) {
    logger.warn('graph.fanoutScan.enabled has no effect while graph.enabled is false');
    return undefined;
  }
  const readClient = client ?? createGraphReadClient(graph);
  return readClient ? new FanoutScanService(readClient, fanoutScanSettings(graph)) : undefined;
}

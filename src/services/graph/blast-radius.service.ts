/**
 * Blast radius: after a malicious verdict, who else in the organization
 * received the message, and did anyone open or answer it?
 *
 * Code-driven (CLAUDE.md invariant 6). The pipeline calls this after the
 * verdict; it is not an agentic tool, the model never sees its input or its
 * output, and the result goes only into the security team's copy of the
 * report. Read-only: every request is a GET issued through the operations
 * library, so hostile strings (a claimed sender, a subject, a Message-ID)
 * enter a request only through `graphPath` and `odataFilter`.
 *
 * Two routes:
 * 1. Message trace — recipients and delivery status without reading a
 *    mailbox. Then, for the recipients that are readable user mailboxes, the
 *    message's folder, read flag and last verb.
 * 2. Per-mailbox search — when trace is unavailable (commonly HTTP 403) or
 *    returns nothing: the same lookup in each licensed, enabled user mailbox,
 *    up to a mailbox cap.
 *
 * The whole lookup runs under a hard time budget. Whatever was established
 * when the budget ends is reported with its coverage stated; partial
 * coverage is never presented as complete. `lookup` never throws.
 *
 * Only counts, routes and Graph status codes are logged — never an address,
 * a subject or a message ID.
 */

import { createHash } from 'crypto';
import { GraphConfig } from '../../config/schema';
import { ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';
import { emitBlastRadiusMetric } from '../../utils/metrics';
import { DirectoryUser, listUsers } from './directory.operations';
import { GraphClient } from './graph.client';
import { createGraphReadClient } from './graph.credential';
import { GraphAuthError, GraphError } from './graph.errors';
import {
  MessageSummary,
  WellKnownMailFolder,
  findMessagesByInternetMessageId,
  findMessagesBySender,
  getLastVerb,
  getMailFolder,
} from './mail.operations';
import { BoundedResult } from './operations.common';
import {
  MessageTrace,
  addAngleBrackets,
  listMessageTracesByMessageId,
  listMessageTracesBySender,
  stripAngleBrackets,
} from './trace.operations';

const logger = createLogger('blast-radius');

export const BLAST_RADIUS_DEFAULT_TIME_BUDGET_MS = 45_000;
export const BLAST_RADIUS_DEFAULT_MAX_MAILBOXES = 2000;

/** Time kept back for sending the reports after the lookup */
const SEND_RESERVE_MS = 20_000;
/** A lookup with less time than this is not started */
const MIN_BUDGET_MS = 2000;
/** Mailboxes read at once. One request per mailbox at a time in the sweep. */
const DEFAULT_CONCURRENCY = 12;
/** Window either side of the original's claimed date (forwarded dates carry no reliable zone) */
const WINDOW_AROUND_MS = 24 * 60 * 60 * 1000;
/** Window back from now when the forward carries no usable date */
const DEFAULT_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000;
/** Oldest original date believed (message trace reaches back 90 days) */
const MAX_AGE_MS = 88 * 24 * 60 * 60 * 1000;
const MAX_SUBJECT_LENGTH = 255;
const MAX_ADDRESS_LENGTH = 254;
const MAX_COPIES_PER_MAILBOX = 5;
const MAX_DIRECTORY_USERS = 20_000;
const MAX_LISTED_RECIPIENTS = 100;
/** 401/403 answers with no success before the mailbox route is declared refused */
const MAX_AUTH_FAILURES = 5;
const USER_CACHE_TTL_MS = 10 * 60 * 1000;
const RESULT_CACHE_TTL_MS = 10 * 60 * 1000;
const RESULT_CACHE_MAX = 20;

/** Tighter than the client defaults: one slow mailbox must not eat the budget */
const CLIENT_OPTIONS = { timeoutMs: 8000, maxAttempts: 2, maxRetryAfterMs: 10_000 };

const ADDRESS_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/;
const MESSAGE_ID_PATTERN = /^<?[^<>\s@]{1,200}@[^<>\s@]{1,255}>?$/;
const DELIVERY_STATUS_PATTERN = /^[A-Za-z][A-Za-z ]{0,39}$/;
const FORWARD_PREFIX_PATTERN = /^(?:\s*(?:fw|fwd|re)\s*:\s*)+/i;

export type BlastRadiusRoute = 'trace' | 'mailbox';
export type BlastRadiusFolder = 'inbox' | 'junk' | 'deleted' | 'recoverable' | 'other' | 'unknown';
export type BlastRadiusResponse = 'replied' | 'forwarded' | 'none' | 'unknown';

/** One recipient. `address` is a directory or trace address: render it escaped. */
export interface BlastRadiusRecipient {
  address: string;
  /** Delivery status from message trace (trace route only) */
  deliveryStatus?: string;
  /** Whether the recipient's mailbox was read, and whether the message was there */
  mailbox: 'found' | 'not_found' | 'not_checked';
  folder?: BlastRadiusFolder;
  isRead?: boolean;
  response?: BlastRadiusResponse;
  /** Raw PidTagLastVerbExecuted value, kept when it did not map to an action */
  lastVerbCode?: number;
  /** Matching messages in the mailbox (or trace rows), when more than one */
  copies?: number;
}

export interface BlastRadiusCoverage {
  /** Mailboxes actually read */
  mailboxesChecked: number;
  /** Mailboxes that should have been read for full coverage */
  mailboxesEligible: number;
  /** True when the directory listing was cut short, so the real total is higher */
  eligibleIsLowerBound: boolean;
  /** Mailboxes with no match whose Recoverable Items were also searched */
  recoverableChecked: number;
  /** Mailboxes with no match (candidates for the Recoverable Items search) */
  recoverableCandidates: number;
}

/**
 * What the security team is told. Everything under `criteria` and every
 * recipient field that came from Graph is hostile data; `note` and `caveats`
 * are written by this code.
 */
export interface BlastRadiusReport {
  status: 'complete' | 'partial' | 'unavailable';
  /** One line saying why there is no result (status `unavailable` only) */
  note?: string;
  route?: BlastRadiusRoute;
  matchedBy?: 'messageId' | 'senderSubject' | 'sender';
  criteria?: {
    senderAddress?: string;
    subject?: string;
    receivedFrom: string;
    receivedTo: string;
  };
  totals?: { recipients: number; read: number; replied: number; forwarded: number };
  /** Most significant first; at most 100 — `totals.recipients` is the full count */
  recipients?: BlastRadiusRecipient[];
  coverage?: BlastRadiusCoverage;
  caveats?: string[];
  /** ISO time the lookup ran (a cached result keeps its original time) */
  lookedUpAt: string;
  /** The reporter's own address, so their row can be marked */
  reporterAddress?: string;
}

/** How the original message is identified. Every string is hostile. */
export interface BlastRadiusKey {
  /** RFC 5322 Message-ID with angle brackets */
  internetMessageId?: string;
  senderAddress?: string;
  subject?: string;
  receivedFrom: Date;
  receivedTo: Date;
}

function firstAddress(value: string | undefined): string | undefined {
  const match = value?.match(ADDRESS_PATTERN);
  return match && match[0].length <= MAX_ADDRESS_LENGTH ? match[0].toLowerCase() : undefined;
}

/**
 * Work out the best key for the original message from a parsed forward:
 * its Message-ID when the parsed email carries one, otherwise the claimed
 * sender address with the subject and a time window. Returns undefined when
 * neither a Message-ID nor a sender address can be found.
 */
export function deriveBlastRadiusKey(
  emailData: ExtractedEmailData,
  now: Date
): BlastRadiusKey | undefined {
  const forwarded = emailData.forwardedHeaders ?? {};

  const rawId = forwarded['Original-Message-ID']?.trim();
  const internetMessageId =
    rawId && MESSAGE_ID_PATTERN.test(rawId) ? addAngleBrackets(rawId) : undefined;

  const senderAddress = firstAddress(forwarded['Original-From']);
  if (!internetMessageId && !senderAddress) {
    return undefined;
  }

  // The original's own subject when the forward quotes it; otherwise the
  // forward's subject without the prefixes the reporter's client added
  const rawSubject = (
    forwarded['Original-Subject'] ?? (emailData.subject ?? '').replace(FORWARD_PREFIX_PATTERN, '')
  ).trim();
  const subject =
    rawSubject.length > 0 && rawSubject.length <= MAX_SUBJECT_LENGTH ? rawSubject : undefined;

  const nowMs = now.getTime();
  const claimed = Date.parse(forwarded['Original-Date'] ?? forwarded['Original-Sent'] ?? '');
  const usable =
    Number.isFinite(claimed) &&
    claimed <= nowMs + WINDOW_AROUND_MS &&
    claimed >= nowMs - MAX_AGE_MS;

  return {
    internetMessageId,
    senderAddress,
    subject,
    receivedFrom: new Date(usable ? claimed - WINDOW_AROUND_MS : nowMs - DEFAULT_LOOKBACK_MS),
    receivedTo: new Date(usable ? Math.min(claimed + WINDOW_AROUND_MS, nowMs) : nowMs),
  };
}

/**
 * PidTagLastVerbExecuted to a reported action. Only the values the MAPI
 * definition gives (102 reply, 103 reply-all, 104 forward) are reported as
 * an action; an unset property is "none"; anything else is "unknown" and the
 * raw value is kept for the reader.
 */
export function describeLastVerb(code: number | undefined): {
  response: BlastRadiusResponse;
  lastVerbCode?: number;
} {
  if (code === undefined) {
    return { response: 'none' };
  }
  if (code === 102 || code === 103) {
    return { response: 'replied' };
  }
  if (code === 104) {
    return { response: 'forwarded' };
  }
  return { response: 'unknown', lastVerbCode: code };
}

type FailureReason = 'no_key' | 'no_time' | 'timeout' | 'denied' | 'throttled' | 'error';

const FAILURE_NOTES: Record<FailureReason, string> = {
  no_key: 'the original message could not be identified from the forwarded email',
  no_time: 'not enough processing time remained',
  timeout: 'it ran out of time before any result',
  denied: 'Microsoft Graph refused the requests (check the app permissions)',
  throttled: 'Microsoft Graph throttled the requests',
  error: 'the Microsoft Graph requests failed',
};

interface MailboxEntry {
  user: DirectoryUser;
  address: string;
  /** The mailbox was searched (all folders `/messages` covers) */
  checked: boolean;
  /** Recoverable Items was searched too */
  recoverableChecked: boolean;
  hit?: MessageSummary;
  copies: number;
  folder?: BlastRadiusFolder;
  response?: BlastRadiusResponse;
  lastVerbCode?: number;
}

interface TraceRecipient {
  address: string;
  status?: string;
  rows: number;
}

/** Everything a run has established so far; readable at any moment */
interface Progress {
  route?: BlastRadiusRoute;
  traceOutcome: 'pending' | 'rows' | 'empty' | 'failed';
  traceRecipients: TraceRecipient[];
  traceTruncated: boolean;
  entries: MailboxEntry[];
  eligible: number;
  eligibleIsLowerBound: boolean;
  capped: boolean;
  errors: number;
  successes: number;
  authFailures: number;
  stop: boolean;
  denied: boolean;
  throttled: boolean;
  timedOut: boolean;
  deadline: number;
}

export interface BlastRadiusServiceOptions {
  client: GraphClient;
  timeBudgetMs?: number;
  maxMailboxes?: number;
  /** Injected for tests */
  concurrency?: number;
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
}

export interface BlastRadiusLookupOptions {
  /** Milliseconds the Lambda has left; the budget shrinks to fit */
  remainingMs?: number;
  /** The reporter's address, marked in the recipient list */
  reporterAddress?: string;
}

export class BlastRadiusService {
  private readonly client: GraphClient;
  private readonly timeBudgetMs: number;
  private readonly maxMailboxes: number;
  private readonly concurrency: number;
  private readonly now: () => number;
  private users?: { at: number; result: BoundedResult<DirectoryUser> };
  private readonly results = new Map<string, { at: number; report: BlastRadiusReport }>();

  constructor(options: BlastRadiusServiceOptions) {
    this.client = options.client;
    this.timeBudgetMs = options.timeBudgetMs ?? BLAST_RADIUS_DEFAULT_TIME_BUDGET_MS;
    this.maxMailboxes = options.maxMailboxes ?? BLAST_RADIUS_DEFAULT_MAX_MAILBOXES;
    this.concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
    this.now = options.now ?? ((): number => Date.now());
  }

  /**
   * Look up the blast radius of the email a reporter forwarded. Call only
   * for a malicious verdict. Never throws: a failure is a report with status
   * `unavailable` and a one-line note.
   */
  async lookup(
    emailData: ExtractedEmailData,
    options: BlastRadiusLookupOptions = {}
  ): Promise<BlastRadiusReport> {
    const startedAt = this.now();
    let report: BlastRadiusReport;
    let errors = 0;
    let cached = false;

    try {
      const key = deriveBlastRadiusKey(emailData, new Date(startedAt));
      const budgetMs = Math.min(
        this.timeBudgetMs,
        options.remainingMs === undefined ? Infinity : options.remainingMs - SEND_RESERVE_MS
      );
      const cacheKey = key ? this.cacheKey(key) : undefined;
      const hit = cacheKey ? this.results.get(cacheKey) : undefined;

      if (!key) {
        report = this.unavailable('no_key', startedAt);
      } else if (hit && startedAt - hit.at < RESULT_CACHE_TTL_MS) {
        report = hit.report;
        cached = true;
      } else if (budgetMs < MIN_BUDGET_MS) {
        report = this.unavailable('no_time', startedAt);
      } else {
        const progress = this.newProgress(startedAt + budgetMs);
        await this.runWithinBudget(key, progress, budgetMs);
        report = this.buildReport(key, progress, startedAt);
        errors = progress.errors;
        if (cacheKey && report.status !== 'unavailable') {
          this.remember(cacheKey, startedAt, report);
        }
      }
    } catch (error) {
      // Nothing above is expected to throw; if it does the report is unchanged
      logger.error('Blast radius lookup failed unexpectedly', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      report = this.unavailable('error', startedAt);
      errors += 1;
    }

    const coverage = report.coverage;
    const summary = {
      route: report.route ?? ('none' as const),
      outcome: report.status,
      recipientsFound: report.totals?.recipients ?? 0,
      mailboxesChecked: coverage?.mailboxesChecked ?? 0,
      mailboxesEligible: coverage?.mailboxesEligible ?? 0,
      errors,
      durationMs: this.now() - startedAt,
      cached,
    };
    emitBlastRadiusMetric(summary);
    logger.info('Blast radius lookup finished', { ...summary, matchedBy: report.matchedBy });

    return options.reporterAddress
      ? { ...report, reporterAddress: options.reporterAddress.toLowerCase() }
      : report;
  }

  private newProgress(deadline: number): Progress {
    return {
      traceOutcome: 'pending',
      traceRecipients: [],
      traceTruncated: false,
      entries: [],
      eligible: 0,
      eligibleIsLowerBound: false,
      capped: false,
      errors: 0,
      successes: 0,
      authFailures: 0,
      stop: false,
      denied: false,
      throttled: false,
      timedOut: false,
      deadline,
    };
  }

  /**
   * Run the lookup, but stop waiting when the budget ends. Work in flight is
   * abandoned (its own request timeouts end it); `progress` holds whatever
   * was established and is what the report is built from.
   */
  private async runWithinBudget(
    key: BlastRadiusKey,
    progress: Progress,
    budgetMs: number
  ): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const outOfTime = new Promise<'timeout'>(resolve => {
      timer = setTimeout(() => resolve('timeout'), budgetMs);
    });
    const work = this.run(key, progress).then(
      () => 'done' as const,
      (error: unknown) => {
        this.noteFailure(progress, error);
        return 'done' as const;
      }
    );
    try {
      if ((await Promise.race([work, outOfTime])) === 'timeout') {
        progress.timedOut = true;
      }
    } finally {
      progress.stop = true;
      clearTimeout(timer);
    }
  }

  private async run(key: BlastRadiusKey, progress: Progress): Promise<void> {
    // Both routes need the directory; ask for it while the trace runs
    const [traces, users] = await Promise.all([
      this.trace(key, progress),
      this.listDirectory(progress),
    ]);

    if (traces && traces.items.length > 0) {
      this.planTraceRoute(traces, users, progress);
    } else if (users) {
      this.planMailboxRoute(users, progress);
    } else {
      return;
    }

    // 1. Is the message in the mailbox (any folder /messages covers)?
    await this.pool(progress.entries, progress, entry => this.searchMailbox(key, entry, progress));
    // 2. For each mailbox holding it: which folder, and was it answered?
    await this.pool(
      progress.entries.filter(entry => entry.hit),
      progress,
      entry => this.describeHit(entry, progress)
    );
    // 3. /messages does not cover Recoverable Items: look there for the rest
    await this.pool(
      progress.entries.filter(entry => entry.checked && !entry.hit),
      progress,
      entry => this.searchRecoverable(key, entry, progress)
    );
  }

  /** Message trace by the best key. Undefined when the route is unavailable. */
  private async trace(
    key: BlastRadiusKey,
    progress: Progress
  ): Promise<BoundedResult<MessageTrace> | undefined> {
    const window = { receivedFrom: key.receivedFrom, receivedTo: key.receivedTo };
    try {
      let result: BoundedResult<MessageTrace> | undefined;
      if (key.internetMessageId) {
        // Whether the service stores the ID with its angle brackets is not
        // documented, so an empty answer is asked again in the other form
        const bare = stripAngleBrackets(key.internetMessageId);
        result = await listMessageTracesByMessageId(this.client, {
          ...window,
          messageId: key.internetMessageId,
        });
        if (result.items.length === 0 && bare !== key.internetMessageId) {
          result = await listMessageTracesByMessageId(this.client, { ...window, messageId: bare });
        }
      } else if (key.senderAddress) {
        result = await listMessageTracesBySender(this.client, {
          ...window,
          senderAddress: key.senderAddress,
          subject: key.subject,
        });
      }
      progress.traceOutcome = result && result.items.length > 0 ? 'rows' : 'empty';
      return result;
    } catch (error) {
      // Expected in tenants without the message-trace service principal
      // (HTTP 403): not a failure of the lookup, just the cue to fall back
      progress.traceOutcome = 'failed';
      logger.info('Message trace unavailable; falling back to per-mailbox search', {
        status: error instanceof GraphError ? error.status : undefined,
        code: error instanceof GraphError ? error.code : undefined,
      });
      if (error instanceof GraphAuthError) {
        this.noteFailure(progress, error);
      }
      return undefined;
    }
  }

  private async listDirectory(
    progress: Progress
  ): Promise<BoundedResult<DirectoryUser> | undefined> {
    if (this.users && this.now() - this.users.at < USER_CACHE_TTL_MS) {
      return this.users.result;
    }
    try {
      const result = await listUsers(this.client, { maxItems: MAX_DIRECTORY_USERS });
      this.users = { at: this.now(), result };
      return result;
    } catch (error) {
      this.noteFailure(progress, error);
      return undefined;
    }
  }

  private planTraceRoute(
    traces: BoundedResult<MessageTrace>,
    users: BoundedResult<DirectoryUser> | undefined,
    progress: Progress
  ): void {
    const recipients = new Map<string, TraceRecipient>();
    for (const row of traces.items) {
      const address = firstAddress(row.recipientAddress);
      if (!address) {
        continue;
      }
      const known = recipients.get(address);
      if (known) {
        known.rows += 1;
      } else {
        const status =
          row.status && DELIVERY_STATUS_PATTERN.test(row.status) ? row.status : undefined;
        recipients.set(address, { address, status, rows: 1 });
      }
    }

    const byAddress = new Map<string, DirectoryUser>();
    for (const user of users?.items ?? []) {
      for (const address of [user.mail, user.userPrincipalName]) {
        if (address) {
          byAddress.set(address.toLowerCase(), user);
        }
      }
    }

    const seen = new Set<string>();
    const entries: MailboxEntry[] = [];
    for (const recipient of recipients.values()) {
      const user = byAddress.get(recipient.address);
      if (user && !seen.has(user.id)) {
        seen.add(user.id);
        entries.push(newEntry(user, recipient.address));
      }
    }

    progress.route = 'trace';
    progress.traceRecipients = [...recipients.values()];
    progress.traceTruncated = traces.truncated;
    progress.eligible = recipients.size;
    progress.capped = entries.length > this.maxMailboxes;
    progress.entries = entries.slice(0, this.maxMailboxes);
  }

  private planMailboxRoute(users: BoundedResult<DirectoryUser>, progress: Progress): void {
    const eligible = users.items.filter(
      user =>
        user.hasExchangePlan &&
        user.accountEnabled !== false &&
        user.userType !== 'Guest' &&
        (user.mail ?? user.userPrincipalName) !== undefined
    );
    progress.route = 'mailbox';
    progress.eligible = eligible.length;
    progress.eligibleIsLowerBound = users.truncated;
    progress.capped = eligible.length > this.maxMailboxes;
    progress.entries = eligible
      .slice(0, this.maxMailboxes)
      .map(user => newEntry(user, (user.mail ?? user.userPrincipalName ?? '').toLowerCase()));
  }

  /** Run `task` over `items`, a few at a time, until done, stopped or out of time */
  private async pool<T>(
    items: T[],
    progress: Progress,
    task: (item: T) => Promise<void>
  ): Promise<void> {
    let next = 0;
    const worker = async (): Promise<void> => {
      while (!progress.stop && this.now() < progress.deadline && next < items.length) {
        const item = items[next++];
        await task(item);
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.concurrency, items.length) }, worker));
  }

  private find(
    key: BlastRadiusKey,
    mailbox: string,
    folder?: WellKnownMailFolder
  ): Promise<BoundedResult<MessageSummary>> {
    if (key.internetMessageId) {
      return findMessagesByInternetMessageId(this.client, {
        mailbox,
        folder,
        internetMessageId: key.internetMessageId,
        maxItems: MAX_COPIES_PER_MAILBOX,
      });
    }
    return findMessagesBySender(this.client, {
      mailbox,
      folder,
      senderAddress: key.senderAddress ?? '',
      receivedFrom: key.receivedFrom,
      receivedTo: key.receivedTo,
      subject: key.subject,
      maxItems: MAX_COPIES_PER_MAILBOX,
    });
  }

  private async searchMailbox(
    key: BlastRadiusKey,
    entry: MailboxEntry,
    progress: Progress
  ): Promise<void> {
    try {
      const found = await this.find(key, entry.user.id);
      entry.checked = true;
      progress.successes += 1;
      if (found.items.length > 0) {
        entry.hit = found.items[0];
        entry.copies = found.items.length;
      }
    } catch (error) {
      this.noteFailure(progress, error);
    }
  }

  private async describeHit(entry: MailboxEntry, progress: Progress): Promise<void> {
    const mailbox = entry.user.id;
    const folderId = async (folder: WellKnownMailFolder): Promise<string | undefined> => {
      try {
        return (await getMailFolder(this.client, { mailbox, folder })).id;
      } catch (error) {
        this.noteFailure(progress, error);
        return undefined;
      }
    };
    // Three requests at once: within Outlook's four per app per mailbox
    const [inbox, junk, deleted] = await Promise.all([
      folderId('inbox'),
      folderId('junkemail'),
      folderId('deleteditems'),
    ]);

    const parent = entry.hit?.parentFolderId;
    if (parent === undefined) {
      entry.folder = 'unknown';
    } else if (parent === inbox) {
      entry.folder = 'inbox';
    } else if (parent === junk) {
      entry.folder = 'junk';
    } else if (parent === deleted) {
      entry.folder = 'deleted';
    } else {
      // "Elsewhere" only when all three were ruled out
      entry.folder = inbox && junk && deleted ? 'other' : 'unknown';
    }

    await this.readLastVerb(entry, progress);
  }

  private async readLastVerb(entry: MailboxEntry, progress: Progress): Promise<void> {
    if (!entry.hit) {
      return;
    }
    try {
      const verb = await getLastVerb(this.client, {
        mailbox: entry.user.id,
        messageId: entry.hit.id,
      });
      const described = describeLastVerb(verb.code);
      entry.response = described.response;
      entry.lastVerbCode = described.lastVerbCode;
    } catch (error) {
      // Needs Mail.Read; without it the answer is simply not known
      entry.response = 'unknown';
      this.noteFailure(progress, error);
    }
  }

  private async searchRecoverable(
    key: BlastRadiusKey,
    entry: MailboxEntry,
    progress: Progress
  ): Promise<void> {
    try {
      const found = await this.find(key, entry.user.id, 'recoverableitemsdeletions');
      entry.recoverableChecked = true;
      if (found.items.length > 0) {
        entry.hit = found.items[0];
        entry.copies = found.items.length;
        entry.folder = 'recoverable';
        await this.readLastVerb(entry, progress);
      }
    } catch (error) {
      this.noteFailure(progress, error);
    }
  }

  /**
   * Record a failed request and decide whether to go on. Throttling stops
   * the lookup (the client has already honoured `Retry-After` as far as it
   * may); a run of refusals with no success means the permission is missing.
   */
  private noteFailure(progress: Progress, error: unknown): void {
    progress.errors += 1;
    if (error instanceof GraphAuthError) {
      progress.denied = true;
      progress.stop = true;
    } else if (error instanceof GraphError && error.status === 429) {
      progress.throttled = true;
      progress.stop = true;
    } else if (error instanceof GraphError && (error.status === 401 || error.status === 403)) {
      progress.authFailures += 1;
      if (progress.successes === 0 && progress.authFailures >= MAX_AUTH_FAILURES) {
        progress.denied = true;
        progress.stop = true;
      }
    }
  }

  private unavailable(reason: FailureReason, at: number): BlastRadiusReport {
    return {
      status: 'unavailable',
      note: `Blast radius lookup could not be completed: ${FAILURE_NOTES[reason]}.`,
      lookedUpAt: new Date(at).toISOString(),
    };
  }

  private failureReason(progress: Progress): FailureReason {
    if (progress.denied) {
      return 'denied';
    }
    if (progress.throttled) {
      return 'throttled';
    }
    return progress.timedOut ? 'timeout' : 'error';
  }

  private buildReport(
    key: BlastRadiusKey,
    progress: Progress,
    startedAt: number
  ): BlastRadiusReport {
    const entries = progress.entries;
    const checked = entries.filter(entry => entry.checked);
    // The mailbox route has an answer only if at least one mailbox was read;
    // the trace route's recipient list stands on its own
    if (!progress.route || (progress.route === 'mailbox' && checked.length === 0)) {
      return this.unavailable(this.failureReason(progress), startedAt);
    }

    const toRecipient = (entry: MailboxEntry): BlastRadiusRecipient => ({
      address: entry.address,
      mailbox: !entry.checked ? 'not_checked' : entry.hit ? 'found' : 'not_found',
      folder: entry.hit ? (entry.folder ?? 'unknown') : undefined,
      isRead: entry.hit?.isRead,
      response: entry.hit ? (entry.response ?? 'unknown') : undefined,
      lastVerbCode: entry.lastVerbCode,
      copies: entry.copies > 1 ? entry.copies : undefined,
    });

    let recipients: BlastRadiusRecipient[];
    if (progress.route === 'trace') {
      const byAddress = new Map(entries.map(entry => [entry.address, entry]));
      recipients = progress.traceRecipients.map(traced => {
        const entry = byAddress.get(traced.address);
        const base: BlastRadiusRecipient = entry
          ? toRecipient(entry)
          : { address: traced.address, mailbox: 'not_checked' };
        return {
          ...base,
          deliveryStatus: traced.status,
          copies: base.copies ?? (traced.rows > 1 ? traced.rows : undefined),
        };
      });
    } else {
      recipients = entries.filter(entry => entry.hit).map(toRecipient);
    }

    const recoverableCandidates = checked.filter(
      entry => !entry.hit || entry.folder === 'recoverable'
    );
    const coverage: BlastRadiusCoverage = {
      mailboxesChecked: checked.length,
      mailboxesEligible: progress.eligible,
      eligibleIsLowerBound: progress.eligibleIsLowerBound,
      recoverableChecked: recoverableCandidates.filter(entry => entry.recoverableChecked).length,
      recoverableCandidates: recoverableCandidates.length,
    };

    const partial =
      coverage.mailboxesChecked < coverage.mailboxesEligible ||
      coverage.recoverableChecked < coverage.recoverableCandidates ||
      coverage.eligibleIsLowerBound ||
      progress.traceTruncated ||
      progress.timedOut ||
      progress.throttled;

    const matchedBy = key.internetMessageId
      ? 'messageId'
      : key.subject
        ? 'senderSubject'
        : 'sender';

    return {
      status: partial ? 'partial' : 'complete',
      route: progress.route,
      matchedBy,
      criteria: {
        senderAddress: key.senderAddress,
        subject: key.subject,
        receivedFrom: key.receivedFrom.toISOString(),
        receivedTo: key.receivedTo.toISOString(),
      },
      totals: {
        recipients: recipients.length,
        read: recipients.filter(recipient => recipient.isRead === true).length,
        replied: recipients.filter(recipient => recipient.response === 'replied').length,
        forwarded: recipients.filter(recipient => recipient.response === 'forwarded').length,
      },
      recipients: [...recipients]
        .sort((a, b) => significance(a) - significance(b))
        .slice(0, MAX_LISTED_RECIPIENTS),
      coverage,
      caveats: this.caveats(progress, coverage, matchedBy),
      lookedUpAt: new Date(startedAt).toISOString(),
    };
  }

  /** Plain statements of what the result does and does not cover */
  private caveats(
    progress: Progress,
    coverage: BlastRadiusCoverage,
    matchedBy: NonNullable<BlastRadiusReport['matchedBy']>
  ): string[] {
    const caveats: string[] = [];
    if (progress.route === 'trace') {
      caveats.push(
        'Recipients come from Exchange message trace (delivery records). Mailbox details are shown only for recipients that are user mailboxes; groups, shared mailboxes and aliases show delivery status only.'
      );
      if (progress.traceTruncated) {
        caveats.push(
          'Message trace returned more rows than the limit: the recipient list is incomplete.'
        );
      }
    } else {
      caveats.push(
        progress.traceOutcome === 'empty'
          ? 'Message trace returned no rows, so mailboxes were searched directly.'
          : 'Message trace was not available, so mailboxes were searched directly.'
      );
      caveats.push(
        'Only licensed, enabled user mailboxes are searched: shared mailboxes, unlicensed and disabled accounts are not covered.'
      );
    }
    if (progress.capped) {
      caveats.push(`The mailbox cap (${this.maxMailboxes}) was reached.`);
    }
    if (coverage.eligibleIsLowerBound) {
      caveats.push('The directory listing was cut short: the organization has more mailboxes.');
    }
    if (progress.timedOut) {
      caveats.push('The lookup stopped at its time budget.');
    }
    if (progress.throttled) {
      caveats.push('The lookup stopped early because Microsoft Graph throttled it.');
    }
    if (progress.denied) {
      caveats.push('Microsoft Graph refused mailbox requests (check the app permissions).');
    }
    if (coverage.recoverableChecked < coverage.recoverableCandidates) {
      caveats.push(
        `Recoverable Items (mail a user deleted and purged) was searched in ${coverage.recoverableChecked} of ${coverage.recoverableCandidates} mailboxes without a match elsewhere.`
      );
    }
    if (matchedBy === 'messageId') {
      caveats.push(
        'Matched on the Message-ID: only copies of this exact message are listed, not other messages from the same campaign.'
      );
    } else if (matchedBy === 'sender') {
      caveats.push(
        'No usable subject was available: every message from the sender in the time window is counted.'
      );
    }
    if (progress.errors > 0) {
      caveats.push(`${progress.errors} Microsoft Graph request(s) failed during the lookup.`);
    }
    return caveats;
  }

  private cacheKey(key: BlastRadiusKey): string {
    // The window is left out when it merely tracks "now", so repeat reports
    // of one message share an entry
    const identity = key.internetMessageId
      ? ['id', key.internetMessageId]
      : ['sender', key.senderAddress, key.subject, key.receivedFrom.toISOString().slice(0, 10)];
    return createHash('sha256').update(JSON.stringify(identity)).digest('hex');
  }

  private remember(cacheKey: string, at: number, report: BlastRadiusReport): void {
    for (const [existing, value] of this.results) {
      if (at - value.at >= RESULT_CACHE_TTL_MS || this.results.size >= RESULT_CACHE_MAX) {
        this.results.delete(existing);
      }
    }
    this.results.set(cacheKey, { at, report });
  }
}

function newEntry(user: DirectoryUser, address: string): MailboxEntry {
  return { user, address, checked: false, recoverableChecked: false, copies: 0 };
}

/** Sort order for the listing: the recipients needing attention first */
function significance(recipient: BlastRadiusRecipient): number {
  if (recipient.response === 'replied') {
    return 0;
  }
  if (recipient.response === 'forwarded') {
    return 1;
  }
  if (recipient.isRead === true) {
    return 2;
  }
  return recipient.mailbox === 'found' ? 3 : 4;
}

/**
 * Build the service from configuration, or undefined unless both
 * `graph.enabled` and `graph.blastRadius.enabled` are set. Nothing is
 * fetched until the first lookup.
 */
export function createBlastRadiusService(
  config: GraphConfig | undefined
): BlastRadiusService | undefined {
  if (!config?.enabled || !config.blastRadius?.enabled) {
    return undefined;
  }
  const client = createGraphReadClient(config, { clientOptions: CLIENT_OPTIONS });
  if (!client) {
    return undefined;
  }
  return new BlastRadiusService({
    client,
    timeBudgetMs: config.blastRadius.timeBudgetMs,
    maxMailboxes: config.blastRadius.maxMailboxes,
  });
}

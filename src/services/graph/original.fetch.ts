/**
 * Original-message fetch: find the original of a forwarded email in the
 * reporter's own mailbox and read its Internet headers.
 *
 * A forward destroys the original's headers; all Phishy otherwise sees is
 * what the mail client pasted into the forwarded block. This lookup reads
 * the real ones from the stored copy. It is code-driven (CLAUDE.md
 * invariant 6): it runs in the pipeline before analysis, the model has no
 * part in it, and every request goes through the read-only operations in
 * `mail.operations.ts`.
 *
 * - **Whose mailbox:** only the one `confirmedReporterMailbox` returns —
 *   never an address taken from email content.
 * - **Which message:** the claimed sender, sent time and subject from the
 *   forwarded block. All three are hostile strings; they enter a request
 *   only as escaped `$filter` literals.
 * - **Matching rule:** exactly one message, counted across the mailbox and
 *   its Recoverable Items, may match. Zero or several: no enrichment.
 * - **Failure:** nothing here throws. Every outcome other than `found`
 *   leaves the pipeline exactly as it is without this feature. A mailbox
 *   Graph does not know (a plus-address or an alias that is not the
 *   mailbox's own name) is `not_found` / `mailbox_not_found`; a plus-address
 *   is retried once without its `+tag` (`enrichWithOriginalVia`).
 *
 * Read-only: GET requests only. What it returns is hostile data.
 */

import {
  EmailMessage,
  ExtractedEmailData,
  RetrievedOriginal,
  RetrievedOriginalIdentity,
} from '../../types';
import { createLogger } from '../../utils/logger';
import { OriginalFetchOutcome, emitOriginalFetchMetric } from '../../utils/metrics';
import { domainMatches, extractEmailAddress } from '../../utils/validation';
import { GraphClient } from './graph.client';
import {
  GRAPH_ITEM_ID_PATTERN,
  MAX_ADDRESS_LENGTH,
  MAX_CLAIMED_TIME_LENGTH,
  MAX_SUBJECT_LENGTH,
  MESSAGE_ID_PATTERN,
} from './graph.limits';
import { GraphAuthError, GraphError } from './graph.errors';
import {
  MessageSummary,
  findMessagesByInternetMessageId,
  findMessagesBySender,
  getMessageHeaders,
} from './mail.operations';

const logger = createLogger('graph-original-fetch');

/** Total time one lookup may add to the pipeline; the reporter is waiting */
export const ORIGINAL_FETCH_BUDGET_MS = 8000;

/**
 * Client bounds for the pipeline: one lookup is three requests and must fit
 * the budget above, so attempts are short and retried at most once.
 */
export const ORIGINAL_FETCH_CLIENT_OPTIONS = {
  timeoutMs: 4000,
  maxAttempts: 2,
  maxRetryAfterMs: 1000,
  baseDelayMs: 250,
} as const;
export const ORIGINAL_FETCH_TOKEN_OPTIONS = { timeoutMs: 4000, maxAttempts: 1 } as const;

const HOUR_MS = 60 * 60 * 1000;
/** Allowance for delivery delay and clock skew between claimed sent time and receipt */
const DELIVERY_SLACK_MS = 3 * HOUR_MS;
/** UTC offsets run from -12:00 to +14:00 */
const MAX_OFFSET_WEST_MS = 12 * HOUR_MS;
const MAX_OFFSET_EAST_MS = 14 * HOUR_MS;
/** Two per location is enough to tell "exactly one" from "more than one" */
const CANDIDATES_PER_LOCATION = 2;
/** Least budget left for which the plus-address retry is still attempted */
const MIN_RETRY_BUDGET_MS = 2000;

/**
 * Graph error codes, on HTTP 404, that mean the mailbox in the path does not
 * exist (or has no Exchange mailbox), as opposed to a missing message or
 * folder (`ErrorItemNotFound`), which stays an error.
 */
const MAILBOX_NOT_FOUND_CODES = new Set([
  'ErrorInvalidUser',
  'ErrorNonExistentMailbox',
  'MailboxNotEnabledForRESTAPI',
  'ResourceNotFound',
  'Request_ResourceNotFound',
]);

/** Fixed reason word for a mailbox Graph does not know */
export const MAILBOX_NOT_FOUND_REASON = 'mailbox_not_found';

function isMailboxNotFound(error: unknown): boolean {
  return (
    error instanceof GraphError &&
    error.kind === 'http' &&
    error.status === 404 &&
    MAILBOX_NOT_FOUND_CODES.has(error.code ?? '')
  );
}

const MONTH_NAMES = [
  'january',
  'february',
  'march',
  'april',
  'may',
  'june',
  'july',
  'august',
  'september',
  'october',
  'november',
  'december',
];

/** A sent time read from a forwarded block */
export interface ClaimedSentTime {
  /** The instant, or the wall-clock time read as UTC when `zoneKnown` is false */
  instant: Date;
  /** False when the text carried no usable UTC offset (the usual case) */
  zoneKnown: boolean;
}

function monthIndex(word: string): number {
  const lower = word.toLowerCase();
  return MONTH_NAMES.findIndex(
    month =>
      month === lower || month.slice(0, 3) === lower || (lower === 'sept' && month[0] === 's')
  );
}

function findNamedDate(text: string): { year: number; month: number; day: number } | undefined {
  // "November 16, 2026" / "Nov 16, 2026"
  for (const match of text.matchAll(
    /([A-Za-z]{3,9})\.? (\d{1,2})(?:st|nd|rd|th)?,? (\d{4})(?!\d)/g
  )) {
    const month = monthIndex(match[1]);
    if (month >= 0) {
      return { year: Number(match[3]), month, day: Number(match[2]) };
    }
  }
  // "16 November 2026" / "16 Nov 2026"
  for (const match of text.matchAll(
    /(?<!\d)(\d{1,2})(?:st|nd|rd|th)? ([A-Za-z]{3,9})\.?,? (\d{4})(?!\d)/g
  )) {
    const month = monthIndex(match[2]);
    if (month >= 0) {
      return { year: Number(match[3]), month, day: Number(match[1]) };
    }
  }
  return undefined;
}

/**
 * Read the sent time a mail client wrote into a forwarded block
 * ("Monday, November 16, 2026 8:00 AM", "Mon, Nov 16, 2026 at 8:00 AM",
 * "Mon, 16 Nov 2026 08:00:00 +0000", ISO 8601). The month must be spelled
 * out in English or the date be ISO: all-numeric dates are ambiguous between
 * day-first and month-first and are refused, as is anything else this does
 * not recognize. Zone abbreviations other than GMT/UTC/Z are ignored (they
 * are ambiguous), which leaves the zone unknown.
 *
 * The input is hostile text; it is only ever matched, never evaluated.
 */
export function parseClaimedSentTime(raw: string): ClaimedSentTime | undefined {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_CLAIMED_TIME_LENGTH) {
    return undefined;
  }
  const text = raw.normalize('NFKC').replace(/\s+/g, ' ').trim();

  const iso = /^(\d{4})-(\d{2})-(\d{2})(?=[T ])/.exec(text);
  const date = iso
    ? { year: Number(iso[1]), month: Number(iso[2]) - 1, day: Number(iso[3]) }
    : findNamedDate(text);
  if (!date || date.year < 2000 || date.year > 2100) {
    return undefined;
  }

  const time = /(?<!\d)(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s?([ap])\.?m\.?(?![a-z]))?/i.exec(text);
  if (!time) {
    return undefined;
  }
  let hour = Number(time[1]);
  const minute = Number(time[2]);
  const second = time[3] === undefined ? 0 : Number(time[3]);
  const meridiem = time[4]?.toLowerCase();
  if (meridiem !== undefined) {
    if (hour < 1 || hour > 12) {
      return undefined;
    }
    hour = (hour % 12) + (meridiem === 'p' ? 12 : 0);
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }

  const wallClock = Date.UTC(date.year, date.month, date.day, hour, minute, second);
  const check = new Date(wallClock);
  if (check.getUTCMonth() !== date.month || check.getUTCDate() !== date.day) {
    return undefined; // e.g. February 30
  }

  const afterTime = text.slice(time.index + time[0].length);
  const offset = /^(?:\.\d+)?\s*\(?(?:GMT|UTC)?\s?([+-])(\d{2}):?(\d{2})(?!\d)/i.exec(afterTime);
  if (offset) {
    const offsetMs = (Number(offset[2]) * 60 + Number(offset[3])) * 60 * 1000;
    if (Number(offset[3]) > 59 || offsetMs > MAX_OFFSET_EAST_MS) {
      return undefined;
    }
    const sign = offset[1] === '-' ? -1 : 1;
    return { instant: new Date(wallClock - sign * offsetMs), zoneKnown: true };
  }
  if (/^(?:\.\d+)?\s*\(?(?:GMT|UTC|Z)(?![A-Za-z])/i.test(afterTime)) {
    return { instant: check, zoneKnown: true };
  }
  return { instant: check, zoneKnown: false };
}

/**
 * The `receivedDateTime` window to search for a claimed sent time. With a
 * known zone it is the instant plus or minus delivery slack. Without one
 * (mail clients print the reporter's local time and no offset) the wall
 * clock could be any zone from UTC-12 to UTC+14, so the window widens to
 * cover them all. A wide window cannot produce a wrong match — the rule is
 * still "exactly one" — only more ambiguous outcomes.
 */
export function searchWindow(claimed: ClaimedSentTime): { from: Date; to: Date } {
  const at = claimed.instant.getTime();
  const before = DELIVERY_SLACK_MS + (claimed.zoneKnown ? 0 : MAX_OFFSET_EAST_MS);
  const after = DELIVERY_SLACK_MS + (claimed.zoneKnown ? 0 : MAX_OFFSET_WEST_MS);
  return { from: new Date(at - before), to: new Date(at + after) };
}

/** The claimed sender's address in its original letter case, or undefined */
function claimedSenderAddress(raw: string | undefined): string | undefined {
  const lower = extractEmailAddress(raw ?? '');
  if (!lower || raw === undefined) {
    return undefined;
  }
  const at = raw.toLowerCase().indexOf(lower);
  return at >= 0 && raw.toLowerCase().length === raw.length
    ? raw.slice(at, at + lower.length)
    : lower;
}

function sameSubject(a: string, b: string): boolean {
  const normalize = (value: string): string =>
    value.normalize('NFKC').replace(/\s+/g, ' ').trim().toLowerCase();
  return normalize(a) === normalize(b);
}

/**
 * The mailbox a lookup may read: the reporter's own, and only when the
 * report demonstrably came from them. `originalForwarder` must be an
 * address on a safe domain (invariant 4), must be the address in the
 * report's own From header (so the weaker sources `originalForwarder` can
 * fall back to — `X-Forwarded-For`, the To line — never choose a mailbox),
 * and the report must have passed SPF or DKIM at SES (the bar the command
 * channel uses). Reports that arrive without SES verdicts, such as API
 * payloads, therefore never trigger a mailbox read.
 */
export function confirmedReporterMailbox(
  msg: EmailMessage,
  emailData: ExtractedEmailData,
  safeDomains: string[]
): string | undefined {
  const forwarder = extractEmailAddress(emailData.originalForwarder);
  if (!forwarder) {
    return undefined;
  }
  const domain = forwarder.split('@')[1] ?? '';
  if (!safeDomains.some(safeDomain => domainMatches(domain, safeDomain))) {
    return undefined;
  }
  if (extractEmailAddress(emailData.headers.From ?? '') !== forwarder) {
    return undefined;
  }
  const spf = msg.authVerdicts?.spf?.toUpperCase();
  const dkim = msg.authVerdicts?.dkim?.toUpperCase();
  if (spf !== 'PASS' && dkim !== 'PASS') {
    return undefined;
  }
  return forwarder;
}

export interface OriginalFetchRequest {
  /** The reporter's mailbox, from `confirmedReporterMailbox` */
  mailbox: string;
  /** Claimed From line of the forwarded block (hostile) */
  claimedFrom?: string;
  /** Claimed Sent/Date line of the forwarded block (hostile) */
  claimedSent?: string;
  /** Claimed Subject line of the forwarded block (hostile) */
  claimedSubject?: string;
}

export interface OriginalFetchOptions {
  /** Overall time budget (default `ORIGINAL_FETCH_BUDGET_MS`) */
  budgetMs?: number;
}

export interface OriginalFetchResult {
  outcome: OriginalFetchOutcome;
  /** Fixed, code-chosen word for logs; never derived from email content */
  reason: string;
  /** Present only when `outcome` is `found` */
  original?: RetrievedOriginal;
}

class BudgetExceededError extends Error {}

function withBudget<T>(work: Promise<T>, budgetMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new BudgetExceededError()), budgetMs);
    work.then(
      value => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error('original fetch failed'));
      }
    );
  });
}

interface Criteria {
  mailbox: string;
  senderAddress: string;
  window: { from: Date; to: Date };
  subject?: string;
}

/** Re-check in code what the `$filter` asked for; a response is not trusted to have honoured it */
function satisfies(candidate: MessageSummary, criteria: Criteria): boolean {
  if (candidate.fromAddress?.toLowerCase() !== criteria.senderAddress.toLowerCase()) {
    return false;
  }
  const received = Date.parse(candidate.receivedDateTime ?? '');
  if (
    Number.isNaN(received) ||
    received < criteria.window.from.getTime() ||
    received >= criteria.window.to.getTime()
  ) {
    return false;
  }
  return criteria.subject === undefined || sameSubject(candidate.subject ?? '', criteria.subject);
}

/** Time kept back from the lookup's budget when the uniqueness search runs */
const UNIQUENESS_RESERVE_MS = 500;
/** Shortest time worth giving the uniqueness search; less and it is `unknown` */
const UNIQUENESS_MIN_MS = 1000;

/**
 * How many messages with this Internet Message-ID the reporter's mailbox
 * holds, across the normal store (`/messages`) and Recoverable Items: `1`,
 * `2+`, or `unknown` when the search failed, did not fit the remaining
 * budget, or (inconsistently) found none. A sender chooses the Message-ID,
 * so a live removal's anchor needs exactly one. Never throws and never
 * delays the lookup past its budget: what does not fit is `unknown`.
 */
async function countByMessageId(
  client: GraphClient,
  mailbox: string,
  internetMessageId: string,
  remainingMs: () => number
): Promise<'1' | '2+' | 'unknown'> {
  const available = remainingMs() - UNIQUENESS_RESERVE_MS;
  if (available < UNIQUENESS_MIN_MS) {
    return 'unknown';
  }
  const search = async (): Promise<'1' | '2+' | 'unknown'> => {
    const query = { mailbox, internetMessageId, maxItems: 2 };
    const [store, recoverable] = await Promise.all([
      findMessagesByInternetMessageId(client, query),
      findMessagesByInternetMessageId(client, { ...query, folder: 'recoverableitemsdeletions' }),
    ]);
    const ids = new Set([...store.items, ...recoverable.items].map(item => item.id));
    if (store.truncated || recoverable.truncated || ids.size > 1) {
      return '2+';
    }
    return ids.size === 1 ? '1' : 'unknown';
  };
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      search(),
      new Promise<'unknown'>(resolve => {
        timer = setTimeout(() => resolve('unknown'), available);
      }),
    ]);
  } catch {
    return 'unknown';
  } finally {
    clearTimeout(timer);
  }
}

async function lookUp(
  client: GraphClient,
  criteria: Criteria,
  expired: () => boolean,
  remainingMs: () => number = (): number => 0
): Promise<OriginalFetchResult> {
  const query = {
    mailbox: criteria.mailbox,
    senderAddress: criteria.senderAddress,
    receivedFrom: criteria.window.from,
    receivedTo: criteria.window.to,
    subject: criteria.subject,
    maxItems: CANDIDATES_PER_LOCATION,
  };
  // `/messages` covers every ordinary folder (Junk Email and Deleted Items
  // included) but not Recoverable Items, where a message goes when the
  // reporter deletes it for good after forwarding it
  let mailbox: Awaited<ReturnType<typeof findMessagesBySender>>;
  let recoverable: Awaited<ReturnType<typeof findMessagesBySender>>;
  try {
    [mailbox, recoverable] = await Promise.all([
      findMessagesBySender(client, query),
      findMessagesBySender(client, { ...query, folder: 'recoverableitemsdeletions' }),
    ]);
  } catch (error) {
    if (isMailboxNotFound(error)) {
      // The address is not a mailbox's own name (a plus-address or an alias):
      // nothing to find there, which is not a failure of the lookup
      return { outcome: 'not_found', reason: MAILBOX_NOT_FOUND_REASON };
    }
    throw error;
  }

  const candidates = new Map<string, { summary: MessageSummary; recoverable: boolean }>();
  for (const summary of mailbox.items) {
    candidates.set(summary.id, { summary, recoverable: false });
  }
  for (const summary of recoverable.items) {
    if (!candidates.has(summary.id)) {
      candidates.set(summary.id, { summary, recoverable: true });
    }
  }

  if (mailbox.truncated || recoverable.truncated || candidates.size > 1) {
    return { outcome: 'ambiguous', reason: 'several_candidates' };
  }
  const [match] = candidates.values();
  if (match === undefined) {
    return { outcome: 'not_found', reason: 'no_candidate' };
  }
  if (!satisfies(match.summary, criteria)) {
    return { outcome: 'not_found', reason: 'candidate_failed_recheck' };
  }
  if (expired()) {
    throw new BudgetExceededError();
  }

  const headers = await getMessageHeaders(client, {
    mailbox: criteria.mailbox,
    messageId: match.summary.id,
  });
  if (headers.items.length === 0) {
    // Received mail always has headers; none usually means the app
    // registration may not read them
    return { outcome: 'error', reason: 'no_headers_returned' };
  }

  // Validated above; re-serialized so only a well-formed timestamp leaves here
  const receivedAt = new Date(Date.parse(match.summary.receivedDateTime ?? '')).toISOString();
  const stored = storedIdentity(match.summary);
  const identity = stored
    ? {
        ...stored,
        sameMessageIdCount: stored.internetMessageId
          ? await countByMessageId(client, criteria.mailbox, stored.internetMessageId, remainingMs)
          : ('unknown' as const),
      }
    : undefined;
  return {
    outcome: 'found',
    reason: match.recoverable ? 'recoverable_items' : 'mailbox',
    original: {
      location: match.recoverable ? 'recoverable_items' : 'mailbox',
      receivedAt,
      headers: headers.items.map(header => ({ name: header.name, value: header.value })),
      headersTruncated: headers.truncated,
      ...(identity ? { identity } : {}),
    },
  };
}

/**
 * The matched message as the mailbox stores it (Graph ID, Internet
 * Message-ID, From address, subject), shape-checked. These come from
 * Exchange's copy of the message, not from the forward's pasted text; the
 * values themselves were still written by the sender and are hostile.
 */
function storedIdentity(
  summary: MessageSummary
): Omit<RetrievedOriginalIdentity, 'sameMessageIdCount'> | undefined {
  if (!GRAPH_ITEM_ID_PATTERN.test(summary.id)) {
    return undefined;
  }
  const internetMessageId = summary.internetMessageId?.trim();
  const senderAddress = summary.fromAddress?.trim().toLowerCase();
  return {
    messageId: summary.id,
    ...(internetMessageId && MESSAGE_ID_PATTERN.test(internetMessageId)
      ? { internetMessageId }
      : {}),
    ...(senderAddress &&
    senderAddress.length <= MAX_ADDRESS_LENGTH &&
    /^[^\s<>@]+@[^\s<>@]+$/.test(senderAddress)
      ? { senderAddress }
      : {}),
    ...(summary.subject !== undefined && summary.subject.length <= MAX_SUBJECT_LENGTH
      ? { subject: summary.subject }
      : {}),
  };
}

function describeFailure(error: unknown): { reason: string; fields: Record<string, unknown> } {
  if (error instanceof BudgetExceededError) {
    return { reason: 'budget_exceeded', fields: {} };
  }
  if (error instanceof GraphError) {
    // Only the fields Phishy or Microsoft chose. `error.detail` can echo the
    // filter text (hostile) and is deliberately not logged
    return {
      reason: `graph_${error.kind}`,
      fields: {
        status: error.status,
        code: error.code,
        requestId: error.requestId,
        pathTemplate: error.pathTemplate,
      },
    };
  }
  if (error instanceof GraphAuthError) {
    return { reason: 'graph_auth', fields: { status: error.status, code: error.code } };
  }
  return { reason: 'unexpected', fields: {} };
}

/** What a lookup searches with, once the claimed values have been read */
export interface PreparedOriginalFetch {
  /** The claimed sender's address alone, without display name */
  senderAddress: string;
  claimedTime: ClaimedSentTime;
  subject?: string;
}

/**
 * Read the claimed sender, sent time and subject of a request, or say why
 * there is nothing to search with (a `skipped` result). Pure: no request is
 * made. Shared by the lookup itself and by a caller that hands the lookup to
 * the Graph broker, so both skip on exactly the same inputs.
 */
export function prepareOriginalFetch(
  request: Pick<OriginalFetchRequest, 'claimedFrom' | 'claimedSent' | 'claimedSubject'>
): { skip: OriginalFetchResult } | { prepared: PreparedOriginalFetch } {
  const senderAddress = claimedSenderAddress(request.claimedFrom);
  if (!senderAddress) {
    return { skip: { outcome: 'skipped', reason: 'no_claimed_sender' } };
  }
  const claimedTime = parseClaimedSentTime(request.claimedSent ?? '');
  if (!claimedTime) {
    return { skip: { outcome: 'skipped', reason: 'no_claimed_time' } };
  }
  // `||` is deliberate: an empty (or whitespace-only) subject means "no subject"
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const subject = request.claimedSubject?.trim() || undefined;
  if (subject !== undefined && subject.length > MAX_SUBJECT_LENGTH) {
    return { skip: { outcome: 'skipped', reason: 'subject_too_long' } };
  }
  return { prepared: { senderAddress, claimedTime, subject } };
}

/**
 * Look for the original of a forwarded message in the reporter's mailbox.
 * Never throws: any failure, timeout, missing input or non-unique match is
 * reported as an outcome, and only `found` carries data.
 */
export async function fetchOriginalMessage(
  client: GraphClient,
  request: OriginalFetchRequest,
  options: OriginalFetchOptions = {}
): Promise<OriginalFetchResult> {
  const read = prepareOriginalFetch(request);
  if ('skip' in read) {
    return read.skip;
  }
  const { senderAddress, claimedTime, subject } = read.prepared;

  const budgetMs = options.budgetMs ?? ORIGINAL_FETCH_BUDGET_MS;
  const deadline = Date.now() + budgetMs;
  const criteria: Criteria = {
    mailbox: request.mailbox,
    senderAddress,
    window: searchWindow(claimedTime),
    subject,
  };

  try {
    return await withBudget(
      lookUp(
        client,
        criteria,
        () => Date.now() >= deadline,
        () => deadline - Date.now()
      ),
      budgetMs
    );
  } catch (error) {
    const { reason, fields } = describeFailure(error);
    logger.warn('Original-message lookup failed; continuing without it', { reason, ...fields });
    return { outcome: 'error', reason };
  }
}

/**
 * Runs one lookup. Directly it is `fetchOriginalMessage` over a Graph
 * client; in broker mode it is an invocation of the Graph broker. Either
 * way it must not throw, and what it returns is hostile data.
 */
export type OriginalMessageFetcher = (
  request: OriginalFetchRequest,
  options: OriginalFetchOptions
) => Promise<OriginalFetchResult>;

/**
 * The address a plus-addressed mailbox delivers to: `name+tag@example.com`
 * becomes `name@example.com`. Undefined when there is no `+tag`, nothing
 * would be left of the local part, or the result is not on a safe domain.
 * Only ever applied to the reporter's own confirmed address, never to an
 * address from email content.
 */
export function plusAddressBase(address: string, safeDomains: string[]): string | undefined {
  const at = address.lastIndexOf('@');
  if (at <= 0) {
    return undefined;
  }
  const local = address.slice(0, at);
  const domain = address.slice(at + 1).toLowerCase();
  const plus = local.indexOf('+');
  if (plus <= 0) {
    return undefined;
  }
  if (!safeDomains.some(safeDomain => domainMatches(domain, safeDomain))) {
    return undefined;
  }
  return `${local.slice(0, plus)}@${domain}`;
}

/** The one parser capability enrichment needs (`EmailParserService` provides it) */
export interface RetrievedOriginalSink {
  attachRetrievedOriginal(emailData: ExtractedEmailData, original: RetrievedOriginal): void;
}

/**
 * The pipeline step: confirm whose mailbox may be read, look the original
 * up, hand a match to the parser to attach to the email facts, and emit the
 * outcome metric. Never throws, and on every outcome but `found` leaves
 * `emailData` untouched. Logs carry outcome, reason and counts only — no
 * address, subject or header content.
 */
export async function enrichWithOriginalMessage(
  client: GraphClient,
  parser: RetrievedOriginalSink,
  msg: EmailMessage,
  emailData: ExtractedEmailData,
  safeDomains: string[],
  options: OriginalFetchOptions = {}
): Promise<OriginalFetchResult> {
  return enrichWithOriginalVia(
    (request, fetchOptions) => fetchOriginalMessage(client, request, fetchOptions),
    parser,
    msg,
    emailData,
    safeDomains,
    options
  );
}

/**
 * `enrichWithOriginalMessage` with the lookup itself supplied by the caller.
 * Everything that decides whose mailbox is read, what is attached and what
 * is measured is here, so it is the same whichever way the lookup is made.
 */
export async function enrichWithOriginalVia(
  fetchOriginal: OriginalMessageFetcher,
  parser: RetrievedOriginalSink,
  msg: EmailMessage,
  emailData: ExtractedEmailData,
  safeDomains: string[],
  options: OriginalFetchOptions = {}
): Promise<OriginalFetchResult> {
  const startedAt = Date.now();
  let result: OriginalFetchResult;
  let aliasRetried = false;
  try {
    const mailbox = confirmedReporterMailbox(msg, emailData, safeDomains);
    const request = (address: string): OriginalFetchRequest => ({
      mailbox: address,
      claimedFrom: emailData.forwardedHeaders['Original-From'],
      claimedSent:
        emailData.forwardedHeaders['Original-Sent'] ?? emailData.forwardedHeaders['Original-Date'],
      claimedSubject: emailData.forwardedHeaders['Original-Subject'],
    });
    result =
      mailbox === undefined
        ? { outcome: 'skipped', reason: 'reporter_not_confirmed' }
        : await fetchOriginal(request(mailbox), options);

    // A plus-address is not a mailbox name Graph resolves: try once more
    // with the +tag removed. Still the reporter's own confirmed address
    // (same local name, same safe domain), within what is left of the budget
    if (
      mailbox !== undefined &&
      result.outcome === 'not_found' &&
      result.reason === MAILBOX_NOT_FOUND_REASON
    ) {
      const base = plusAddressBase(mailbox, safeDomains);
      const remainingMs = (options.budgetMs ?? ORIGINAL_FETCH_BUDGET_MS) - (Date.now() - startedAt);
      if (base !== undefined && remainingMs >= MIN_RETRY_BUDGET_MS) {
        aliasRetried = true;
        result = await fetchOriginal(request(base), { ...options, budgetMs: remainingMs });
      }
    }
    if (result.outcome === 'found' && result.original) {
      parser.attachRetrievedOriginal(emailData, result.original);
    }
  } catch {
    emailData.retrievedOriginal = undefined;
    result = { outcome: 'error', reason: 'unexpected' };
  }

  const durationMs = Date.now() - startedAt;
  emitOriginalFetchMetric(result.outcome, durationMs);
  logger.info('Original-message lookup finished', {
    outcome: result.outcome,
    reason: result.reason,
    durationMs,
    aliasRetried,
    headers: emailData.retrievedOriginal?.headers.length ?? 0,
  });
  return result;
}

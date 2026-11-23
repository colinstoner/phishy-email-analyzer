/**
 * The Graph write broker's wire format: the one thing the main function may
 * ask of the write broker, and what it may be told back.
 *
 * There is exactly one operation, `remove_messages`: for each named mailbox,
 * move each named message to that mailbox's Deleted Items, after re-reading
 * it and confirming that ALL of its own expected values still hold: its
 * Internet Message-ID, its From address, the SHA-256 of its normalized
 * subject, and that it was received inside the given window. There is no path, URL, folder, filter, query or "call Graph"
 * field, and no field is ever used as one. A new write capability is a new
 * operation added here, in code, where it is reviewed (CLAUDE.md
 * invariant 7).
 *
 * Both directions are untrusted:
 * - A request is built by the function that parses hostile email. The write
 *   broker validates it against `GraphWriteRequestSchema` (unknown
 *   operations, unknown fields, other versions and out-of-bounds lists are
 *   refused) before anything else happens.
 * - The response is validated by the main function against
 *   `RemoveMessagesResultSchema`, and then checked against what it asked for
 *   (`reconcileRemovalResult`): an outcome for a mailbox or message it did
 *   not name is ignored, and a message it named with no outcome is
 *   `unknown`. Totals are recomputed from the outcomes, never taken from the
 *   broker.
 *
 * This file imports only Zod, the shared limits and the subject-hash
 * pattern, so loading it can never construct a Graph client.
 */

import { z } from 'zod';
import {
  DIRECTORY_ID_PATTERN,
  GRAPH_ITEM_ID_PATTERN,
  MAX_ADDRESS_LENGTH,
  MAX_REPORTED_COPY_IDS,
  MESSAGE_ID_PATTERN,
} from '../graph/graph.limits';
import { SUBJECT_HASH_PATTERN } from '../graph/subject.key';

/** 2: each message carries its own expected values (sender, subject hash, window) */
export const GRAPH_WRITE_VERSION = 2;

export const GRAPH_WRITE_OPERATIONS = ['remove_messages'] as const;
export type GraphWriteOperation = (typeof GRAPH_WRITE_OPERATIONS)[number];

/**
 * Why the write broker did not run the operation at all. Fixed words chosen
 * by the broker's code; never derived from a request.
 * - `invalid_request`: the request did not match the schema
 * - `write_disabled`: the broker's own kill switch is off (the default)
 * - `misconfigured`: enabled, but its credential settings are missing or invalid
 * - `internal_error`: something unexpected; nothing more is said
 */
export const GRAPH_WRITE_REFUSALS = [
  'invalid_request',
  'write_disabled',
  'misconfigured',
  'internal_error',
] as const;
export type GraphWriteRefusal = (typeof GRAPH_WRITE_REFUSALS)[number];

// ── Bounds (one place; applied by both sides) ──────────────────────────────

/** Most mailboxes one call may name */
export const MAX_WRITE_MAILBOXES_PER_CALL = 50;
/** Most messages one mailbox may name: the copies blast radius keeps per mailbox */
export const MAX_WRITE_MESSAGES_PER_MAILBOX = MAX_REPORTED_COPY_IDS;
/** Most messages one call may name across all its mailboxes */
export const MAX_WRITE_MESSAGES_PER_CALL = 100;
/** Widest received-time window a copy may be checked against: 6 hours either side, the largest sameMessageSpreadMinutes (360) */
export const MAX_RECEIVED_WINDOW_MS = 2 * 6 * 3_600_000;
/** Shortest and longest time budget a caller may give one call */
export const MIN_WRITE_BUDGET_MS = 1000;
export const MAX_WRITE_BUDGET_MS = 80_000;
/** Mailboxes the broker works on at once */
export const WRITE_MAILBOX_CONCURRENCY = 4;
/** Largest response accepted, checked before the payload is parsed */
export const GRAPH_WRITE_MAX_RESPONSE_BYTES = 256 * 1024;

const MailboxId = z.string().regex(DIRECTORY_ID_PATTERN);
const MessageId = z.string().regex(GRAPH_ITEM_ID_PATTERN);
const InternetMessageId = z.string().regex(MESSAGE_ID_PATTERN);
const SenderAddress = z
  .string()
  .max(MAX_ADDRESS_LENGTH)
  .regex(/^[^\s<>@A-Z]+@[^\s<>@A-Z]+$/, 'a lower-case address');

function unique(values: string[]): boolean {
  return new Set(values.map(value => value.toLowerCase())).size === values.length;
}

// ── Request ─────────────────────────────────────────────────────────────────

/**
 * One copy to move, with everything it must still be when the write broker
 * re-reads it. Each value came from Phishy's own lookups (the anchor and the
 * copy's stored details); the subject travels only as a SHA-256 of its
 * normalized form, so no email text reaches the write function.
 */
const RemoveMessage = z
  .strictObject({
    /** Graph message ID in that mailbox, exactly as the approved scope names it */
    messageId: MessageId,
    /** The copy's own Internet Message-ID, as the lookup read it */
    expectedInternetMessageId: InternetMessageId,
    /** The anchor's From address */
    expectedSenderAddress: SenderAddress,
    /** `subjectKeyHash` of the anchor's subject */
    expectedSubjectSha256: z.string().regex(SUBJECT_HASH_PATTERN),
    /** The copy must have been received inside this window */
    receivedFrom: z.iso.datetime(),
    receivedTo: z.iso.datetime(),
  })
  .refine(
    message => {
      const span = Date.parse(message.receivedTo) - Date.parse(message.receivedFrom);
      return span >= 0 && span <= MAX_RECEIVED_WINDOW_MS;
    },
    { message: 'the received window is empty or too wide' }
  );

const RemoveMessagesMailbox = z
  .strictObject({
    /** Entra directory object ID of the mailbox, as the approved scope recorded it */
    mailboxId: MailboxId,
    messages: z.array(RemoveMessage).min(1).max(MAX_WRITE_MESSAGES_PER_MAILBOX),
  })
  .refine(
    mailbox => new Set(mailbox.messages.map(m => m.messageId)).size === mailbox.messages.length,
    {
      message: 'message IDs must be unique within a mailbox',
    }
  );

const RemoveMessagesParams = z
  .strictObject({
    /**
     * The response action this call carries out: a UUID, echoed in the write
     * broker's logs so a removal can be traced to its approval. Not an
     * approval reference and authorizes nothing.
     */
    actionId: z.string().regex(DIRECTORY_ID_PATTERN),
    mailboxes: z.array(RemoveMessagesMailbox).min(1).max(MAX_WRITE_MAILBOXES_PER_CALL),
    /** How long the caller will wait, in milliseconds */
    budgetMs: z.number().int().min(MIN_WRITE_BUDGET_MS).max(MAX_WRITE_BUDGET_MS),
  })
  .refine(params => unique(params.mailboxes.map(m => m.mailboxId)), {
    message: 'each mailbox may be named once',
  })
  .refine(
    params =>
      params.mailboxes.reduce((n, m) => n + m.messages.length, 0) <= MAX_WRITE_MESSAGES_PER_CALL,
    { message: 'too many messages in one call' }
  );

/**
 * A request to the write broker. Strict at every level: an unknown
 * operation, an unknown or missing field, a wrong type, another version or
 * a list over its bound is not a request. No HTTP event or event-source
 * record matches it.
 */
export const GraphWriteRequestSchema = z.discriminatedUnion('operation', [
  z.strictObject({
    version: z.literal(GRAPH_WRITE_VERSION),
    operation: z.literal('remove_messages'),
    params: RemoveMessagesParams,
  }),
]);

export type GraphWriteRequest = z.infer<typeof GraphWriteRequestSchema>;
export type RemoveMessagesParams = z.infer<typeof RemoveMessagesParams>;
export type RemoveMessagesMailbox = z.infer<typeof RemoveMessagesMailbox>;
export type RemoveMessage = z.infer<typeof RemoveMessage>;

// ── Response ────────────────────────────────────────────────────────────────

/**
 * What happened to one message:
 * - `moved`: moved to the mailbox's Deleted Items by this call
 * - `already_deleted`: already in Deleted Items; left where it is
 * - `not_found`: no such message in that mailbox (already moved, purged or
 *   never there); left alone
 * - `mismatch`: its Internet Message-ID is not one the scope expected;
 *   refused and left alone
 * - `not_allowed`: the mailbox is outside the write broker's allowlist;
 *   refused and left alone
 * - `error`: a request failed; see the fixed `reason` word
 * - `not_attempted`: a bound (time, throttling, a stop) was reached first;
 *   see `reason`
 */
export const REMOVAL_OUTCOMES = [
  'moved',
  'already_deleted',
  'not_found',
  'mismatch',
  'not_allowed',
  'error',
  'not_attempted',
] as const;
export type RemovalOutcome = (typeof REMOVAL_OUTCOMES)[number];

/**
 * Fixed reason words, written by the broker's code and never taken from a
 * Graph response (whose error text can carry mailbox content).
 */
export const REMOVAL_REASONS = [
  'time_budget',
  'throttled',
  'auth_failed',
  'stopped',
  'mailbox_not_found',
  'folder_unavailable',
  'read_failed',
  'move_failed',
  'move_unconfirmed',
  'forbidden',
] as const;
export type RemovalReason = (typeof REMOVAL_REASONS)[number];

const MessageOutcomeSchema = z.strictObject({
  messageId: MessageId,
  outcome: z.enum(REMOVAL_OUTCOMES),
  reason: z.enum(REMOVAL_REASONS).optional(),
});

const MailboxOutcomeSchema = z.strictObject({
  mailboxId: MailboxId,
  messages: z.array(MessageOutcomeSchema).max(MAX_WRITE_MESSAGES_PER_MAILBOX),
});

const Count = z.number().int().min(0).max(1_000_000);

/** The bounds the broker applied, disclosed so the caller can say so */
const AppliedBoundsSchema = z.strictObject({
  maxMailboxes: Count,
  maxMessagesPerMailbox: Count,
  maxMessages: Count,
  budgetMs: Count,
  concurrency: Count,
});

export const RemoveMessagesResultSchema = z.strictObject({
  mailboxes: z.array(MailboxOutcomeSchema).max(MAX_WRITE_MAILBOXES_PER_CALL),
  bounds: AppliedBoundsSchema,
  /** Set when work stopped before every message was attempted */
  stoppedBy: z.enum(['time_budget', 'throttled', 'auth_failed']).optional(),
  durationMs: Count,
});

export type MessageOutcome = z.infer<typeof MessageOutcomeSchema>;
export type MailboxOutcome = z.infer<typeof MailboxOutcomeSchema>;
export type RemoveMessagesResult = z.infer<typeof RemoveMessagesResultSchema>;

/**
 * The envelope. `result` is validated separately against
 * `RemoveMessagesResultSchema`.
 */
export const GraphWriteResponseSchema = z.discriminatedUnion('ok', [
  z.strictObject({ ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ ok: z.literal(false), reason: z.enum(GRAPH_WRITE_REFUSALS) }),
]);

export type GraphWriteResponse =
  { ok: true; result: RemoveMessagesResult } | { ok: false; reason: GraphWriteRefusal };

/** Per-outcome counts; `unknown` is the caller's word for "asked, but no answer" */
export interface RemovalOutcomeCounts {
  moved: number;
  alreadyDeleted: number;
  notFound: number;
  mismatch: number;
  notAllowed: number;
  error: number;
  notAttempted: number;
  unknown: number;
}

export function emptyRemovalCounts(): RemovalOutcomeCounts {
  return {
    moved: 0,
    alreadyDeleted: 0,
    notFound: 0,
    mismatch: 0,
    notAllowed: 0,
    error: 0,
    notAttempted: 0,
    unknown: 0,
  };
}

const COUNT_KEY: Record<RemovalOutcome | 'unknown', keyof RemovalOutcomeCounts> = {
  moved: 'moved',
  already_deleted: 'alreadyDeleted',
  not_found: 'notFound',
  mismatch: 'mismatch',
  not_allowed: 'notAllowed',
  error: 'error',
  not_attempted: 'notAttempted',
  unknown: 'unknown',
};

export function countOutcome(
  counts: RemovalOutcomeCounts,
  outcome: RemovalOutcome | 'unknown',
  by = 1
): void {
  counts[COUNT_KEY[outcome]] += by;
}

/** One requested message, with the outcome the caller will act on */
export interface ReconciledMessage {
  messageId: string;
  outcome: RemovalOutcome | 'unknown';
  reason?: RemovalReason;
}

export interface ReconciledMailbox {
  mailboxId: string;
  messages: ReconciledMessage[];
}

/**
 * Check a validated result against the request it answers. Only mailboxes
 * and messages the request named are kept, each exactly once (the first
 * outcome reported for it); a named message the broker gave no outcome for
 * is `unknown`, since the caller cannot know whether it was moved.
 */
export function reconcileRemovalResult(
  request: Pick<RemoveMessagesParams, 'mailboxes'>,
  result: Pick<RemoveMessagesResult, 'mailboxes'>
): ReconciledMailbox[] {
  const reported = new Map<string, Map<string, MessageOutcome>>();
  for (const mailbox of result.mailboxes) {
    const key = mailbox.mailboxId.toLowerCase();
    const messages = reported.get(key) ?? new Map<string, MessageOutcome>();
    for (const message of mailbox.messages) {
      if (!messages.has(message.messageId)) {
        messages.set(message.messageId, message);
      }
    }
    reported.set(key, messages);
  }
  return request.mailboxes.map(mailbox => {
    const messages = reported.get(mailbox.mailboxId.toLowerCase());
    return {
      mailboxId: mailbox.mailboxId,
      messages: mailbox.messages.map(({ messageId }) => {
        const found = messages?.get(messageId);
        return found
          ? { messageId, outcome: found.outcome, ...(found.reason ? { reason: found.reason } : {}) }
          : { messageId, outcome: 'unknown' as const };
      }),
    };
  });
}

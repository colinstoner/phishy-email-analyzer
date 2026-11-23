/**
 * `remove_messages`: move exactly the named copies to each mailbox's Deleted
 * Items, after checking each one is still the message the approved scope
 * named.
 *
 * Per mailbox (a few mailboxes at a time, one request at a time inside a
 * mailbox):
 *   1. outside the allowlist → every message `not_allowed`, no request made
 *   2. GET the Deleted Items folder's ID (once)
 *   3. per message: GET it by ID with
 *      `$select=internetMessageId,parentFolderId,from,subject,receivedDateTime`
 *      - 404 → `not_found` (left alone)
 *      - any expected value not met (Internet Message-ID, From address,
 *        subject hash, received window) → `mismatch` (left alone)
 *      - already in Deleted Items → `already_deleted`
 *      - otherwise POST move to `deleteditems` → `moved`
 *
 * Bounded: the request's own list bounds (checked by the schema), the time
 * budget, the mailbox concurrency, and the client's retry rules. When the
 * budget ends, throttling cannot be waited out or authentication fails,
 * nothing new is started and every message not yet attempted is reported
 * `not_attempted` with the reason, so the caller can say so. Never throws.
 *
 * Nothing here logs a message ID, an Internet Message-ID or anything read
 * from a mailbox; the handler logs counts.
 */

import {
  MAX_WRITE_MAILBOXES_PER_CALL,
  MAX_WRITE_MESSAGES_PER_CALL,
  MAX_WRITE_MESSAGES_PER_MAILBOX,
  MailboxOutcome,
  MessageOutcome,
  RemovalReason,
  RemoveMessage,
  RemoveMessagesMailbox,
  RemoveMessagesParams,
  RemoveMessagesResult,
  WRITE_MAILBOX_CONCURRENCY,
} from './write.protocol';
import { GraphWriteClient, GraphWriteRequestError, MessageState } from './write.client';
import { subjectKeyHash } from '../graph/subject.key';

/** Time kept back from the budget to build and return the answer */
const ANSWER_RESERVE_MS = 500;

export interface RemoveMessagesOptions {
  /** Mailbox IDs this broker may change; undefined means any mailbox */
  allowedMailboxIds?: ReadonlySet<string>;
  /** The broker's own remaining Lambda time, when known */
  remainingMs?: number;
  /** Injected for tests */
  now?: () => number;
}

type StopReason = 'time_budget' | 'throttled' | 'auth_failed';

/** Angle brackets and surrounding space removed: the form Message-IDs are compared in */
export function bareMessageId(value: string): string {
  return value.trim().replace(/^</, '').replace(/>$/, '');
}

/**
 * Does the message as stored still match every expected value? Internet
 * Message-ID exact (angle brackets aside), From address equal (case aside),
 * the SHA-256 of the normalized subject equal, and received inside the
 * window. Any missing value is a mismatch. Nothing compared is kept.
 */
export function matchesExpected(
  current: Extract<MessageState, { kind: 'found' }>,
  expected: RemoveMessage
): boolean {
  if (
    !current.internetMessageId ||
    bareMessageId(current.internetMessageId) !== bareMessageId(expected.expectedInternetMessageId)
  ) {
    return false;
  }
  if (current.senderAddress?.trim().toLowerCase() !== expected.expectedSenderAddress) {
    return false;
  }
  if (
    current.subject === undefined ||
    subjectKeyHash(current.subject) !== expected.expectedSubjectSha256
  ) {
    return false;
  }
  const received = Date.parse(current.receivedDateTime ?? '');
  return (
    Number.isFinite(received) &&
    received >= Date.parse(expected.receivedFrom) &&
    received <= Date.parse(expected.receivedTo)
  );
}

interface RunState {
  deadline: number;
  stoppedBy?: StopReason;
}

function failureReason(
  error: unknown,
  state: RunState,
  stage: 'folder' | 'read' | 'move',
  now: () => number
): { reason: RemovalReason; stop?: StopReason } {
  if (!(error instanceof GraphWriteRequestError)) {
    return { reason: stage === 'move' ? 'move_unconfirmed' : 'read_failed' };
  }
  switch (error.kind) {
    case 'throttled':
      return { reason: 'throttled', stop: 'throttled' };
    case 'auth_failed':
      return { reason: 'auth_failed', stop: 'auth_failed' };
    case 'forbidden':
      return { reason: 'forbidden' };
    case 'unconfirmed':
      return { reason: 'move_unconfirmed' };
    case 'timeout':
      return now() >= state.deadline
        ? { reason: 'time_budget', stop: 'time_budget' }
        : { reason: stage === 'move' ? 'move_failed' : 'read_failed' };
    default:
      return {
        reason:
          stage === 'folder'
            ? 'folder_unavailable'
            : stage === 'move'
              ? 'move_failed'
              : 'read_failed',
      };
  }
}

async function removeInMailbox(
  client: GraphWriteClient,
  mailbox: RemoveMessagesMailbox,
  state: RunState,
  now: () => number
): Promise<MessageOutcome[]> {
  const outcomes: MessageOutcome[] = [];
  const rest = (from: number, outcome: MessageOutcome['outcome'], reason: RemovalReason): void => {
    for (const { messageId } of mailbox.messages.slice(from)) {
      outcomes.push({ messageId, outcome, reason });
    }
  };
  const stopped = (): boolean => {
    if (!state.stoppedBy && now() >= state.deadline) {
      state.stoppedBy = 'time_budget';
    }
    return state.stoppedBy !== undefined;
  };

  if (stopped()) {
    rest(0, 'not_attempted', state.stoppedBy ?? 'stopped');
    return outcomes;
  }

  let deletedItemsId: string;
  try {
    const folder = await client.getDeletedItemsFolderId(mailbox.mailboxId, state.deadline);
    if (folder.kind === 'mailbox_not_found') {
      rest(0, 'error', 'mailbox_not_found');
      return outcomes;
    }
    deletedItemsId = folder.id;
  } catch (error) {
    const { reason, stop } = failureReason(error, state, 'folder', now);
    if (stop) {
      state.stoppedBy ??= stop;
      rest(0, 'not_attempted', reason);
    } else {
      rest(0, 'error', reason);
    }
    return outcomes;
  }

  for (let index = 0; index < mailbox.messages.length; index++) {
    const expected = mailbox.messages[index];
    const messageId = expected.messageId;
    if (stopped()) {
      rest(index, 'not_attempted', state.stoppedBy ?? 'stopped');
      return outcomes;
    }

    let stage: 'read' | 'move' = 'read';
    try {
      const current = await client.getMessageState(mailbox.mailboxId, messageId, state.deadline);
      if (current.kind === 'not_found') {
        outcomes.push({ messageId, outcome: 'not_found' });
        continue;
      }
      // Every expected value must hold: a message that is not provably the
      // one the approved scope recorded is never moved
      if (!matchesExpected(current, expected)) {
        outcomes.push({ messageId, outcome: 'mismatch' });
        continue;
      }
      if (current.parentFolderId !== undefined && current.parentFolderId === deletedItemsId) {
        outcomes.push({ messageId, outcome: 'already_deleted' });
        continue;
      }
      if (stopped()) {
        rest(index, 'not_attempted', state.stoppedBy ?? 'stopped');
        return outcomes;
      }
      stage = 'move';
      const moved = await client.moveToDeletedItems(mailbox.mailboxId, messageId, state.deadline);
      outcomes.push({ messageId, outcome: moved === 'moved' ? 'moved' : 'not_found' });
    } catch (error) {
      const { reason, stop } = failureReason(error, state, stage, now);
      if (stop) {
        // Every stopping failure happens before the request takes effect
        // (throttled, refused token, or the deadline checked before sending;
        // a move cut off in flight is `unconfirmed` instead), so this
        // message and the rest were not attempted
        state.stoppedBy ??= stop;
        rest(index, 'not_attempted', reason);
        return outcomes;
      }
      outcomes.push({ messageId, outcome: 'error', reason });
    }
  }
  return outcomes;
}

/**
 * Run the operation. `params` has already passed `GraphWriteRequestSchema`.
 */
export async function removeMessages(
  client: GraphWriteClient,
  params: RemoveMessagesParams,
  options: RemoveMessagesOptions = {}
): Promise<RemoveMessagesResult> {
  const now = options.now ?? ((): number => Date.now());
  const startedAt = now();
  const budget = Math.min(
    params.budgetMs,
    options.remainingMs !== undefined ? options.remainingMs - ANSWER_RESERVE_MS : params.budgetMs
  );
  const state: RunState = { deadline: startedAt + Math.max(0, budget - ANSWER_RESERVE_MS) };
  const allowed = options.allowedMailboxIds;

  const results = new Map<number, MessageOutcome[]>();
  const queue = params.mailboxes.map((mailbox, index) => ({ mailbox, index }));

  // Refused before any request: outside the allowlist
  const work = queue.filter(({ mailbox, index }) => {
    if (allowed && !allowed.has(mailbox.mailboxId.toLowerCase())) {
      results.set(
        index,
        mailbox.messages.map(({ messageId }) => ({ messageId, outcome: 'not_allowed' as const }))
      );
      return false;
    }
    return true;
  });

  const workers = Array.from(
    { length: Math.min(WRITE_MAILBOX_CONCURRENCY, work.length) },
    async () => {
      for (;;) {
        const next = work.shift();
        if (!next) {
          return;
        }
        try {
          results.set(next.index, await removeInMailbox(client, next.mailbox, state, now));
        } catch {
          // removeInMailbox handles its own failures; this is belt and braces
          results.set(
            next.index,
            next.mailbox.messages.map(({ messageId }) => ({
              messageId,
              outcome: 'error' as const,
              reason: 'move_unconfirmed' as const,
            }))
          );
        }
      }
    }
  );
  await Promise.all(workers);

  const mailboxes: MailboxOutcome[] = params.mailboxes.map((mailbox, index) => ({
    mailboxId: mailbox.mailboxId,
    messages: results.get(index) ?? [],
  }));

  return {
    mailboxes,
    bounds: {
      maxMailboxes: MAX_WRITE_MAILBOXES_PER_CALL,
      maxMessagesPerMailbox: MAX_WRITE_MESSAGES_PER_MAILBOX,
      maxMessages: MAX_WRITE_MESSAGES_PER_CALL,
      budgetMs: Math.max(0, budget),
      concurrency: WRITE_MAILBOX_CONCURRENCY,
    },
    ...(state.stoppedBy ? { stoppedBy: state.stoppedBy } : {}),
    durationMs: Math.max(0, now() - startedAt),
  };
}

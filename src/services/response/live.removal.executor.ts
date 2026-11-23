/**
 * The live removal executor: carries out an approved, re-checked LIVE
 * removal by asking the Graph write broker (a separate function with its
 * own credential) to move exactly those copies to Deleted Items.
 *
 * Selected by `createRemovalExecutor` only when
 * `campaignResponse.removal.mode` is `live` and a write broker function is
 * configured, and run only for an action whose scope was proposed live
 * (`scope.mode === 'live'`, computed by `computeLiveRemovalScope` from the
 * incident's anchor). This module never talks to Microsoft and holds no
 * Graph credential: it only invokes the write broker.
 *
 * What it sends, and never more:
 * - `recheckRemoval` runs first, exactly as for the dry run: only approved
 *   message IDs the incident's latest reach still shows are kept, per
 *   approved mailbox; copies new since approval are never included and the
 *   scope is never widened.
 * - Per copy, the check the scope recorded for it (`verify`): its own
 *   Internet Message-ID, the anchor's From address, the SHA-256 of the
 *   anchor's normalized subject and the allowed received window. The write
 *   broker refuses the copy unless all of them still hold. No address or
 *   email text is sent.
 * - In batches within the write protocol's bounds, one at a time, while the
 *   main function has time; what is left is reported `not_attempted`.
 *
 * What it returns: `dryRun: false`, a summary for the approver by outcome,
 * `removalOutcome` (the counts, recorded in the audit row), and `removed`:
 * per mailbox, the copies the write broker reported `moved`. That list, and
 * only that list, makes `CampaignResponseService.sendRemovalNotices` email
 * anyone. When the write broker's answer is missing or unusable, every copy
 * in that call is `unknown`: nobody is told their copy was removed, and the
 * approver is told so and how to check.
 *
 * Logs: the incident and action IDs and counts. Never an address, a message
 * ID or anything from the suspicious email.
 */

import { createLogger } from '../../utils/logger';
import { emitCampaignResponseMetric } from '../../utils/metrics';
import { GraphWriteBrokerClient, failureChangedNothing } from '../graph-write/write.broker.client';
import {
  MAX_WRITE_BUDGET_MS,
  MAX_WRITE_MAILBOXES_PER_CALL,
  MAX_WRITE_MESSAGES_PER_CALL,
  MAX_WRITE_MESSAGES_PER_MAILBOX,
  MIN_WRITE_BUDGET_MS,
  RemovalOutcomeCounts,
  RemoveMessagesMailbox,
  countOutcome,
  emptyRemovalCounts,
  reconcileRemovalResult,
} from '../graph-write/write.protocol';
import { displayText } from './display';
import type { RemovalExecutionOptions, RemovalExecutor } from './executors';
import {
  DEFAULT_SAME_MESSAGE_SPREAD_MINUTES,
  computeLiveRemovalScope,
} from './removal.eligibility';
import { stripAngleBrackets } from '../graph/trace.operations';
import {
  ActionResult,
  IncidentReach,
  RemovalMailbox,
  RemovalScope,
  RemovedMailbox,
  ResponseAction,
} from './response.types';
import { recheckRemoval } from './scope';

const logger = createLogger('campaign-response');

/** Main-function time kept for the removal notices and the approver's reply */
const MAIN_RESERVE_MS = 25_000;
/**
 * Time between the write broker's own deadline and the moment this stops
 * waiting: the invoke round trip plus a cold start (bundle load, the
 * certificate from Secrets Manager, the first token), so a cold write
 * broker still answers before the main function gives up on it.
 */
export const CALL_OVERHEAD_MS = 10_000;
/** Mailboxes listed by address in the approver's reply */
const MAX_LISTED_MAILBOXES = 10;

export interface LiveRemovalExecutorOptions {
  client: Pick<GraphWriteBrokerClient, 'removeMessages'>;
}

function chunk(mailboxes: RemoveMessagesMailbox[]): RemoveMessagesMailbox[][] {
  const batches: RemoveMessagesMailbox[][] = [];
  let current: RemoveMessagesMailbox[] = [];
  let messages = 0;
  for (const mailbox of mailboxes) {
    if (
      current.length >= MAX_WRITE_MAILBOXES_PER_CALL ||
      messages + mailbox.messages.length > MAX_WRITE_MESSAGES_PER_CALL
    ) {
      batches.push(current);
      current = [];
      messages = 0;
    }
    current.push(mailbox);
    messages += mailbox.messages.length;
  }
  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

/**
 * The request entry for one re-checked mailbox: each remaining copy with
 * the check the approved scope recorded for it. A copy without a recorded
 * check is not sent (counted by the caller).
 */
function toRequest(
  mailbox: RemovalMailbox,
  anchorMessageId: string | undefined
): {
  request?: RemoveMessagesMailbox;
  unchecked: number;
  notSameMessage: number;
} {
  // A scope stored by the version that also admitted copies on message
  // size may name copies with another Message-ID: never sent
  const allChecks = mailbox.verify ?? [];
  const sameMessage = allChecks.filter(
    check =>
      anchorMessageId !== undefined &&
      stripAngleBrackets(check.internetMessageId.trim()) ===
        stripAngleBrackets(anchorMessageId.trim())
  );
  const checks = new Map(sameMessage.map(check => [check.messageId, check]));
  const stillNamed = new Set(mailbox.messageIds);
  const notSameMessage = allChecks.filter(
    check => !sameMessage.includes(check) && stillNamed.has(check.messageId)
  ).length;
  const messages = mailbox.messageIds
    .map(id => checks.get(id))
    .filter((check): check is NonNullable<typeof check> => check !== undefined)
    .slice(0, MAX_WRITE_MESSAGES_PER_MAILBOX)
    .map(check => ({
      messageId: check.messageId,
      expectedInternetMessageId: check.internetMessageId,
      expectedSenderAddress: check.senderAddress,
      expectedSubjectSha256: check.subjectHash,
      receivedFrom: check.receivedFrom,
      receivedTo: check.receivedTo,
    }));
  return {
    ...(messages.length > 0 ? { request: { mailboxId: mailbox.mailboxId, messages } } : {}),
    unchecked: mailbox.messageIds.length - messages.length - notSameMessage,
    notSameMessage,
  };
}

const messagesIn = (batch: RemoveMessagesMailbox[]): number =>
  batch.reduce((n, mailbox) => n + mailbox.messages.length, 0);

export class LiveRemovalExecutor implements RemovalExecutor {
  readonly name = 'graph_write_removal';
  readonly changesMailboxes = true;

  private readonly client: Pick<GraphWriteBrokerClient, 'removeMessages'>;

  constructor(options: LiveRemovalExecutorOptions) {
    this.client = options.client;
  }

  async execute(
    action: ResponseAction,
    approved: RemovalScope,
    currentReach: IncidentReach,
    options: RemovalExecutionOptions = {}
  ): Promise<ActionResult> {
    const counts = emptyRemovalCounts();
    const removed: RemovedMailbox[] = [];
    const errorMailboxes = new Set<string>();
    const unknownMailboxes = new Set<string>();
    let notAttemptedForTime = 0;
    let unchecked = 0;
    let notSameMessage = 0;
    let refusal: string | undefined;

    // 1. The same re-check the dry run uses: never wider than approved
    const { mailboxes: still, counts: recheck } = recheckRemoval(approved, currentReach);
    const addressOf = new Map(approved.mailboxes.map(m => [m.mailboxId, m.address]));

    // 2. Each copy with its own recorded check; none without one
    const requests: RemoveMessagesMailbox[] = [];
    for (const mailbox of still) {
      const entry = toRequest(mailbox, approved.live?.anchor.internetMessageId);
      if (entry.request) {
        requests.push(entry.request);
      }
      if (entry.unchecked > 0) {
        unchecked += entry.unchecked;
        countOutcome(counts, 'not_attempted', entry.unchecked);
      }
      if (entry.notSameMessage > 0) {
        notSameMessage += entry.notSameMessage;
        countOutcome(counts, 'not_attempted', entry.notSameMessage);
      }
    }

    // 3. One call per batch, while there is time
    const batches = chunk(requests);
    for (let index = 0; index < batches.length; index++) {
      const batch = batches[index];
      const remaining = options.getRemainingMs?.();
      const available =
        remaining === undefined
          ? MAX_WRITE_BUDGET_MS + CALL_OVERHEAD_MS
          : Math.min(MAX_WRITE_BUDGET_MS + CALL_OVERHEAD_MS, remaining - MAIN_RESERVE_MS);
      const budgetMs = Math.floor(available - CALL_OVERHEAD_MS);
      if (refusal || budgetMs < MIN_WRITE_BUDGET_MS) {
        // Not sent: out of time, or the write broker already refused
        const left = batches.slice(index).reduce((n, b) => n + messagesIn(b), 0);
        countOutcome(counts, 'not_attempted', left);
        if (!refusal) {
          notAttemptedForTime += left;
        }
        break;
      }

      const call = await this.client.removeMessages(
        { actionId: action.id, mailboxes: batch, budgetMs },
        available
      );

      if (!call.ok) {
        if (failureChangedNothing(call.failure, call.refusal)) {
          countOutcome(counts, 'not_attempted', messagesIn(batch));
          if (call.failure === 'refused') {
            refusal = call.refusal ?? 'refused';
          }
        } else {
          // The write broker may have moved some of them: say so, and
          // tell nobody their copy was removed
          countOutcome(counts, 'unknown', messagesIn(batch));
          for (const mailbox of batch) {
            unknownMailboxes.add(mailbox.mailboxId);
          }
        }
        continue;
      }

      for (const mailbox of reconcileRemovalResult({ mailboxes: batch }, call.result)) {
        let moved = 0;
        for (const message of mailbox.messages) {
          countOutcome(counts, message.outcome);
          if (message.outcome === 'moved') {
            moved += 1;
          }
          if (message.outcome === 'error') {
            errorMailboxes.add(mailbox.mailboxId);
          }
          if (message.outcome === 'unknown') {
            unknownMailboxes.add(mailbox.mailboxId);
          }
          if (
            message.outcome === 'not_attempted' &&
            (message.reason === 'time_budget' || message.reason === 'throttled')
          ) {
            notAttemptedForTime += 1;
          }
        }
        if (moved > 0) {
          removed.push({ mailboxId: mailbox.mailboxId, messages: moved });
        }
      }
    }

    // Copies the latest reach shows that the anchor rule would admit but the
    // approved scope does not name: reported, never included
    const newEligible = this.newEligibleSinceApproval(approved, currentReach);

    this.emitMetrics(counts);
    logger.info('Campaign removal executed', {
      incidentId: action.incidentId,
      actionId: action.id,
      mailboxes: still.length,
      calls: batches.length,
      ...counts,
      refusal,
    });

    const list = (ids: Set<string>): { shown: string[]; more: number } => {
      const shown = [...ids]
        .map(id => displayText(addressOf.get(id)) ?? 'unknown address')
        .slice(0, MAX_LISTED_MAILBOXES);
      return { shown, more: ids.size - shown.length };
    };
    const summary = this.summary(counts, {
      mailboxesRemoved: removed.length,
      newSinceApproval: newEligible,
      noLongerMatched: recheck.noLongerMatched,
      unchecked,
      notSameMessage,
      notAttemptedForTime,
      refusal,
      errors: list(errorMailboxes),
      unknown: list(unknownMailboxes),
    });

    return {
      executor: this.name,
      dryRun: false,
      summary,
      removalOutcome: { ...counts },
      removed,
    };
  }

  private newEligibleSinceApproval(approved: RemovalScope, current: IncidentReach): number {
    if (!approved.live) {
      return 0;
    }
    const named = new Set(approved.mailboxes.flatMap(m => m.messageIds));
    const now = computeLiveRemovalScope(
      current,
      { maxMailboxes: Number.MAX_SAFE_INTEGER, maxMessages: Number.MAX_SAFE_INTEGER },
      approved.live.anchor,
      {
        sameMessageSpreadMinutes:
          approved.live.sameMessageSpreadMinutes ?? DEFAULT_SAME_MESSAGE_SPREAD_MINUTES,
      }
    );
    return now.mailboxes.flatMap(m => m.messageIds).filter(id => !named.has(id)).length;
  }

  private emitMetrics(counts: RemovalOutcomeCounts): void {
    emitCampaignResponseMetric('CampaignMessagesRemoved', counts.moved);
    emitCampaignResponseMetric('CampaignRemovalErrors', counts.error + counts.unknown);
    emitCampaignResponseMetric('CampaignRemovalRefused', counts.mismatch, { Reason: 'mismatch' });
    emitCampaignResponseMetric('CampaignRemovalRefused', counts.notAllowed, {
      Reason: 'not_allowed',
    });
    emitCampaignResponseMetric('CampaignRemovalNotAttempted', counts.notAttempted);
  }

  private summary(
    counts: RemovalOutcomeCounts,
    detail: {
      mailboxesRemoved: number;
      newSinceApproval: number;
      noLongerMatched: number;
      unchecked: number;
      notSameMessage: number;
      notAttemptedForTime: number;
      refusal?: string;
      errors: { shown: string[]; more: number };
      unknown: { shown: string[]; more: number };
    }
  ): string[] {
    const named = (l: { shown: string[]; more: number }): string =>
      `${l.shown.join(', ')}${l.more > 0 ? ` and ${l.more} more` : ''}`;
    const lines = [
      `Removal carried out by the Graph write broker: ${counts.moved} message(s) moved to Deleted Items in ${detail.mailboxesRemoved} mailbox(es). Nothing was permanently deleted; each person can restore the message from Deleted Items.`,
      `  moved to Deleted Items: ${counts.moved}`,
      `  already in Deleted Items (left there): ${counts.alreadyDeleted}`,
      `  not found (already moved or purged; left alone): ${counts.notFound}`,
      `  refused, no longer provably the approved email (Message-ID, sender, subject or arrival time differed; left alone): ${counts.mismatch}`,
      `  refused, mailbox outside the write broker's allowlist: ${counts.notAllowed}`,
      `  errors: ${counts.error}`,
      `  not attempted: ${counts.notAttempted}`,
    ];
    if (counts.unknown > 0) {
      lines.push(
        `  outcome unknown: ${counts.unknown}`,
        `The write broker did not answer in time for ${counts.unknown} message(s) in ${detail.unknown.shown.length + detail.unknown.more} mailbox(es) (${named(detail.unknown)}). Some of them may have been moved. Those people were NOT sent a removal notice. To check, look in the write broker's log for this action's line (it gives the moved count) or in those mailboxes' Deleted Items, and tell those people yourself if their copy was moved.`
      );
    }
    if (detail.refusal) {
      lines.push(
        `The write broker refused the request (${detail.refusal}): no further mailboxes were sent. ${
          detail.refusal === 'write_disabled'
            ? 'Its kill switch (PHISHY_GRAPH_WRITE_ENABLED) is off.'
            : 'See its log.'
        }`
      );
    }
    if (detail.notAttemptedForTime > 0) {
      lines.push(
        `${detail.notAttemptedForTime} message(s) were not attempted because the time available ran out or Microsoft throttled the requests. Approve a new removal from the next incident update to finish.`
      );
    }
    if (detail.unchecked > 0) {
      lines.push(
        `${detail.unchecked} message(s) were not attempted: the approved scope recorded no check for them. They were left alone.`
      );
    }
    if (detail.notSameMessage > 0) {
      lines.push(
        `${detail.notSameMessage} message(s) were not attempted: they were proposed because their size matched, not because they carry the reported copy's Internet Message-ID, and this version of Phishy removes only copies with that Message-ID. They were left alone.`
      );
    }
    if (detail.noLongerMatched > 0) {
      lines.push(
        `${detail.noLongerMatched} approved message(s) were no longer found where the latest lookup looked; they were not sent for removal.`
      );
    }
    if (detail.newSinceApproval > 0) {
      lines.push(
        `${detail.newSinceApproval} newer copy(ies) of the same email were found that the approved scope does not name; they were not included (a new approval would be needed).`
      );
    }
    if (detail.errors.shown.length > 0) {
      lines.push(`Mailboxes with errors: ${named(detail.errors)}.`);
    }
    return lines;
  }
}

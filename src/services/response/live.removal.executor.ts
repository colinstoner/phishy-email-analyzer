/**
 * The live removal executor: carries out an approved, re-checked removal by
 * asking the Graph write broker (a separate function with its own
 * credential) to move exactly those copies to Deleted Items.
 *
 * Selected by `createRemovalExecutor` only when
 * `campaignResponse.removal.mode` is `live` and a write broker function is
 * configured; the dry run stays the default. This module never talks to
 * Microsoft and holds no Graph credential: it only invokes the write broker
 * through `GraphWriteBrokerClient`.
 *
 * What it sends, and never more:
 * - `recheckRemoval` runs first, exactly as for the dry run: only approved
 *   message IDs the incident's latest reach still shows are kept, per
 *   approved mailbox; copies new since approval are never included and the
 *   scope is never widened.
 * - Per mailbox: the approved scope's mailbox ID, those message IDs, and the
 *   Internet Message-IDs the scope recorded for them. A mailbox whose scope
 *   has no recorded Internet Message-ID (proposed before they were recorded)
 *   is not sent at all: nothing could be checked, so nothing is attempted.
 *   No address is sent.
 * - In batches within the write protocol's bounds, one at a time, while the
 *   main function has time; what is left is reported `not_attempted`.
 *
 * What it returns: `dryRun: false`, a summary for the approver by outcome,
 * `removalOutcome` (the counts, recorded in the audit row), and `removed`:
 * per mailbox, the copies the write broker reported `moved`. That list, and
 * only that list, is what makes `CampaignResponseService.sendRemovalNotices`
 * email anyone (by the address the approved scope recorded, safe-domain
 * checked). When the write broker's answer is missing or unusable, every
 * message in that call is `unknown`: nobody is told their copy was removed.
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
import { MESSAGE_ID_PATTERN } from '../graph/graph.limits';
import { displayText } from './display';
import type { RemovalExecutionOptions, RemovalExecutor } from './executors';
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
/** Time between the write broker's own deadline and the moment this stops waiting */
const CALL_OVERHEAD_MS = 3000;
/** Mailboxes with errors listed by address in the approver's reply */
const MAX_LISTED_ERROR_MAILBOXES = 10;

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
      messages + mailbox.messageIds.length > MAX_WRITE_MESSAGES_PER_CALL
    ) {
      batches.push(current);
      current = [];
      messages = 0;
    }
    current.push(mailbox);
    messages += mailbox.messageIds.length;
  }
  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

/** The request entry for one approved mailbox, or undefined when it cannot be checked */
function toRequest(mailbox: RemovalMailbox): RemoveMessagesMailbox | undefined {
  const expected = (mailbox.internetMessageIds ?? []).filter(id => MESSAGE_ID_PATTERN.test(id));
  if (expected.length === 0 || mailbox.messageIds.length === 0) {
    return undefined;
  }
  return {
    mailboxId: mailbox.mailboxId,
    messageIds: mailbox.messageIds.slice(0, MAX_WRITE_MESSAGES_PER_MAILBOX),
    expectedInternetMessageIds: expected.slice(0, MAX_WRITE_MESSAGES_PER_MAILBOX),
  };
}

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
    let notAttemptedForTime = 0;
    let noExpectedId = 0;
    let refusal: string | undefined;

    // 1. The same re-check the dry run uses: never wider than approved
    const { mailboxes: still, counts: recheck } = recheckRemoval(approved, currentReach);
    const addressOf = new Map(approved.mailboxes.map(m => [m.mailboxId, m.address]));

    // 2. Only mailboxes whose copies can be checked by Internet Message-ID
    const requests: RemoveMessagesMailbox[] = [];
    for (const mailbox of still) {
      const request = toRequest(mailbox);
      if (request) {
        requests.push(request);
        const cut = mailbox.messageIds.length - request.messageIds.length;
        if (cut > 0) {
          countOutcome(counts, 'not_attempted', cut);
        }
      } else {
        noExpectedId += mailbox.messageIds.length;
        countOutcome(counts, 'not_attempted', mailbox.messageIds.length);
      }
    }

    // 3. One call per batch, while there is time
    const batches = chunk(requests);
    for (let index = 0; index < batches.length; index++) {
      const batch = batches[index];
      const messagesInBatch = batch.reduce((n, m) => n + m.messageIds.length, 0);
      const remaining = options.getRemainingMs?.();
      const available =
        remaining === undefined
          ? MAX_WRITE_BUDGET_MS + CALL_OVERHEAD_MS
          : Math.min(MAX_WRITE_BUDGET_MS + CALL_OVERHEAD_MS, remaining - MAIN_RESERVE_MS);
      const budgetMs = Math.floor(available - CALL_OVERHEAD_MS);
      if (refusal || budgetMs < MIN_WRITE_BUDGET_MS) {
        // Not sent: out of time, or the write broker already refused
        const left = batches
          .slice(index)
          .reduce((n, b) => n + b.reduce((m, mailbox) => m + mailbox.messageIds.length, 0), 0);
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
        if (failureChangedNothing(call.failure)) {
          countOutcome(counts, 'not_attempted', messagesInBatch);
          if (call.failure === 'refused') {
            refusal = call.refusal ?? 'refused';
          }
        } else {
          // The write broker may have moved some of them: say so, and
          // tell nobody their copy was removed
          countOutcome(counts, 'unknown', messagesInBatch);
          for (const mailbox of batch) {
            errorMailboxes.add(mailbox.mailboxId);
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
          if (message.outcome === 'error' || message.outcome === 'unknown') {
            errorMailboxes.add(mailbox.mailboxId);
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

    this.emitMetrics(counts);
    logger.info('Campaign removal executed', {
      incidentId: action.incidentId,
      actionId: action.id,
      mailboxes: still.length,
      calls: batches.length,
      ...counts,
      refusal,
    });

    const summary = this.summary(counts, {
      mailboxesRemoved: removed.length,
      newSinceApproval: recheck.newSinceApproval,
      noLongerMatched: recheck.noLongerMatched,
      noExpectedId,
      notAttemptedForTime,
      refusal,
      errorAddresses: [...errorMailboxes]
        .map(id => displayText(addressOf.get(id)) ?? 'unknown address')
        .slice(0, MAX_LISTED_ERROR_MAILBOXES),
      errorMailboxes: errorMailboxes.size,
    });

    return {
      executor: this.name,
      dryRun: false,
      summary,
      removalOutcome: { ...counts },
      removed,
    };
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
      noExpectedId: number;
      notAttemptedForTime: number;
      refusal?: string;
      errorAddresses: string[];
      errorMailboxes: number;
    }
  ): string[] {
    const lines = [
      `Removal carried out by the Graph write broker: ${counts.moved} message(s) moved to Deleted Items in ${detail.mailboxesRemoved} mailbox(es). Nothing was permanently deleted; each person can restore the message from Deleted Items.`,
      `  moved to Deleted Items: ${counts.moved}`,
      `  already in Deleted Items (left there): ${counts.alreadyDeleted}`,
      `  not found (already moved or purged; left alone): ${counts.notFound}`,
      `  refused, not the approved message (Internet Message-ID did not match; left alone): ${counts.mismatch}`,
      `  refused, mailbox outside the write broker's allowlist: ${counts.notAllowed}`,
      `  errors: ${counts.error}`,
      `  not attempted: ${counts.notAttempted}`,
    ];
    if (counts.unknown > 0) {
      lines.push(
        `  outcome unknown (the write broker did not answer in time; some may have been moved): ${counts.unknown}`
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
    if (detail.noExpectedId > 0) {
      lines.push(
        `${detail.noExpectedId} message(s) were not attempted: the approved scope did not record their Internet Message-ID, so they could not be checked. They were left alone.`
      );
    }
    if (detail.noLongerMatched > 0) {
      lines.push(
        `${detail.noLongerMatched} approved message(s) were no longer found where the latest lookup looked; they were not sent for removal.`
      );
    }
    if (detail.newSinceApproval > 0) {
      lines.push(
        `${detail.newSinceApproval} newer copy(ies) were found that the approved scope does not name; they were not included (a new approval would be needed).`
      );
    }
    if (detail.errorMailboxes > 0) {
      const more = detail.errorMailboxes - detail.errorAddresses.length;
      lines.push(
        `Mailboxes with errors or an unknown outcome: ${detail.errorAddresses.join(', ')}${more > 0 ? ` and ${more} more` : ''}.`
      );
    }
    return lines;
  }
}

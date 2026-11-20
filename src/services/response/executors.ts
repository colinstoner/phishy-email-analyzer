/**
 * Response-action executors.
 *
 * An executor carries out one approved action whose scope the service has
 * already re-checked. Two exist in this version:
 *
 * - `SesWarningExecutor` sends the employee warning, one email per person
 *   (nobody sees another address), through SES, to safe-domain addresses
 *   only. It also sends the removal notice (below), the same way.
 * - `DryRunRemovalExecutor` for "remove remaining copies": it records what
 *   a removal WOULD do and changes nothing. No Graph write exists anywhere
 *   in Phishy.
 *
 * The seam for a real removal (not built): a `RemovalExecutor` with
 * `changesMailboxes: true`, in its own module, that sends the approved
 * scope — mailbox IDs and Graph message IDs, never a search — to a second,
 * separate broker function holding its own certificate and `Mail.ReadWrite`.
 * The main function and the read broker never hold that credential.
 * `createRemovalExecutor` is where it would be chosen. It must return
 * `dryRun: false` and list in `removed` each mailbox a copy was actually
 * moved out of: only those mailboxes get the removal notice. Until that
 * tier exists, no removal notice is ever sent.
 */

import { EmailSendResult } from '../../types';
import { createLogger } from '../../utils/logger';
import { emitCampaignResponseMetric } from '../../utils/metrics';
import {
  RenderedEmail,
  WarningContext,
  buildDistributionWarning,
  buildEmployeeWarning,
  buildRemovalNotice,
} from '../../templates/campaign.response.html';
import {
  ActionResult,
  CampaignIncident,
  IncidentReach,
  RemovalScope,
  ResponseAction,
  WarningScope,
} from './response.types';
import { isSafeRecipient, recheckRemoval } from './scope';

const logger = createLogger('campaign-response');

/** Sends one email to one address (no Cc) */
export interface WarningMailer {
  sendEmail(
    recipient: string,
    subject: string,
    htmlBody: string,
    textBody: string,
    ccAddresses?: string[]
  ): Promise<EmailSendResult>;
}

/** Stop starting new sends when the Lambda has less than this left */
const SEND_RESERVE_MS = 8000;
/** Warnings sent at once (SES default sending rates are low) */
const SEND_CONCURRENCY = 4;

export interface WarningExecutionContext {
  incident: CampaignIncident;
  warning: Omit<WarningContext, 'warnedCount'>;
  safeDomains: string[];
  distributionList?: string;
  getRemainingMs?: () => number | undefined;
}

export class SesWarningExecutor {
  readonly name = 'ses_warning';
  readonly changesMailboxes = false;

  constructor(private readonly mailer: WarningMailer) {}

  private outOfTime(context: Pick<WarningExecutionContext, 'getRemainingMs'>): boolean {
    const remaining = context.getRemainingMs?.();
    return remaining !== undefined && remaining < SEND_RESERVE_MS;
  }

  /** One email to one address; false when skipped (unsafe) or SES failed (`onFailure` called) */
  private async send(
    address: string,
    email: RenderedEmail,
    safeDomains: string[],
    onFailure: () => void
  ): Promise<boolean> {
    // Invariant 4, applied again at the moment of sending
    if (!isSafeRecipient(address, safeDomains)) {
      emitCampaignResponseMetric('CampaignWarningsSkipped', 1, { Reason: 'unsafe_address' });
      return false;
    }
    try {
      const result = await this.mailer.sendEmail(
        address,
        email.subject,
        email.html,
        email.text,
        []
      );
      if (result.success) {
        return true;
      }
    } catch {
      // counted by the caller
    }
    onFailure();
    return false;
  }

  /** Send one email to each address, a few at a time, stopping when time runs short */
  private async sendEach(
    addresses: string[],
    build: (address: string, index: number) => RenderedEmail,
    context: Pick<WarningExecutionContext, 'getRemainingMs' | 'safeDomains'>
  ): Promise<{ sent: string[]; failed: number; notSentForTime: number }> {
    const sent: string[] = [];
    let failed = 0;
    let notSentForTime = 0;
    const queue = addresses.map((address, index) => ({ address, index }));
    const workers = Array.from({ length: Math.min(SEND_CONCURRENCY, queue.length) }, async () => {
      for (;;) {
        const next = queue.shift();
        if (!next) {
          return;
        }
        if (this.outOfTime(context)) {
          notSentForTime += 1;
          continue;
        }
        const ok = await this.send(
          next.address,
          build(next.address, next.index),
          context.safeDomains,
          () => {
            failed += 1;
          }
        );
        if (ok) {
          sent.push(next.address);
        }
      }
    });
    await Promise.all(workers);
    return { sent, failed, notSentForTime };
  }

  async execute(scope: WarningScope, context: WarningExecutionContext): Promise<ActionResult> {
    let distributionSent = false;

    // 1. The people who received it (reporters are never in the scope)
    const recipients = scope.recipients;
    const sent = await this.sendEach(
      recipients.map(r => r.address),
      (_address, index) => buildEmployeeWarning(context.warning, recipients[index]),
      context
    );
    const warned = sent.sent;
    let failed = sent.failed;
    const notSentForTime = sent.notSentForTime;

    // 2. The distribution list, when the approved scope includes it
    if (scope.distribution && context.distributionList) {
      distributionSent = await this.send(
        context.distributionList,
        buildDistributionWarning(context.warning),
        context.safeDomains,
        () => {
          failed += 1;
        }
      );
    }

    emitCampaignResponseMetric('CampaignWarningsSent', warned.length, { Audience: 'recipients' });
    emitCampaignResponseMetric('CampaignWarningsSent', distributionSent ? 1 : 0, {
      Audience: 'distribution',
    });
    emitCampaignResponseMetric('CampaignWarningSendFailures', failed);
    emitCampaignResponseMetric('CampaignWarningsSkipped', notSentForTime, { Reason: 'no_time' });
    logger.info('Campaign warning sent', {
      incidentId: context.incident.id,
      warned: warned.length,
      distributionSent,
      failed,
      notSentForTime,
    });

    const summary = [`Warned ${warned.length} recipient(s), each in a separate email.`];
    if (scope.distribution) {
      summary.push(
        distributionSent
          ? 'Sent the warning to the distribution list.'
          : 'The warning to the distribution list was NOT sent.'
      );
    }
    if (failed > 0) {
      summary.push(`${failed} email(s) could not be sent (SES refused or failed).`);
    }
    if (notSentForTime > 0) {
      summary.push(
        `${notSentForTime} email(s) were not sent because processing time ran out; they will be proposed again in the next incident update.`
      );
    }
    return {
      executor: this.name,
      dryRun: false,
      summary,
      warned,
      distributionSent,
      failed,
      notSentForTime,
    };
  }

  /**
   * The removal notice, one email per person, to addresses the service has
   * already checked (taken from the approved removal scope for mailboxes the
   * write tier reported as actually changed; never twice; within the cap).
   * Safe-domain checked again here. Never called after a dry run.
   */
  async sendRemovalNotices(
    addresses: string[],
    context: Omit<WarningExecutionContext, 'distributionList'>
  ): Promise<{ notified: string[]; failed: number; notSentForTime: number }> {
    const notice = buildRemovalNotice(context.warning);
    const { sent, failed, notSentForTime } = await this.sendEach(addresses, () => notice, context);
    emitCampaignResponseMetric('CampaignRemovalNoticesSent', sent.length);
    emitCampaignResponseMetric('CampaignWarningSendFailures', failed);
    emitCampaignResponseMetric('CampaignWarningsSkipped', notSentForTime, { Reason: 'no_time' });
    logger.info('Campaign removal notices sent', {
      incidentId: context.incident.id,
      notified: sent.length,
      failed,
      notSentForTime,
    });
    return { notified: sent, failed, notSentForTime };
  }
}

/** What a removal executor is given: the approved, re-checked scope */
export interface RemovalExecutor {
  readonly name: string;
  /** False for the dry run. A real implementation must be a separate module and credential. */
  readonly changesMailboxes: boolean;
  /**
   * A real implementation returns `dryRun: false` and `removed` (per
   * mailbox, by the approved scope's mailbox ID, the copies actually moved
   * to Deleted Items): that list is what triggers the removal notices.
   */
  execute(
    action: ResponseAction,
    approved: RemovalScope,
    currentReach: IncidentReach
  ): Promise<ActionResult>;
}

export const WRITE_TIER_NOT_INSTALLED =
  'No mailbox was changed: the mailbox write tier is not installed in this version of Phishy.';

export class DryRunRemovalExecutor implements RemovalExecutor {
  readonly name = 'dry_run_removal';
  readonly changesMailboxes = false;

  execute(
    action: ResponseAction,
    approved: RemovalScope,
    currentReach: IncidentReach
  ): Promise<ActionResult> {
    const { counts } = recheckRemoval(approved, currentReach);
    emitCampaignResponseMetric('ResponseActionsDryRun', 1, { ActionType: action.type });
    const summary = [
      `DRY RUN. Phishy re-checked the approved scope and would remove ${counts.messages} message(s) from ${counts.mailboxes} mailbox(es):`,
      `  unread in the inbox: ${counts.unreadInInbox}`,
      `  read in the inbox: ${counts.readInInbox}`,
      `  in Junk Email: ${counts.inJunk}`,
      `  already in Deleted Items: ${counts.alreadyInDeletedItems}`,
      `  in another folder: ${counts.elsewhere}`,
    ];
    if (counts.noLongerMatched > 0) {
      summary.push(
        `${counts.noLongerMatched} approved message(s) were no longer found where the latest lookup looked (already purged or moved); they would be left alone.`
      );
    }
    if (counts.newSinceApproval > 0) {
      summary.push(
        `${counts.newSinceApproval} newer copy(ies) were found that the approved scope does not name; they are not included (a new approval would be needed).`
      );
    }
    if (currentReach.lookedUpAt) {
      summary.push(`Mailbox states as of the blast-radius lookup at ${currentReach.lookedUpAt}.`);
    }
    summary.push(WRITE_TIER_NOT_INSTALLED);
    return Promise.resolve({ executor: this.name, dryRun: true, summary, wouldRemove: counts });
  }
}

/**
 * The removal executor for this deployment. Always the dry run: the write
 * tier (a separate broker function with its own certificate and
 * `Mail.ReadWrite`) is not built.
 */
export function createRemovalExecutor(): RemovalExecutor {
  return new DryRunRemovalExecutor();
}

/**
 * Response-action executors.
 *
 * An executor carries out one approved action whose scope the service has
 * already re-checked. Two exist in this version:
 *
 * - `SesWarningExecutor` sends the employee warning and the reporters'
 *   thank-you notes, one email per person (nobody sees another address),
 *   through SES, to safe-domain addresses only.
 * - `DryRunRemovalExecutor` for "remove remaining copies": it records what
 *   a removal WOULD do and changes nothing. No Graph write exists anywhere
 *   in Phishy.
 *
 * The seam for a real removal (not built): a `RemovalExecutor` with
 * `changesMailboxes: true`, in its own module, that sends the approved
 * scope — mailbox IDs and Graph message IDs, never a search — to a second,
 * separate broker function holding its own certificate and `Mail.ReadWrite`.
 * The main function and the read broker never hold that credential.
 * `createRemovalExecutor` is where it would be chosen.
 */

import { EmailSendResult } from '../../types';
import { createLogger } from '../../utils/logger';
import { emitCampaignResponseMetric } from '../../utils/metrics';
import {
  RenderedEmail,
  WarningContext,
  buildDistributionWarning,
  buildEmployeeWarning,
  buildReporterThanks,
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

  async execute(scope: WarningScope, context: WarningExecutionContext): Promise<ActionResult> {
    const warned: string[] = [];
    const thanked: string[] = [];
    let failed = 0;
    let notSentForTime = 0;
    let distributionSent = false;

    const outOfTime = (): boolean => {
      const remaining = context.getRemainingMs?.();
      return remaining !== undefined && remaining < SEND_RESERVE_MS;
    };

    const send = async (address: string, email: RenderedEmail): Promise<boolean> => {
      // Invariant 4, applied again at the moment of sending
      if (!isSafeRecipient(address, context.safeDomains)) {
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
        // counted below
      }
      failed += 1;
      return false;
    };

    // 1. The people who received it
    const queue = [...scope.recipients];
    const workers = Array.from({ length: Math.min(SEND_CONCURRENCY, queue.length) }, async () => {
      for (;;) {
        const recipient = queue.shift();
        if (!recipient) {
          return;
        }
        if (outOfTime()) {
          notSentForTime += 1;
          continue;
        }
        if (await send(recipient.address, buildEmployeeWarning(context.warning, recipient))) {
          warned.push(recipient.address);
        }
      }
    });
    await Promise.all(workers);

    // 2. The people who reported it
    const thanks = buildReporterThanks({ ...context.warning, warnedCount: warned.length });
    for (const reporter of scope.reporters) {
      if (outOfTime()) {
        notSentForTime += 1;
        continue;
      }
      if (await send(reporter, thanks)) {
        thanked.push(reporter);
      }
    }

    // 3. The distribution list, when the approved scope includes it
    if (scope.distribution && context.distributionList) {
      if (await send(context.distributionList, buildDistributionWarning(context.warning))) {
        distributionSent = true;
      }
    }

    emitCampaignResponseMetric('CampaignWarningsSent', warned.length, { Audience: 'recipients' });
    emitCampaignResponseMetric('CampaignThanksSent', thanked.length, { Audience: 'reporters' });
    emitCampaignResponseMetric('CampaignWarningsSent', distributionSent ? 1 : 0, {
      Audience: 'distribution',
    });
    emitCampaignResponseMetric('CampaignWarningSendFailures', failed);
    emitCampaignResponseMetric('CampaignWarningsSkipped', notSentForTime, { Reason: 'no_time' });
    logger.info('Campaign warning sent', {
      incidentId: context.incident.id,
      warned: warned.length,
      thanked: thanked.length,
      distributionSent,
      failed,
      notSentForTime,
    });

    const summary = [
      `Warned ${warned.length} recipient(s), each in a separate email.`,
      `Sent ${thanked.length} reporter(s) a thank-you note.`,
    ];
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
      thanked,
      distributionSent,
      failed,
      notSentForTime,
    };
  }
}

/** What a removal executor is given: the approved, re-checked scope */
export interface RemovalExecutor {
  readonly name: string;
  /** False for the dry run. A real implementation must be a separate module and credential. */
  readonly changesMailboxes: boolean;
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

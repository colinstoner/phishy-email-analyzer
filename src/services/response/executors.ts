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
  LISTED_IN_INCIDENT,
  RenderedEmail,
  WarningContext,
  buildDistributionWarning,
  buildEmployeeWarning,
  buildRemovalNotice,
} from '../../templates/campaign.response.html';
import { displayText, displayTime } from './display';
import {
  ActionResult,
  CampaignIncident,
  IncidentReach,
  RemovalRecipientCounts,
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

/** Addresses listed by name in a dry-run reply (the incident email's own listing limit) */
const LISTED_NOT_OPENED = LISTED_IN_INCIDENT;

/** "12 minutes", "1 hour 5 minutes", "less than a minute" */
function describeInterval(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) {
    return 'less than a minute';
  }
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  const part = (n: number, unit: string): string => `${n} ${unit}${n === 1 ? '' : 's'}`;
  if (hours === 0) {
    return part(minutes, 'minute');
  }
  return rest === 0 ? part(hours, 'hour') : `${part(hours, 'hour')} ${part(rest, 'minute')}`;
}

export interface DryRunRemovalOptions {
  /** IANA zone the reply's times are shown in (`campaignResponse.timeZone`) */
  timeZone?: string;
  /** Injected for tests; used only when the action carries no approval time */
  now?: () => Date;
}

/**
 * What a removal would do, from the incident's stored blast-radius data.
 * It reads no mailbox: the approval path has no Graph lookup, so the reply
 * says that the states come from the most recent lookup and how old it is,
 * never that the mailboxes were read again.
 */
export class DryRunRemovalExecutor implements RemovalExecutor {
  readonly name = 'dry_run_removal';
  readonly changesMailboxes = false;
  private readonly timeZone: string;
  private readonly now: () => Date;

  constructor(options: DryRunRemovalOptions = {}) {
    this.timeZone = options.timeZone ?? 'UTC';
    this.now = options.now ?? ((): Date => new Date());
  }

  execute(
    action: ResponseAction,
    approved: RemovalScope,
    currentReach: IncidentReach
  ): Promise<ActionResult> {
    const { counts, recipients, notOpened } = recheckRemoval(approved, currentReach);
    emitCampaignResponseMetric('ResponseActionsDryRun', 1, { ActionType: action.type });
    const toMove = counts.toMove ?? 0;
    const summary = [
      `DRY RUN. A removal would move ${toMove} copy(ies) in ${counts.toMoveMailboxes ?? 0} mailbox(es) to Deleted Items:`,
      `  unread in the inbox: ${counts.unreadInInbox}`,
      `  read in the inbox: ${counts.readInInbox}`,
      `  in Junk Email: ${counts.inJunk}`,
      `  in another folder, or one Phishy could not identify: ${counts.elsewhere}`,
      `Already in Deleted Items, left where they are: ${counts.alreadyInDeletedItems} copy(ies) in ${counts.alreadyInDeletedItemsMailboxes ?? 0} mailbox(es).`,
    ];
    if (counts.noLongerMatched > 0) {
      summary.push(
        `${counts.noLongerMatched} approved copy(ies) were no longer found where the most recent lookup looked (purged or moved); they would be left alone.`
      );
    }
    if (counts.newSinceApproval > 0) {
      summary.push(
        `${counts.newSinceApproval} newer copy(ies) were found that the approved scope does not name; they are not included (a new approval would be needed).`
      );
    }
    summary.push(...this.recipientLines(recipients, notOpened));
    summary.push(this.whenLine(action, currentReach));
    summary.push(WRITE_TIER_NOT_INSTALLED);
    return Promise.resolve({
      executor: this.name,
      dryRun: true,
      summary,
      wouldRemove: counts,
      removalRecipients: recipients,
    });
  }

  /** Every recipient in one category, so the numbers add up to the total */
  private recipientLines(recipients: RemovalRecipientCounts, notOpened: string[]): string[] {
    if (recipients.total === 0) {
      return ['The incident has no blast-radius recipients to account for.'];
    }
    const rows: Array<[number, string]> = [
      [recipients.toMove, 'a copy would be moved to Deleted Items'],
      [recipients.alreadyInDeletedItems, 'their copy is already in Deleted Items'],
      [
        recipients.noLongerMatched,
        'in the approved scope, but the approved copy is no longer matched (purged, moved, or the mailbox was not read again)',
      ],
      [
        recipients.onlyInRecoverableItems,
        'their copy is only in Recoverable Items (already deleted and emptied): nothing to move',
      ],
      [
        recipients.noCopyFound,
        'their mailbox was read and holds no copy (deleted and purged, or never placed in the mailbox)',
      ],
      [
        recipients.mailboxNotOpened,
        'delivered, but Phishy did not open the mailbox: not a mailbox it can read (such as a shared mailbox, group or alias), or the lookup did not reach it (time budget, mailbox cap or a failed request); the data does not say which',
      ],
      [recipients.notDelivered, 'not delivered (message trace)'],
      [recipients.noIdentifiers, 'a copy was found, but without a usable mailbox or message ID'],
      [
        recipients.notInApprovedScope,
        'a copy was found, but the approved scope does not name the mailbox (over a cap when it was proposed, or found by a later lookup); a new approval would be needed',
      ],
      [recipients.sameMailbox, 'another address of a mailbox already counted'],
      [
        recipients.unlisted,
        'counted by a lookup but not listed by it, so Phishy has no address for them',
      ],
    ];
    const lines = [`All ${recipients.total} recipient(s) the incident's lookups list or count:`];
    for (const [count, label] of rows) {
      if (count > 0) {
        lines.push(`  ${count}: ${label}`);
      }
    }
    const shown = notOpened
      .slice(0, LISTED_NOT_OPENED)
      .map(address => displayText(address, 120))
      .filter((address): address is string => !!address);
    if (shown.length > 0) {
      lines.push(
        'Mailboxes Phishy did not open (check these by hand):',
        ...shown.map(address => `  - ${address}`)
      );
      if (notOpened.length > shown.length) {
        lines.push(`  ${notOpened.length - shown.length} more not listed here.`);
      }
    }
    return lines;
  }

  /** When the states were read: the stored lookup, never a claimed re-read */
  private whenLine(action: ResponseAction, reach: IncidentReach): string {
    const read = 'Phishy did not read the mailboxes again for this dry run.';
    const lookedUp = Date.parse(reach.lookedUpAt ?? '');
    if (!Number.isFinite(lookedUp)) {
      return `Mailbox states come from the incident's blast-radius data; when it was looked up is not recorded. ${read}`;
    }
    const at = displayTime(reach.lookedUpAt, this.timeZone) ?? reach.lookedUpAt;
    const approvedAt = (action.approvedAt ?? this.now()).getTime();
    const age =
      approvedAt >= lookedUp
        ? `, ${describeInterval(approvedAt - lookedUp)} before this approval`
        : '';
    return `Mailbox states are compared with the incident's most recent blast-radius lookup, made at ${at}${age}. ${read}`;
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

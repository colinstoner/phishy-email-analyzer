/**
 * Campaign response: scopes, computed by code.
 *
 * Pure functions, no I/O. They decide who may be emailed and which mailbox
 * copies a removal may name, from Phishy's own blast-radius data, under the
 * configured caps. Nothing here reads the suspicious email: every address
 * comes from a Graph lookup Phishy made, or from the campaign's reporters
 * (`originalForwarder`, already safe-domain checked), and is checked again
 * against the safe domains before it may be emailed.
 */

import { createHash } from 'crypto';
import type { BlastRadiusRecipient, BlastRadiusReport } from '../graph/blast-radius.service';
import { domainMatches } from '../../utils/validation';
import {
  ActionScope,
  IncidentReach,
  RemovalCounts,
  RemovalMailbox,
  RemovalRecipientCounts,
  RemovalScope,
  WarningRecipient,
  WarningScope,
} from './response.types';

/** Most recipients an incident keeps across its lookups */
export const MAX_INCIDENT_RECIPIENTS = 1000;
/** Most caveat lines an incident keeps (from the latest lookup) */
const MAX_INCIDENT_CAVEATS = 12;

/** One plain address and nothing else (no display name, no comment, no spaces) */
const PLAIN_ADDRESS = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

/**
 * May Phishy email this address? Only a plain address whose domain is one
 * of the configured safe domains (or a subdomain of one): invariant 4's
 * rule, applied to every address campaign response emails, whatever its
 * source.
 */
export function isSafeRecipient(address: string | undefined, safeDomains: string[]): boolean {
  if (!address || address.length > 254 || !PLAIN_ADDRESS.test(address)) {
    return false;
  }
  const domain = address.split('@')[1].toLowerCase();
  return safeDomains.some(safe => domainMatches(domain, safe.trim().toLowerCase()));
}

function recount(recipients: BlastRadiusRecipient[]): IncidentReach['totals'] {
  const reached = recipients.filter(r => r.mailbox !== 'not_delivered');
  return {
    recipients: reached.length,
    read: reached.filter(r => r.isRead === true).length,
    replied: reached.filter(r => r.response === 'replied').length,
    forwarded: reached.filter(r => r.response === 'forwarded').length,
    stillInInbox: reached.filter(r => r.mailbox === 'found' && r.folder === 'inbox').length,
    notDelivered: recipients.length - reached.length,
  };
}

/** The empty reach for an incident with no usable lookup */
export function emptyReach(status: IncidentReach['status'], note?: string): IncidentReach {
  return {
    status,
    ...(note ? { note } : {}),
    totals: {
      recipients: 0,
      read: 0,
      replied: 0,
      forwarded: 0,
      stillInInbox: 0,
      notDelivered: 0,
    },
    unlisted: 0,
    recipients: [],
    caveats: [],
  };
}

/**
 * Fold one blast-radius lookup into the incident's reach. The newer lookup
 * wins for every recipient it lists (it is the current state of that
 * mailbox); recipients only an earlier lookup listed are kept. A failed
 * lookup changes nothing but the note.
 */
export function mergeReach(
  previous: IncidentReach | undefined,
  report: BlastRadiusReport | undefined,
  blastRadiusEnabled: boolean
): IncidentReach {
  if (!report) {
    return (
      previous ??
      emptyReach(
        blastRadiusEnabled ? 'unavailable' : 'not_enabled',
        blastRadiusEnabled ? undefined : 'Blast radius is not enabled.'
      )
    );
  }
  if (report.status === 'unavailable') {
    return previous && previous.recipients.length > 0
      ? { ...previous, note: report.note }
      : emptyReach('unavailable', report.note);
  }

  const byAddress = new Map<string, BlastRadiusRecipient>();
  for (const recipient of previous?.recipients ?? []) {
    byAddress.set(recipient.address.toLowerCase(), recipient);
  }
  for (const recipient of report.recipients ?? []) {
    byAddress.set(recipient.address.toLowerCase(), recipient);
  }
  const recipients = [...byAddress.values()].slice(0, MAX_INCIDENT_RECIPIENTS);
  const listed = report.recipients?.length ?? 0;
  const reportTotal = (report.totals?.recipients ?? listed) + (report.totals?.notDelivered ?? 0);
  const unlisted = Math.max(
    reportTotal - listed,
    previous?.unlisted ?? 0,
    byAddress.size - recipients.length
  );

  return {
    status: report.status,
    lookedUpAt: report.lookedUpAt,
    totals: recount(recipients),
    unlisted,
    recipients,
    caveats: (report.caveats ?? []).slice(0, MAX_INCIDENT_CAVEATS),
    ...(report.coverage
      ? {
          coverage: {
            mailboxesChecked: report.coverage.mailboxesChecked,
            mailboxesEligible: report.coverage.mailboxesEligible,
            lowerBound: report.coverage.eligibleIsLowerBound,
          },
        }
      : {}),
  };
}

/** Earliest delivery time any mailbox recorded, when known */
export function firstDelivery(reach: IncidentReach): string | undefined {
  let earliest: number | undefined;
  for (const recipient of reach.recipients) {
    const at = Date.parse(recipient.receivedAt ?? '');
    if (Number.isFinite(at) && (earliest === undefined || at < earliest)) {
      earliest = at;
    }
  }
  return earliest === undefined ? undefined : new Date(earliest).toISOString();
}

export interface WarningScopeInput {
  reach: IncidentReach;
  /** Addresses that reported the campaign (`campaigns.unique_recipients`): never warned */
  reporters: string[];
  safeDomains: string[];
  /** Addresses already emailed for this campaign */
  alreadyContacted: Set<string>;
  /** Employee emails this campaign may still send */
  remaining: number;
  targeted: boolean;
  distribution: boolean;
}

/**
 * Who a warning goes to. Recipients whose copy was never delivered are
 * never warned. Reporters are not warned either: they reported it
 * themselves.
 */
export function computeWarningScope(input: WarningScopeInput): WarningScope {
  const skipped = {
    notDelivered: 0,
    unsafeAddress: 0,
    alreadyContacted: 0,
    overCap: 0,
    unlisted: input.targeted ? input.reach.unlisted : 0,
  };
  const reporters = new Set(input.reporters.map(address => address.trim().toLowerCase()));
  const targets: WarningRecipient[] = [];
  const seen = new Set<string>();

  if (input.targeted) {
    for (const recipient of input.reach.recipients) {
      const address = recipient.address.trim().toLowerCase();
      if (seen.has(address)) {
        continue;
      }
      seen.add(address);
      // not_checked on the trace route: message trace says delivered, the
      // mailbox was not read (a shared mailbox, or the lookup ran out of time)
      if (reporters.has(address)) {
        continue; // a reporter: they reported it themselves
      } else if (recipient.mailbox === 'not_delivered' || recipient.mailbox === 'not_found') {
        skipped.notDelivered += 1;
      } else if (!isSafeRecipient(address, input.safeDomains)) {
        skipped.unsafeAddress += 1;
      } else if (input.alreadyContacted.has(address)) {
        skipped.alreadyContacted += 1;
      } else {
        targets.push({
          address,
          ...(recipient.receivedAt ? { receivedAt: recipient.receivedAt } : {}),
          ...(recipient.folder ? { folder: recipient.folder } : {}),
        });
      }
    }
  }

  const recipients = targets.slice(0, Math.max(0, input.remaining));
  skipped.overCap = targets.length - recipients.length;

  return {
    kind: 'send_warning',
    recipients,
    distribution: input.distribution,
    skipped,
  };
}

export interface RemovalLimits {
  maxMailboxes: number;
  maxMessages: number;
}

/**
 * Which copies a removal would act on: exactly the Graph message IDs the
 * blast-radius lookup matched for this campaign, per mailbox. Never a
 * search expression. Purged copies are left out (nothing remains), as is
 * anything over the caps.
 */
export function computeRemovalScope(reach: IncidentReach, limits: RemovalLimits): RemovalScope {
  const skipped = { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 };
  const mailboxes: RemovalMailbox[] = [];
  let messageCount = 0;

  for (const recipient of reach.recipients) {
    if (recipient.mailbox !== 'found') {
      continue;
    }
    if (recipient.folder === 'recoverable') {
      skipped.alreadyPurged += 1;
      continue;
    }
    const ids = recipient.messageIds ?? [];
    if (!recipient.mailboxId || ids.length === 0) {
      skipped.noIdentifiers += 1;
      continue;
    }
    if (mailboxes.length >= limits.maxMailboxes) {
      skipped.overMailboxCap += 1;
      continue;
    }
    if (messageCount + ids.length > limits.maxMessages) {
      skipped.overMessageCap += 1;
      continue;
    }
    mailboxes.push({
      address: recipient.address.toLowerCase(),
      mailboxId: recipient.mailboxId,
      messageIds: [...ids],
      ...(recipient.internetMessageIds?.length
        ? { internetMessageIds: [...recipient.internetMessageIds] }
        : {}),
      folder: recipient.folder ?? 'unknown',
      ...(recipient.isRead !== undefined ? { isRead: recipient.isRead } : {}),
    });
    messageCount += ids.length;
  }

  return {
    kind: 'remove_messages',
    mailboxes,
    messageCount,
    limits: { maxMailboxes: limits.maxMailboxes, maxMessages: limits.maxMessages },
    skipped,
    ...(reach.lookedUpAt ? { reachLookedUpAt: reach.lookedUpAt } : {}),
  };
}

/** True when a scope has nothing to do */
export function isEmptyScope(scope: ActionScope): boolean {
  return scope.kind === 'send_warning'
    ? scope.recipients.length === 0 && !scope.distribution
    : scope.mailboxes.length === 0;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonical);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map(key => [key, canonical((value as Record<string, unknown>)[key])])
    );
  }
  return value;
}

/** SHA-256 of the scope with keys sorted: two equal scopes hash equal */
export function scopeHash(scope: ActionScope): string {
  return createHash('sha256')
    .update(JSON.stringify(canonical(scope)))
    .digest('hex');
}

/** What happened to one approved mailbox at re-check */
type ApprovedOutcome = 'toMove' | 'alreadyInDeletedItems' | 'noLongerMatched';

/**
 * Put every recipient the reach lists or counts in exactly one category, so
 * the categories add up to the total. A recipient is matched to the approved
 * scope by mailbox ID, or by address when the newer lookup no longer gave a
 * mailbox ID. Approved mailboxes the reach no longer lists at all are added
 * as "no longer matched" (and to the total), so nothing approved goes
 * unaccounted for.
 */
function accountRecipients(
  approved: RemovalScope,
  current: IncidentReach,
  outcomes: Map<string, ApprovedOutcome>
): { recipients: RemovalRecipientCounts; notOpened: string[] } {
  const recipients: RemovalRecipientCounts = {
    total: current.recipients.length + current.unlisted,
    toMove: 0,
    alreadyInDeletedItems: 0,
    noLongerMatched: 0,
    onlyInRecoverableItems: 0,
    noCopyFound: 0,
    mailboxNotOpened: 0,
    notDelivered: 0,
    noIdentifiers: 0,
    notInApprovedScope: 0,
    sameMailbox: 0,
    unlisted: current.unlisted,
  };
  const notOpened: string[] = [];
  const approvedByAddress = new Map(
    approved.mailboxes.map(mailbox => [mailbox.address.toLowerCase(), mailbox.mailboxId])
  );
  const counted = new Set<string>();

  for (const recipient of current.recipients) {
    const byId =
      recipient.mailboxId && outcomes.has(recipient.mailboxId) ? recipient.mailboxId : undefined;
    const byAddress = recipient.mailboxId
      ? undefined
      : approvedByAddress.get(recipient.address.toLowerCase());
    const approvedId = byId ?? byAddress;
    if (approvedId !== undefined && counted.has(approvedId)) {
      recipients.sameMailbox += 1;
      continue;
    }
    if (approvedId !== undefined) {
      counted.add(approvedId);
      recipients[outcomes.get(approvedId) ?? 'noLongerMatched'] += 1;
      continue;
    }
    if (recipient.mailboxId && counted.has(recipient.mailboxId)) {
      recipients.sameMailbox += 1;
      continue;
    }
    if (recipient.mailboxId) {
      counted.add(recipient.mailboxId);
    }
    if (recipient.mailbox === 'not_delivered') {
      recipients.notDelivered += 1;
    } else if (recipient.mailbox === 'not_checked') {
      recipients.mailboxNotOpened += 1;
      notOpened.push(recipient.address);
    } else if (recipient.mailbox === 'not_found') {
      recipients.noCopyFound += 1;
    } else if (recipient.folder === 'recoverable') {
      recipients.onlyInRecoverableItems += 1;
    } else if (!recipient.mailboxId || (recipient.messageIds ?? []).length === 0) {
      recipients.noIdentifiers += 1;
    } else {
      recipients.notInApprovedScope += 1;
    }
  }

  // Approved mailboxes the reach no longer lists (it keeps every recipient
  // an earlier lookup listed, so only past its own recipient cap)
  for (const mailboxId of outcomes.keys()) {
    if (!counted.has(mailboxId)) {
      counted.add(mailboxId);
      recipients.noLongerMatched += 1;
      recipients.total += 1;
    }
  }
  return { recipients, notOpened };
}

/**
 * Re-check a removal scope against the incident's current reach. Only the
 * approved copies are ever counted: a copy the newer lookup found that the
 * approved scope did not name is reported as new and not acted on.
 *
 * `counts.messages` is every approved copy still found, Deleted Items
 * included; `counts.toMove` is the ones a removal would actually move.
 * `recipients` puts every recipient the reach knows of in one category, and
 * `notOpened` lists the addresses whose mailbox was not read (for the
 * security team to handle by hand).
 */
export function recheckRemoval(
  approved: RemovalScope,
  current: IncidentReach
): {
  counts: RemovalCounts;
  mailboxes: RemovalMailbox[];
  recipients: RemovalRecipientCounts;
  notOpened: string[];
} {
  const now = new Map<string, BlastRadiusRecipient>();
  for (const recipient of current.recipients) {
    if (recipient.mailboxId) {
      now.set(recipient.mailboxId, recipient);
    }
  }
  const counts: RemovalCounts = {
    mailboxes: 0,
    messages: 0,
    unreadInInbox: 0,
    readInInbox: 0,
    inJunk: 0,
    alreadyInDeletedItems: 0,
    elsewhere: 0,
    noLongerMatched: 0,
    newSinceApproval: 0,
  };
  let toMove = 0;
  let toMoveMailboxes = 0;
  let deletedMailboxes = 0;
  const still: RemovalMailbox[] = [];
  const approvedMailboxes = new Set<string>();
  const outcomes = new Map<string, ApprovedOutcome>();

  for (const mailbox of approved.mailboxes) {
    approvedMailboxes.add(mailbox.mailboxId);
    const latest = now.get(mailbox.mailboxId);
    const latestIds = new Set(latest?.mailbox === 'found' ? (latest.messageIds ?? []) : []);
    const ids = mailbox.messageIds.filter(id => latestIds.has(id));
    counts.noLongerMatched += mailbox.messageIds.length - ids.length;
    counts.newSinceApproval += [...latestIds].filter(id => !mailbox.messageIds.includes(id)).length;
    if (ids.length === 0 || !latest || latest.folder === 'recoverable') {
      if (latest?.folder === 'recoverable') {
        counts.noLongerMatched += ids.length;
      }
      if (!outcomes.has(mailbox.mailboxId)) {
        outcomes.set(mailbox.mailboxId, 'noLongerMatched');
      }
      continue;
    }
    const folder = latest.folder ?? mailbox.folder;
    counts.mailboxes += 1;
    counts.messages += ids.length;
    if (folder === 'deleted') {
      deletedMailboxes += 1;
    } else {
      toMove += ids.length;
      toMoveMailboxes += 1;
    }
    outcomes.set(mailbox.mailboxId, folder === 'deleted' ? 'alreadyInDeletedItems' : 'toMove');
    if (folder === 'inbox') {
      if (latest.isRead === true) {
        counts.readInInbox += ids.length;
      } else {
        counts.unreadInInbox += ids.length;
      }
    } else if (folder === 'junk') {
      counts.inJunk += ids.length;
    } else if (folder === 'deleted') {
      counts.alreadyInDeletedItems += ids.length;
    } else {
      counts.elsewhere += ids.length;
    }
    still.push({ ...mailbox, messageIds: ids, folder, isRead: latest.isRead });
  }
  for (const recipient of current.recipients) {
    if (
      recipient.mailboxId &&
      recipient.mailbox === 'found' &&
      recipient.folder !== 'recoverable' &&
      !approvedMailboxes.has(recipient.mailboxId)
    ) {
      counts.newSinceApproval += recipient.messageIds?.length ?? 0;
    }
  }
  return {
    counts: {
      ...counts,
      toMove,
      toMoveMailboxes,
      alreadyInDeletedItemsMailboxes: deletedMailboxes,
    },
    mailboxes: still,
    ...accountRecipients(approved, current, outcomes),
  };
}

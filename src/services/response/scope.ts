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
  /** Addresses that reported the campaign (`campaigns.unique_recipients`) */
  reporters: string[];
  safeDomains: string[];
  /** Addresses already warned or thanked for this campaign */
  alreadyContacted: Set<string>;
  /** Employee emails this campaign may still send */
  remaining: number;
  targeted: boolean;
  distribution: boolean;
}

/**
 * Who a warning goes to. Recipients whose copy was never delivered are
 * never warned. Reporters get the thank-you note instead of the warning.
 * Warnings come before thank-you notes when the cap is reached.
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
        continue; // thanked below
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

  const thanks: string[] = [];
  if (input.targeted) {
    for (const reporter of reporters) {
      if (!isSafeRecipient(reporter, input.safeDomains)) {
        skipped.unsafeAddress += 1;
      } else if (input.alreadyContacted.has(reporter)) {
        skipped.alreadyContacted += 1;
      } else {
        thanks.push(reporter);
      }
    }
  }

  const remaining = Math.max(0, input.remaining);
  const recipients = targets.slice(0, remaining);
  const thanked = thanks.slice(0, Math.max(0, remaining - recipients.length));
  skipped.overCap = targets.length - recipients.length + (thanks.length - thanked.length);

  return {
    kind: 'send_warning',
    recipients,
    reporters: thanked,
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
    ? scope.recipients.length === 0 && scope.reporters.length === 0 && !scope.distribution
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

/**
 * Re-check a removal scope against the incident's current reach. Only the
 * approved copies are ever counted: a copy the newer lookup found that the
 * approved scope did not name is reported as new and not acted on.
 */
export function recheckRemoval(
  approved: RemovalScope,
  current: IncidentReach
): { counts: RemovalCounts; mailboxes: RemovalMailbox[] } {
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
  const still: RemovalMailbox[] = [];
  const approvedMailboxes = new Set<string>();

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
      continue;
    }
    const folder = latest.folder ?? mailbox.folder;
    counts.mailboxes += 1;
    counts.messages += ids.length;
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
  return { counts, mailboxes: still };
}

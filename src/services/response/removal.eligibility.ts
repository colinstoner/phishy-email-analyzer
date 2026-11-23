/**
 * Which copies a LIVE removal may name. Pure functions, no I/O.
 *
 * Blast radius finds copies by what the forward's text claims (sender,
 * subject, a window, or a Message-ID), and a hostile email can steer that:
 * plant a fake forwarded-header block, or reuse a real email's Message-ID.
 * That was acceptable for a warning or a dry run; it is not for a move. So
 * a live removal rests on an **anchor** Phishy read itself, and names only
 * copies provably the same email as the anchor:
 *
 * 1. The anchor is the original message Phishy's original-message lookup
 *    found in the reporter's own mailbox (`retrievedOriginal.identity`: its
 *    Graph ID, Internet Message-ID, From address and subject as Exchange
 *    stored them), confirmed by the same report's blast-radius row for the
 *    reporter: that mailbox holds the copy with the same Graph ID, the same
 *    stored values, and Exchange's last-verb property says the reporter
 *    forwarded it. A planted block that steers the lookup to some other
 *    message in the reporter's mailbox fails here unless the reporter had
 *    forwarded that other message too.
 * 2. A copy is eligible only when ALL hold: it has a mailbox ID and Graph
 *    ID; its From address equals the anchor's (case aside); its normalized
 *    subject equals the anchor's exactly (`subjectKeyHash`); it arrived
 *    within `windowHours` of the anchor; and either its Internet Message-ID
 *    is the anchor's, or both sizes are known from message trace and differ
 *    by at most `sizeTolerancePercent`. Missing data is never a match.
 * 3. Copies that fail stay in the reach (warnings are unchanged) and are
 *    counted as excluded, never silently dropped.
 */

import type { BlastRadiusReport, CopyDetail } from '../graph/blast-radius.service';
import { subjectKeyHash } from '../graph/subject.key';
import { stripAngleBrackets } from '../graph/trace.operations';
import type { ExtractedEmailData } from '../../types';
import type {
  IncidentReach,
  LiveCopyCheck,
  LiveRemovalBasis,
  RemovalAnchor,
  RemovalMailbox,
  RemovalScope,
} from './response.types';
import type { RemovalLimits } from './scope';

export const DEFAULT_REMOVAL_WINDOW_HOURS = 6;
export const DEFAULT_REMOVAL_SIZE_TOLERANCE_PERCENT = 1;

export interface LiveRemovalRules {
  windowHours: number;
  sizeTolerancePercent: number;
}

/** Why a report gave no anchor (fixed words, for logs) */
export type AnchorRejection =
  | 'report_button'
  | 'no_original'
  | 'incomplete_identity'
  | 'no_blast_radius'
  | 'reporter_copy_not_found'
  | 'reporter_copy_differs'
  | 'not_forwarded_by_reporter';

const sameId = (a: string | undefined, b: string | undefined): boolean =>
  a !== undefined && b !== undefined && stripAngleBrackets(a) === stripAngleBrackets(b);

/**
 * The anchor this report supplies, or why it supplies none. Only values
 * Phishy's own lookups produced are used: the original-message lookup's
 * stored identity and the report's own blast-radius row for the reporter.
 * Nothing is taken from the forward's text.
 */
export function anchorFromReport(
  emailData: Pick<ExtractedEmailData, 'retrievedOriginal' | 'userReport'>,
  blastRadius: BlastRadiusReport | undefined
): { anchor: RemovalAnchor } | { rejected: AnchorRejection } {
  if (emailData.userReport) {
    return { rejected: 'report_button' };
  }
  const original = emailData.retrievedOriginal;
  if (!original) {
    return { rejected: 'no_original' };
  }
  const identity = original.identity;
  const receivedAt = Date.parse(original.receivedAt ?? '');
  if (
    !identity?.internetMessageId ||
    !identity.senderAddress ||
    identity.subject === undefined ||
    !Number.isFinite(receivedAt)
  ) {
    return { rejected: 'incomplete_identity' };
  }
  const reporter = blastRadius?.reporterAddress?.toLowerCase();
  if (
    !blastRadius ||
    !reporter ||
    (blastRadius.status !== 'complete' && blastRadius.status !== 'partial')
  ) {
    return { rejected: 'no_blast_radius' };
  }
  const row = (blastRadius.recipients ?? []).find(
    r => r.address.toLowerCase() === reporter && r.mailbox === 'found'
  );
  const index = row?.messageIds?.indexOf(identity.messageId) ?? -1;
  if (!row?.mailboxId || index < 0) {
    return { rejected: 'reporter_copy_not_found' };
  }
  const subjectHash = subjectKeyHash(identity.subject);
  const detail = row.copyDetails?.[index];
  if (
    detail?.messageId !== identity.messageId ||
    !sameId(detail.internetMessageId, identity.internetMessageId) ||
    detail.senderAddress !== identity.senderAddress.toLowerCase() ||
    detail.subjectHash !== subjectHash
  ) {
    return { rejected: 'reporter_copy_differs' };
  }
  // The folder and last verb blast radius reports belong to the first copy
  if (index !== 0 || row.response !== 'forwarded') {
    return { rejected: 'not_forwarded_by_reporter' };
  }
  return {
    anchor: {
      mailboxId: row.mailboxId,
      messageId: identity.messageId,
      internetMessageId: identity.internetMessageId,
      senderAddress: identity.senderAddress.toLowerCase(),
      subject: identity.subject,
      subjectHash,
      receivedAt: new Date(receivedAt).toISOString(),
      ...(detail.size !== undefined ? { size: detail.size } : {}),
    },
  };
}

/** The received-time window a live copy must fall in */
export function anchorWindow(
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): { from: number; to: number } {
  const at = Date.parse(anchor.receivedAt);
  const span = rules.windowHours * 3_600_000;
  return { from: at - span, to: at + span };
}

/** How a copy is (or is not) provably the anchor's email */
export function copyEligibility(
  detail: CopyDetail | undefined,
  messageId: string,
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): 'same_message_id' | 'same_size' | undefined {
  if (detail?.messageId !== messageId) {
    return undefined;
  }
  if (!detail.senderAddress || detail.senderAddress !== anchor.senderAddress) {
    return undefined;
  }
  if (!detail.subjectHash || detail.subjectHash !== anchor.subjectHash) {
    return undefined;
  }
  const received = Date.parse(detail.receivedAt ?? '');
  const window = anchorWindow(anchor, rules);
  if (!Number.isFinite(received) || received < window.from || received > window.to) {
    return undefined;
  }
  if (!detail.internetMessageId) {
    return undefined;
  }
  if (sameId(detail.internetMessageId, anchor.internetMessageId)) {
    return 'same_message_id';
  }
  if (
    rules.sizeTolerancePercent > 0 &&
    anchor.size !== undefined &&
    detail.size !== undefined &&
    Math.abs(detail.size - anchor.size) <= (anchor.size * rules.sizeTolerancePercent) / 100
  ) {
    return 'same_size';
  }
  return undefined;
}

/**
 * The live removal scope: only eligible copies, per mailbox, each with what
 * the write broker must re-verify. Same caps and skips as
 * `computeRemovalScope`, plus the count of copies matched but not provably
 * the same email.
 */
export function computeLiveRemovalScope(
  reach: IncidentReach,
  limits: RemovalLimits,
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): RemovalScope {
  const skipped = { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 };
  const mailboxes: RemovalMailbox[] = [];
  const window = anchorWindow(anchor, rules);
  const receivedFrom = new Date(window.from).toISOString();
  const receivedTo = new Date(window.to).toISOString();
  let messageCount = 0;
  let excluded = 0;
  let sameMessageIdAsAnchor = 0;
  let matchedOnSize = 0;
  const distinct = new Set<string>();
  let first: number | undefined;
  let last: number | undefined;

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
    const eligible: Array<{ id: string; check: LiveCopyCheck; how: string; at: number }> = [];
    ids.forEach((id, index) => {
      const detail = recipient.copyDetails?.[index];
      const how = copyEligibility(detail, id, anchor, rules);
      if (!how || !detail?.internetMessageId) {
        excluded += 1;
        return;
      }
      eligible.push({
        id,
        how,
        at: Date.parse(detail.receivedAt ?? ''),
        check: {
          messageId: id,
          internetMessageId: detail.internetMessageId,
          senderAddress: anchor.senderAddress,
          subjectHash: anchor.subjectHash,
          receivedFrom,
          receivedTo,
        },
      });
    });
    if (eligible.length === 0) {
      continue;
    }
    if (mailboxes.length >= limits.maxMailboxes) {
      skipped.overMailboxCap += 1;
      continue;
    }
    if (messageCount + eligible.length > limits.maxMessages) {
      skipped.overMessageCap += 1;
      continue;
    }
    for (const copy of eligible) {
      distinct.add(stripAngleBrackets(copy.check.internetMessageId));
      if (copy.how === 'same_message_id') {
        sameMessageIdAsAnchor += 1;
      } else {
        matchedOnSize += 1;
      }
      first = first === undefined ? copy.at : Math.min(first, copy.at);
      last = last === undefined ? copy.at : Math.max(last, copy.at);
    }
    mailboxes.push({
      address: recipient.address.toLowerCase(),
      mailboxId: recipient.mailboxId,
      messageIds: eligible.map(copy => copy.id),
      verify: eligible.map(copy => copy.check),
      folder: recipient.folder ?? 'unknown',
      ...(recipient.isRead !== undefined ? { isRead: recipient.isRead } : {}),
    });
    messageCount += eligible.length;
  }

  const live: LiveRemovalBasis = {
    anchor,
    windowHours: rules.windowHours,
    sizeTolerancePercent: rules.sizeTolerancePercent,
    distinctMessages: distinct.size,
    sameMessageIdAsAnchor,
    matchedOnSize,
    ...(first !== undefined ? { firstReceivedAt: new Date(first).toISOString() } : {}),
    ...(last !== undefined ? { lastReceivedAt: new Date(last).toISOString() } : {}),
    excluded,
  };
  return {
    kind: 'remove_messages',
    mode: 'live',
    live,
    mailboxes,
    messageCount,
    limits: { maxMailboxes: limits.maxMailboxes, maxMessages: limits.maxMessages },
    skipped,
    ...(reach.lookedUpAt ? { reachLookedUpAt: reach.lookedUpAt } : {}),
  };
}

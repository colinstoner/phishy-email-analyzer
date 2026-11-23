/**
 * Which copies a LIVE removal may name. Pure functions, no I/O.
 *
 * Blast radius finds copies by what the forward's text claims (sender,
 * subject, a window, or a Message-ID), and a hostile email can steer that:
 * plant a fake forwarded-header block, or reuse a real email's Message-ID.
 * That was acceptable for a warning or a dry run; it is not for a move. So
 * a live removal rests on an **anchor**, and names only copies that match
 * it on every rule below.
 *
 * 1. The anchor is the original message Phishy's original-message lookup
 *    found in the reporter's own mailbox, as Exchange stored it
 *    (`retrievedOriginal.identity`: Graph ID, Internet Message-ID, From
 *    address, subject; its received time). It is bound to THIS forward by
 *    the report's own top-level headers, as SES received them: the anchor's
 *    Internet Message-ID must be the report's single `In-Reply-To` ID, or,
 *    without one, its last `References` entry; and the report's own Subject
 *    (reply/forward prefixes removed) must match the anchor's. A
 *    Message-ID search must find it exactly once in the reporter's mailbox;
 *    the reporter's blast-radius row must hold it once, first, with the same
 *    stored values; Exchange's last verb on it must be "forwarded"; its
 *    normalized subject must not be empty.
 * 2. One eligibility rule. A copy is eligible only when ALL hold: it has a
 *    mailbox ID and Graph ID; its Internet Message-ID is the anchor's; its
 *    From address equals the anchor's (case aside); its normalized subject
 *    equals the anchor's exactly (`subjectKeyHash`); and it arrived within
 *    `sameMessageSpreadMinutes` of the anchor (one Message-ID is one
 *    submission, whose deliveries cluster). Missing data is never a match.
 *    There is no setting that loosens this.
 * 3. Copies that fail stay in the reach (warnings are unchanged) and are
 *    counted as excluded, never silently dropped.
 */

import type { BlastRadiusReport, CopyDetail } from '../graph/blast-radius.service';
import { stripReplyForwardPrefixes, subjectGroupKey, subjectKeyHash } from '../graph/subject.key';
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

export const DEFAULT_SAME_MESSAGE_SPREAD_MINUTES = 60;

export interface LiveRemovalRules {
  sameMessageSpreadMinutes: number;
}

/** Why a report gave no anchor (fixed words, for logs) */
export type AnchorRejection =
  | 'report_button'
  | 'no_original'
  | 'incomplete_identity'
  | 'not_the_forwarded_message'
  | 'no_blast_radius'
  | 'reporter_copy_not_found'
  | 'ambiguous_message_id'
  | 'uniqueness_unknown'
  | 'reporter_copy_differs'
  | 'not_forwarded_by_reporter';

const bare = (id: string): string => stripAngleBrackets(id.trim());

const sameId = (a: string | undefined, b: string | undefined): boolean =>
  a !== undefined && b !== undefined && bare(a) === bare(b);

/** Longest header value read; a longer one binds nothing */
const MAX_HEADER_CHARS = 20_000;

/**
 * The Message-IDs in a report's own top-level header (all lines with that
 * name, any case), bare and in order, or undefined when the header is too
 * long to read whole. Only the report's headers as SES received them are
 * read: never body text, never an attached message's headers.
 */
function headerIds(
  headers: Record<string, string> | undefined,
  name: string
): string[] | undefined {
  const wanted = name.toLowerCase();
  const ids: string[] = [];
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() !== wanted || typeof value !== 'string') {
      continue;
    }
    if (value.length > MAX_HEADER_CHARS) {
      return undefined;
    }
    for (const match of value.matchAll(/<([^<>\s]{1,460})>/g)) {
      ids.push(bare(match[1]));
    }
  }
  return ids;
}

/**
 * The Message-ID this report says it forwards: its single `In-Reply-To`
 * ID; or, when it has no `In-Reply-To`, only the LAST `References` ID (the
 * parent, RFC 5322). The other `References` entries may have been copied
 * from the original, whose sender wrote them, so they never bind. An
 * `In-Reply-To` naming more than one ID binds nothing.
 */
export function forwardedMessageId(
  headers: Record<string, string> | undefined
): string | undefined {
  const inReplyTo = headerIds(headers, 'In-Reply-To');
  if (inReplyTo === undefined || inReplyTo.length > 1) {
    return undefined;
  }
  if (inReplyTo.length === 1) {
    return inReplyTo[0];
  }
  const references = headerIds(headers, 'References');
  return references && references.length > 0 ? references[references.length - 1] : undefined;
}

/** Is `internetMessageId` the message this report's own headers say it forwards? */
export function namedByForward(
  headers: Record<string, string> | undefined,
  internetMessageId: string
): boolean {
  const named = forwardedMessageId(headers);
  return named !== undefined && named === bare(internetMessageId);
}

/**
 * The anchor this report supplies, or why it supplies none. Only values
 * Phishy's own lookups produced, and the report's own top-level headers,
 * are used; nothing from the forward's body text.
 */
export function anchorFromReport(
  emailData: Partial<
    Pick<ExtractedEmailData, 'retrievedOriginal' | 'userReport' | 'headers' | 'subject'>
  >,
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
    subjectGroupKey(identity.subject) === '' ||
    !Number.isFinite(receivedAt)
  ) {
    return { rejected: 'incomplete_identity' };
  }
  // Bound to THIS forward by its own headers: the ID its client wrote, and
  // its own subject (decoded, top level) agreeing with the stored one
  if (
    !namedByForward(emailData.headers, identity.internetMessageId) ||
    subjectGroupKey(stripReplyForwardPrefixes(emailData.subject)) !==
      subjectGroupKey(identity.subject)
  ) {
    return { rejected: 'not_the_forwarded_message' };
  }
  // Unique in the reporter's mailbox by a real Message-ID search
  if (identity.sameMessageIdCount === '2+') {
    return { rejected: 'ambiguous_message_id' };
  }
  if (identity.sameMessageIdCount !== '1') {
    return { rejected: 'uniqueness_unknown' };
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
  // A sender chooses the Message-ID: the reporter's mailbox must hold only
  // one message with it, or which one was forwarded is not known
  const withId = (row.copyDetails ?? []).filter(d =>
    sameId(d.internetMessageId, identity.internetMessageId)
  ).length;
  if (withId !== 1) {
    return { rejected: 'ambiguous_message_id' };
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
    },
  };
}

/** The received-time window around the anchor: anchor ± `sameMessageSpreadMinutes` */
export function anchorWindow(
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): { from: number; to: number } {
  const at = Date.parse(anchor.receivedAt);
  const span = rules.sameMessageSpreadMinutes * 60_000;
  return { from: at - span, to: at + span };
}

/** Is this copy eligible: the anchor's Message-ID, sender, exact subject, inside the window? */
export function copyEligible(
  detail: CopyDetail | undefined,
  messageId: string,
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): boolean {
  if (detail?.messageId !== messageId) {
    return false;
  }
  if (!sameId(detail.internetMessageId, anchor.internetMessageId)) {
    return false;
  }
  if (!detail.senderAddress || detail.senderAddress !== anchor.senderAddress) {
    return false;
  }
  if (!detail.subjectHash || detail.subjectHash !== anchor.subjectHash) {
    return false;
  }
  const received = Date.parse(detail.receivedAt ?? '');
  const window = anchorWindow(anchor, rules);
  return Number.isFinite(received) && received >= window.from && received <= window.to;
}

/**
 * The live removal scope: only eligible copies, per mailbox, each with what
 * the write broker must re-verify (the anchor's Message-ID, sender, subject
 * hash and the anchor ± spread window). Same caps and skips as
 * `computeRemovalScope`, plus the count of copies the lookup matched but
 * that are not eligible.
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
    const eligible: Array<{ check: LiveCopyCheck; at: number }> = [];
    ids.forEach((id, index) => {
      const detail = recipient.copyDetails?.[index];
      if (!copyEligible(detail, id, anchor, rules) || !detail?.internetMessageId) {
        excluded += 1;
        return;
      }
      eligible.push({
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
      first = first === undefined ? copy.at : Math.min(first, copy.at);
      last = last === undefined ? copy.at : Math.max(last, copy.at);
    }
    mailboxes.push({
      address: recipient.address.toLowerCase(),
      mailboxId: recipient.mailboxId,
      messageIds: eligible.map(copy => copy.check.messageId),
      verify: eligible.map(copy => copy.check),
      folder: recipient.folder ?? 'unknown',
      ...(recipient.isRead !== undefined ? { isRead: recipient.isRead } : {}),
    });
    messageCount += eligible.length;
  }

  const live: LiveRemovalBasis = {
    anchor,
    sameMessageSpreadMinutes: rules.sameMessageSpreadMinutes,
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

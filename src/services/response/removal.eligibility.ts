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
 *    Internet Message-ID must be the report's `In-Reply-To`, or one of its
 *    `References` (a mail client writes the forwarded message's ID there;
 *    the attacker's body text cannot set the forward's headers). It must be
 *    the only message with that Internet Message-ID in the reporter's
 *    blast-radius row, that row's first copy must be the same Graph ID with
 *    the same stored values, and Exchange's last verb on it must be
 *    "forwarded". The normalized subject must not be empty.
 * 2. A copy is eligible only when ALL hold: it has a mailbox ID and Graph
 *    ID; its From address equals the anchor's (case aside); its normalized
 *    subject equals the anchor's exactly (`subjectKeyHash`); and EITHER its
 *    Internet Message-ID is the anchor's and it arrived within
 *    `sameMessageSpreadMinutes` of the anchor (one Message-ID is one
 *    submission, whose deliveries cluster), OR `sizeTolerancePercent` is
 *    above 0 (it is 0 by default), both message-trace sizes are known and
 *    within that percentage, and it arrived within `windowHours`. Missing
 *    data is never a match.
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

export const DEFAULT_REMOVAL_WINDOW_HOURS = 6;
/** Off by default: only copies with the anchor's own Message-ID are eligible */
export const DEFAULT_REMOVAL_SIZE_TOLERANCE_PERCENT = 0;
export const DEFAULT_SAME_MESSAGE_SPREAD_MINUTES = 60;

export interface LiveRemovalRules {
  windowHours: number;
  sizeTolerancePercent: number;
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
      ...(detail.size !== undefined ? { size: detail.size } : {}),
    },
  };
}

/** The received-time window around the anchor for one admission basis */
export function anchorWindow(
  anchor: RemovalAnchor,
  rules: LiveRemovalRules,
  basis: 'same_message_id' | 'same_size' = 'same_size'
): { from: number; to: number } {
  const at = Date.parse(anchor.receivedAt);
  const span =
    basis === 'same_message_id'
      ? Math.min(rules.sameMessageSpreadMinutes * 60_000, rules.windowHours * 3_600_000)
      : rules.windowHours * 3_600_000;
  return { from: at - span, to: at + span };
}

const within = (at: number, window: { from: number; to: number }): boolean =>
  Number.isFinite(at) && at >= window.from && at <= window.to;

/** How a copy matches the anchor, or undefined when it does not */
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
  if (!detail.internetMessageId) {
    return undefined;
  }
  const received = Date.parse(detail.receivedAt ?? '');
  if (sameId(detail.internetMessageId, anchor.internetMessageId)) {
    return within(received, anchorWindow(anchor, rules, 'same_message_id'))
      ? 'same_message_id'
      : undefined;
  }
  if (
    rules.sizeTolerancePercent > 0 &&
    anchor.size !== undefined &&
    detail.size !== undefined &&
    Math.abs(detail.size - anchor.size) <= (anchor.size * rules.sizeTolerancePercent) / 100 &&
    within(received, anchorWindow(anchor, rules, 'same_size'))
  ) {
    return 'same_size';
  }
  return undefined;
}

interface Spread {
  first?: number;
  last?: number;
}

function widen(spread: Spread, at: number): void {
  spread.first = spread.first === undefined ? at : Math.min(spread.first, at);
  spread.last = spread.last === undefined ? at : Math.max(spread.last, at);
}

const iso = (at: number | undefined): string | undefined =>
  at === undefined ? undefined : new Date(at).toISOString();

/**
 * The live removal scope: only eligible copies, per mailbox, each with what
 * the write broker must re-verify (a same-Message-ID copy within the tight
 * spread window, a size-matched one within `windowHours`). Same caps and
 * skips as `computeRemovalScope`, plus the count of copies matched by the
 * lookup but not admitted.
 */
export function computeLiveRemovalScope(
  reach: IncidentReach,
  limits: RemovalLimits,
  anchor: RemovalAnchor,
  rules: LiveRemovalRules
): RemovalScope {
  const skipped = { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 };
  const mailboxes: RemovalMailbox[] = [];
  const windows = {
    same_message_id: anchorWindow(anchor, rules, 'same_message_id'),
    same_size: anchorWindow(anchor, rules, 'same_size'),
  };
  let messageCount = 0;
  let excluded = 0;
  let sameMessageIdAsAnchor = 0;
  let matchedOnSize = 0;
  const distinct = new Set<string>();
  const overall: Spread = {};
  const sameIdSpread: Spread = {};
  const sizeSpread: Spread = {};

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
    const eligible: Array<{
      id: string;
      check: LiveCopyCheck;
      how: 'same_message_id' | 'same_size';
      at: number;
    }> = [];
    ids.forEach((id, index) => {
      const detail = recipient.copyDetails?.[index];
      const how = copyEligibility(detail, id, anchor, rules);
      if (!how || !detail?.internetMessageId) {
        excluded += 1;
        return;
      }
      const window = windows[how];
      eligible.push({
        id,
        how,
        at: Date.parse(detail.receivedAt ?? ''),
        check: {
          messageId: id,
          internetMessageId: detail.internetMessageId,
          senderAddress: anchor.senderAddress,
          subjectHash: anchor.subjectHash,
          receivedFrom: new Date(window.from).toISOString(),
          receivedTo: new Date(window.to).toISOString(),
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
      distinct.add(bare(copy.check.internetMessageId));
      if (copy.how === 'same_message_id') {
        sameMessageIdAsAnchor += 1;
        widen(sameIdSpread, copy.at);
      } else {
        matchedOnSize += 1;
        widen(sizeSpread, copy.at);
      }
      widen(overall, copy.at);
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
    sameMessageSpreadMinutes: rules.sameMessageSpreadMinutes,
    distinctMessages: distinct.size,
    sameMessageIdAsAnchor,
    matchedOnSize,
    ...(overall.first !== undefined ? { firstReceivedAt: iso(overall.first) } : {}),
    ...(overall.last !== undefined ? { lastReceivedAt: iso(overall.last) } : {}),
    ...(sameIdSpread.first !== undefined
      ? { sameIdReceived: { first: iso(sameIdSpread.first)!, last: iso(sameIdSpread.last)! } }
      : {}),
    ...(sizeSpread.first !== undefined
      ? { sizeReceived: { first: iso(sizeSpread.first)!, last: iso(sizeSpread.last)! } }
      : {}),
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

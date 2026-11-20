/**
 * Addressing facts: what the original message's From, To, Cc and Reply-To
 * say about how it was sent, computed by code.
 *
 * A compromised mailbox mailing its address book typically addresses the
 * message To itself with every real recipient in Bcc, and often sets a
 * Reply-To naming somebody else. Those are comparisons code can make
 * exactly; the model should not have to infer them from a pasted block.
 *
 * Provenance. The inputs are the original's headers, which the sender
 * wrote. They come either from the forwarded message (the block an
 * employee's client pasted, a forward-as-attachment original, or a
 * Report-button attachment: all CLAIMED) or from the delivered copy that the
 * optional original-message lookup retrieved (retrieval verified, contents
 * still written by the sender). Each fact says which.
 *
 * Unknown stays unknown: a fact is produced only when every header it needs
 * is present and every address in it could be read. Nothing here quotes an
 * address or name, so no attacker-chosen text reaches the rendered lines.
 *
 * Pure computation, no I/O.
 */

import { ExtractedEmailData } from '../types';
import { isValidEmail } from './validation';

/** Longest header value parsed; a longer one is not interpreted at all */
const MAX_ADDRESS_HEADER = 8000;
/** Most entries parsed from one header; more and the list is incomplete */
const MAX_ADDRESS_ENTRIES = 200;

export interface Mailbox {
  /** Lower-cased address */
  address: string;
  /** Display name, when one was written */
  name?: string;
}

export interface AddressList {
  entries: Mailbox[];
  /** False when an entry had no readable address or a bound was hit */
  complete: boolean;
}

export type AddressingFactCode =
  | 'bcc_to_self'
  | 'reporter_not_visible'
  | 'reply_to_other_domain'
  | 'reply_to_same_domain'
  | 'reply_to_name_differs';

export interface AddressingFacts {
  /** Where the headers came from */
  source: 'forwarded' | 'retrieved';
  facts: AddressingFactCode[];
}

/** Split at top-level separators, ignoring those inside quotes or angle brackets */
function splitTopLevel(value: string, separator: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  let angle = 0;
  for (const ch of value) {
    if (ch === '"') quoted = !quoted;
    else if (!quoted && ch === '<') angle++;
    else if (!quoted && ch === '>') angle = Math.max(0, angle - 1);
    if (ch === separator && !quoted && angle === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts.map(p => p.trim()).filter(Boolean);
}

function parseMailbox(entry: string): Mailbox | null {
  const bracketed =
    /<\s*(?:mailto:)?([^<>\s]+@[^<>\s]+)\s*>/i.exec(entry) ??
    /\[\s*mailto:([^[\]\s]+@[^[\]\s]+)\s*\]/i.exec(entry);
  const bare = /(?:^|\s)([^\s<>"[\]]+@[^\s<>"[\]]+)(?=\s|$)/.exec(entry);
  const raw = (bracketed ?? bare)?.[1];
  if (!raw || !isValidEmail(raw)) return null;
  const address = raw.toLowerCase();

  const name = entry
    .replace(/<[^>]*>/g, ' ')
    .replace(/\[\s*mailto:[^\]]*\]/gi, ' ')
    .replace(raw, ' ')
    .replace(/["']/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return name && name.toLowerCase() !== address ? { address, name } : { address };
}

/**
 * Parse an address header (`Name <a@x>, "Last, First" <b@y>` or Outlook's
 * `Last, First <a@x>; Other <b@y>`). Outlook's unquoted "Last, First" is
 * handled by joining a fragment with no address onto the next one.
 */
export function parseAddressList(value: string | undefined): AddressList | undefined {
  if (value === undefined) return undefined;
  const text = value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
  if (text.length > MAX_ADDRESS_HEADER) return { entries: [], complete: false };
  if (text.length === 0) return { entries: [], complete: true };

  const fragments = text.includes(';') ? splitTopLevel(text, ';') : splitTopLevel(text, ',');
  const merged: string[] = [];
  let pending = '';
  for (const fragment of fragments) {
    const joined = pending ? `${pending}, ${fragment}` : fragment;
    if (fragment.includes('@')) {
      merged.push(joined);
      pending = '';
    } else {
      pending = joined;
    }
  }

  let complete = pending === '';
  const entries: Mailbox[] = [];
  for (const entry of merged.slice(0, MAX_ADDRESS_ENTRIES)) {
    const mailbox = parseMailbox(entry);
    if (mailbox) entries.push(mailbox);
    else complete = false;
  }
  if (merged.length > MAX_ADDRESS_ENTRIES) complete = false;
  return { entries, complete };
}

/** A display name reduced for comparison: case, punctuation and word order ignored */
function nameKey(name: string): string {
  return name
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .sort()
    .join(' ');
}

function domainOf(address: string): string {
  return address.split('@')[1]?.split('.').filter(Boolean).slice(-2).join('.') ?? '';
}

interface HeaderSet {
  source: 'forwarded' | 'retrieved';
  from?: string;
  to?: string;
  cc?: string;
  replyTo?: string;
  /** A missing Cc means the original had none (false when the header list may be incomplete) */
  ccAbsenceMeansNone: boolean;
}

/** One header from a retrieved original, or undefined when absent or repeated */
function singleHeader(
  headers: Array<{ name: string; value: string }>,
  name: string
): string | undefined {
  const matches = headers.filter(h => h.name.toLowerCase() === name.toLowerCase());
  return matches.length === 1 ? matches[0].value : undefined;
}

function headerSet(emailData: ExtractedEmailData): HeaderSet | undefined {
  const retrieved = emailData.retrievedOriginal;
  if (retrieved && singleHeader(retrieved.headers, 'From') !== undefined) {
    const ccCount = retrieved.headers.filter(h => h.name.toLowerCase() === 'cc').length;
    return {
      source: 'retrieved',
      from: singleHeader(retrieved.headers, 'From'),
      to: singleHeader(retrieved.headers, 'To'),
      cc: singleHeader(retrieved.headers, 'Cc'),
      replyTo: singleHeader(retrieved.headers, 'Reply-To'),
      // A repeated Cc is unreadable, not absent; a truncated list may have lost it
      ccAbsenceMeansNone: ccCount === 0 && !retrieved.headersTruncated,
    };
  }
  const forwarded = emailData.forwardedHeaders ?? {};
  if (!forwarded['Original-From']) return undefined;
  return {
    source: 'forwarded',
    from: forwarded['Original-From'],
    to: forwarded['Original-To'],
    cc: forwarded['Original-Cc'],
    replyTo: forwarded['Original-Reply-To'],
    // Mail clients write a Cc line into the forward header whenever the
    // original had one, and Phishy's forward-as-attachment block does too
    ccAbsenceMeansNone: true,
  };
}

/** The claimed sender's address: from the retrieved original when there is one */
export function claimedSenderAddress(emailData: ExtractedEmailData): string | undefined {
  const set = headerSet(emailData);
  const from = parseAddressList(set?.from);
  return from?.complete && from.entries.length === 1 ? from.entries[0].address : undefined;
}

/** Domain part of the claimed sender's address, or undefined */
export function claimedSenderDomain(emailData: ExtractedEmailData): string | undefined {
  return claimedSenderAddress(emailData)?.split('@')[1];
}

/**
 * Compute the addressing facts for an email. Returns undefined when there is
 * no original sender to compare against, and an empty fact list when the
 * headers were there but established nothing.
 */
export function computeAddressingFacts(emailData: ExtractedEmailData): AddressingFacts | undefined {
  const set = headerSet(emailData);
  if (!set) return undefined;
  const from = parseAddressList(set.from);
  if (!from?.complete || from.entries.length !== 1) return undefined;
  const sender = from.entries[0];

  const facts: AddressingFactCode[] = [];
  const to = parseAddressList(set.to);
  const cc = parseAddressList(set.cc);
  // The visible recipients are known only when To was readable and Cc was
  // either readable or certainly absent
  const ccKnown = cc ? cc.complete : set.ccAbsenceMeansNone;
  const visible = to?.complete && ccKnown ? [...to.entries, ...(cc?.entries ?? [])] : undefined;

  if (visible?.length === 1 && visible[0].address === sender.address) {
    facts.push('bcc_to_self');
  }

  const reporter = emailData.originalForwarder?.toLowerCase();
  if (
    visible &&
    reporter &&
    reporter !== sender.address &&
    !visible.some(m => m.address === reporter)
  ) {
    facts.push('reporter_not_visible');
  }

  const replyTo = parseAddressList(set.replyTo);
  if (replyTo?.complete && replyTo.entries.length === 1) {
    const reply = replyTo.entries[0];
    if (reply.address !== sender.address) {
      facts.push(
        domainOf(reply.address) === domainOf(sender.address)
          ? 'reply_to_same_domain'
          : 'reply_to_other_domain'
      );
    }
    if (reply.name && sender.name && nameKey(reply.name) !== nameKey(sender.name)) {
      facts.push('reply_to_name_differs');
    }
  }

  return { source: set.source, facts };
}

/** How each fact is stated in the prompt. No value from the email appears. */
export const ADDRESSING_FACT_TEXT: Readonly<Record<AddressingFactCode, string>> = {
  bcc_to_self:
    "The original was addressed To the sender's own address, with no other visible recipient (no other To, no Cc). Everyone who received it, the reporter included, was a hidden (Bcc) recipient: the shape of a message sent to a whole address book. Some legitimate bulk notices are sent this way too.",
  reporter_not_visible:
    "The reporter's own address is not among the visible To/Cc recipients: they received it as a Bcc recipient or through a list or alias.",
  reply_to_other_domain:
    'Reply-To is a different address from From, on a different domain: replies would not go to the sender.',
  reply_to_same_domain:
    'Reply-To is a different address from From, on the same domain: replies would go to another mailbox than the sender.',
  reply_to_name_differs:
    'The Reply-To display name is a different person from the From display name: replies would go to someone presenting as somebody else.',
};

/** The provenance line for a fact set */
export function addressingSourceText(source: AddressingFacts['source']): string {
  return source === 'retrieved'
    ? "Source: the headers of the delivered copy Phishy retrieved from the reporter's mailbox (see ORIGINAL MESSAGE LOOKUP). The retrieval is verified; the header contents were written by the sender."
    : "Source: the original's headers as quoted in the forwarded message (CLAIMED: written by the sender and copied by the forwarding client; Phishy cannot authenticate them). Phishy computed the comparisons below; only the headers are unverified.";
}

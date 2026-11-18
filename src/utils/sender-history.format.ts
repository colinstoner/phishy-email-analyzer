/**
 * Wording for sender-relationship facts, shared by the prompt and the report
 * so both state the same thing the same way. By default every value rendered
 * here is a number, a date or an enum computed by Phishy: no address, domain
 * or IP. Only `includeBurstIps` adds the burst's sending IPs, and only a
 * report copy addressed to the security team alone may ask for it.
 *
 * A count that was cut short by a row cap is always written "at least N"
 * (CLAUDE.md invariant 5): it is never presented as exact.
 */

import { BoundedCount, SenderHistoryFacts } from '../types';

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return count === 1 ? singular : pluralForm;
}

/** `12 messages`, `at least 2000 messages`, `1 message` */
export function formatBoundedCount(
  value: BoundedCount,
  singular: string,
  pluralForm?: string
): string {
  return `${value.atLeast ? 'at least ' : ''}${value.count} ${plural(value.count, singular, pluralForm)}`;
}

function formatInbound(
  messages: BoundedCount,
  recipients: BoundedCount,
  firstSeen: string | undefined
): string {
  if (messages.count === 0 && !messages.atLeast) {
    return 'none';
  }
  const seen = firstSeen
    ? `; first seen ${messages.atLeast ? 'on or before ' : ''}${firstSeen}`
    : '';
  return `${formatBoundedCount(messages, 'message')} to ${formatBoundedCount(
    recipients,
    'distinct internal recipient'
  )}${seen}`;
}

export interface SenderHistoryFormatOptions {
  /**
   * List the burst's sending IPs. Security-team-only report copies only:
   * never the prompt, the reporter's copy or the combined report.
   */
  includeBurstIps?: boolean;
}

/** `198.51.100.7 (not seen before); 192.0.2.10 (seen before); and 3 more` */
function formatBurstIps(sendingIps: SenderHistoryFacts['sendingIps']): string | undefined {
  const listed = sendingIps.burstIps ?? [];
  const omitted = sendingIps.burstIpsOmitted ?? 0;
  if (listed.length === 0 && omitted === 0) {
    return undefined;
  }
  // Against a history that was cut short, "not seen" is only "not in the rows read"
  const unseen = sendingIps.historyComplete
    ? 'not seen in the history period'
    : 'not in the history rows read';
  const parts = listed.map(
    entry => `${entry.ip} (${entry.seenInHistory ? 'seen in the history period' : unseen})`
  );
  if (omitted > 0) {
    parts.push(listed.length > 0 ? `and ${omitted} more` : `${omitted} not listed`);
  }
  return parts.join('; ');
}

/**
 * The facts as label/value lines. Callers add their own framing (the prompt
 * its provenance label and guidance, the report its heading).
 */
export function formatSenderHistoryLines(
  facts: SenderHistoryFacts,
  options: SenderHistoryFormatOptions = {}
): Array<[string, string]> {
  const lines: Array<[string, string]> = [['Classification', facts.classification]];

  lines.push([
    `History (${facts.lookbackDays}-day lookback, excluding the burst window)`,
    formatInbound(facts.history.messages, facts.history.recipients, facts.history.firstSeen),
  ]);

  const { twoWay } = facts;
  lines.push([
    'Two-way contact (same history period)',
    twoWay.messages.count === 0 && !twoWay.messages.atLeast
      ? 'none: no mail from the organization to this address'
      : `${formatBoundedCount(twoWay.messages, 'message')} to this address from ${formatBoundedCount(
          twoWay.internalSenders,
          'distinct internal sender'
        )}`,
  ]);

  const { burst } = facts;
  let burstText: string;
  if (burst.messages.count === 0 && !burst.messages.atLeast) {
    burstText = 'no mail from this address';
  } else {
    burstText = `${formatBoundedCount(burst.messages, 'message')} to ${formatBoundedCount(
      burst.recipients,
      'distinct internal recipient'
    )}; `;
    burstText +=
      burst.newRecipients === null
        ? 'how many of them are new to this address could not be determined (history was cut short)'
        : `${burst.newRecipients.atLeast ? 'at least ' : ''}${burst.newRecipients.count} of them had no mail from this address in the history period`;
  }
  lines.push([`Burst window (the last ${facts.burstWindowHours} hours)`, burstText]);

  const { sameSubject } = burst;
  if (sameSubject.recipients.count > 0) {
    lines.push([
      'Widest single message in the burst',
      `${formatBoundedCount(sameSubject.recipients, 'distinct internal recipient')} received the same subject; ${
        sameSubject.newRecipients === null
          ? 'how many of them are new to this address could not be determined (history was cut short)'
          : `${sameSubject.newRecipients.atLeast ? 'at least ' : ''}${sameSubject.newRecipients.count} of them had no mail from this address in the history period`
      }`,
    ]);
  }

  const { sendingIps } = facts;
  lines.push([
    'Sending IPs in the burst window',
    sendingIps.burst === 0
      ? 'none recorded'
      : `${sendingIps.burst} distinct; ${sendingIps.historyComplete ? '' : 'at least '}${sendingIps.seenInHistory} of them also seen in the history period`,
  ]);

  const burstIps = options.includeBurstIps ? formatBurstIps(sendingIps) : undefined;
  if (burstIps) {
    lines.push(['Burst sending IPs (security team only)', burstIps]);
  }

  if (facts.truncated) {
    lines.push([
      'Elision',
      'counts marked "at least" were cut short by a row cap; they are minimums, not totals',
    ]);
  }

  return lines;
}

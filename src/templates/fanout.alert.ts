/**
 * The security team's fan-out alert (HTML and plain text).
 *
 * Addressed to the security team alone, never to an employee: it lists
 * internal recipient addresses and the burst's sending IPs. The sender
 * address, the subject and every recipient address come from mail flow and
 * are hostile strings: each is escaped in HTML, and none of them appears in
 * the email's own Subject line, which is written entirely by this code.
 *
 * The alert is a behaviour-based flag from message-trace metadata, not a
 * verdict on content; it says so, and lists the common benign explanations.
 */

import type { BlastRadiusReport } from '../services/graph/blast-radius.service';
import type {
  FanoutFlag,
  FanoutIncompleteReason,
  FanoutStatusCounts,
} from '../services/graph/fanout.scan';
import { formatSenderHistoryLines } from '../utils/sender-history.format';
import { buildBlastRadiusHtml, buildBlastRadiusText, escapeHtml } from './report.html';

export interface FanoutAlertInput {
  /** Stable reference of the wave (`FANOUT-…`) */
  reference: string;
  /** A first alert, or an update because the wave grew */
  kind: 'new' | 'growth';
  /** Recipients the previous alert reported (updates only) */
  previousRecipients?: number;
  flag: FanoutFlag;
  /** Distinct internal recipients of the wave so far (window and history together) */
  waveRecipients: number;
  /** Earliest sighting of the wave (ISO) */
  waveFirstSeen: string;
  /** The window this scan read */
  window: { from: string; to: string };
  incompleteReasons: FanoutIncompleteReason[];
  /** Present when blast radius is enabled */
  blastRadius?: BlastRadiusReport;
}

export interface FanoutAlertEmail {
  subject: string;
  html: string;
  text: string;
}

/** The one plain sentence on what the flag means */
export const FANOUT_MEANING =
  'An external address the organization has corresponded with in both directions suddenly sent one ' +
  'email to far more of our people than it ever has, most of whom it had never written to: the ' +
  'pattern of a taken-over supplier or partner mailbox mailing its address book.';

export const FANOUT_NOT_A_VERDICT =
  'This is a behaviour-based flag computed from mail-flow records (message trace), not a verdict on ' +
  'the content. No message was opened and no AI model was involved.';

export const FANOUT_BENIGN_EXPLANATIONS = [
  'a newsletter or announcement from a real contact who has just started mailing more of us',
  'a bid invitation, tender or request for quotation sent to many people at once',
  'a notice from a supplier (new bank details, an office move, holiday hours): real, or exactly what a takeover sends',
  'an event, webinar or meeting invitation sent to a large group',
  'the contact being newly added to a distribution list or shared mailbox',
];

export const FANOUT_NEXT_STEPS = [
  'Confirm with the sender through a channel you already have (a phone number on file, not one from this email) whether they sent it.',
  'Until confirmed, treat it as hostile: look at the message itself in your mail security tools before anyone acts on it.',
  'If it is not legitimate: remove the message from the recipients listed below, block the sender (and any unfamiliar sending IPs below), and warn the recipients not to open its links or attachments.',
  'Contact anyone who replied to it, forwarded it, or may have entered credentials or approved a payment (see the blast radius, when shown).',
  'If it is legitimate, nothing needs doing: this wave is not alerted again unless it at least doubles.',
];

const STATUS_LABEL: Record<keyof FanoutStatusCounts, string> = {
  delivered: 'Delivered',
  junk: 'Junk Email (filtered as spam)',
  quarantined: 'Quarantined',
  failed: 'Delivery failed',
  other: 'Other / pending',
};

const INCOMPLETE_TEXT: Record<FanoutIncompleteReason, string> = {
  page_limit: 'the window had more mail-flow rows than the page limit allows',
  page_error: 'a later page of mail-flow rows could not be read',
  candidate_limit: 'more senders reached the threshold than one scan checks',
  request_allowance: 'the scan used its share of the message-trace request limit',
  time_budget: 'the scan ran out of time',
  history_unavailable: "a sender's history could not be read",
};

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The email's Subject line: code-written only, nothing from mail flow */
function alertSubject(input: FanoutAlertInput): string {
  return input.kind === 'growth'
    ? `Phishy fan-out alert ${input.reference} (update): one external sender has now reached ${input.waveRecipients} internal recipients`
    : `Phishy fan-out alert ${input.reference}: one external sender reached ${input.waveRecipients} internal recipients`;
}

function deliverySummary(statuses: FanoutStatusCounts): string {
  const filtered = statuses.quarantined + statuses.junk;
  return (
    `${statuses.delivered} reached a mailbox; the mail filter already quarantined ` +
    `${statuses.quarantined} and sent ${statuses.junk} to Junk Email` +
    (filtered > 0 && statuses.delivered === 0 ? ' (none reached an inbox in this window)' : '') +
    '.'
  );
}

/** Label/value rows of what was seen. Values from mail flow are returned unescaped. */
function seenRows(input: FanoutAlertInput): Array<[string, string]> {
  const { flag } = input;
  const rows: Array<[string, string]> = [
    ['Sender (from mail flow)', flag.senderAddress],
    ['Subject (from mail flow)', flag.subject || '(no subject)'],
    ['First seen', input.waveFirstSeen],
    ['Latest in this scan', flag.lastSeen],
    [
      'This scan',
      `${plural(flag.windowRecipients, 'distinct internal recipient')} (${plural(flag.windowMessages, 'message')}) between ${input.window.from} and ${input.window.to}`,
    ],
    ['Wave so far', plural(input.waveRecipients, 'distinct internal recipient')],
  ];
  if (input.kind === 'growth' && input.previousRecipients !== undefined) {
    rows.push([
      'Update',
      `the previous alert for this wave reported ${input.previousRecipients}; it has now reached ${input.waveRecipients}`,
    ]);
  }
  rows.push(['Delivery (this scan)', deliverySummary(flag.statuses)]);
  for (const key of Object.keys(STATUS_LABEL) as Array<keyof FanoutStatusCounts>) {
    rows.push([`  ${STATUS_LABEL[key]}`, String(flag.statuses[key])]);
  }
  return rows;
}

function incompleteLine(reasons: FanoutIncompleteReason[]): string | undefined {
  if (reasons.length === 0) {
    return undefined;
  }
  return `Scan incomplete: ${reasons.map(reason => INCOMPLETE_TEXT[reason]).join('; ')}. Counts are what was seen, and other waves may not have been checked.`;
}

const CELL =
  'padding: 4px 8px; border-bottom: 1px solid #e9ecef; text-align: left; vertical-align: top;';

function tableHtml(rows: Array<[string, string]>): string {
  return `<table style="width: 100%; border-collapse: collapse; font-size: 13px;">${rows
    .map(
      ([label, value]) =>
        `<tr><td style="${CELL} font-weight: bold; white-space: nowrap;">${escapeHtml(label)}</td><td style="${CELL} word-break: break-all;">${escapeHtml(value)}</td></tr>`
    )
    .join('')}</table>`;
}

function listHtml(items: string[]): string {
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

export function buildFanoutAlert(input: FanoutAlertInput): FanoutAlertEmail {
  const { flag } = input;
  const historyRows = formatSenderHistoryLines(flag.facts, { includeBurstIps: true });
  const incomplete = incompleteLine(input.incompleteReasons);
  const recipientRows: Array<[string, string]> = flag.recipients.map(recipient => [
    recipient.address,
    STATUS_LABEL[recipient.status],
  ]);

  const html = `<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishy Fan-out Alert ${escapeHtml(input.reference)}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #333; margin: 0; padding: 20px; background-color: #f9f9f9; }
            .container { max-width: 800px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
            .header { background-color: #2C3E50; color: white; padding: 20px; }
            .header h1 { margin: 0; font-size: 22px; }
            .analysis { padding: 20px; border-bottom: 1px solid #eee; }
            h2 { margin-top: 0; color: #2C3E50; font-size: 18px; }
            ul { margin-top: 10px; padding-left: 25px; }
            li { margin-bottom: 5px; }
            .verdict-banner { border-radius: 6px; padding: 14px 16px; margin: 12px 0; background-color: #fff4e5; border-left: 4px solid #fd7e14; }
            .verdict-line { margin: 0; font-size: 16px; }
            .no-items { color: #6c757d; font-style: italic; font-size: 13px; }
            .metadata { padding: 15px 20px; background-color: #f8f9fa; border-top: 1px solid #eee; font-size: 13px; color: #6c757d; }
            .metadata p { margin: 5px 0; }
            .ref-line { font-size: 11px; color: #adb5bd; }
            .footer { font-size: 12px; color: #777; padding: 15px 20px; background-color: #f5f5f5; border-top: 1px solid #eee; }
            @media only screen and (max-width: 600px) { body { padding: 10px; } .header, .analysis, .metadata, .footer { padding: 15px; } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Phishy Fan-out Alert${input.kind === 'growth' ? ' (update)' : ''}</h1>
            </div>
            <div class="analysis">
                <div class="verdict-banner">
                    <p class="verdict-line"><strong>Security team only.</strong> ${escapeHtml(FANOUT_NOT_A_VERDICT)}</p>
                </div>
                <h2>What it means</h2>
                <p>${escapeHtml(FANOUT_MEANING)}</p>
                ${incomplete ? `<p><strong>${escapeHtml(incomplete)}</strong></p>` : ''}
            </div>
            <div class="analysis">
                <h2>What was seen</h2>
                ${tableHtml(seenRows(input))}
            </div>
            <div class="analysis">
                <h2>Why it stands out: the sender's history with us</h2>
                ${tableHtml(historyRows)}
                <p class="no-items">Counts from message trace for this sender address. A familiar sender is not evidence of safety: a taken-over mailbox has the same history.</p>
            </div>
            <div class="analysis">
                <h2>What to do next</h2>
                <ol>${FANOUT_NEXT_STEPS.map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>
                <h2>Common benign explanations</h2>
                ${listHtml(FANOUT_BENIGN_EXPLANATIONS)}
            </div>
            ${input.blastRadius ? buildBlastRadiusHtml(input.blastRadius) : ''}
            <div class="analysis">
                <h2>Recipients in this scan (security team only)</h2>
                ${recipientRows.length ? tableHtml(recipientRows) : '<p class="no-items">None listed.</p>'}
                ${flag.recipientsOmitted > 0 ? `<p class="no-items">${flag.recipientsOmitted} more recipient(s) not listed.</p>` : ''}
            </div>
            <div class="metadata">
                <p><strong>Reference:</strong> ${escapeHtml(input.reference)}</p>
                <p>Quote this reference when you discuss this wave. Replying does not trigger any action.</p>
                <p class="ref-line">Scanned window: ${escapeHtml(input.window.from)} to ${escapeHtml(input.window.to)}</p>
            </div>
            <div class="footer">
                <p>Generated by Phishy's scheduled fan-out scan from Exchange message-trace metadata. No AI model was involved and no message content was read.</p>
            </div>
        </div>
    </body>
</html>`;

  const text: string[] = [
    `PHISHY FAN-OUT ALERT${input.kind === 'growth' ? ' (UPDATE)' : ''}: ${input.reference}`,
    '='.repeat(60),
    `SECURITY TEAM ONLY. ${FANOUT_NOT_A_VERDICT}`,
    '',
    'WHAT IT MEANS',
    FANOUT_MEANING,
  ];
  if (incomplete) {
    text.push('', incomplete);
  }
  text.push('', 'WHAT WAS SEEN', '-'.repeat(40));
  for (const [label, value] of seenRows(input)) {
    text.push(`${label}: ${value}`);
  }
  text.push('', "WHY IT STANDS OUT: THE SENDER'S HISTORY WITH US", '-'.repeat(40));
  for (const [label, value] of historyRows) {
    text.push(`${label}: ${value}`);
  }
  text.push(
    'A familiar sender is not evidence of safety: a taken-over mailbox has the same history.',
    '',
    'WHAT TO DO NEXT',
    '-'.repeat(40),
    ...FANOUT_NEXT_STEPS.map((step, index) => `${index + 1}. ${step}`),
    '',
    'COMMON BENIGN EXPLANATIONS',
    '-'.repeat(40),
    ...FANOUT_BENIGN_EXPLANATIONS.map(item => `- ${item}`)
  );
  if (input.blastRadius) {
    text.push('', ...buildBlastRadiusText(input.blastRadius));
  }
  text.push('', 'RECIPIENTS IN THIS SCAN (security team only)', '-'.repeat(40));
  for (const [address, status] of recipientRows) {
    text.push(`  ${address} | ${status}`);
  }
  if (flag.recipientsOmitted > 0) {
    text.push(`  ${flag.recipientsOmitted} more recipient(s) not listed.`);
  }
  text.push(
    '',
    `Reference: ${input.reference}`,
    'Quote this reference when you discuss this wave. Replying does not trigger any action.',
    `Scanned window: ${input.window.from} to ${input.window.to}`,
    '',
    "Generated by Phishy's scheduled fan-out scan from Exchange message-trace metadata. No AI model was involved and no message content was read."
  );

  return { subject: alertSubject(input), html, text: text.join('\n') };
}

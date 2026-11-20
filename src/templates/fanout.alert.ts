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
import { displayTime } from '../services/response/display';
import {
  SENDER_RELATIONSHIP_LABEL,
  formatSenderHistoryLines,
} from '../utils/sender-history.format';
import {
  Fact,
  TEXT_SUBRULE,
  block,
  bulletList,
  callout,
  dataTable,
  emailShell,
  facts,
  heading,
  hero,
  instructions,
  paragraph,
  stats,
  textFacts,
} from './layout';
import { buildBlastRadiusHtml, buildBlastRadiusText } from './report.html';

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
  /** IANA time zone the alert's times are written in (default UTC) */
  timeZone?: string;
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

/** A time as the security team reads it, in the configured zone (the raw value if unparseable) */
function when(input: FanoutAlertInput, iso: string): string {
  return displayTime(iso, input.timeZone ?? 'UTC') ?? iso;
}

/** The scanned window, both ends in the configured zone */
function windowText(input: FanoutAlertInput): string {
  return `${when(input, input.window.from)} to ${when(input, input.window.to)}`;
}

/** Label/value rows of what was seen. Values from mail flow are returned unescaped. */
function seenRows(input: FanoutAlertInput): Fact[] {
  const { flag } = input;
  const rows: Fact[] = [
    { label: 'Sender (from mail flow)', value: flag.senderAddress },
    { label: 'Subject (from mail flow)', value: flag.subject || '(no subject)' },
    { label: 'First seen', value: when(input, input.waveFirstSeen) },
    { label: 'Latest in this scan', value: when(input, flag.lastSeen) },
    {
      label: 'This scan',
      value: `${plural(flag.windowRecipients, 'distinct internal recipient')} (${plural(flag.windowMessages, 'message')}) from ${windowText(input)}`,
    },
    { label: 'Wave so far', value: plural(input.waveRecipients, 'distinct internal recipient') },
  ];
  if (input.kind === 'growth' && input.previousRecipients !== undefined) {
    rows.push({
      label: 'Update',
      value: `the previous alert for this wave reported ${input.previousRecipients}; it has now reached ${input.waveRecipients}`,
    });
  }
  rows.push({ label: 'Delivery (this scan)', value: deliverySummary(flag.statuses) });
  return rows;
}

/** Every delivery state with its count */
function statusRows(statuses: FanoutStatusCounts): Fact[] {
  return (Object.keys(STATUS_LABEL) as Array<keyof FanoutStatusCounts>).map(key => ({
    label: STATUS_LABEL[key],
    value: String(statuses[key]),
  }));
}

/** The scan-incomplete sentence (also used in a scan-opened incident's reasons) */
export function incompleteLine(reasons: FanoutIncompleteReason[]): string | undefined {
  if (reasons.length === 0) {
    return undefined;
  }
  return `Scan incomplete: ${reasons.map(reason => INCOMPLETE_TEXT[reason]).join('; ')}. Counts are what was seen, and other waves may not have been checked.`;
}

/** The headline: who and how many, written by code (no mail-flow text) */
function alertHeadline(input: FanoutAlertInput): string {
  return input.kind === 'growth'
    ? `One external sender has now reached ${plural(input.waveRecipients, 'internal recipient')}`
    : `One external sender reached ${plural(input.waveRecipients, 'internal recipient')}`;
}

const HISTORY_CAVEAT =
  'A familiar sender is not evidence of safety: a taken-over mailbox has the same history.';
const REPLY_NOTE =
  'Quote this reference when you discuss this wave. Replying does not trigger any action.';
const GENERATED_BY =
  "Generated by Phishy's scheduled fan-out scan from Exchange message-trace metadata. No AI model was involved and no message content was read.";

/**
 * Who sent it, how many it reached, why it stands out and what to check
 * come first; the benign explanations, blast radius and recipient list
 * after.
 */
export function buildFanoutAlert(input: FanoutAlertInput): FanoutAlertEmail {
  const { flag } = input;
  // The classification in plain words: this email is read by people, not parsed
  const historyRows = formatSenderHistoryLines(flag.facts, { includeBurstIps: true }).map(
    ([label, value]) => ({
      label,
      value:
        label === 'Classification' ? SENDER_RELATIONSHIP_LABEL[flag.facts.classification] : value,
    })
  );
  const incomplete = incompleteLine(input.incompleteReasons);
  const recipientRows: Array<[string, string]> = flag.recipients.map(recipient => [
    recipient.address,
    STATUS_LABEL[recipient.status],
  ]);
  const update = input.kind === 'growth' ? ' (update)' : '';
  const headline = alertHeadline(input);
  const s = flag.statuses;

  const rows: string[] = [
    block(
      hero({
        tone: 'caution',
        word: 'Security team only',
        headline,
        html: paragraph(FANOUT_NOT_A_VERDICT, { quiet: true }),
      })
    ),
  ];
  if (incomplete) {
    rows.push(block(callout({ tone: 'caution', lines: [incomplete] })));
  }
  rows.push(
    block(
      `${heading('Who sent it and what arrived')}${stats([
        { label: 'Recipients so far', value: String(input.waveRecipients) },
        {
          label: 'Reached a mailbox',
          value: String(s.delivered),
          ...(s.delivered ? { tone: 'caution' as const } : {}),
        },
        { label: 'Quarantined', value: String(s.quarantined) },
        { label: 'Junk Email', value: String(s.junk) },
      ])}${facts(seenRows(input), { labelWidth: 130 })}${
        s.failed || s.other
          ? paragraph(`Delivery failed: ${s.failed}. Other / pending: ${s.other}.`, { quiet: true })
          : ''
      }`
    ),
    block(
      `${heading('Why it stands out')}${paragraph(FANOUT_MEANING)}${paragraph("The sender's history with us", { quiet: true, bold: true })}${facts(historyRows, { labelWidth: 140 })}${paragraph(
        `Counts from message trace for this sender address. ${HISTORY_CAVEAT}`,
        { quiet: true }
      )}`
    ),
    block(instructions({ title: 'What to check', steps: FANOUT_NEXT_STEPS, long: true })),
    block(
      `${heading('Common benign explanations', { quiet: true })}${bulletList(FANOUT_BENIGN_EXPLANATIONS, { quiet: true })}`
    )
  );
  if (input.blastRadius) {
    rows.push(buildBlastRadiusHtml(input.blastRadius));
  }
  rows.push(
    block(
      `${heading('Recipients in this scan (security team only)', { quiet: true })}${
        recipientRows.length
          ? dataTable(['Recipient', 'Delivery'], recipientRows)
          : paragraph('None listed.', { quiet: true })
      }${flag.recipientsOmitted > 0 ? paragraph(`${flag.recipientsOmitted} more recipient(s) not listed.`, { quiet: true }) : ''}`
    )
  );

  const html = emailShell({
    title: `Phishy Fan-out Alert${update} ${input.reference}`,
    preheader: `${headline}. Security team only: a behaviour-based flag, not a verdict.`,
    label: `Security team · Fan-out alert${update}`,
    tone: 'caution',
    bodyHtml: rows.join('\n'),
    footer: [
      `Reference: ${input.reference}`,
      REPLY_NOTE,
      `Scanned window: ${windowText(input)}`,
      GENERATED_BY,
    ],
  });

  const text: string[] = [
    `PHISHY FAN-OUT ALERT${update.toUpperCase()}: ${input.reference}`,
    '='.repeat(60),
    `SECURITY TEAM ONLY. ${FANOUT_NOT_A_VERDICT}`,
    '',
    `${headline}.`,
    '',
  ];
  if (incomplete) {
    text.push(incomplete, '');
  }
  text.push(
    'WHO SENT IT AND WHAT ARRIVED',
    TEXT_SUBRULE,
    ...textFacts(seenRows(input)),
    ...textFacts(statusRows(s)).map(line => `  ${line}`),
    '',
    'WHY IT STANDS OUT',
    TEXT_SUBRULE,
    FANOUT_MEANING,
    ...textFacts(historyRows),
    HISTORY_CAVEAT,
    '',
    'WHAT TO CHECK',
    TEXT_SUBRULE,
    ...FANOUT_NEXT_STEPS.map((step, index) => `${index + 1}. ${step}`),
    '',
    'COMMON BENIGN EXPLANATIONS',
    TEXT_SUBRULE,
    ...FANOUT_BENIGN_EXPLANATIONS.map(item => `- ${item}`)
  );
  if (input.blastRadius) {
    text.push('', ...buildBlastRadiusText(input.blastRadius));
  }
  text.push('', 'RECIPIENTS IN THIS SCAN (security team only)', TEXT_SUBRULE);
  for (const [address, status] of recipientRows) {
    text.push(`  ${address} | ${status}`);
  }
  if (flag.recipientsOmitted > 0) {
    text.push(`  ${flag.recipientsOmitted} more recipient(s) not listed.`);
  }
  text.push(
    '',
    `Reference: ${input.reference}`,
    REPLY_NOTE,
    `Scanned window: ${windowText(input)}`,
    '',
    GENERATED_BY
  );

  return { subject: alertSubject(input), html, text: text.join('\n') };
}

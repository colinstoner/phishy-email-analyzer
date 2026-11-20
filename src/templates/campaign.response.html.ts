/**
 * Campaign-response emails: the employee warning, the reporters' thank-you
 * note, the distribution-list warning, and the security team's incident
 * email and its updates.
 *
 * Same voice and structure as the analysis report: plain language first,
 * technical detail below; the verdict label, risk score and Confidence line
 * come from the report's own helpers, so they read the same everywhere.
 *
 * Every value that came from the suspicious email (subject, sender, the
 * model's description of it, its reasons) has been through `displayText`
 * (one line, defanged so nothing is a link) and is HTML-escaped here. No
 * template ever renders a link from the email.
 */

import type { BlastRadiusRecipient } from '../services/graph/blast-radius.service';
import { displaySender, displayText, displayTime } from '../services/response/display';
import type {
  CampaignIncident,
  IncidentSummary,
  ResponseAction,
  WarningRecipient,
} from '../services/response/response.types';
import {
  ReportRisk,
  describeVerdict,
  escapeEmailHtml as esc,
  riskScoreHtml,
  riskScoreLines,
} from './report.html';

export interface RenderedEmail {
  subject: string;
  html: string;
  text: string;
}

export interface WarningContext {
  summary: IncidentSummary;
  reportCount: number;
  timeZone: string;
  /** The organization's own "if you already clicked" text (plain, operator-written) */
  alreadyClickedInstructions: string;
  incidentReference: string;
  /** Who confirmed the verdict, as the employee is told */
  confirmedBy: 'security_team' | 'phishy';
  /** Recipients warned, for the reporters' note */
  warnedCount: number;
}

const DEFANG_NOTE =
  'Phishy never puts links in its warnings. Web and email addresses in this message are written with [.] so they cannot be clicked.';

/** The incident's risk as the report helpers take it */
export function summaryRisk(summary: IncidentSummary): ReportRisk {
  return {
    verdict: summary.verdict,
    riskScore: summary.riskScore,
    riskLevel: summary.riskLevel,
    reasons: summary.reasons,
    confidence: summary.confidence,
    confidenceBasis: summary.confidenceBasis,
  };
}

/** One header-safe line for a Subject (no line breaks, bounded) */
function subjectLine(text: string): string {
  return text.replace(/[\r\n]+/g, ' ').slice(0, 200);
}

function quotedSubject(summary: IncidentSummary, max = 80): string | undefined {
  const subject = displayText(summary.subject, max);
  return subject ? `"${subject}"` : undefined;
}

// ---------------------------------------------------------------------------
// Shared layout
// ---------------------------------------------------------------------------

interface Section {
  heading: string;
  /** Plain-text lines; each becomes a paragraph (or a list item when it starts with "- ") */
  lines: string[];
  tone?: 'danger' | 'caution' | 'note';
}

const TONE_STYLE: Record<NonNullable<Section['tone']>, string> = {
  danger: 'background-color: #fdecea; border-left: 4px solid #dc3545;',
  caution: 'background-color: #fff4e5; border-left: 4px solid #fd7e14;',
  note: 'background-color: #f8f9fa; border-left: 4px solid #6c757d;',
};

function sectionHtml(section: Section, extraHtml = ''): string {
  const items = section.lines.filter(line => line.startsWith('- '));
  const paragraphs = section.lines.filter(line => !line.startsWith('- '));
  const style = section.tone
    ? `${TONE_STYLE[section.tone]} padding: 10px 14px; border-radius: 6px;`
    : '';
  return `
      <div style="margin: 0 0 18px 0; ${style}">
        <h3 style="margin: 0 0 8px 0; font-size: 16px; color: #2C3E50;">${esc(section.heading)}</h3>
        ${paragraphs.map(line => `<p style="margin: 4px 0;">${esc(line)}</p>`).join('')}
        ${items.length ? `<ul style="margin: 6px 0; padding-left: 22px;">${items.map(line => `<li>${esc(line.slice(2))}</li>`).join('')}</ul>` : ''}
        ${extraHtml}
      </div>`;
}

function sectionText(section: Section): string[] {
  return [section.heading.toUpperCase(), ...section.lines, ''];
}

function layout(options: {
  title: string;
  lead: string;
  leadTone: 'danger' | 'caution' | 'safe';
  sections: Section[];
  riskBlock?: { label: string; risk: ReportRisk; plain?: string };
  footer: string[];
  extraHtml?: Record<number, string>;
}): { html: string; text: string } {
  const leadStyle =
    options.leadTone === 'safe'
      ? 'background-color: #e9f7ef; border-left: 4px solid #28a745;'
      : TONE_STYLE[options.leadTone];
  const risk = options.riskBlock;
  const riskHtml = risk
    ? `
      <div style="margin: 0 0 18px 0; padding: 12px 16px; border-radius: 6px; ${TONE_STYLE[describeVerdict(risk.risk.verdict).tone === 'danger' ? 'danger' : 'caution']}">
        <p style="margin: 0; font-size: 18px;"><strong>${esc(risk.label)}</strong></p>
        ${riskScoreHtml(risk.risk)}
        ${risk.plain ? `<p style="margin: 6px 0 0 0;"><strong>What this means:</strong> ${esc(risk.plain)}</p>` : ''}
      </div>`
    : '';

  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(options.title)}</title>
  </head>
  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #333; margin: 0; padding: 20px; background-color: #f9f9f9;">
    <div style="max-width: 720px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden;">
      <div style="background-color: #2C3E50; color: white; padding: 18px 20px;">
        <h1 style="margin: 0; font-size: 22px;">${esc(options.title)}</h1>
      </div>
      <div style="padding: 20px;">
        <p style="margin: 0 0 18px 0; padding: 12px 16px; border-radius: 6px; font-size: 16px; ${leadStyle}"><strong>${esc(options.lead)}</strong></p>
        ${riskHtml}
        ${options.sections.map((section, index) => sectionHtml(section, options.extraHtml?.[index] ?? '')).join('')}
      </div>
      <div style="font-size: 12px; color: #777; padding: 15px 20px; background-color: #f5f5f5; border-top: 1px solid #eee;">
        ${options.footer.map(line => `<p style="margin: 4px 0;">${esc(line)}</p>`).join('')}
      </div>
    </div>
  </body>
</html>`;

  const divider = '='.repeat(50);
  const text = [
    options.title.toUpperCase(),
    divider,
    '',
    options.lead,
    '',
    // The verdict and risk score straight after the plain lead, as in the report
    ...(risk
      ? [
          `Verdict: ${risk.label}`,
          ...riskScoreLines(risk.risk),
          ...(risk.plain ? [`What this means: ${risk.plain}`] : []),
          '',
        ]
      : []),
    ...options.sections.flatMap(sectionText),
    divider,
    ...options.footer,
  ].join('\n');

  return { html, text };
}

// ---------------------------------------------------------------------------
// Employee emails
// ---------------------------------------------------------------------------

function whatToDo(): Section {
  return {
    heading: 'What to do',
    lines: [
      '- Do not click any link or open any attachment in it.',
      '- Do not reply to it.',
      '- Delete it.',
      'You do not need to forward it or report it: your security team already knows about it.',
    ],
  };
}

function alreadyClicked(context: WarningContext): Section {
  return {
    heading: 'If you already clicked or entered your password',
    lines: [context.alreadyClickedInstructions.replace(/\s+/g, ' ').trim()],
    tone: 'caution',
  };
}

function whyYouAreGettingThis(context: WarningContext): string {
  if (context.reportCount === 0) {
    return 'Phishy noticed this email reaching many people at once, and your security team checked it.';
  }
  const who = context.reportCount === 1 ? '1 colleague' : `${context.reportCount} colleagues`;
  return context.confirmedBy === 'security_team'
    ? `${who} reported this email. Phishy checked it and your security team confirmed it.`
    : `${who} reported this email and Phishy checked it.`;
}

function whatArrived(
  context: WarningContext,
  recipient: WarningRecipient
): { lines: string[]; lead: string } {
  const subject = quotedSubject(context.summary);
  const sender = displaySender(context.summary.senderAddress, context.summary.senderName);
  const when = displayTime(
    recipient.receivedAt ?? context.summary.firstDeliveryAt,
    context.timeZone
  );
  const lines = [
    subject ? `An email with the subject ${subject}` : 'An email',
    ...(sender ? [`from ${sender}`] : []),
  ];
  const on = when ? ` on ${when}` : '';
  switch (recipient.folder) {
    case 'junk':
      lines.push(
        `arrived in your Junk Email folder${on}. It is still dangerous there: do not open it.`
      );
      break;
    case 'deleted':
      lines.push(
        `arrived in your mailbox${on} and is now in your Deleted Items. If you did not open it, there is nothing else to do.`
      );
      break;
    case 'recoverable':
      lines.push(`arrived in your mailbox${on}. You have already deleted it.`);
      break;
    default:
      lines.push(`arrived in your mailbox${on}.`);
  }
  return { lines, lead: 'A phishing email reached your mailbox. Please delete it.' };
}

/** The warning to one person who received the attack */
export function buildEmployeeWarning(
  context: Omit<WarningContext, 'warnedCount'>,
  recipient: WarningRecipient
): RenderedEmail {
  const verdict = describeVerdict(context.summary.verdict);
  const subject = quotedSubject(context.summary, 60);
  const arrived = whatArrived({ ...context, warnedCount: 0 }, recipient);
  const { html, text } = layout({
    title: 'Security warning from Phishy',
    lead: arrived.lead,
    leadTone: 'danger',
    sections: [
      { heading: 'What arrived', lines: arrived.lines },
      whatToDo(),
      alreadyClicked({ ...context, warnedCount: 0 }),
      {
        heading: 'Why you are getting this',
        lines: [whyYouAreGettingThis({ ...context, warnedCount: 0 })],
      },
    ],
    riskBlock: { label: verdict.label, risk: summaryRisk(context.summary), plain: verdict.plain },
    footer: [
      DEFANG_NOTE,
      `Reference: ${context.incidentReference}`,
      'Phishy, for your security team',
    ],
  });
  return {
    subject: subjectLine(
      subject
        ? `Security warning: delete the email ${subject}. It is phishing`
        : 'Security warning: a phishing email reached your mailbox'
    ),
    html,
    text,
  };
}

/** The shorter note to someone who already reported the attack */
export function buildReporterThanks(context: WarningContext): RenderedEmail {
  const verdict = describeVerdict(context.summary.verdict);
  const subject = quotedSubject(context.summary);
  const confirmed =
    context.confirmedBy === 'security_team'
      ? 'Your security team confirmed it.'
      : 'Phishy confirmed it.';
  const did: string[] = [];
  if (context.warnedCount > 0) {
    did.push(
      `- Warned the ${context.warnedCount} other ${context.warnedCount === 1 ? 'person' : 'people'} who received it, each in a separate email.`
    );
  }
  did.push('- Recorded the attack, so new copies are flagged straight away.');
  if (context.reportCount > 1) {
    did.push(`- ${context.reportCount} people reported it in all. Every report helped.`);
  }
  const { html, text } = layout({
    title: 'Thank you for reporting',
    lead: `The email you reported${subject ? `, ${subject},` : ''} was phishing. ${confirmed}`,
    leadTone: 'safe',
    sections: [
      { heading: 'What we did', lines: did },
      {
        heading: 'What to do',
        lines: ['Nothing else. If you have not already, delete the email.'],
      },
      alreadyClicked(context),
    ],
    riskBlock: { label: verdict.label, risk: summaryRisk(context.summary) },
    footer: [
      DEFANG_NOTE,
      `Reference: ${context.incidentReference}`,
      'Phishy, for your security team',
    ],
  });
  return { subject: 'Thank you: the email you reported was phishing', html, text };
}

/** The broadcast to the distribution list (campaign response on) */
export function buildDistributionWarning(
  context: Omit<WarningContext, 'warnedCount'>
): RenderedEmail {
  const verdict = describeVerdict(context.summary.verdict);
  const subject = quotedSubject(context.summary, 60);
  const sender = displaySender(context.summary.senderAddress, context.summary.senderName);
  const first = displayTime(
    context.summary.firstDeliveryAt ?? context.summary.firstReportAt,
    context.timeZone
  );
  const { html, text } = layout({
    title: 'Security warning from Phishy',
    lead: 'A phishing email is going around. If you received it, delete it.',
    leadTone: 'danger',
    sections: [
      {
        heading: 'What to look for',
        lines: [
          subject ? `An email with the subject ${subject}` : 'An email',
          ...(sender ? [`from ${sender}`] : []),
          ...(first ? [`first seen on ${first}.`] : []),
        ],
      },
      whatToDo(),
      alreadyClicked({ ...context, warnedCount: 0 }),
      {
        heading: 'Why you are getting this',
        lines: [whyYouAreGettingThis({ ...context, warnedCount: 0 })],
      },
    ],
    riskBlock: { label: verdict.label, risk: summaryRisk(context.summary), plain: verdict.plain },
    footer: [
      DEFANG_NOTE,
      `Reference: ${context.incidentReference}`,
      'Phishy, for your security team',
    ],
  });
  return {
    subject: subjectLine(
      subject
        ? `Security warning: phishing email ${subject} is going around`
        : 'Security warning: a phishing email is going around'
    ),
    html,
    text,
  };
}

// ---------------------------------------------------------------------------
// Security team: the incident email
// ---------------------------------------------------------------------------

export interface IncidentEmailContext {
  incident: CampaignIncident;
  /** Proposed actions waiting for approval, in the order they are listed */
  proposed: ResponseAction[];
  /** What Phishy has already done (code-written lines) */
  done: string[];
  /** Other code-written notes (why something was not proposed) */
  notes: string[];
  /** Set for an update to an existing incident: what changed */
  changes?: string[];
  commandsEnabled: boolean;
  timeZone: string;
}

/**
 * The incident thread's subject: stable, so every update threads under it.
 * It carries the reference only, never the suspicious email's own subject:
 * a subject line that repeats a phishing lure gets the incident email itself
 * filtered as phishing by the receiving mail system. The lure's subject is in
 * the body.
 */
export function incidentSubject(incident: CampaignIncident): string {
  return subjectLine(`[Phishy incident ${incident.reference}] Active phishing campaign`);
}

const FOLDER_LABEL: Record<string, string> = {
  inbox: 'Inbox',
  junk: 'Junk',
  deleted: 'Deleted Items',
  recoverable: 'Purged (Recoverable Items)',
  other: 'Other folder',
  unknown: 'Unknown',
};

function recipientCells(recipient: BlastRadiusRecipient): string[] {
  if (recipient.mailbox === 'not_delivered') {
    return [recipient.address, 'Not delivered', '-', '-'];
  }
  if (recipient.mailbox !== 'found') {
    return [recipient.address, 'Mailbox not checked', '-', '-'];
  }
  const read = recipient.isRead === undefined ? 'Unknown' : recipient.isRead ? 'Read' : 'Unread';
  const response =
    recipient.response === 'replied'
      ? 'REPLIED'
      : recipient.response === 'forwarded'
        ? 'FORWARDED'
        : recipient.response === 'none'
          ? 'None recorded'
          : 'Unknown';
  return [
    recipient.address,
    FOLDER_LABEL[recipient.folder ?? 'unknown'] ?? 'Unknown',
    read,
    response,
  ];
}

const LISTED_IN_INCIDENT = 25;
const RECIPIENT_COLUMNS = ['Recipient', 'Location', 'Read', 'Replied / forwarded'];

function inShort(incident: CampaignIncident): string {
  const reach = incident.reach;
  const label = describeVerdict(incident.summary.verdict).label.toLowerCase();
  const opening =
    incident.trigger === 'fanout_scan' && incident.reportCount === 0
      ? `Phishy's fan-out scan saw this email reach many people before anyone reported it.`
      : `${incident.reportCount} ${incident.reportCount === 1 ? 'person has' : 'people have'} reported the same ${label} email.`;
  if (
    reach.status === 'not_enabled' ||
    (reach.status === 'unavailable' && reach.recipients.length === 0)
  ) {
    return `${opening} Phishy could not look up who else received it.`;
  }
  const atLeast = reach.unlisted > 0 || reach.status === 'partial' ? 'at least ' : '';
  const t = reach.totals;
  return `${opening} It reached ${atLeast}${t.recipients} mailbox(es): ${t.read} opened it, ${t.replied} replied, ${t.forwarded} forwarded it, and ${t.stillInInbox} still have it in their inbox.`;
}

function attackSection(incident: CampaignIncident): Section {
  const summary = incident.summary;
  const sender = displaySender(summary.senderAddress, summary.senderName);
  const lines = [
    ...(summary.subject ? [`Subject: ${quotedSubject(summary, 120) ?? ''}`] : []),
    ...(sender ? [`Claimed sender: ${sender}`] : []),
    ...(summary.lure ? [`Lure: ${displayText(summary.lure, 400) ?? ''}`] : []),
    `Detected by: ${summary.detectedBy}`,
  ];
  const reasons = summary.reasons
    .slice(0, 5)
    .map(reason => displayText(reason, 240))
    .filter((reason): reason is string => !!reason)
    .map(reason => `- ${reason}`);
  if (reasons.length) {
    lines.push('Main reasons:', ...reasons);
  }
  return { heading: 'What the attack is', lines };
}

function timelineSection(incident: CampaignIncident, timeZone: string): Section {
  const s = incident.summary;
  const t = (iso?: string): string => displayTime(iso, timeZone) ?? 'unknown';
  return {
    heading: 'Timeline',
    lines: [
      `First delivery: ${s.firstDeliveryAt ? `${t(s.firstDeliveryAt)} (from mailbox records)` : 'unknown'}`,
      `First report: ${s.firstReportAt ? t(s.firstReportAt) : 'none yet'}`,
      ...(s.lastReportAt && s.lastReportAt !== s.firstReportAt
        ? [`Latest report: ${t(s.lastReportAt)}`]
        : []),
      `Reports so far: ${incident.reportCount}`,
    ],
  };
}

function reachSection(incident: CampaignIncident): {
  section: Section;
  table: string;
  rows: string[];
} {
  const reach = incident.reach;
  if (reach.status === 'not_enabled') {
    return {
      section: {
        heading: 'Blast radius',
        lines: [
          'Blast radius is not enabled, so Phishy cannot say who else received it or warn them directly.',
        ],
      },
      table: '',
      rows: [],
    };
  }
  if (reach.recipients.length === 0) {
    return {
      section: {
        heading: 'Blast radius',
        lines: [reach.note ?? 'The blast-radius lookup produced no result.'],
      },
      table: '',
      rows: [],
    };
  }
  const t = reach.totals;
  const lines = [
    `Recipients: ${t.recipients} · Read: ${t.read} · Replied: ${t.replied} · Forwarded: ${t.forwarded} · Still in inbox: ${t.stillInInbox} · Not delivered: ${t.notDelivered}`,
  ];
  if (reach.coverage) {
    const eligible = `${reach.coverage.lowerBound ? 'at least ' : ''}${reach.coverage.mailboxesEligible}`;
    lines.push(
      reach.status === 'partial'
        ? `PARTIAL COVERAGE: checked ${reach.coverage.mailboxesChecked} of ${eligible} mailboxes. Recipients or details may be missing.`
        : `Coverage: checked ${reach.coverage.mailboxesChecked} of ${eligible} mailboxes.`
    );
  }
  if (reach.unlisted > 0) {
    lines.push(
      `${reach.unlisted} more recipient(s) were counted but not listed by a lookup, so Phishy has no address for them.`
    );
  }
  if (reach.lookedUpAt) {
    lines.push(`Latest lookup: ${reach.lookedUpAt}.`);
  }
  for (const caveat of reach.caveats.slice(0, 6)) {
    lines.push(`- ${caveat}`);
  }

  // The people needing attention first: replied, forwarded, opened, in a mailbox
  const rank = (r: BlastRadiusRecipient): number =>
    r.response === 'replied'
      ? 0
      : r.response === 'forwarded'
        ? 1
        : r.isRead === true
          ? 2
          : r.mailbox === 'found'
            ? 3
            : r.mailbox === 'not_delivered'
              ? 5
              : 4;
  const listed = [...reach.recipients]
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, LISTED_IN_INCIDENT);
  const cell = 'padding: 4px 8px; border-bottom: 1px solid #e9ecef; text-align: left;';
  let table = '<table style="width: 100%; border-collapse: collapse; font-size: 13px;">';
  table += `<tr>${RECIPIENT_COLUMNS.map(name => `<th style="${cell}">${name}</th>`).join('')}</tr>`;
  for (const recipient of listed) {
    table += `<tr>${recipientCells(recipient)
      .map(value => `<td style="${cell}">${esc(value)}</td>`)
      .join('')}</tr>`;
  }
  table += '</table>';
  const more = reach.recipients.length - listed.length;
  if (more > 0) {
    table += `<p style="font-size: 12px; color: #6c757d;">${more} more recipient(s) not listed here.</p>`;
  }
  const rows = [
    `  ${RECIPIENT_COLUMNS.join(' | ')}`,
    ...listed.map(recipient => `  ${recipientCells(recipient).join(' | ')}`),
    ...(more > 0 ? [`  ${more} more recipient(s) not listed here.`] : []),
  ];
  return { section: { heading: 'Blast radius', lines }, table, rows };
}

/** The exact reply line that approves an action */
export function approvalLine(action: ResponseAction): string {
  return `APPROVE ${action.type === 'send_warning' ? 'WARNING' : 'REMOVAL'} ${action.reference}`;
}

function describeProposal(action: ResponseAction): {
  title: string;
  does: string;
  notIncluded?: string;
} {
  const scope = action.scope;
  if (scope.kind === 'send_warning') {
    const parts: string[] = [];
    if (scope.recipients.length) {
      parts.push(
        `emails a warning to ${scope.recipients.length} recipient(s), one email each (nobody sees anyone else's address)`
      );
    }
    if (scope.reporters.length) {
      parts.push(`sends a thank-you note to ${scope.reporters.length} reporter(s)`);
    }
    if (scope.distribution) {
      parts.push('sends the warning to the distribution list');
    }
    const s = scope.skipped;
    const left = [
      s.notDelivered ? `${s.notDelivered} not delivered` : '',
      s.unsafeAddress ? `${s.unsafeAddress} not on a safe domain` : '',
      s.alreadyContacted ? `${s.alreadyContacted} already contacted` : '',
      s.overCap ? `${s.overCap} over the per-campaign cap` : '',
      s.unlisted ? `${s.unlisted} with no known address` : '',
    ].filter(Boolean);
    return {
      title: 'Warn the people who received it',
      does: `${parts.join(', ')}. The warning contains no links.`,
      ...(left.length ? { notIncluded: left.join(', ') } : {}),
    };
  }
  const s = scope.skipped;
  const left = [
    s.alreadyPurged ? `${s.alreadyPurged} already purged` : '',
    s.noIdentifiers ? `${s.noIdentifiers} without a usable message ID` : '',
    s.overMailboxCap
      ? `${s.overMailboxCap} over the mailbox cap (${scope.limits.maxMailboxes})`
      : '',
    s.overMessageCap
      ? `${s.overMessageCap} over the message cap (${scope.limits.maxMessages})`
      : '',
  ].filter(Boolean);
  return {
    title: 'Remove remaining copies from mailboxes (dry run)',
    does: `re-checks the ${scope.messageCount} copy(ies) in ${scope.mailboxes.length} mailbox(es) that the blast-radius lookup matched for this incident (exact message IDs, never a search) and replies with what a removal would do. No mailbox is changed: the mailbox write tier is not installed.`,
    ...(left.length ? { notIncluded: left.join(', ') } : {}),
  };
}

function proposalLines(context: IncidentEmailContext): string[] {
  const lines: string[] = [];
  if (!context.commandsEnabled) {
    lines.push(
      'The email command channel is off (PHISHY_EMAIL_COMMANDS_ENABLED), so Phishy cannot receive approvals. These actions are listed for information only.'
    );
  } else if (context.proposed.length === 0) {
    lines.push('No action is waiting for approval.');
  } else {
    const expiry = context.proposed[0].expiresAt;
    lines.push(
      `Reply to this email with the line shown, on a line of its own. Each approval is good until ${displayTime(expiry.toISOString(), context.timeZone) ?? expiry.toISOString()} and applies to this incident only.`
    );
  }
  let n = 0;
  for (const action of context.proposed) {
    n += 1;
    const { title, does, notIncluded } = describeProposal(action);
    lines.push(`${n}. ${title}`);
    lines.push(`   Reply with this line:  ${approvalLine(action)}`);
    lines.push(`   What it does: ${does.charAt(0).toUpperCase()}${does.slice(1)}`);
    if (notIncluded) {
      lines.push(`   Not included: ${notIncluded}.`);
    }
  }
  if (context.incident.summary.analysisId) {
    n += 1;
    lines.push(`${n}. Mark the campaign as a false positive`);
    lines.push('   Reply with this line:  false positive');
    lines.push(
      '   What it does: records "false positive" for every report in this campaign, lowers its threat indicators and cancels the proposed actions above.'
    );
  }
  return lines;
}

function proposalHtml(lines: string[]): string {
  return `<div style="font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 13px; white-space: pre-wrap; background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 10px;">${lines.map(line => esc(line)).join('\n')}</div>`;
}

/** The incident email, or an update to it (`changes` set) */
export function buildIncidentEmail(context: IncidentEmailContext): RenderedEmail {
  const incident = context.incident;
  const verdict = describeVerdict(incident.summary.verdict);
  const reach = reachSection(incident);
  const proposals = proposalLines(context);
  const sections: Section[] = [];
  if (context.changes?.length) {
    sections.push({
      heading: 'What changed',
      lines: context.changes.map(line => `- ${line}`),
      tone: 'note',
    });
  }
  sections.push(
    attackSection(incident),
    timelineSection(incident, context.timeZone),
    reach.section
  );
  sections.push({
    heading: 'What Phishy has done',
    lines: [...context.done, ...context.notes].map(line => `- ${line}`),
  });
  const proposalIndex = sections.length;
  sections.push({ heading: 'Proposed actions', lines: [] });

  const reachIndex = sections.indexOf(reach.section);
  const { html } = layout({
    title: context.changes
      ? `Phishy incident update ${incident.reference}`
      : `Phishy incident ${incident.reference}`,
    lead: inShort(incident),
    leadTone: verdict.tone === 'safe' ? 'caution' : verdict.tone,
    sections,
    riskBlock: { label: verdict.label, risk: summaryRisk(incident.summary) },
    footer: footerLines(incident),
    extraHtml: { [reachIndex]: reach.table, [proposalIndex]: proposalHtml(proposals) },
  });

  // Plain text: the table rows and the proposals in place
  const textSections = sections.map((section, index) => {
    if (index === reachIndex) {
      return { ...section, lines: [...section.lines, ...reach.rows] };
    }
    if (index === proposalIndex) {
      return { ...section, lines: proposals };
    }
    return section;
  });
  const { text } = layout({
    title: context.changes
      ? `Phishy incident update ${incident.reference}`
      : `Phishy incident ${incident.reference}`,
    lead: inShort(incident),
    leadTone: 'caution',
    sections: textSections,
    riskBlock: { label: verdict.label, risk: summaryRisk(incident.summary) },
    footer: footerLines(incident),
  });

  const subject = incidentSubject(incident);
  return { subject: context.changes ? `Re: ${subject}` : subject, html, text };
}

function footerLines(incident: CampaignIncident): string[] {
  return [
    'Security team only. Addresses from the suspicious email are written with [.] so they cannot be clicked.',
    `Incident reference: ${incident.reference}`,
    ...(incident.summary.analysisId ? [`Analysis ID: ${incident.summary.analysisId}`] : []),
  ];
}

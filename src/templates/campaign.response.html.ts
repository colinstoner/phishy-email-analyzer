/**
 * Campaign-response emails: the employee warning, the removal notice, the
 * distribution-list warning, and the security team's incident email and its
 * updates.
 *
 * Same voice and structure as the analysis report: plain language first,
 * technical detail below; the verdict label, risk score and Confidence line
 * come from the report's own helpers, so they read the same everywhere. The
 * page itself is built from the shared blocks in `layout.ts`.
 *
 * Every value that came from the suspicious email (subject, sender, the
 * model's description of it, its reasons) has been through `displayText`
 * (one line, defanged so nothing is a link) and is HTML-escaped here: it is
 * only ever handed to the layout blocks as plain text, never as markup. No
 * template ever renders a link from the email.
 */

import type { BlastRadiusRecipient } from '../services/graph/blast-radius.service';
import {
  Fact,
  TEXT_RULE,
  Tone,
  block,
  bulletList,
  callout,
  codeInline,
  dataTable,
  divider,
  emailShell,
  facts,
  heading,
  hero,
  instructions,
  panel,
  paragraph,
  paragraphHtml,
  stats,
  textFacts,
  textSection,
} from './layout';
import { displaySender, displayText, displayTime } from '../services/response/display';
import type {
  CampaignIncident,
  IncidentSummary,
  ResponseAction,
  WarningRecipient,
} from '../services/response/response.types';
import { ReportRisk, describeVerdict, riskScoreHtml, riskScoreLines } from './report.html';

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
  /** Recipients warned (no longer shown: the reporters' note was removed) */
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
// Sections: simple notices written as headed lists of lines
// ---------------------------------------------------------------------------

interface Section {
  heading: string;
  /** Plain-text lines; each becomes a paragraph (or a list item when it starts with "- ") */
  lines: string[];
  tone?: 'danger' | 'caution' | 'note';
}

const SECTION_TONE: Record<NonNullable<Section['tone']>, Tone> = {
  danger: 'danger',
  caution: 'caution',
  note: 'neutral',
};

/** One section as a card row: a tinted callout when it has a tone */
function sectionBlock(section: Section): string {
  const items = section.lines.filter(line => line.startsWith('- ')).map(line => line.slice(2));
  const paragraphs = section.lines.filter(line => !line.startsWith('- '));
  if (section.tone) {
    return block(
      callout({
        tone: SECTION_TONE[section.tone],
        title: section.heading,
        lines: paragraphs,
        html: bulletList(items),
      })
    );
  }
  return block(
    `${heading(section.heading)}${paragraphs.map(line => paragraph(line)).join('')}${bulletList(items)}`
  );
}

/**
 * A notice made of a lead (the hero, with its severity word) and sections,
 * in both formats. For emails with no score and no special structure.
 */
function renderSections(options: {
  title: string;
  label: string;
  lead: string;
  tone: Tone;
  word: string;
  sections: Section[];
  footer: string[];
}): { html: string; text: string } {
  const html = emailShell({
    title: options.title,
    preheader: options.lead,
    label: options.label,
    tone: options.tone,
    bodyHtml: [
      block(hero({ tone: options.tone, word: options.word, headline: options.lead })),
      ...options.sections.map(sectionBlock),
    ].join('\n'),
    footer: options.footer,
  });
  const text = [
    options.title.toUpperCase(),
    TEXT_RULE,
    '',
    options.lead,
    '',
    ...options.sections.flatMap(section => textSection(section.heading, section.lines)),
    TEXT_RULE,
    ...options.footer,
  ].join('\n');
  return { html, text };
}

// ---------------------------------------------------------------------------
// Employee emails
// ---------------------------------------------------------------------------

const WHAT_TO_DO_STEPS = [
  'Do not click any link or open any attachment in it.',
  'Do not reply to it.',
  'Delete it.',
];
const NO_NEED_TO_REPORT =
  'You do not need to forward it or report it: your security team already knows about it.';

const EMPLOYEE_FOOTER = (reference: string): string[] => [
  DEFANG_NOTE,
  `Reference: ${reference}`,
  'Phishy, for your security team',
];

/**
 * The parts every employee warning has, in one order for both formats:
 * the lead, the verdict and score, which email (labelled facts), what to
 * do, what to do if they already clicked, why they are getting it.
 */
interface WarningParts {
  title: string;
  preheader: string;
  lead: string;
  verdictLabel: string;
  risk: ReportRisk;
  emailHeading: string;
  emailFacts: Fact[];
  clicked: Section;
  why: string;
  reference: string;
}

function renderWarning(parts: WarningParts): { html: string; text: string } {
  const rows = [
    block(
      hero({
        tone: 'danger',
        word: parts.verdictLabel,
        headline: parts.lead,
        html: riskScoreHtml(parts.risk),
      })
    ),
    block(`${heading(parts.emailHeading)}${facts(parts.emailFacts, { labelWidth: 90 })}`),
    block(instructions({ title: 'What to do', steps: WHAT_TO_DO_STEPS, note: NO_NEED_TO_REPORT })),
    block(callout({ tone: 'caution', title: parts.clicked.heading, lines: parts.clicked.lines })),
    block(paragraph(parts.why, { quiet: true })),
  ];
  const html = emailShell({
    title: parts.title,
    preheader: parts.preheader,
    label: 'Security warning',
    tone: 'danger',
    bodyHtml: rows.join('\n'),
    footer: EMPLOYEE_FOOTER(parts.reference),
  });

  const text = [
    parts.title.toUpperCase(),
    TEXT_RULE,
    '',
    parts.lead,
    '',
    `Verdict: ${parts.verdictLabel}`,
    ...riskScoreLines(parts.risk),
    '',
    ...textSection(parts.emailHeading, textFacts(parts.emailFacts)),
    ...textSection('What to do', [
      ...WHAT_TO_DO_STEPS.map((step, index) => `${index + 1}. ${step}`),
      NO_NEED_TO_REPORT,
    ]),
    ...textSection(parts.clicked.heading, parts.clicked.lines),
    ...textSection('Why you are getting this', [parts.why]),
    TEXT_RULE,
    ...EMPLOYEE_FOOTER(parts.reference),
  ].join('\n');
  return { html, text };
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

/** Where the recipient's own copy is, in their terms */
const WHERE_IT_IS: Record<string, string> = {
  junk: 'Your Junk Email folder. It is still dangerous there: do not open it.',
  deleted: 'Your Deleted Items. If you did not open it, there is nothing else to do.',
  recoverable: 'You have already deleted it.',
};

/** The subject and sender as labelled facts: defanged by `displayText`, escaped when rendered */
function identifyingFacts(summary: IncidentSummary): Fact[] {
  const subject = quotedSubject(summary, 80);
  const sender = displaySender(summary.senderAddress, summary.senderName);
  return [
    ...(subject ? [{ label: 'Subject', value: subject }] : []),
    ...(sender ? [{ label: 'From', value: sender }] : []),
  ];
}

/** The warning to one person who received the attack */
export function buildEmployeeWarning(
  context: Omit<WarningContext, 'warnedCount'>,
  recipient: WarningRecipient
): RenderedEmail {
  const verdict = describeVerdict(context.summary.verdict);
  const subject = quotedSubject(context.summary, 60);
  const when = displayTime(
    recipient.receivedAt ?? context.summary.firstDeliveryAt,
    context.timeZone
  );
  const lead = 'A phishing email reached your mailbox. Please delete it.';
  const { html, text } = renderWarning({
    title: 'Security warning from Phishy',
    preheader: lead,
    lead,
    verdictLabel: verdict.label,
    risk: summaryRisk(context.summary),
    emailHeading: 'Which email',
    emailFacts: [
      ...identifyingFacts(context.summary),
      ...(when ? [{ label: 'Arrived', value: when }] : []),
      {
        label: 'Where',
        value: WHERE_IT_IS[recipient.folder ?? ''] ?? 'In your mailbox.',
      },
    ],
    clicked: alreadyClicked({ ...context, warnedCount: 0 }),
    why: whyYouAreGettingThis({ ...context, warnedCount: 0 }),
    reference: context.incidentReference,
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

/**
 * The notice to someone whose copy was actually removed from their mailbox
 * (moved to Deleted Items) by an approved removal. Sent only for removals a
 * real write tier reports per mailbox; the dry run never causes one.
 */
export function buildRemovalNotice(context: Omit<WarningContext, 'warnedCount'>): RenderedEmail {
  const subject = quotedSubject(context.summary);
  const sender = displaySender(context.summary.senderAddress, context.summary.senderName);
  const { html, text } = renderSections({
    title: 'Security notice from Phishy',
    label: 'Security notice',
    lead: 'Your security team removed a phishing email from your mailbox. You do not need to do anything.',
    tone: 'safe',
    word: 'Removed',
    sections: [
      {
        heading: 'What happened',
        lines: [
          'Your security team identified a phishing email in your mailbox and moved it to your Deleted Items folder.',
          ...(subject || sender
            ? [
                `It ${[
                  subject ? `had the subject ${subject}` : '',
                  sender ? `came from ${sender}` : '',
                ]
                  .filter(Boolean)
                  .join(' and ')}.`,
              ]
            : []),
        ],
      },
      {
        heading: 'What to do',
        lines: [
          'Nothing. No action is needed.',
          '- Do not restore it from Deleted Items or open it there.',
        ],
      },
      {
        heading: 'If you clicked a link or entered your password',
        lines: [
          'Contact your security team straight away.',
          context.alreadyClickedInstructions.replace(/\s+/g, ' ').trim(),
        ],
        tone: 'caution',
      },
    ],
    footer: [
      DEFANG_NOTE,
      `Reference: ${context.incidentReference}`,
      'Phishy, for your security team',
    ],
  });
  // The lure's subject stays out of the Subject line: repeating it gets the
  // notice itself filtered as phishing
  return {
    subject: 'Security notice: a phishing email was removed from your mailbox',
    html,
    text,
  };
}

/** The broadcast to the distribution list (campaign response on) */
export function buildDistributionWarning(
  context: Omit<WarningContext, 'warnedCount'>
): RenderedEmail {
  const verdict = describeVerdict(context.summary.verdict);
  const subject = quotedSubject(context.summary, 60);
  const first = displayTime(
    context.summary.firstDeliveryAt ?? context.summary.firstReportAt,
    context.timeZone
  );
  const lead = 'A phishing email is going around. If you received it, delete it.';
  const { html, text } = renderWarning({
    title: 'Security warning from Phishy',
    preheader: lead,
    lead,
    verdictLabel: verdict.label,
    risk: summaryRisk(context.summary),
    emailHeading: 'What to look for',
    emailFacts: [
      ...identifyingFacts(context.summary),
      ...(first ? [{ label: 'First seen', value: first }] : []),
    ],
    clicked: alreadyClicked({ ...context, warnedCount: 0 }),
    why: whyYouAreGettingThis({ ...context, warnedCount: 0 }),
    reference: context.incidentReference,
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

/** What the attack is, as labelled facts plus its main reasons (all defanged) */
function attackView(incident: CampaignIncident): { facts: Fact[]; reasons: string[] } {
  const summary = incident.summary;
  const sender = displaySender(summary.senderAddress, summary.senderName);
  const facts: Fact[] = [
    ...(summary.subject ? [{ label: 'Subject', value: quotedSubject(summary, 120) ?? '' }] : []),
    ...(sender ? [{ label: 'Claimed sender', value: sender }] : []),
    ...(summary.lure ? [{ label: 'Lure', value: displayText(summary.lure, 400) ?? '' }] : []),
    { label: 'Detected by', value: summary.detectedBy },
  ];
  const reasons = summary.reasons
    .slice(0, 5)
    .map(reason => displayText(reason, 240))
    .filter((reason): reason is string => !!reason);
  return { facts, reasons };
}

function attackText(view: { facts: Fact[]; reasons: string[] }): string[] {
  return [
    ...textFacts(view.facts),
    ...(view.reasons.length ? ['Main reasons:', ...view.reasons.map(reason => `- ${reason}`)] : []),
  ];
}

function timelineFacts(incident: CampaignIncident, timeZone: string): Fact[] {
  const s = incident.summary;
  const t = (iso?: string): string => displayTime(iso, timeZone) ?? 'unknown';
  return [
    {
      label: 'First delivery',
      value: s.firstDeliveryAt ? `${t(s.firstDeliveryAt)} (from mailbox records)` : 'unknown',
    },
    { label: 'First report', value: s.firstReportAt ? t(s.firstReportAt) : 'none yet' },
    ...(s.lastReportAt && s.lastReportAt !== s.firstReportAt
      ? [{ label: 'Latest report', value: t(s.lastReportAt) }]
      : []),
    { label: 'Reports so far', value: String(incident.reportCount) },
  ];
}

/**
 * How far it reached, split into the decision-level numbers (near the top)
 * and the evidence (the recipient list, caveats, lookup time: at the end).
 */
interface ReachView {
  /** The totals in one line (plain text; the HTML shows them as numbers) */
  totalsLine?: string;
  /** Coverage, unlisted recipients, or why there is no lookup */
  notes: string[];
  caveats: string[];
  lookedUp?: string;
  /** Recipients needing attention first, at most LISTED_IN_INCIDENT */
  listed: BlastRadiusRecipient[];
  more: number;
}

function reachView(incident: CampaignIncident): ReachView {
  const reach = incident.reach;
  const empty = { caveats: [], listed: [], more: 0 };
  if (reach.status === 'not_enabled') {
    return {
      ...empty,
      notes: [
        'Blast radius is not enabled, so Phishy cannot say who else received it or warn them directly.',
      ],
    };
  }
  if (reach.recipients.length === 0) {
    return { ...empty, notes: [reach.note ?? 'The blast-radius lookup produced no result.'] };
  }
  const t = reach.totals;
  const notes: string[] = [];
  if (reach.coverage) {
    const eligible = `${reach.coverage.lowerBound ? 'at least ' : ''}${reach.coverage.mailboxesEligible}`;
    notes.push(
      reach.status === 'partial'
        ? `PARTIAL COVERAGE: checked ${reach.coverage.mailboxesChecked} of ${eligible} mailboxes. Recipients or details may be missing.`
        : `Coverage: checked ${reach.coverage.mailboxesChecked} of ${eligible} mailboxes.`
    );
  }
  if (reach.unlisted > 0) {
    notes.push(
      `${reach.unlisted} more recipient(s) were counted but not listed by a lookup, so Phishy has no address for them.`
    );
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
  return {
    totalsLine: `Recipients: ${t.recipients} · Read: ${t.read} · Replied: ${t.replied} · Forwarded: ${t.forwarded} · Still in inbox: ${t.stillInInbox} · Not delivered: ${t.notDelivered}`,
    notes,
    caveats: reach.caveats.slice(0, 6),
    ...(reach.lookedUpAt ? { lookedUp: `Latest lookup: ${reach.lookedUpAt}.` } : {}),
    listed,
    more: reach.recipients.length - listed.length,
  };
}

function reachHtml(incident: CampaignIncident, view: ReachView): string {
  const t = incident.reach.totals;
  const attention = (count: number, tone: Tone): Tone | undefined => (count > 0 ? tone : undefined);
  const tile = (
    label: string,
    value: number,
    tone?: Tone
  ): { label: string; value: string; tone?: Tone } => ({
    label,
    value: String(value),
    ...(tone ? { tone } : {}),
  });
  const numbers = view.totalsLine
    ? stats([
        tile('Reports', incident.reportCount),
        tile('Recipients', t.recipients),
        tile('Still in inbox', t.stillInInbox, attention(t.stillInInbox, 'caution')),
      ]) +
      stats([
        tile('Opened', t.read, attention(t.read, 'caution')),
        tile('Replied', t.replied, attention(t.replied, 'danger')),
        tile('Forwarded', t.forwarded, attention(t.forwarded, 'danger')),
      ]) +
      (t.notDelivered ? paragraph(`Not delivered: ${t.notDelivered}`, { quiet: true }) : '')
    : '';
  return `${heading('Reach')}${numbers}${view.notes.map(line => paragraph(line, { quiet: !!view.totalsLine })).join('')}`;
}

function reachText(view: ReachView): string[] {
  return [...(view.totalsLine ? [view.totalsLine] : []), ...view.notes];
}

function recipientsText(view: ReachView): string[] {
  if (!view.listed.length) {
    return [];
  }
  return [
    ...view.caveats.map(caveat => `- ${caveat}`),
    ...(view.lookedUp ? [view.lookedUp] : []),
    `  ${RECIPIENT_COLUMNS.join(' | ')}`,
    ...view.listed.map(recipient => `  ${recipientCells(recipient).join(' | ')}`),
    ...(view.more > 0 ? [`  ${view.more} more recipient(s) not listed here.`] : []),
  ];
}

function recipientsHtml(view: ReachView): string {
  if (!view.listed.length) {
    return '';
  }
  return `${heading('Recipients', { quiet: true })}${bulletList(view.caveats, { quiet: true })}${dataTable(
    RECIPIENT_COLUMNS,
    view.listed.map(recipientCells)
  )}${view.more > 0 ? paragraph(`${view.more} more recipient(s) not listed here.`, { quiet: true }) : ''}${
    view.lookedUp ? paragraph(view.lookedUp, { quiet: true }) : ''
  }`;
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

interface Proposals {
  /** How approving works, or why it cannot */
  intro: string;
  items: Array<{ title: string; reply: string; does: string; notIncluded?: string }>;
}

function proposals(context: IncidentEmailContext): Proposals {
  let intro: string;
  if (!context.commandsEnabled) {
    intro =
      'The email command channel is off (PHISHY_EMAIL_COMMANDS_ENABLED), so Phishy cannot receive approvals. These actions are listed for information only.';
  } else if (context.proposed.length === 0) {
    intro = 'No action is waiting for approval.';
  } else {
    const expiry = context.proposed[0].expiresAt;
    intro = `Reply to this email with the line shown, on a line of its own. Each approval is good until ${displayTime(expiry.toISOString(), context.timeZone) ?? expiry.toISOString()} and applies to this incident only.${context.proposed.some(a => a.type === 'send_warning') ? ' For the warning only, a reply to this email with just the two words "approve warning" also works.' : ''}`;
  }
  const items: Proposals['items'] = context.proposed.map(action => {
    const { title, does, notIncluded } = describeProposal(action);
    return {
      title,
      reply: approvalLine(action),
      does: `${does.charAt(0).toUpperCase()}${does.slice(1)}`,
      ...(notIncluded ? { notIncluded } : {}),
    };
  });
  if (context.incident.summary.analysisId) {
    items.push({
      title: 'Mark the campaign as a false positive',
      reply: 'false positive',
      does: 'records "false positive" for every report in this campaign, lowers its threat indicators and cancels the proposed actions above.',
    });
  }
  return { intro, items };
}

/**
 * Plain text. The command never stands on a line of its own ("Reply with
 * this line:" comes first), so a quoted copy of this email cannot approve.
 */
function proposalText(view: Proposals): string[] {
  const lines = [view.intro];
  view.items.forEach((item, index) => {
    lines.push(`${index + 1}. ${item.title}`);
    lines.push(`   Reply with this line:  ${item.reply}`);
    lines.push(`   What it does: ${item.does}`);
    if (item.notIncluded) {
      lines.push(`   Not included: ${item.notIncluded}.`);
    }
  });
  return lines;
}

/**
 * HTML. As in the text, the command sits inside the same paragraph as
 * "Reply with this line:", so the text a mail client makes of a quoted copy
 * never has it on a line of its own.
 */
function proposalHtml(view: Proposals): string[] {
  return view.items.map((item, index) =>
    panel(
      `${paragraph(`${index + 1}. ${item.title}`, { bold: true })}${paragraphHtml(
        `Reply with this line:&nbsp; ${codeInline(item.reply)}`
      )}${paragraph(`What it does: ${item.does}`, { quiet: true })}${
        item.notIncluded ? paragraph(`Not included: ${item.notIncluded}.`, { quiet: true }) : ''
      }`,
      'info'
    )
  );
}

/** The decision the incident email asks for, in a few words (code-written) */
function decisionHeadline(context: IncidentEmailContext): string {
  const waiting = context.proposed.length;
  if (!context.commandsEnabled) {
    return 'For information: approvals are off';
  }
  if (waiting === 0) {
    return 'No action is waiting for you';
  }
  return waiting === 1
    ? '1 action is waiting for your approval'
    : `${waiting} actions are waiting for your approval`;
}

/**
 * The incident email, or an update to it (`changes` set). Decision first:
 * what changed (updates), what it is and how far it reached, what Phishy
 * did, the proposed actions with their exact reply lines; then the attack,
 * the timeline and the recipient evidence.
 */
export function buildIncidentEmail(context: IncidentEmailContext): RenderedEmail {
  const incident = context.incident;
  const verdict = describeVerdict(incident.summary.verdict);
  const tone: Tone = verdict.tone === 'safe' ? 'caution' : verdict.tone;
  const title = context.changes
    ? `Phishy incident update ${incident.reference}`
    : `Phishy incident ${incident.reference}`;
  const lead = inShort(incident);
  const headline = decisionHeadline(context);
  const reach = reachView(incident);
  const attack = attackView(incident);
  const timeline = timelineFacts(incident, context.timeZone);
  const done = [...context.done, ...context.notes];
  const proposed = proposals(context);
  const risk = summaryRisk(incident.summary);

  const rows: string[] = [];
  if (context.changes?.length) {
    rows.push(
      block(callout({ tone: 'info', title: 'What changed', html: bulletList(context.changes) }))
    );
  }
  rows.push(
    block(
      hero({
        tone,
        word: verdict.label,
        headline,
        html: `${paragraph(lead)}${riskScoreHtml(risk)}`,
      })
    ),
    block(reachHtml(incident, reach))
  );
  if (done.length) {
    rows.push(block(`${heading('What Phishy has done')}${bulletList(done)}`));
  }
  rows.push(block(`${heading('Proposed actions')}${paragraph(proposed.intro)}`, { bottom: 12 }));
  for (const card of proposalHtml(proposed)) {
    rows.push(block(card, { bottom: 12 }));
  }
  rows.push(
    block(divider(), { bottom: 18 }),
    block(
      `${heading('What the attack is', { quiet: true })}${facts(attack.facts)}${
        attack.reasons.length
          ? `${paragraph('Main reasons', { quiet: true, bold: true })}${bulletList(attack.reasons, { quiet: true })}`
          : ''
      }`
    ),
    block(`${heading('Timeline', { quiet: true })}${facts(timeline)}`)
  );
  const evidence = recipientsHtml(reach);
  if (evidence) {
    rows.push(block(evidence));
  }

  const html = emailShell({
    title,
    preheader: `${headline}. ${incident.reportCount} report(s) so far.`,
    label: 'Security team',
    tone,
    bodyHtml: rows.join('\n'),
    footer: footerLines(incident),
  });

  const text = [
    title.toUpperCase(),
    TEXT_RULE,
    '',
    ...textSection(
      'What changed',
      (context.changes ?? []).map(line => `- ${line}`)
    ),
    `${headline}.`,
    lead,
    '',
    `Verdict: ${verdict.label}`,
    ...riskScoreLines(risk),
    '',
    ...textSection('Reach', reachText(reach)),
    ...textSection(
      'What Phishy has done',
      done.map(line => `- ${line}`)
    ),
    ...textSection('Proposed actions', proposalText(proposed)),
    ...textSection('What the attack is', attackText(attack)),
    ...textSection('Timeline', textFacts(timeline)),
    ...textSection('Recipients', recipientsText(reach)),
    TEXT_RULE,
    ...footerLines(incident),
  ].join('\n');

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

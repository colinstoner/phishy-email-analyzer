/**
 * Email Report Templates
 * HTML and plain text templates for analysis reports
 */

import { AnalysisResult, ExtractedEmailData, EmailAttachment } from '../types';
import { normalizeConfidence } from '../services/ai/provider.interface';
import type {
  BlastRadiusRecipient,
  BlastRadiusReport,
} from '../services/graph/blast-radius.service';
import { formatSenderHistoryLines } from '../utils/sender-history.format';
import { summarizeInspectionForReport } from '../services/attachments/report';
import {
  COLOR,
  FONT,
  MONO,
  TEXT_RULE,
  TEXT_SUBRULE,
  Tone,
  TONE,
  block,
  bulletList,
  callout,
  codeBox,
  dataTable,
  divider,
  emailShell,
  escapeHtml,
  facts,
  heading,
  hero,
  instructions,
  meter,
  paragraph,
  paragraphHtml,
} from './layout';

export { escapeHtml };

/** Reasons shown in the report's first screen; the rest move to "More detail" */
const TOP_REASONS = 3;

/** Maximum length for email body display */
const MAX_BODY_LENGTH = 10000;

/** Security-relevant headers to display, in priority order */
const SECURITY_HEADERS = [
  'From',
  'Reply-To',
  'Return-Path',
  'Date',
  'Message-ID',
  'X-Originating-IP',
  'X-Forwarded-For',
  'Received',
  'X-Original-From',
  'Authentication-Results',
];

/** Headers extracted from forwarded message content */
const FORWARDED_HEADERS = [
  'Original-From',
  'Original-To',
  'Original-Date',
  'Original-Subject',
  'Original-Reply-To',
  'Original-Sent',
];

/**
 * Optional extras for report rendering
 */
export interface ReportOptions {
  /**
   * Intelligence database ID for this analysis. Rendered into the report so
   * security-team replies can be matched back to the analysis (quoted reply
   * bodies survive mail clients that strip threading headers).
   */
  analysisId?: string;
  /**
   * Fused risk decision (verdict + 0-100 score + the intelligence reasons
   * behind it). When present the report leads with this instead of the raw
   * confidence label.
   */
  risk?: {
    verdict: string;
    riskScore: number;
    riskLevel: string;
    reasons: string[];
    /** Confidence label for the outcome (the model's own certainty when it decided) */
    confidence?: string;
    /** What decided the outcome; drives the confidence line's wording */
    confidenceBasis?:
      'model' | 'security_team' | 'threat_intel' | 'attachment_inspection' | 'unassessed';
    /**
     * Checklist scoring mode only: fixed-wording reasons derived from the
     * checklist answers, written by code. When set, the "why" list shows
     * these in place of the model's free-text indicators.
     */
    checklistReasons?: string[];
  };
  /**
   * Who reads this particular email, when it is not the usual combined one
   * (reporter with the security team in Cc). It decides how much of the
   * sender-relationship result is shown: `reporter` gets none of the detail
   * (at most the one plain sentence that arrives through `risk.reasons`);
   * `security` — an email addressed to the security team alone — gets all of
   * it, including the burst's sending IPs. Unset means the combined email:
   * counts and the classification, no IPs.
   */
  audience?: 'reporter' | 'security';
  /**
   * Who else received the email and what they did with it. **Security-team
   * copy only**: the caller must never set this on the reporter's copy.
   */
  blastRadius?: BlastRadiusReport;
  /**
   * Set when the analysis came from an Outlook Report-button submission and
   * is being sent to the security team only. Replaces the reporter thank-you
   * with a line saying who reported it and that they were not notified.
   */
  silentReport?: {
    reporter: string;
  };
  /**
   * The email command channel is on: an email addressed to the security
   * team alone says how to reply with a verdict.
   */
  replyCommands?: boolean;
}

/**
 * The confidence line under the risk score. The model's certainty in its
 * verdict when the model decided; when a security-team ruling or a known
 * threat decided, say that instead of a number. Nothing when unassessed (the
 * banner already says the email was not checked) or not provided.
 */
function confidenceText(risk: NonNullable<ReportOptions['risk']>): string | undefined {
  switch (risk.confidenceBasis) {
    case 'security_team':
      return "Decided by your security team's review";
    case 'threat_intel':
      return 'Based on a known threat from earlier reports';
    case 'attachment_inspection':
      return "Based on Phishy's inspection of the attachment";
    case 'model':
      return risk.confidence && risk.confidence !== 'Unknown' && risk.confidence !== 'N/A'
        ? normalizeConfidence(risk.confidence)
        : undefined;
    default:
      return undefined;
  }
}

/** The fused risk as every Phishy email shows it */
export type ReportRisk = NonNullable<ReportOptions['risk']>;

/**
 * The risk score and Confidence lines, plain text, exactly as the report
 * shows them. Every Phishy email that states a risk uses this. A failed
 * analysis has no real score: never "0/100 (safe)", which would read as a
 * clean bill of health for an email nobody checked.
 */
export function riskScoreLines(risk: ReportRisk): string[] {
  if (risk.verdict === 'undetermined') {
    return ['Risk score: not assessed'];
  }
  const lines = [`Risk score: ${risk.riskScore}/100 (${risk.riskLevel})`];
  const confidence = confidenceText(risk);
  if (confidence) {
    lines.push(`Confidence: ${confidence}`);
  }
  return lines;
}

/**
 * The same two lines as HTML. By default one compact line, as the warnings
 * and the incident email carry it; `prominent` (the analysis report) makes
 * the score the big number with a meter, since employees engage with it.
 * The level is always a word, never only the meter's colour.
 */
export function riskScoreHtml(risk: ReportRisk, options: { prominent?: boolean } = {}): string {
  const confidence = confidenceText(risk);
  const line = (html: string): string =>
    `<p class="ph-muted" style="margin:0 0 4px 0;font-family:${FONT};font-size:14px;line-height:20px;color:${COLOR.muted};">${html}</p>`;
  if (risk.verdict === 'undetermined') {
    return line('Risk score: <strong>not assessed</strong>');
  }
  const confidenceHtml = confidence ? `Confidence: <strong>${escapeHtml(confidence)}</strong>` : '';
  if (!options.prominent) {
    return line(
      `Risk score: <strong>${risk.riskScore}/100</strong> (${escapeHtml(risk.riskLevel)})${confidenceHtml ? ` &nbsp;&middot;&nbsp; ${confidenceHtml}` : ''}`
    );
  }
  const tone: Tone = describeVerdict(risk.verdict).tone;
  const score = Math.max(0, Math.min(100, risk.riskScore));
  return `<p class="ph-muted" style="margin:14px 0 0 0;font-family:${FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:${COLOR.muted};">Risk score</p>
<p class="ph-ink-${tone}" style="margin:0;font-family:${FONT};color:${TONE[tone].ink};"><strong style="font-size:44px;line-height:50px;font-weight:800;">${risk.riskScore}</strong><span style="font-size:20px;line-height:50px;font-weight:600;">/100</span><span style="font-size:15px;line-height:50px;font-weight:700;">&nbsp;&nbsp;${escapeHtml(risk.riskLevel)} risk</span></p>
${meter(score / 100, tone)}${confidenceHtml ? line(confidenceHtml) : ''}`;
}

/** A verdict's label, plain-language gloss and "what to do", as the report words them */
export function describeVerdict(verdict: string): {
  label: string;
  plain?: string;
  action?: string;
  tone: 'danger' | 'caution' | 'safe';
} {
  const display = VERDICT_DISPLAY[verdict];
  return display
    ? { label: display.label, plain: display.plain, action: display.action, tone: display.tone }
    : { label: verdict.toUpperCase(), tone: 'caution' };
}

/**
 * In an email addressed to the security team alone (and carrying the
 * reference replies are matched by): how to correct the verdict. The same
 * words as the incident email's proposed actions. Never in a copy the
 * reporter reads.
 */
function securityReplyHint(options?: ReportOptions): string | undefined {
  return options?.audience === 'security' && options.analysisId && options.replyCommands
    ? 'Security team: reply to this email with "confirmed phishing" or "false positive" to record your verdict for the whole campaign.'
    : undefined;
}

/** HTML-escape text for any Phishy email (the same function as `escapeHtml`) */
export function escapeEmailHtml(text: string): string {
  return escapeHtml(text);
}

/** Lead line for a report sent to the security team about a silent button report */
function silentReportNotice(reporter: string): string {
  return `Reported by ${reporter} with the Outlook Report button. The reporter was not sent this analysis.`;
}

/** Shown with the sender-relationship counts so they are not read as a clearance */
const SENDER_HISTORY_CAVEAT =
  'Counts from message trace, matched on the sender address the email claims. A known sender is not ' +
  'evidence of safety: a taken-over mailbox has the same history.';

/**
 * Per-verdict presentation for the employee report: a label, a color tone, a
 * plain-language gloss (most employees don't know what "BEC" means), and the
 * one-line "what to do" framing. tone drives the banner color and whether the
 * email reads as urgent, cautious, or reassuring.
 */
type VerdictTone = 'danger' | 'caution' | 'safe';
const VERDICT_DISPLAY: Record<
  string,
  {
    label: string;
    tone: VerdictTone;
    plain: string;
    action: string;
    /** The verdict in a few plain words: the report's headline */
    headline: string;
    /** `action` as steps to follow, for the report's "What to do now" */
    steps: string[];
    /** A line under the steps that is not itself a step */
    stepsNote?: string;
  }
> = {
  bec: {
    label: 'BUSINESS EMAIL COMPROMISE',
    tone: 'danger',
    plain:
      'Someone is impersonating a colleague, executive, or vendor to trick you into sending money, data, or credentials.',
    action:
      'Do not reply or act on the request. Verify it with the real person through a known phone number or in person.',
    headline: 'This email is a scam',
    steps: [
      'Do not reply or act on the request.',
      'Check it with the real person, by a phone number you already know or in person.',
    ],
  },
  phishing: {
    label: 'PHISHING',
    tone: 'danger',
    plain:
      'This email is trying to steal your password or personal information, usually through a fake login page.',
    action: 'Do not click any links or enter any information. Delete it.',
    headline: 'This email is a phishing attack',
    steps: ['Do not click any links or enter any information.', 'Delete it.'],
  },
  malware_delivery: {
    label: 'MALWARE DELIVERY',
    tone: 'danger',
    plain: 'This email is trying to get you to open a file or link that would infect your device.',
    action: 'Do not open the attachment or click any links. Delete it.',
    headline: 'This email carries malware',
    steps: ['Do not open the attachment or click any links.', 'Delete it.'],
  },
  suspicious: {
    label: 'SUSPICIOUS',
    tone: 'caution',
    plain: "We couldn't confirm this is an attack, but something about it is off.",
    action: "Treat it with caution. Don't act on it until you've verified the sender another way.",
    headline: 'Be careful with this email',
    steps: [
      "Don't click links, open attachments or act on any request in it yet.",
      'Check with the sender another way first (a phone number you already know).',
    ],
  },
  spam: {
    label: 'SPAM',
    tone: 'caution',
    plain: 'This looks like unwanted bulk email rather than a targeted attack.',
    action: 'No real harm expected — you can safely delete it.',
    headline: 'This email is junk mail',
    steps: ['No real harm expected. You can safely delete it.'],
  },
  graymail: {
    label: 'LEGITIMATE BULK EMAIL',
    tone: 'safe',
    plain:
      'This is real, legitimate mail (a newsletter, survey, or marketing message) — just the kind you may not want.',
    action: "It's safe. If you'd rather not receive these, use the unsubscribe link.",
    headline: 'This email is safe, just unwanted',
    steps: ["It's safe. If you'd rather not receive these, use the unsubscribe link."],
  },
  legitimate: {
    label: 'LIKELY LEGITIMATE',
    tone: 'safe',
    plain: 'This appears to be a genuine, expected email with no signs of an attack.',
    action: 'It looks safe to proceed as normal.',
    headline: 'This email looks safe',
    steps: ['It looks safe to proceed as normal.'],
  },
  undetermined: {
    label: 'ANALYSIS UNAVAILABLE',
    tone: 'caution',
    plain:
      "We couldn't analyze this email — our analysis service was temporarily unavailable. This is not a clean bill of health; the email has not been checked.",
    action:
      "Treat it with caution. Don't click links, open attachments, reply, or act on any request until you've verified the sender another way. Your security team has been notified.",
    headline: 'We could not check this email',
    steps: [
      "Don't click links, open attachments, reply, or act on any request in it.",
      'Check with the sender another way before you do anything.',
    ],
    stepsNote: 'Your security team has been notified.',
  },
};

/** Without a fused risk decision: the analysis' own yes/no */
const FALLBACK_DISPLAY: Record<'danger' | 'safe', { label: string; headline: string }> = {
  danger: { label: 'POTENTIALLY MALICIOUS', headline: 'Treat this email as dangerous' },
  safe: { label: 'LIKELY LEGITIMATE', headline: 'This email looks safe' },
};

const TONE_CLASS: Record<VerdictTone, string> = {
  danger: 'verdict-phishing',
  caution: 'verdict-suspicious',
  safe: 'verdict-legitimate',
};

/**
 * "How to spot this next time" tips, keyed by the threat vector the model
 * identified. Turns each report into a small, specific lesson.
 */
const THREAT_VECTOR_TIPS: Record<string, string> = {
  credential_harvest:
    'Legitimate services never ask you to confirm your password through an email link. Go to the site directly instead of clicking.',
  wire_fraud:
    'Always verify payment or banking changes by phone using a number you already trust — never the contact details in the email.',
  gift_card_fraud:
    'No real executive will ask you to buy gift cards. Treat any gift-card request as fraud.',
  malware:
    "Don't open unexpected attachments. If a file seems important, confirm with the sender through another channel first.",
  reconnaissance:
    'Attackers often open with a harmless-looking note ("Are you available?") to start a conversation before the real ask. Be wary of unexpected messages like that.',
  data_exfiltration:
    'Be cautious about sharing internal data or documents in response to unsolicited requests.',
  extortion:
    "Threatening emails demanding payment are almost always bluffs. Don't pay — report it.",
  other:
    'When an email pressures you to act quickly or secretly, slow down and verify before doing anything.',
};

/**
 * What the report says, decided once for both formats: the verdict in plain
 * words, the steps, the lead line, and the reasons split into the few shown
 * first and the rest.
 */
interface ReportView {
  tone: VerdictTone;
  label: string;
  headline: string;
  plain?: string;
  steps: string[];
  stepsNote?: string;
  /** The reporter thank-you, or for a silent report who reported it */
  lead: string;
  silent: boolean;
  topReasons: string[];
  moreReasons: string[];
  tips: string[];
}

const THANKS_SAFE =
  'Thanks for checking — flagging anything that looks off is exactly the right habit.';
const THANKS =
  'Good catch, and thanks for reporting. Sending this to Phishy helped protect you and your colleagues.';

/** Steps when there is no fused risk decision (the analysis' own yes/no only) */
const FALLBACK_STEPS = ['Do not click any links, open attachments or reply to it.', 'Delete it.'];

function reportView(analysis: AnalysisResult, options?: ReportOptions): ReportView {
  const display = options?.risk ? VERDICT_DISPLAY[options.risk.verdict] : undefined;
  const tone: VerdictTone = display?.tone ?? (analysis.isPhishing ? 'danger' : 'safe');
  const fallback = FALLBACK_DISPLAY[analysis.isPhishing ? 'danger' : 'safe'];
  const label = options?.risk
    ? (display?.label ?? options.risk.verdict.toUpperCase())
    : fallback.label;

  // The model's indicators (or, in checklist scoring mode, the checklist's
  // fixed reasons) plus the intelligence reasons behind the score
  const reasons = whyBase(analysis, options);
  if (options?.risk?.reasons.length) {
    reasons.push(...options.risk.reasons);
  }

  return {
    tone,
    label,
    headline: display?.headline ?? (options?.risk ? label : fallback.headline),
    ...(display?.plain ? { plain: display.plain } : {}),
    steps: display?.steps ?? (options?.risk || !analysis.isPhishing ? [] : FALLBACK_STEPS),
    ...(display?.stepsNote ? { stepsNote: display.stepsNote } : {}),
    // Thank the reporter every time — reinforcing the habit is the point, and
    // it keeps people forwarding even when the email turns out to be harmless.
    // A silent button report tells the security team who reported it instead.
    lead: options?.silentReport
      ? silentReportNotice(options.silentReport.reporter)
      : tone === 'safe'
        ? THANKS_SAFE
        : THANKS,
    silent: !!options?.silentReport,
    topReasons: reasons.slice(0, TOP_REASONS),
    moreReasons: reasons.slice(TOP_REASONS),
    tips: buildTeachingTips(analysis),
  };
}

function whyHeading(tone: VerdictTone): string {
  return tone === 'safe' ? 'What we checked' : 'Why we flagged it';
}

/** The verdict block: severity word, plain headline, score, what it means */
function verdictHeroHtml(
  view: ReportView,
  analysis: AnalysisResult,
  options?: ReportOptions
): string {
  const score = options?.risk
    ? riskScoreHtml(options.risk, { prominent: true })
    : paragraphHtml(
        `Confidence: <strong>${escapeHtml(normalizeConfidence(analysis.confidence))}</strong>`,
        { quiet: true }
      );
  const meaning = view.plain
    ? `<p class="ph-muted" style="margin:14px 0 2px 0;font-family:${FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:${COLOR.muted};">What this means</p>${paragraph(view.plain)}`
    : '';
  return `<div class="verdict-banner ${TONE_CLASS[view.tone]}-bg">${hero({
    tone: view.tone,
    word: view.label,
    headline: view.headline,
    html: `${score}${meaning}`,
  })}</div>`;
}

/**
 * Build complete HTML email for analysis report. First screen: the verdict
 * in plain words with the score, then the one thing to do, then the top
 * reasons; detail and the IT-review copy of the email come after, quieter.
 */
export function buildEmailHtml(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData,
  options?: ReportOptions
): string {
  const timestamp = new Date().toLocaleString();
  const view = reportView(analysis, options);
  const rows: string[] = [];

  if (view.silent) {
    rows.push(block(callout({ tone: 'neutral', lines: [view.lead] })));
  }
  rows.push(block(verdictHeroHtml(view, analysis, options)));
  if (view.steps.length) {
    rows.push(
      block(
        instructions({
          title: 'What to do now',
          steps: view.steps,
          ...(view.stepsNote ? { note: view.stepsNote } : {}),
        })
      )
    );
  }
  const hint = securityReplyHint(options);
  if (hint) {
    rows.push(block(callout({ tone: 'info', lines: [hint] })));
  }
  if (!view.silent) {
    rows.push(
      block(
        `<p class="thanks ph-muted" style="margin:0;font-family:${FONT};font-size:15px;line-height:22px;color:${COLOR.muted};">${escapeHtml(view.lead)}</p>`
      )
    );
  }

  if (analysis.summary || view.topReasons.length) {
    rows.push(
      block(
        `${heading(view.topReasons.length ? whyHeading(view.tone) : 'Summary')}${
          analysis.summary ? paragraph(analysis.summary) : ''
        }${bulletList(view.topReasons)}`
      )
    );
  }

  // Teaching moment: how to spot this kind of email next time, driven by the
  // threat vectors the model identified
  if (view.tips.length) {
    rows.push(
      block(callout({ tone: 'neutral', title: 'How to spot this next time', lines: view.tips }))
    );
  }

  const recommendations = analysis.recommendations ?? [];
  if (view.moreReasons.length || recommendations.length) {
    let detail = heading('More detail', { quiet: true });
    if (view.moreReasons.length) {
      detail += paragraph('Other findings', { quiet: true, bold: true });
      detail += bulletList(view.moreReasons, { quiet: true });
    }
    if (recommendations.length) {
      detail += paragraph('Recommendations', { quiet: true, bold: true });
      detail += bulletList(recommendations, { quiet: true });
    }
    rows.push(block(divider(), { bottom: 18 }), block(detail));
  }

  if (options?.blastRadius) {
    rows.push(buildBlastRadiusHtml(options.blastRadius));
  }

  rows.push(
    block(
      `${heading('About this report', { quiet: true })}${facts([
        { label: 'Subject', value: emailData.subject },
        { label: 'Reported by', value: emailData.from_email },
      ])}`
    )
  );
  rows.push(buildOriginalEmailSection(emailData, options?.audience));

  return emailShell({
    title: 'Phishy analysis report',
    preheader: `${view.headline}. ${options?.risk ? riskScoreLines(options.risk)[0] : view.label}.`,
    label:
      options?.audience === 'security' || view.silent ? 'Security team copy' : 'Analysis report',
    tone: view.tone,
    bodyHtml: rows.join('\n'),
    footer: [
      ...(options?.analysisId ? [`Reference: ${options.analysisId}`] : []),
      "Analysis by Phishy, powered by Anthropic's Claude AI.",
      `Report time: ${timestamp}`,
    ],
  });
}

/**
 * The first part of the "why" list: the checklist's code-written reasons in
 * checklist scoring mode, otherwise the model's indicators.
 */
function whyBase(analysis: AnalysisResult, options?: ReportOptions): string[] {
  const checklistReasons = options?.risk?.checklistReasons;
  return checklistReasons ? [...checklistReasons] : [...(analysis.indicators ?? [])];
}

/** Pick the "how to spot it" tips for the threat vectors in this assessment */
function buildTeachingTips(analysis: AnalysisResult): string[] {
  const vectors = analysis.assessment?.threatVectors ?? [];
  const tips: string[] = [];
  for (const vector of vectors) {
    const tip = THREAT_VECTOR_TIPS[vector];
    if (tip && !tips.includes(tip)) {
      tips.push(tip);
    }
  }
  return tips;
}

/**
 * Build plain text report: the same order as the HTML
 */
export function buildPlainTextReport(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData,
  options?: ReportOptions
): string {
  const view = reportView(analysis, options);
  const lines: string[] = ['PHISHY ANALYSIS REPORT', TEXT_RULE, ''];

  if (view.silent) {
    lines.push(view.lead, '');
  }

  // Verdict + risk
  lines.push(`Verdict: ${view.label}`, `${view.headline}.`);
  if (options?.risk) {
    lines.push(...riskScoreLines(options.risk));
  } else {
    lines.push(`Confidence: ${normalizeConfidence(analysis.confidence)}`);
  }
  if (view.plain) {
    lines.push(`What this means: ${view.plain}`);
  }
  lines.push('');

  if (view.steps.length) {
    lines.push('What to do:');
    view.steps.forEach((step, index) => lines.push(`  ${index + 1}. ${step}`));
    if (view.stepsNote) {
      lines.push(`  ${view.stepsNote}`);
    }
    lines.push('');
  }

  const hint = securityReplyHint(options);
  if (hint) {
    lines.push(hint, '');
  }
  if (!view.silent) {
    lines.push(view.lead, '');
  }

  if (analysis.summary) {
    lines.push(`Summary: ${analysis.summary}`, '');
  }
  const list = (title: string, items: string[]): void => {
    if (items.length) {
      lines.push(`${title}:`, ...items.map(item => `  - ${item}`), '');
    }
  };
  list(whyHeading(view.tone), view.topReasons);
  list('How to spot this next time', view.tips);
  list('Other findings', view.moreReasons);
  list('Recommendations', analysis.recommendations ?? []);

  if (options?.blastRadius) {
    lines.push(...buildBlastRadiusText(options.blastRadius), '');
  }

  lines.push(TEXT_RULE, 'Email Details:');
  lines.push(`  Subject: ${emailData.subject}`);
  lines.push(`  Reported by: ${emailData.from_email}`);
  if (options?.analysisId) {
    lines.push(`  Reference: ${options.analysisId}`);
  }
  lines.push('');

  // Original email section
  lines.push(buildOriginalEmailTextSection(emailData, options?.audience));

  lines.push(TEXT_RULE);
  lines.push("Analysis by Phishy, powered by Anthropic's Claude AI.");
  lines.push(`Report generated: ${new Date().toLocaleString()}`);

  return lines.join('\n');
}

const BLAST_FOLDER_LABEL: Record<string, string> = {
  inbox: 'Inbox',
  junk: 'Junk',
  deleted: 'Deleted Items',
  recoverable: 'Purged (Recoverable Items)',
  other: 'Other folder',
  unknown: 'Unknown',
};

const BLAST_COLUMNS = ['Recipient', 'Delivery', 'Location', 'Read', 'Replied / forwarded'];

/** The cells of one recipient row, as plain (unescaped) text */
function blastRadiusRow(recipient: BlastRadiusRecipient, reporter?: string): string[] {
  const address =
    recipient.address + (reporter && recipient.address === reporter ? ' (reporter)' : '');
  let location: string;
  let read = '-';
  let response = '-';
  if (recipient.mailbox === 'found') {
    location = BLAST_FOLDER_LABEL[recipient.folder ?? 'unknown'] ?? 'Unknown';
    if (recipient.copies) {
      location += ` (${recipient.copies} copies)`;
    }
    read = recipient.isRead === undefined ? 'Unknown' : recipient.isRead ? 'Read' : 'Unread';
    if (recipient.response === 'replied') {
      response = 'REPLIED';
    } else if (recipient.response === 'forwarded') {
      response = 'FORWARDED';
    } else if (recipient.response === 'none') {
      response = 'None recorded';
    } else {
      response =
        recipient.lastVerbCode === undefined
          ? 'Unknown'
          : `Unknown (last-verb code ${recipient.lastVerbCode})`;
    }
  } else if (recipient.mailbox === 'not_delivered') {
    location = 'Not delivered';
  } else {
    location = recipient.mailbox === 'not_found' ? 'Not in mailbox' : 'Mailbox not checked';
  }
  return [address, recipient.deliveryStatus ?? '-', location, read, response];
}

/** Recipients counted in the totals but left out of the (capped) listing */
function blastRadiusUnlisted(report: BlastRadiusReport): number {
  const listed = report.recipients?.length ?? 0;
  const total = (report.totals?.recipients ?? listed) + (report.totals?.notDelivered ?? 0);
  return total - listed;
}

/**
 * The statements of a blast-radius result, shared by both formats. Values
 * taken from the suspicious email (sender, subject) are returned unescaped:
 * the HTML builder escapes every line.
 */
function blastRadiusLines(report: BlastRadiusReport): string[] {
  const lines: string[] = [];
  const totals = report.totals ?? { recipients: 0, read: 0, replied: 0, forwarded: 0 };
  const coverage = report.coverage;

  lines.push(
    report.route === 'trace'
      ? `Message trace shows ${totals.recipients} recipient(s) in the organization.`
      : `Found in ${totals.recipients} mailbox(es).`
  );
  if (totals.notDelivered) {
    lines.push(`Delivery failed for ${totals.notDelivered} more recipient(s).`);
  }
  lines.push(
    `Marked read by ${totals.read}; replied to by ${totals.replied}; forwarded by ${totals.forwarded}.`
  );
  if (coverage) {
    const eligible = `${coverage.eligibleIsLowerBound ? 'at least ' : ''}${coverage.mailboxesEligible}`;
    const unit = report.route === 'trace' ? 'recipient mailboxes' : 'mailboxes';
    lines.push(
      report.status === 'partial'
        ? `PARTIAL COVERAGE: checked ${coverage.mailboxesChecked} of ${eligible} ${unit}. Recipients or details may be missing.`
        : `Coverage: checked ${coverage.mailboxesChecked} of ${eligible} ${unit}.`
    );
  }
  if (report.criteria) {
    const window = `between ${report.criteria.receivedFrom} and ${report.criteria.receivedTo}`;
    if (report.matchedBy === 'messageId') {
      lines.push('Matched on: the original Message-ID.');
    } else if (report.matchedBy === 'senderSubject') {
      lines.push(
        `Matched on: sender ${report.criteria.senderAddress ?? ''} and subject "${report.criteria.subject ?? ''}", received ${window}.`
      );
    } else {
      lines.push(`Matched on: sender ${report.criteria.senderAddress ?? ''}, received ${window}.`);
    }
  }
  const reporter = report.reporterAddress;
  if (
    reporter &&
    report.recipients?.some(row => row.address === reporter && row.response === 'forwarded')
  ) {
    lines.push('The reporter forwarding the email to Phishy counts as a forward.');
  }
  return lines;
}

/**
 * Blast-radius section (HTML) for the security team's copy. Recipient
 * addresses are the organization's own, but they and the sender/subject
 * come from mail flow: everything is escaped.
 */
export function buildBlastRadiusHtml(report: BlastRadiusReport): string {
  if (report.status === 'unavailable') {
    return block(
      callout({
        tone: 'neutral',
        html: paragraphHtml(
          `<strong>Security team only:</strong> ${escapeHtml(report.note ?? 'Blast radius lookup could not be completed.')}`
        ),
      })
    );
  }

  const recipients = report.recipients ?? [];
  let table = '';
  if (recipients.length) {
    table = dataTable(
      BLAST_COLUMNS,
      recipients.map(recipient => blastRadiusRow(recipient, report.reporterAddress))
    );
    const unlisted = blastRadiusUnlisted(report);
    if (unlisted > 0) {
      table += paragraph(`${unlisted} more recipient(s) not listed.`, { quiet: true });
    }
  }

  const statements = blastRadiusLines(report)
    .map(line => paragraph(line))
    .join('');

  return block(
    `${heading('Blast radius (security team only)')}${statements}${table}${bulletList(
      report.caveats ?? [],
      { quiet: true }
    )}${paragraph(`Looked up ${report.lookedUpAt}. This section is not in the reporter's copy.`, { quiet: true })}`
  );
}

/** Blast-radius section (plain text) for the security team's copy */
export function buildBlastRadiusText(report: BlastRadiusReport): string[] {
  if (report.status === 'unavailable') {
    return [`Security team only: ${report.note ?? 'Blast radius lookup could not be completed.'}`];
  }

  const lines = ['BLAST RADIUS (security team only)', TEXT_SUBRULE, ...blastRadiusLines(report)];
  const recipients = report.recipients ?? [];
  if (recipients.length) {
    lines.push(`  ${BLAST_COLUMNS.join(' | ')}`);
    for (const recipient of recipients) {
      lines.push(`  ${blastRadiusRow(recipient, report.reporterAddress).join(' | ')}`);
    }
    const unlisted = blastRadiusUnlisted(report);
    if (unlisted > 0) {
      lines.push(`  ${unlisted} more recipient(s) not listed.`);
    }
  }
  for (const caveat of report.caveats ?? []) {
    lines.push(`  Note: ${caveat}`);
  }
  lines.push(`Looked up ${report.lookedUpAt}. This section is not in the reporter's copy.`);
  return lines;
}

/**
 * Strip HTML tags and convert to plain text for safe display
 * This prevents XSS from malicious email content
 */
function stripHtmlForDisplay(html: string): string {
  if (!html) return '';
  return html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Build the original email section for HTML report: the IT-review copy,
 * set apart and quieter than everything above it. Every value is hostile
 * and escaped; nothing is a link.
 */
function buildOriginalEmailSection(
  emailData: ExtractedEmailData,
  audience?: ReportOptions['audience']
): string {
  // Text-only display of the email content: an HTML body is reduced to its
  // text and escaped, since this is potentially malicious content
  const content = emailData.text || (emailData.html ? stripHtmlForDisplay(emailData.html) : '');
  const emailContent = content
    ? codeBox(content, { mono: false })
    : paragraph('No email content available', { quiet: true });

  const sub = (text: string): string => heading(text, { quiet: true });
  const parts: string[] = [];

  // Only show forwarded headers if we found any
  if (Object.keys(emailData.forwardedHeaders || {}).length > 0) {
    parts.push(
      sub('Original sender info (from forwarded message)') +
        formatForwardedHeadersForDisplay(emailData.forwardedHeaders)
    );
  }
  const senderHistory = buildSenderHistorySection(emailData, audience);
  if (senderHistory) {
    parts.push(senderHistory);
  }
  parts.push(sub('Original email content') + emailContent);
  parts.push(sub('Envelope headers (forwarder)') + formatHeadersForDisplay(emailData.headers));
  parts.push(
    sub(`Links detected (${emailData.links.length})`) + formatLinksForDisplay(emailData.links)
  );
  parts.push(
    sub(`Attachments (${emailData.attachments.length})`) +
      formatAttachmentsForDisplay(emailData.attachments)
  );

  return [
    block(divider(), { bottom: 18 }),
    block(
      `${heading('Original Email for IT Review')}${paragraph(
        'A text-only copy of the reported email, for your IT team. Do not visit any address in it.',
        { quiet: true }
      )}`,
      { bottom: 10 }
    ),
    ...parts.map(part => block(part, { bottom: 18 })),
  ].join('\n');
}

/** Heading of the sender-relationship block, by who reads the email */
function senderHistoryHeading(audience: ReportOptions['audience']): string {
  return audience === 'security'
    ? 'Sender Relationship (organization mail-flow records; security team only)'
    : 'Sender Relationship (organization mail-flow records)';
}

/**
 * The sender-relationship lines for one copy of the report, or none.
 * - reporter's own copy: nothing (the reporter is never told a sender is
 *   "known"; the one plain sentence on anomalous fan-out is a risk reason);
 * - combined email (reporter + security team in Cc): counts, dates and the
 *   classification — no IPs, because the reporter reads it too;
 * - security-team-only copy: the same plus the burst's sending IPs.
 * No copy ever shows a recipient address.
 */
function senderHistoryReportLines(
  emailData: ExtractedEmailData,
  audience: ReportOptions['audience']
): Array<[string, string]> | undefined {
  if (!emailData.senderHistory || audience === 'reporter') {
    return undefined;
  }
  return formatSenderHistoryLines(emailData.senderHistory, {
    includeBurstIps: audience === 'security',
  });
}

/**
 * Sender-relationship block for the IT-review part of the report (HTML).
 * Every value is escaped: the IPs come from mail flow.
 */
function buildSenderHistorySection(
  emailData: ExtractedEmailData,
  audience: ReportOptions['audience']
): string {
  const lines = senderHistoryReportLines(emailData, audience);
  if (!lines) {
    return '';
  }
  return `${heading(senderHistoryHeading(audience), { quiet: true })}${facts(
    lines.map(([label, value]) => ({ label, value })),
    { labelWidth: 140 }
  )}${paragraph(SENDER_HISTORY_CAVEAT, { quiet: true })}`;
}

/**
 * Build the original email section for plain text report
 */
function buildOriginalEmailTextSection(
  emailData: ExtractedEmailData,
  audience?: ReportOptions['audience']
): string {
  const lines: string[] = [];
  const divider = TEXT_RULE;
  const subDivider = TEXT_SUBRULE;

  lines.push(divider);
  lines.push('ORIGINAL EMAIL FOR IT REVIEW');
  lines.push(divider);
  lines.push('');

  // Sender relationship (how much depends on who reads this copy)
  const senderHistoryLines = senderHistoryReportLines(emailData, audience);
  if (senderHistoryLines) {
    lines.push(`${senderHistoryHeading(audience)}:`);
    lines.push(subDivider);
    for (const [label, value] of senderHistoryLines) {
      lines.push(`  ${label}: ${value}`);
    }
    lines.push(`  Note: ${SENDER_HISTORY_CAVEAT}`);
    lines.push('');
  }

  // Headers
  lines.push('Security-Relevant Headers:');
  lines.push(subDivider);
  const headers = getSecurityHeaders(emailData.headers);
  if (headers.length === 0) {
    lines.push('  (No security-relevant headers found)');
  } else {
    for (const [name, value] of headers) {
      lines.push(`  ${name}: ${value}`);
    }
  }
  lines.push('');

  // Links
  lines.push(`Links Detected (${emailData.links.length}):`);
  lines.push(subDivider);
  if (emailData.links.length === 0) {
    lines.push('  (No links detected)');
  } else {
    for (const link of emailData.links) {
      lines.push(`  - ${link}`);
    }
  }
  lines.push('');

  // Attachments
  lines.push(`Attachments (${emailData.attachments.length}):`);
  lines.push(subDivider);
  if (emailData.attachments.length === 0) {
    lines.push('  (No attachments)');
  } else {
    for (const attachment of emailData.attachments) {
      const size = formatFileSize(attachment.size);
      lines.push(`  - ${attachment.filename} (${attachment.contentType}, ${size})`);
      const inspected = summarizeInspectionForReport(attachment.analysis);
      if (inspected) lines.push(`    ${inspected}`);
    }
  }
  lines.push('');

  // Body
  lines.push('Email Body (Plain Text):');
  lines.push(subDivider);
  const { text: bodyText, truncated } = truncateBody(emailData.text, MAX_BODY_LENGTH);
  lines.push(bodyText);
  if (truncated) {
    lines.push('');
    lines.push(
      `[TRUNCATED - Original length exceeded ${MAX_BODY_LENGTH.toLocaleString()} characters]`
    );
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Format security-relevant headers for HTML display
 */
function formatHeadersForDisplay(headers: Record<string, string>): string {
  const securityHeaders = getSecurityHeaders(headers);

  if (securityHeaders.length === 0) {
    return paragraph('No security-relevant headers found', { quiet: true });
  }

  return facts(
    securityHeaders.map(([label, value]) => ({ label, value })),
    { labelWidth: 150, mono: true }
  );
}

/**
 * Get security-relevant headers from headers object
 */
function getSecurityHeaders(headers: Record<string, string>): Array<[string, string]> {
  const result: Array<[string, string]> = [];

  // Normalize header keys to lowercase for lookup
  const normalizedHeaders: Record<string, { originalKey: string; value: string }> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = { originalKey: key, value };
  }

  // Extract headers in priority order
  for (const headerName of SECURITY_HEADERS) {
    const normalized = headerName.toLowerCase();
    const entry = normalizedHeaders[normalized];
    if (entry) {
      result.push([headerName, entry.value]);
    }
  }

  return result;
}

/**
 * Format forwarded headers for HTML display
 */
function formatForwardedHeadersForDisplay(headers: Record<string, string>): string {
  if (!headers || Object.keys(headers).length === 0) {
    return paragraph('No forwarded headers found', { quiet: true });
  }

  // Displayed without the "Original-" prefix for a cleaner look
  return facts(
    FORWARDED_HEADERS.filter(name => headers[name]).map(name => ({
      label: name.replace('Original-', ''),
      value: headers[name],
    })),
    { labelWidth: 90, mono: true }
  );
}

/**
 * Format attachments for HTML display
 */
function formatAttachmentsForDisplay(attachments: EmailAttachment[]): string {
  if (attachments.length === 0) {
    return paragraph('No attachments', { quiet: true });
  }

  const items = attachments.map(attachment => {
    const size = formatFileSize(attachment.size);
    const inspected = summarizeInspectionForReport(attachment.analysis);
    return `<li style="margin:0 0 6px 0;"><span style="font-family:${MONO};font-size:12px;color:${COLOR.text};" class="ph-text">${escapeHtml(attachment.filename)}</span> (${escapeHtml(attachment.contentType)}, ${size})${
      inspected ? `<br>${escapeHtml(inspected)}` : ''
    }</li>`;
  });
  return `<ul class="ph-muted" style="margin:0 0 8px 0;padding:0 0 0 20px;font-family:${FONT};font-size:13px;line-height:20px;color:${COLOR.muted};word-break:break-word;">${items.join('')}</ul>`;
}

/**
 * Format links for HTML display (as escaped text, never an anchor)
 */
function formatLinksForDisplay(links: string[]): string {
  if (links.length === 0) {
    return paragraph('No links detected', { quiet: true });
  }

  return `<ul class="ph-muted" style="margin:0 0 8px 0;padding:0 0 0 20px;font-family:${MONO};font-size:12px;line-height:18px;color:${COLOR.muted};word-break:break-all;">${links
    .map(link => `<li style="margin:0 0 6px 0;">${escapeHtml(link)}</li>`)
    .join('')}</ul>`;
}

/**
 * Truncate text to maximum length with indicator
 */
function truncateBody(text: string, maxLength: number): { text: string; truncated: boolean } {
  if (!text) {
    return { text: '(No text content)', truncated: false };
  }

  if (text.length <= maxLength) {
    return { text, truncated: false };
  }

  return {
    text: text.substring(0, maxLength) + '\n\n[...]',
    truncated: true,
  };
}

/**
 * Format file size in human-readable format
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

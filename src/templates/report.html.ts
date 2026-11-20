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
  { label: string; tone: VerdictTone; plain: string; action: string }
> = {
  bec: {
    label: 'BUSINESS EMAIL COMPROMISE',
    tone: 'danger',
    plain:
      'Someone is impersonating a colleague, executive, or vendor to trick you into sending money, data, or credentials.',
    action:
      'Do not reply or act on the request. Verify it with the real person through a known phone number or in person.',
  },
  phishing: {
    label: 'PHISHING',
    tone: 'danger',
    plain:
      'This email is trying to steal your password or personal information, usually through a fake login page.',
    action: 'Do not click any links or enter any information. Delete it.',
  },
  malware_delivery: {
    label: 'MALWARE DELIVERY',
    tone: 'danger',
    plain: 'This email is trying to get you to open a file or link that would infect your device.',
    action: 'Do not open the attachment or click any links. Delete it.',
  },
  suspicious: {
    label: 'SUSPICIOUS',
    tone: 'caution',
    plain: "We couldn't confirm this is an attack, but something about it is off.",
    action: "Treat it with caution. Don't act on it until you've verified the sender another way.",
  },
  spam: {
    label: 'SPAM',
    tone: 'caution',
    plain: 'This looks like unwanted bulk email rather than a targeted attack.',
    action: 'No real harm expected — you can safely delete it.',
  },
  graymail: {
    label: 'LEGITIMATE BULK EMAIL',
    tone: 'safe',
    plain:
      'This is real, legitimate mail (a newsletter, survey, or marketing message) — just the kind you may not want.',
    action: "It's safe. If you'd rather not receive these, use the unsubscribe link.",
  },
  legitimate: {
    label: 'LIKELY LEGITIMATE',
    tone: 'safe',
    plain: 'This appears to be a genuine, expected email with no signs of an attack.',
    action: 'It looks safe to proceed as normal.',
  },
  undetermined: {
    label: 'ANALYSIS UNAVAILABLE',
    tone: 'caution',
    plain:
      "We couldn't analyze this email — our analysis service was temporarily unavailable. This is not a clean bill of health; the email has not been checked.",
    action:
      "Treat it with caution. Don't click links, open attachments, reply, or act on any request until you've verified the sender another way. Your security team has been notified.",
  },
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
 * Build complete HTML email for analysis report
 */
export function buildEmailHtml(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData,
  options?: ReportOptions
): string {
  const timestamp = new Date().toLocaleString();
  const analysisHtml = buildAnalysisSection(analysis, options);
  const originalSubject = emailData.subject;

  return `<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishy Analysis: ${escapeHtml(originalSubject)}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.5;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f9f9f9;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .header {
                background-color: #2C3E50;
                color: white;
                padding: 20px;
            }
            .header h1 {
                margin: 0;
                font-size: 22px;
            }
            .analysis {
                padding: 20px;
                border-bottom: 1px solid #eee;
            }
            h2 {
                margin-top: 0;
                color: #2C3E50;
                font-size: 18px;
            }
            h3 {
                color: #2c3e50;
                margin-top: 20px;
                font-size: 16px;
            }
            ul {
                margin-top: 10px;
                padding-left: 25px;
            }
            li {
                margin-bottom: 5px;
            }
            .verdict-phishing {
                color: #dc3545;
                font-weight: bold;
            }
            .verdict-legitimate {
                color: #28a745;
                font-weight: bold;
            }
            .verdict-suspicious {
                color: #fd7e14;
                font-weight: bold;
            }
            .thanks {
                color: #555;
                font-style: italic;
                margin-bottom: 16px;
            }
            .verdict-banner {
                border-radius: 6px;
                padding: 14px 16px;
                margin: 12px 0;
            }
            .verdict-line {
                margin: 0;
                font-size: 18px;
            }
            .risk-score {
                margin: 6px 0 0 0;
                font-size: 15px;
            }
            .verdict-phishing-bg {
                background-color: #fdecea;
                border-left: 4px solid #dc3545;
            }
            .verdict-suspicious-bg {
                background-color: #fff4e5;
                border-left: 4px solid #fd7e14;
            }
            .verdict-legitimate-bg {
                background-color: #e9f7ef;
                border-left: 4px solid #28a745;
            }
            .metadata {
                padding: 15px 20px;
                background-color: #f8f9fa;
                border-top: 1px solid #eee;
                font-size: 13px;
                color: #6c757d;
            }
            .ref-line {
                font-size: 11px;
                color: #adb5bd;
            }
            .metadata p {
                margin: 5px 0;
            }
            .footer {
                font-size: 12px;
                color: #777;
                padding: 15px 20px;
                background-color: #f5f5f5;
                border-top: 1px solid #eee;
            }
            /* Original email section styles */
            .original-email {
                padding: 20px;
                border-top: 1px solid #eee;
            }
            .original-email h2 {
                margin: 0 0 15px 0;
                font-size: 18px;
                color: #2C3E50;
            }
            .email-section {
                padding: 15px;
                margin-bottom: 15px;
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }
            .email-section:last-child {
                margin-bottom: 0;
            }
            .email-section h3 {
                margin: 0 0 10px 0;
                font-size: 14px;
                color: #495057;
            }
            .email-headers table {
                width: 100%;
                border-collapse: collapse;
                font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
                font-size: 12px;
            }
            .email-headers td {
                padding: 4px 8px;
                vertical-align: top;
                border-bottom: 1px solid #e9ecef;
            }
            .email-headers td:first-child {
                font-weight: bold;
                white-space: nowrap;
                width: 150px;
                color: #495057;
            }
            .email-headers td:last-child {
                word-break: break-all;
                color: #212529;
            }
            .email-links ul,
            .email-attachments ul {
                margin: 0;
                padding-left: 20px;
            }
            .email-links li,
            .email-attachments li {
                font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
                font-size: 12px;
                word-break: break-all;
                margin-bottom: 6px;
                color: #495057;
            }
            .email-body-preview {
                padding: 15px;
                background-color: #fff;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            .no-items {
                color: #6c757d;
                font-style: italic;
                font-size: 13px;
            }
            @media only screen and (max-width: 600px) {
                body {
                    padding: 10px;
                }
                .header, .analysis, .metadata, .footer, .original-email {
                    padding: 15px;
                }
                .email-section {
                    padding: 10px;
                }
                .email-headers td:first-child {
                    width: 100px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Phishy Analysis</h1>
            </div>
            <div class="analysis">
                ${analysisHtml}
            </div>
            ${options?.blastRadius ? buildBlastRadiusHtml(options.blastRadius) : ''}
            <div class="metadata">
                <p><strong>Analyzed Email Subject:</strong> ${escapeHtml(originalSubject)}</p>
                <p><strong>From:</strong> ${escapeHtml(emailData.from_email)}</p>
                ${options?.analysisId ? `<p class="ref-line">Reference: ${escapeHtml(options.analysisId)}</p>` : ''}
            </div>
            ${buildOriginalEmailSection(emailData, options?.audience)}
            <div class="footer">
                <p>This analysis was performed by Phishy powered by Anthropic's Claude AI.</p>
                <p>Delivered via Amazon SES | Report time: ${timestamp}</p>
            </div>
        </div>
    </body>
</html>`;
}

/**
 * Build the analysis section HTML
 */
function buildAnalysisSection(analysis: AnalysisResult, options?: ReportOptions): string {
  let html = '';

  const display = options?.risk ? VERDICT_DISPLAY[options.risk.verdict] : undefined;
  const tone: VerdictTone = display?.tone ?? (analysis.isPhishing ? 'danger' : 'safe');

  // Thank the reporter every time — reinforcing the habit is the point, and it
  // keeps people forwarding even when the email turns out to be harmless.
  const thanks =
    tone === 'safe'
      ? 'Thanks for checking — flagging anything that looks off is exactly the right habit.'
      : 'Good catch, and thanks for reporting. Sending this to Phishy helped protect you and your colleagues.';
  html += options?.silentReport
    ? `<p class="thanks">${escapeHtml(silentReportNotice(options.silentReport.reporter))}</p>`
    : `<p class="thanks">${thanks}</p>`;

  // Verdict banner: label + plain-language gloss + the prominent score/level
  // employees engage with.
  if (options?.risk) {
    const label = display?.label ?? options.risk.verdict.toUpperCase();
    html += `<div class="verdict-banner ${TONE_CLASS[tone]}-bg">`;
    html += `<p class="verdict-line"><span class="${TONE_CLASS[tone]}">${escapeHtml(label)}</span></p>`;
    // A failed analysis has no real score — never render "0/100 (safe)", which
    // would read as a clean bill of health for an email we never checked.
    if (options.risk.verdict === 'undetermined') {
      html += `<p class="risk-score">Risk score: <strong>not assessed</strong></p>`;
    } else {
      html += `<p class="risk-score">Risk score: <strong>${options.risk.riskScore}/100</strong> (${escapeHtml(options.risk.riskLevel)})</p>`;
      const confidence = confidenceText(options.risk);
      if (confidence) {
        html += `<p class="risk-score">Confidence: <strong>${escapeHtml(confidence)}</strong></p>`;
      }
    }
    html += `</div>`;
    if (display?.plain) {
      html += `<p><strong>What this means:</strong> ${escapeHtml(display.plain)}</p>`;
    }
  } else {
    const verdictText = analysis.isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
    html += `<div class="verdict-banner ${TONE_CLASS[tone]}-bg">`;
    html += `<p class="verdict-line"><span class="${TONE_CLASS[tone]}">${verdictText}</span></p>`;
    html += `<p class="risk-score">Confidence: <strong>${normalizeConfidence(analysis.confidence)}</strong></p>`;
    html += `</div>`;
  }

  // What to do — the single most important line, framed by verdict.
  if (display?.action) {
    html += `<p><strong>What to do:</strong> ${escapeHtml(display.action)}</p>`;
  }

  // Summary
  if (analysis.summary) {
    html += `<p><strong>Summary:</strong> ${escapeHtml(analysis.summary)}</p>`;
  }

  // Why Phishy reached this verdict — the model's indicators plus the
  // intelligence reasons behind the score.
  const whyItems = [...(analysis.indicators ?? [])];
  if (options?.risk?.reasons.length) {
    whyItems.push(...options.risk.reasons);
  }
  if (whyItems.length) {
    html += `<h3>Why we flagged it</h3>`;
    html += '<ul>';
    for (const item of whyItems) {
      html += `<li>${escapeHtml(item)}</li>`;
    }
    html += '</ul>';
  }

  // Recommendations from the analysis
  if (analysis.recommendations?.length) {
    html += `<h3>Recommendations</h3>`;
    html += '<ul>';
    for (const recommendation of analysis.recommendations) {
      html += `<li>${escapeHtml(recommendation)}</li>`;
    }
    html += '</ul>';
  }

  // Teaching moment: how to spot this kind of email next time, driven by the
  // threat vectors the model identified.
  const tips = buildTeachingTips(analysis);
  if (tips.length) {
    html += `<h3>How to spot this next time</h3>`;
    html += '<ul>';
    for (const tip of tips) {
      html += `<li>${escapeHtml(tip)}</li>`;
    }
    html += '</ul>';
  }

  return html;
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
 * Build plain text report
 */
export function buildPlainTextReport(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData,
  options?: ReportOptions
): string {
  const lines: string[] = [];
  const divider = '='.repeat(50);

  lines.push('PHISHY ANALYSIS REPORT');
  lines.push(divider);
  lines.push('');

  const display = options?.risk ? VERDICT_DISPLAY[options.risk.verdict] : undefined;
  const tone: VerdictTone = display?.tone ?? (analysis.isPhishing ? 'danger' : 'safe');

  // Thank the reporter — or, for a silent button report, tell the security
  // team who reported it and that the reporter was not notified
  lines.push(
    options?.silentReport
      ? silentReportNotice(options.silentReport.reporter)
      : tone === 'safe'
        ? 'Thanks for checking — flagging anything that looks off is exactly the right habit.'
        : 'Good catch, and thanks for reporting. Sending this to Phishy helped protect you and your colleagues.'
  );
  lines.push('');

  // Verdict + risk
  if (options?.risk) {
    lines.push(`Verdict: ${display?.label ?? options.risk.verdict.toUpperCase()}`);
    // A failed analysis has no real score — don't print "0/100 (safe)".
    if (options.risk.verdict === 'undetermined') {
      lines.push('Risk score: not assessed');
    } else {
      lines.push(`Risk score: ${options.risk.riskScore}/100 (${options.risk.riskLevel})`);
      const confidence = confidenceText(options.risk);
      if (confidence) {
        lines.push(`Confidence: ${confidence}`);
      }
    }
    if (display?.plain) {
      lines.push(`What this means: ${display.plain}`);
    }
  } else {
    const verdictText = analysis.isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
    lines.push(`Verdict: ${verdictText}`);
    lines.push(`Confidence: ${normalizeConfidence(analysis.confidence)}`);
  }
  if (display?.action) {
    lines.push(`What to do: ${display.action}`);
  }
  lines.push('');

  // Summary
  if (analysis.summary) {
    lines.push(`Summary: ${analysis.summary}`);
    lines.push('');
  }

  // Why we flagged it (indicators + intelligence reasons)
  const whyItems = [...(analysis.indicators ?? [])];
  if (options?.risk?.reasons.length) {
    whyItems.push(...options.risk.reasons);
  }
  if (whyItems.length) {
    lines.push('Why we flagged it:');
    for (const item of whyItems) {
      lines.push(`  - ${item}`);
    }
    lines.push('');
  }

  // Recommendations
  if (analysis.recommendations?.length) {
    lines.push('Recommendations:');
    for (const recommendation of analysis.recommendations) {
      lines.push(`  - ${recommendation}`);
    }
    lines.push('');
  }

  // How to spot this next time
  const tips = buildTeachingTips(analysis);
  if (tips.length) {
    lines.push('How to spot this next time:');
    for (const tip of tips) {
      lines.push(`  - ${tip}`);
    }
    lines.push('');
  }

  if (options?.blastRadius) {
    lines.push(...buildBlastRadiusText(options.blastRadius), '');
  }

  // Metadata
  lines.push(divider);
  lines.push('Email Details:');
  lines.push(`  Subject: ${emailData.subject}`);
  lines.push(`  From: ${emailData.from_email}`);

  if (options?.analysisId) {
    lines.push(`  Reference: ${options.analysisId}`);
  }

  lines.push('');

  // Original email section
  lines.push(buildOriginalEmailTextSection(emailData, options?.audience));

  lines.push(divider);
  lines.push("This analysis was performed by Phishy powered by Anthropic's Claude AI.");
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
function buildBlastRadiusHtml(report: BlastRadiusReport): string {
  if (report.status === 'unavailable') {
    return `
            <div class="analysis blast-radius">
                <p><strong>Security team only:</strong> ${escapeHtml(report.note ?? 'Blast radius lookup could not be completed.')}</p>
            </div>`;
  }

  const recipients = report.recipients ?? [];
  const cell = 'padding: 4px 8px; border-bottom: 1px solid #e9ecef; text-align: left;';
  let table = '';
  if (recipients.length) {
    table += '<table style="width: 100%; border-collapse: collapse; font-size: 13px;">';
    table += `<tr>${BLAST_COLUMNS.map(name => `<th style="${cell}">${name}</th>`).join('')}</tr>`;
    for (const recipient of recipients) {
      const cells = blastRadiusRow(recipient, report.reporterAddress);
      table += `<tr>${cells.map(text => `<td style="${cell}">${escapeHtml(text)}</td>`).join('')}</tr>`;
    }
    table += '</table>';
    const unlisted = blastRadiusUnlisted(report);
    if (unlisted > 0) {
      table += `<p class="no-items">${unlisted} more recipient(s) not listed.</p>`;
    }
  }

  const statements = blastRadiusLines(report)
    .map(line => `<p>${escapeHtml(line)}</p>`)
    .join('');
  const caveats = (report.caveats ?? []).map(text => `<li>${escapeHtml(text)}</li>`).join('');

  return `
            <div class="analysis blast-radius">
                <h2>Blast radius (security team only)</h2>
                ${statements}
                ${table}
                ${caveats ? `<ul style="font-size: 13px; color: #6c757d;">${caveats}</ul>` : ''}
                <p class="ref-line">Looked up ${escapeHtml(report.lookedUpAt)}. This section is not in the reporter's copy.</p>
            </div>`;
}

/** Blast-radius section (plain text) for the security team's copy */
function buildBlastRadiusText(report: BlastRadiusReport): string[] {
  if (report.status === 'unavailable') {
    return [`Security team only: ${report.note ?? 'Blast radius lookup could not be completed.'}`];
  }

  const lines = ['BLAST RADIUS (security team only)', '-'.repeat(40), ...blastRadiusLines(report)];
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
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };

  return text.replace(/[&<>"']/g, char => htmlEntities[char] ?? char);
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
 * Build the original email section for HTML report
 */
function buildOriginalEmailSection(
  emailData: ExtractedEmailData,
  audience?: ReportOptions['audience']
): string {
  const forwardedHeadersHtml = formatForwardedHeadersForDisplay(emailData.forwardedHeaders);
  const headersHtml = formatHeadersForDisplay(emailData.headers);
  const linksHtml = formatLinksForDisplay(emailData.links);
  const attachmentsHtml = formatAttachmentsForDisplay(emailData.attachments);

  // Format email content - sanitize HTML to prevent XSS from malicious emails
  // Use text-only display since this is analyzing potentially malicious content
  const emailContent = emailData.text
    ? escapeHtml(emailData.text).replace(/\n/g, '<br>')
    : emailData.html
      ? escapeHtml(stripHtmlForDisplay(emailData.html)).replace(/\n/g, '<br>')
      : '<em>No email content available</em>';

  // Only show forwarded headers section if we found any
  const forwardedHeadersSection =
    Object.keys(emailData.forwardedHeaders || {}).length > 0
      ? `
                <div class="email-section email-forwarded-headers" style="background-color: #fff3cd; border: 1px solid #ffc107;">
                    <h3>Original Sender Info (from forwarded message)</h3>
                    ${forwardedHeadersHtml}
                </div>`
      : '';

  return `
            <div class="original-email">
                <h2>Original Email for IT Review</h2>
                ${forwardedHeadersSection}
                ${buildSenderHistorySection(emailData, audience)}

                <div class="email-section email-content">
                    <h3>Original Email Content</h3>
                    <div class="email-body-preview">
                        ${emailContent}
                    </div>
                </div>

                <div class="email-section email-headers">
                    <h3>Envelope Headers (forwarder)</h3>
                    ${headersHtml}
                </div>

                <div class="email-section email-links">
                    <h3>Links Detected (${emailData.links.length})</h3>
                    ${linksHtml}
                </div>

                <div class="email-section email-attachments">
                    <h3>Attachments (${emailData.attachments.length})</h3>
                    ${attachmentsHtml}
                </div>
            </div>`;
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
  let rows = '';
  for (const [label, value] of lines) {
    rows += `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`;
  }
  return `
                <div class="email-section email-headers email-sender-history">
                    <h3>${escapeHtml(senderHistoryHeading(audience))}</h3>
                    <table>${rows}</table>
                    <p class="no-items">${escapeHtml(SENDER_HISTORY_CAVEAT)}</p>
                </div>`;
}

/**
 * Build the original email section for plain text report
 */
function buildOriginalEmailTextSection(
  emailData: ExtractedEmailData,
  audience?: ReportOptions['audience']
): string {
  const lines: string[] = [];
  const divider = '='.repeat(50);
  const subDivider = '-'.repeat(40);

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
    return '<p class="no-items">No security-relevant headers found</p>';
  }

  let html = '<table>';
  for (const [name, value] of securityHeaders) {
    html += `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(value)}</td></tr>`;
  }
  html += '</table>';

  return html;
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
    return '<p class="no-items">No forwarded headers found</p>';
  }

  let html = '<table>';
  for (const headerName of FORWARDED_HEADERS) {
    if (headers[headerName]) {
      // Display without "Original-" prefix for cleaner look
      const displayName = headerName.replace('Original-', '');
      html += `<tr><td>${escapeHtml(displayName)}</td><td>${escapeHtml(headers[headerName])}</td></tr>`;
    }
  }
  html += '</table>';

  return html;
}

/**
 * Format attachments for HTML display
 */
function formatAttachmentsForDisplay(attachments: EmailAttachment[]): string {
  if (attachments.length === 0) {
    return '<p class="no-items">No attachments</p>';
  }

  let html = '<ul>';
  for (const attachment of attachments) {
    const size = formatFileSize(attachment.size);
    const inspected = summarizeInspectionForReport(attachment.analysis);
    const inspectedHtml = inspected
      ? `<br><span style="color: #6c757d; font-size: 0.9em;">${escapeHtml(inspected)}</span>`
      : '';
    html += `<li>${escapeHtml(attachment.filename)} <span style="color: #6c757d;">(${escapeHtml(attachment.contentType)}, ${size})</span>${inspectedHtml}</li>`;
  }
  html += '</ul>';

  return html;
}

/**
 * Format links for HTML display (as text, not clickable)
 */
function formatLinksForDisplay(links: string[]): string {
  if (links.length === 0) {
    return '<p class="no-items">No links detected</p>';
  }

  let html = '<ul>';
  for (const link of links) {
    html += `<li>${escapeHtml(link)}</li>`;
  }
  html += '</ul>';

  return html;
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

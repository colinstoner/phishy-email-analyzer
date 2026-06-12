/**
 * Email Command Service
 * Lets the security team direct Phishy over email. Replies to an analysis
 * report (or mail referencing an Analysis ID) from an authorized sender are
 * parsed for intent, executed, and answered with the completed actions.
 *
 * Authorization is two-factor: the sender must be in the security team
 * distribution list AND the inbound message must pass SES SPF or DKIM
 * verification, so a spoofed From header is not enough to issue commands.
 *
 * v1 command set: verdict corrections ("confirmed phishing" /
 * "false positive"). The channel is designed to grow — safelist changes,
 * campaign queries, and free-text questions land here in later phases.
 */

import { createLogger } from '../../utils/logger';
import { EmailMessage, ExtractedEmailData } from '../../types';
import { IntelligenceDatabaseService, FeedbackRecord } from '../intelligence/database.service';
import { SESNotifier } from '../notification/ses.notifier';

const logger = createLogger('email-commands');

export interface CommandResult {
  /** True when this email was handled as a command (skip the analysis pipeline) */
  handled: boolean;
  action?: 'verdict_recorded' | 'help_sent' | 'no_match';
}

export class EmailCommandService {
  constructor(
    private db: IntelligenceDatabaseService,
    private notifier: SESNotifier,
    private securityTeam: string[]
  ) {}

  /**
   * Cheap pre-check: could this inbound email be a command? True when the
   * sender is on the security team and the mail looks like a reply to a
   * Phishy report or mentions an Analysis ID.
   */
  looksLikeCommand(msg: EmailMessage, emailData: ExtractedEmailData): boolean {
    if (!this.isSecurityTeamSender(emailData.from_email)) {
      return false;
    }

    const subject = emailData.subject.toLowerCase();
    const isReplyToReport = subject.includes('phishing analysis');
    const mentionsAnalysisId = ANALYSIS_ID_PATTERN.test(msg.text);
    const hasReplyHeaders = !!this.getInReplyTo(msg);

    return isReplyToReport || mentionsAnalysisId || hasReplyHeaders;
  }

  /**
   * Process a candidate command email end-to-end.
   */
  async process(msg: EmailMessage, emailData: ExtractedEmailData): Promise<CommandResult> {
    const sender = emailData.from_email;

    // Hard authentication gate: From-header membership is not enough
    if (!this.passesAuthentication(msg)) {
      logger.warn('Command rejected: sender failed SPF/DKIM verification', {
        sender,
        spf: msg.authVerdicts?.spf,
        dkim: msg.authVerdicts?.dkim,
      });
      return { handled: false };
    }

    const analysisId = await this.matchAnalysis(msg);
    if (!analysisId) {
      logger.info('Security-team email did not match any analysis', { sender });
      await this.reply(
        emailData,
        'Phishy could not match your message to an analysis',
        [
          'Reply directly to a Phishy analysis report, or include the line',
          '"Analysis ID: <id>" from the report you are referring to.',
        ].join('\n')
      );
      return { handled: true, action: 'no_match' };
    }

    const verdict = parseVerdictCommand(extractFreshText(msg.text));
    if (!verdict) {
      await this.reply(
        emailData,
        'Phishy did not understand that command',
        [
          'Supported commands (anywhere in your reply):',
          '  "confirmed phishing"  - confirm the verdict and strengthen its indicators',
          '  "false positive"      - overturn the verdict and decay its indicators',
          '',
          `Analysis ID: ${analysisId}`,
        ].join('\n')
      );
      return { handled: true, action: 'help_sent' };
    }

    await this.db.recordFeedback({
      analysisId,
      verdict,
      source: 'email_reply',
      submittedBy: sender,
      notes: extractFreshText(msg.text).substring(0, 500),
    });
    const adjusted = await this.db.applyFeedbackToIndicators(analysisId, verdict);

    logger.info('Verdict command executed', { sender, analysisId, verdict, adjusted });

    const verdictLabel = verdict === 'confirmed_phishing' ? 'Confirmed phishing' : 'False positive';
    await this.reply(
      emailData,
      `Done — verdict recorded: ${verdictLabel}`,
      [
        'Completed actions:',
        `  - Recorded "${verdictLabel}" for analysis ${analysisId} (submitted by ${sender})`,
        `  - Adjusted confidence on ${adjusted} threat indicator${adjusted === 1 ? '' : 's'} from this campaign`,
        verdict === 'false_positive'
          ? '  - Indicators that fell below the confidence floor were deactivated'
          : '  - Future emails reusing these indicators will be flagged with higher confidence',
        '',
        'Changed your mind? Reply again with the other verdict — the latest answer wins.',
      ].join('\n')
    );

    return { handled: true, action: 'verdict_recorded' };
  }

  private isSecurityTeamSender(fromEmail: string): boolean {
    const sender = fromEmail.toLowerCase().trim();
    return this.securityTeam.some(member => member.toLowerCase().trim() === sender);
  }

  private passesAuthentication(msg: EmailMessage): boolean {
    const spf = msg.authVerdicts?.spf?.toUpperCase();
    const dkim = msg.authVerdicts?.dkim?.toUpperCase();
    return spf === 'PASS' || dkim === 'PASS';
  }

  private getInReplyTo(msg: EmailMessage): string | null {
    const headers = msg.headers ?? {};
    for (const name of ['In-Reply-To', 'in-reply-to', 'References', 'references']) {
      if (headers[name]) {
        return headers[name];
      }
    }
    return null;
  }

  /**
   * Match a reply to its analysis: In-Reply-To header against the stored
   * outbound report message ID first, quoted "Analysis ID:" line as fallback.
   */
  private async matchAnalysis(msg: EmailMessage): Promise<string | null> {
    const inReplyTo = this.getInReplyTo(msg);
    if (inReplyTo) {
      // Header form is <ses-message-id@region.amazonses.com>; we store the bare SES ID
      const ids = inReplyTo.match(/<([^@>]+)@[^>]*>/g) ?? [];
      for (const raw of ids) {
        const sesId = raw.replace(/^<|@[^>]*>$/g, '');
        const analysisId = await this.db.findAnalysisIdByReportMessageId(sesId);
        if (analysisId) {
          return analysisId;
        }
      }
    }

    const idMatch = msg.text.match(ANALYSIS_ID_PATTERN);
    return idMatch ? idMatch[1] : null;
  }

  private async reply(emailData: ExtractedEmailData, heading: string, body: string): Promise<void> {
    const subject = emailData.subject.startsWith('Re:')
      ? emailData.subject
      : `Re: ${emailData.subject}`;
    const text = `${heading}\n\n${body}\n\n— Phishy`;
    const html = `<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #333;"><p><strong>${escapeHtml(heading)}</strong></p><pre style="font-family: inherit; white-space: pre-wrap;">${escapeHtml(body)}</pre><p>— Phishy</p></div>`;

    await this.notifier.sendEmail(emailData.from_email, subject, html, text);
  }
}

const ANALYSIS_ID_PATTERN =
  /Analysis ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;

/**
 * Strip quoted history and signature blocks, keeping only the text the
 * sender actually wrote in this reply.
 */
export function extractFreshText(text: string): string {
  const lines = text.split('\n');
  const fresh: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    // Stop at common reply separators
    if (
      /^On .+wrote:\s*$/.test(trimmed) ||
      /^-{2,}\s*Original Message\s*-{2,}/i.test(trimmed) ||
      /^_{5,}\s*$/.test(trimmed) ||
      /^From:\s/.test(trimmed)
    ) {
      break;
    }
    // Skip quoted lines but keep scanning (some clients interleave)
    if (trimmed.startsWith('>')) {
      continue;
    }
    fresh.push(line);
  }

  return fresh.join('\n').trim();
}

/**
 * Parse a verdict command from reply text. Deterministic keyword matching —
 * negative forms ("not phishing") are checked before positive ones, so order
 * matters here.
 */
export function parseVerdictCommand(text: string): FeedbackRecord['verdict'] | null {
  const t = text.toLowerCase();

  if (/false\s*positive|not\s+(a\s+)?phish|\blegit(imate)?\b|\bsafe\b|\bbenign\b/.test(t)) {
    return 'false_positive';
  }

  if (/\bconfirm(ed)?\b|\bphish(ing|y)?\b|\bmalicious\b|\bcorrect\b|\bagreed?\b/.test(t)) {
    return 'confirmed_phishing';
  }

  return null;
}

function escapeHtml(text: string): string {
  const entities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return text.replace(/[&<>"']/g, char => entities[char] ?? char);
}

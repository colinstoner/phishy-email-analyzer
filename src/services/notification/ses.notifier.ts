/**
 * SES Notifier Service
 * Handles sending analysis reports via Amazon SES
 */

import { SES, SendEmailCommandOutput } from '@aws-sdk/client-ses';
import { AnalysisResult, EmailSendResult, ExtractedEmailData } from '../../types';
import { contentFacts, createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';
import { buildEmailHtml, buildPlainTextReport, ReportOptions } from '../../templates/report.html';
import { normalizeConfidence } from '../ai/provider.interface';

const logger = createLogger('ses-notifier');

export interface SESNotifierConfig {
  region: string;
  senderEmail: string;
  senderName?: string;
  securityTeamDistribution?: string[];
  configSet?: string;
}

/**
 * The domain of the Message-ID header SES writes (`<id@domain>`):
 * `email.amazonses.com` in us-east-1, `<region>.amazonses.com` elsewhere.
 */
export function sesMessageIdDomain(region: string): string {
  return region === 'us-east-1' ? 'email.amazonses.com' : `${region}.amazonses.com`;
}

export class SESNotifier {
  private client: SES;
  private senderEmail: string;
  private senderName: string;
  private securityTeamDistribution: string[];
  private configSet?: string;
  private region: string;

  constructor(config: SESNotifierConfig) {
    this.client = new SES({ region: config.region });
    this.region = config.region;
    this.senderEmail = config.senderEmail;
    this.senderName = config.senderName ?? 'Phishy';
    this.securityTeamDistribution = config.securityTeamDistribution ?? [];
    this.configSet = config.configSet;

    logger.info('SES Notifier initialized', {
      senderEmail: this.senderEmail,
      securityTeamDistribution: this.securityTeamDistribution,
      hasSecurityTeam: this.securityTeamDistribution.length > 0,
    });
  }

  /**
   * Send analysis report email
   */
  async sendAnalysisReport(
    recipient: string,
    analysis: AnalysisResult,
    emailData: ExtractedEmailData,
    ccOverride?: string[],
    reportOptions?: ReportOptions
  ): Promise<EmailSendResult> {
    const ccAddresses = ccOverride ?? this.securityTeamDistribution;

    logger.info('Sending analysis report', {
      recipient,
      subject: contentFacts(emailData.subject),
      isPhishing: analysis.isPhishing,
      ccSecurityTeam: ccAddresses,
    });

    try {
      const htmlContent = buildEmailHtml(analysis, emailData, reportOptions);
      const textContent = buildPlainTextReport(analysis, emailData, reportOptions);
      const subject = `Phishing Analysis: ${emailData.subject}`;

      const result = await this.sendEmail(
        recipient,
        subject,
        htmlContent,
        textContent,
        ccAddresses
      );

      logger.info('Analysis report sent successfully', {
        recipient,
        messageId: result.messageId,
      });

      return result;
    } catch (error) {
      logger.error('Failed to send analysis report', {
        recipient,
        error: error instanceof Error ? error.message : String(error),
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Send generic email
   */
  async sendEmail(
    recipient: string,
    subject: string,
    htmlBody: string,
    textBody: string,
    ccAddresses?: string[]
  ): Promise<EmailSendResult> {
    return withRetry(
      async () => {
        const params = {
          Source: `"${this.senderName}" <${this.senderEmail}>`,
          Destination: {
            ToAddresses: [recipient],
            CcAddresses: ccAddresses?.length ? ccAddresses : undefined,
          },
          Message: {
            Subject: {
              Data: subject,
              Charset: 'UTF-8',
            },
            Body: {
              Text: {
                Data: textBody,
                Charset: 'UTF-8',
              },
              Html: {
                Data: htmlBody,
                Charset: 'UTF-8',
              },
            },
          },
          ConfigurationSetName: this.configSet,
        };

        const result: SendEmailCommandOutput = await this.client.sendEmail(params);

        return {
          success: true,
          messageId: result.MessageId,
        };
      },
      {
        maxRetries: 3,
        baseDelayMs: 1000,
        shouldRetry: isRetryableHttpError,
      }
    );
  }

  /**
   * Send one email as a reply in an existing thread: `In-Reply-To` and
   * `References` name the earlier email by the Message-ID SES gave it. SES's
   * SendEmail cannot set those headers, so this builds the MIME itself
   * (multipart/alternative, base64 parts, an RFC 2047 subject). Every
   * header value is code-written or checked; nothing here can add a header.
   */
  async sendThreadedEmail(
    recipients: string[],
    subject: string,
    htmlBody: string,
    textBody: string,
    inReplyToSesMessageId?: string
  ): Promise<EmailSendResult> {
    const to = recipients.filter(address => /^[^\s<>,;"]+@[^\s<>,;"]+$/.test(address));
    if (to.length === 0) {
      return { success: false, error: 'no valid recipient' };
    }
    const reference =
      inReplyToSesMessageId && /^[A-Za-z0-9-]{1,120}$/.test(inReplyToSesMessageId)
        ? `<${inReplyToSesMessageId}@${sesMessageIdDomain(this.region)}>`
        : undefined;
    const boundary = `phishy-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    const encodedSubject = `=?UTF-8?B?${Buffer.from(subject.replace(/[\r\n]+/g, ' '), 'utf8').toString('base64')}?=`;
    const base64 = (text: string): string =>
      (
        Buffer.from(text, 'utf8')
          .toString('base64')
          .match(/.{1,76}/g) ?? []
      ).join('\r\n');
    const fromName = this.senderName.replace(/["\r\n\\]/g, '');
    const mime = [
      `From: "${fromName}" <${this.senderEmail}>`,
      `To: ${to.join(', ')}`,
      `Subject: ${encodedSubject}`,
      'MIME-Version: 1.0',
      ...(reference ? [`In-Reply-To: ${reference}`, `References: ${reference}`] : []),
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      base64(textBody),
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      base64(htmlBody),
      `--${boundary}--`,
      '',
    ].join('\r\n');

    try {
      return await withRetry(
        async () => {
          const result = await this.client.sendRawEmail({
            RawMessage: { Data: Buffer.from(mime, 'utf8') },
            ConfigurationSetName: this.configSet,
          });
          return { success: true, messageId: result.MessageId };
        },
        { maxRetries: 3, baseDelayMs: 1000, shouldRetry: isRetryableHttpError }
      );
    } catch (error) {
      logger.error('Failed to send threaded email', {
        error: error instanceof Error ? error.message : String(error),
      });
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  /**
   * Format analysis result as HTML for email body
   */
  formatAnalysisHtml(analysis: AnalysisResult): string {
    let html = '';

    // Summary
    if (analysis.summary) {
      html += `<p><strong>Summary:</strong> ${analysis.summary}</p>`;
    }

    // Verdict
    const verdictColor = analysis.isPhishing ? 'red' : 'green';
    const verdictText = analysis.isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
    html += `<p><strong>Verdict:</strong> <span style="color: ${verdictColor}; font-weight: bold;">${verdictText}</span></p>`;

    // Confidence
    if (analysis.confidence) {
      html += `<p><strong>Confidence:</strong> ${normalizeConfidence(analysis.confidence)}</p>`;
    }

    // Indicators
    if (analysis.indicators?.length) {
      html += `<h3>Suspicious Indicators</h3>`;
      html += '<ul>' + analysis.indicators.map(i => `<li>${i}</li>`).join('') + '</ul>';
    }

    // Recommendations
    if (analysis.recommendations?.length) {
      html += `<h3>Recommendations</h3>`;
      html += '<ul>' + analysis.recommendations.map(r => `<li>${r}</li>`).join('') + '</ul>';
    }

    return html;
  }
}

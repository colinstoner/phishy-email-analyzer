/**
 * SES Notifier Service
 * Handles sending analysis reports via Amazon SES
 */

import { SES, SendEmailCommandOutput } from '@aws-sdk/client-ses';
import { AnalysisResult, EmailSendResult, ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';
import { buildEmailHtml, buildPlainTextReport } from '../../templates/report.html';
import { normalizeConfidence } from '../ai/provider.interface';

const logger = createLogger('ses-notifier');

export interface SESNotifierConfig {
  region: string;
  senderEmail: string;
  senderName?: string;
  securityTeamDistribution?: string[];
  configSet?: string;
}

export class SESNotifier {
  private client: SES;
  private senderEmail: string;
  private senderName: string;
  private securityTeamDistribution: string[];
  private configSet?: string;

  constructor(config: SESNotifierConfig) {
    this.client = new SES({ region: config.region });
    this.senderEmail = config.senderEmail;
    this.senderName = config.senderName ?? 'Phishy';
    this.securityTeamDistribution = config.securityTeamDistribution ?? [];
    this.configSet = config.configSet;
  }

  /**
   * Send analysis report email
   */
  async sendAnalysisReport(
    recipient: string,
    analysis: AnalysisResult,
    emailData: ExtractedEmailData
  ): Promise<EmailSendResult> {
    logger.info('Sending analysis report', {
      recipient,
      subject: emailData.subject,
      isPhishing: analysis.isPhishing,
    });

    try {
      const htmlContent = buildEmailHtml(analysis, emailData);
      const textContent = buildPlainTextReport(analysis, emailData);
      const subject = `Phishing Analysis: ${emailData.subject}`;

      const result = await this.sendEmail(
        recipient,
        subject,
        htmlContent,
        textContent,
        this.securityTeamDistribution
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

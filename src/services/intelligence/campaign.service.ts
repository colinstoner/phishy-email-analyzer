/**
 * Campaign Detection and Alert Service
 * Detects phishing campaigns and sends employee notifications
 */

import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { createLogger } from '../../utils/logger';
import { IntelligenceDatabaseService, CampaignRecord } from './database.service';

const logger = createLogger('campaign-service');

export interface CampaignAlertConfig {
  enabled: boolean;
  distributionList: string;
  senderEmail: string;
  senderName?: string;
  region?: string;
}

export class CampaignAlertService {
  private db: IntelligenceDatabaseService;
  private sesClient: SESClient;
  private config: CampaignAlertConfig;

  constructor(db: IntelligenceDatabaseService, config: CampaignAlertConfig) {
    this.db = db;
    this.config = config;
    this.sesClient = new SESClient({ region: config.region ?? 'us-west-2' });
  }

  /**
   * Process a high-confidence phishing detection for campaign tracking
   * Returns true if an alert was sent
   */
  async processDetection(
    senderDomain: string,
    subject: string,
    recipientEmail: string,
    riskLevel: 'critical' | 'high' | 'medium' | 'low',
    indicators: string[]
  ): Promise<boolean> {
    if (!this.config.enabled) {
      return false;
    }

    // Only track high/critical risk detections for campaign alerts
    if (riskLevel !== 'high' && riskLevel !== 'critical') {
      return false;
    }

    try {
      const match = await this.db.trackCampaignDetection(
        senderDomain,
        subject,
        recipientEmail,
        riskLevel,
        indicators
      );

      if (!match) {
        return false;
      }

      logger.info('Campaign detection tracked', {
        signature: match.signature,
        detectionCount: match.detectionCount,
        uniqueRecipients: match.uniqueRecipientCount,
        shouldAlert: match.shouldAlert,
      });

      if (match.shouldAlert) {
        const campaign = await this.db.getCampaignDetails(match.campaignId);
        if (campaign) {
          await this.sendCampaignAlert(campaign);
          await this.db.markCampaignAlerted(match.campaignId);
          return true;
        }
      }

      return false;
    } catch (error) {
      logger.error('Failed to process campaign detection', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Send employee alert for detected campaign
   */
  private async sendCampaignAlert(campaign: CampaignRecord): Promise<void> {
    const { subject, htmlBody, textBody } = this.buildAlertEmail(campaign);

    const command = new SendEmailCommand({
      Source: this.config.senderName
        ? `${this.config.senderName} <${this.config.senderEmail}>`
        : this.config.senderEmail,
      Destination: {
        ToAddresses: [this.config.distributionList],
      },
      Message: {
        Subject: { Data: subject, Charset: 'UTF-8' },
        Body: {
          Html: { Data: htmlBody, Charset: 'UTF-8' },
          Text: { Data: textBody, Charset: 'UTF-8' },
        },
      },
    });

    await this.sesClient.send(command);

    logger.info('Campaign alert sent', {
      campaignId: campaign.id,
      distributionList: this.config.distributionList,
      senderDomain: campaign.senderDomain,
    });
  }

  /**
   * Build employee-friendly alert email
   */
  private buildAlertEmail(campaign: CampaignRecord): {
    subject: string;
    htmlBody: string;
    textBody: string;
  } {
    const senderDisplay = this.formatSenderForDisplay(campaign.senderDomain);
    const indicatorsList = campaign.sampleIndicators
      .slice(0, 3)
      .map(i => `- ${i}`)
      .join('\n');

    const subject = `Phishy Alert: Suspicious emails from ${senderDisplay}`;

    const textBody = `PHISHY ALERT

We're seeing fraudulent emails appearing to come from ${senderDisplay}.

WHAT TO LOOK FOR:
- Sender addresses ending in @${campaign.senderDomain}
- Subject lines like: "${campaign.subjectPattern}"
${indicatorsList ? `\nRED FLAGS:\n${indicatorsList}` : ''}

WHAT TO DO:
- Don't click links or open attachments
- Don't reply or provide information
- Delete the email

Already interacted with one of these emails? Contact IT.

---
Phishy detected ${campaign.detectionCount} of these in the last few hours.
`;

    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
    .alert-header { background: #1a237e; color: white; padding: 20px; text-align: center; }
    .alert-header h1 { margin: 0; font-size: 22px; }
    .content { padding: 20px; }
    .section { margin-bottom: 20px; }
    .section-title { font-weight: bold; color: #1a237e; margin-bottom: 8px; font-size: 16px; }
    .highlight-box { background: #e3f2fd; border-left: 4px solid #1976d2; padding: 12px; margin: 10px 0; }
    .action-box { background: #f5f5f5; border-left: 4px solid #616161; padding: 12px; margin: 10px 0; }
    .warning-box { background: #fff3e0; border-left: 4px solid #f57c00; padding: 12px; margin: 10px 0; }
    ul { margin: 8px 0; padding-left: 20px; }
    li { margin-bottom: 6px; }
    .footer { font-size: 12px; color: #666; border-top: 1px solid #ddd; padding-top: 15px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="alert-header">
    <h1>Phishy Alert</h1>
  </div>
  <div class="content">
    <p>We're seeing <strong>fraudulent emails</strong> appearing to come from <strong>${this.escapeHtml(senderDisplay)}</strong>.</p>

    <div class="section">
      <div class="section-title">What to Look For</div>
      <div class="highlight-box">
        <ul>
          <li>Sender addresses ending in <strong>@${this.escapeHtml(campaign.senderDomain)}</strong></li>
          <li>Subject lines like: <em>"${this.escapeHtml(campaign.subjectPattern)}"</em></li>
        </ul>
      </div>
    </div>

    ${campaign.sampleIndicators.length > 0 ? `
    <div class="section">
      <div class="section-title">Red Flags</div>
      <ul>
        ${campaign.sampleIndicators.slice(0, 3).map(i => `<li>${this.escapeHtml(i)}</li>`).join('')}
      </ul>
    </div>
    ` : ''}

    <div class="section">
      <div class="section-title">What to Do</div>
      <div class="action-box">
        <ul>
          <li>Don't click links or open attachments</li>
          <li>Don't reply or provide information</li>
          <li>Delete the email</li>
        </ul>
      </div>
    </div>

    <div class="warning-box">
      <strong>Already interacted with one of these emails?</strong> Contact IT.
    </div>

    <div class="footer">
      Phishy detected ${campaign.detectionCount} of these in the last few hours.
    </div>
  </div>
</body>
</html>
`;

    return { subject, htmlBody, textBody };
  }

  /**
   * Format sender domain for human-readable display
   */
  private formatSenderForDisplay(domain: string): string {
    // Extract company-like name from domain
    const parts = domain.split('.');
    if (parts.length >= 2) {
      // Take the main part (e.g., "acme" from "acme.com" or "mail.acme.com")
      const mainPart = parts.length > 2 ? parts[parts.length - 2] : parts[0];
      return mainPart.charAt(0).toUpperCase() + mainPart.slice(1);
    }
    return domain;
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

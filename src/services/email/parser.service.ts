/**
 * Email Parser Service
 * Handles parsing of email messages from various sources
 */

import {
  EmailMessage,
  ExtractedEmailData,
  SESRecord,
  SESEvent,
  EmailEvent,
  S3Location,
} from '../../types';
import { createLogger } from '../../utils/logger';
import {
  extractEmailAddress,
  extractUrls,
  extractHrefUrls,
  containsHtml,
  stripHtml,
} from '../../utils/validation';
import { S3Service } from '../storage/s3.service';

const logger = createLogger('email-parser');

/**
 * Essential email headers for security analysis
 */
const ESSENTIAL_HEADER_NAMES = [
  'From',
  'Return-Path',
  'Reply-To',
  'X-Sender',
  'X-Originating-IP',
  'X-Forwarded-For',
  'Message-ID',
  'In-Reply-To',
  'References',
];

/**
 * Headers that might contain original sender information in forwarded emails
 */
const ORIGINAL_SENDER_HEADERS = [
  'X-Original-From',
  'X-Sender',
  'Original-From',
  'X-Envelope-From',
];

export class EmailParserService {
  private s3Service: S3Service;
  private safeDomains: string[];
  private defaultBucket: string;

  constructor(s3Service: S3Service, safeDomains: string[], defaultBucket: string) {
    this.s3Service = s3Service;
    this.safeDomains = safeDomains.map(d => d.toLowerCase());
    this.defaultBucket = defaultBucket;
  }

  /**
   * Parse email events from various input formats
   */
  async parseEmailEvents(rawInput: unknown): Promise<EmailEvent[]> {
    try {
      logger.info('Parsing email event payload', { type: typeof rawInput });

      if (!rawInput) return [];

      // Case 1: Direct SES invocation
      if (this.isSESEvent(rawInput)) {
        const sesEvent = rawInput as SESEvent;
        const result = await this.parseSESRecords(sesEvent.Records);
        logger.info('Parsed SES records', { count: result.length });
        return result;
      }

      // Case 2: String data (API Gateway or other sources)
      const bodyStr = this.convertToString(rawInput);

      // Try JSON parsing
      try {
        const jsonBody = JSON.parse(bodyStr);

        if (Array.isArray(jsonBody)) {
          return jsonBody as EmailEvent[];
        }

        if (jsonBody.Records && Array.isArray(jsonBody.Records)) {
          return await this.parseSESRecords(jsonBody.Records as SESRecord[]);
        }

        if (jsonBody.email_events) {
          const events = Array.isArray(jsonBody.email_events)
            ? jsonBody.email_events
            : JSON.parse(jsonBody.email_events as string);
          return Array.isArray(events) ? events : [];
        }
      } catch {
        logger.debug('Not a JSON payload');
      }

      // Case 3: URL-encoded form data
      if (bodyStr.includes('email_events=')) {
        try {
          const params = new URLSearchParams(bodyStr);
          const emailEvents = params.get('email_events');
          if (emailEvents) {
            const events = JSON.parse(emailEvents);
            return Array.isArray(events) ? events : [];
          }
        } catch {
          logger.debug('Failed to parse URL-encoded data');
        }
      }

      logger.warn('No parseable email events found in payload');
      return [];
    } catch (error) {
      logger.error('Error parsing payload', {
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }

  /**
   * Parse SES records into email events
   */
  async parseSESRecords(records: SESRecord[]): Promise<EmailEvent[]> {
    logger.info('Processing SES records', { count: records.length });

    const results = await Promise.all(
      records.map(async record => {
        if (!record.ses?.mail) {
          return null;
        }

        try {
          const { content, s3Location } = await this.extractEmailContent(record);

          if (!content || content.length < 10) {
            logger.warn('Empty or very short email content received');
          }

          const forwarded = this.parseEmailContent(content);

          const msg: EmailMessage = {
            from_email: record.ses.mail.source,
            subject: record.ses.mail.commonHeaders?.subject ?? 'No Subject',
            headers: this.extractHeaders(record.ses.mail.headers),
            text: forwarded.text || record.ses.mail.commonHeaders?.subject || 'No email content',
            html: forwarded.html,
            to: record.ses.mail.destination?.join(', ') ?? '',
            original_sender: record.ses.mail.commonHeaders?.from?.[0] ?? '',
            messageId: record.ses.mail.messageId ?? '',
            sesMailTimestamp: record.ses.mail.timestamp ?? '',
            s3Reference: s3Location ? `s3://${s3Location.bucket}/${s3Location.key}` : null,
            s3Location: s3Location ?? undefined,
          };

          logger.debug('Processed email', {
            subject: msg.subject,
            contentLength: msg.text.length,
          });

          return { msg };
        } catch (error) {
          logger.error('Error processing SES record', {
            error: error instanceof Error ? error.message : String(error),
          });
          return null;
        }
      })
    );

    return results.filter((item): item is EmailEvent => item !== null);
  }

  /**
   * Extract email content from SES record
   */
  private async extractEmailContent(
    record: SESRecord
  ): Promise<{ content: string; s3Location: S3Location | null }> {
    let s3Location: S3Location | null = null;

    // Check for direct content in various locations
    if (record.ses.content) {
      return { content: record.ses.content, s3Location: null };
    }

    if (record.ses.mail.content) {
      return { content: record.ses.mail.content, s3Location: null };
    }

    if (record.ses.receipt?.content) {
      return { content: record.ses.receipt.content, s3Location: null };
    }

    // Try S3 if action specifies bucket and key
    const action = record.ses.receipt?.action;
    if (action?.objectKey && action?.bucketName) {
      s3Location = { bucket: action.bucketName, key: action.objectKey };

      try {
        const content = await this.s3Service.getObject(s3Location.bucket, s3Location.key);
        if (content && content.length > 0) {
          logger.info('Retrieved email content from S3', {
            bucket: s3Location.bucket,
            key: s3Location.key,
            length: content.length,
          });
          return { content, s3Location };
        }
      } catch (error) {
        logger.error('Error retrieving email from S3', {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Try standard S3 path using message ID
    const messageId = record.ses.mail.messageId;
    if (messageId) {
      const standardKey = `emails/${messageId}`;
      s3Location = { bucket: this.defaultBucket, key: standardKey };

      try {
        const content = await this.s3Service.getObject(s3Location.bucket, s3Location.key);
        if (content && content.length > 0) {
          return { content, s3Location };
        }
      } catch {
        logger.debug('Email not found at standard S3 path');
      }
    }

    // Fallback: create minimal content from headers
    return {
      content: this.createMinimalContent(record),
      s3Location,
    };
  }

  /**
   * Parse email content (raw or processed)
   */
  private parseEmailContent(content: string): { text: string; html: string | null } {
    const result = { text: '', html: null as string | null };

    if (!content) return result;

    // Check if it's raw email format
    const isRawEmail =
      content.includes('From:') &&
      (content.includes('Content-Type:') || content.includes('MIME-Version:'));

    if (isRawEmail) {
      // Extract HTML content
      const htmlMatch = content.match(/<html[\s\S]*?<\/html>/i);
      if (htmlMatch) {
        result.html = htmlMatch[0];
      }

      // Extract text content
      const bodyStart = content.indexOf('\r\n\r\n');
      if (bodyStart > 0) {
        result.text = content.substring(bodyStart + 4);
        if (containsHtml(result.text)) {
          result.text = stripHtml(result.text);
        }
      }

      // Handle MIME multipart
      if (content.includes('Content-Type: multipart/')) {
        const mimeText = this.extractTextFromMIME(content);
        if (mimeText) {
          result.text = mimeText;
        }
      }
    } else {
      result.text = content;
      if (containsHtml(content)) {
        result.html = content;
      }
    }

    // Generate text from HTML if needed
    if (result.html && (!result.text || result.text.length < 10)) {
      result.text = stripHtml(result.html);
    }

    return result;
  }

  /**
   * Extract text content from MIME formatted email
   */
  private extractTextFromMIME(mimeContent: string): string {
    try {
      // Look for text/plain part
      const textPartMatch = mimeContent.match(
        /Content-Type: text\/plain[\s\S]*?(?=Content-Type:|--)/i
      );
      if (textPartMatch) {
        const text = this.extractMIMEPartContent(textPartMatch[0]);
        if (text) return text;
      }

      // Fall back to HTML part
      const htmlPartMatch = mimeContent.match(
        /Content-Type: text\/html[\s\S]*?(?=Content-Type:|--)/i
      );
      if (htmlPartMatch) {
        const html = this.extractMIMEPartContent(htmlPartMatch[0]);
        if (html) return stripHtml(html);
      }

      return '';
    } catch (error) {
      logger.error('Error extracting text from MIME', {
        error: error instanceof Error ? error.message : String(error),
      });
      return '';
    }
  }

  /**
   * Extract and decode content from a MIME part
   */
  private extractMIMEPartContent(partContent: string): string {
    const bodyStartIdx = partContent.indexOf('\r\n\r\n');
    if (bodyStartIdx === -1) return '';

    const headers = partContent.substring(0, bodyStartIdx).toLowerCase();
    let body = partContent.substring(bodyStartIdx + 4).trim();

    // Check for base64 encoding
    if (headers.includes('content-transfer-encoding: base64')) {
      try {
        // Remove line breaks and decode
        const cleaned = body.replace(/[\r\n\s]/g, '');
        body = Buffer.from(cleaned, 'base64').toString('utf-8');
      } catch (e) {
        logger.warn('Failed to decode base64 content', {
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }

    // Check for quoted-printable encoding
    if (headers.includes('content-transfer-encoding: quoted-printable')) {
      body = this.decodeQuotedPrintable(body);
    }

    return body;
  }

  /**
   * Decode quoted-printable encoded content
   */
  private decodeQuotedPrintable(text: string): string {
    return text
      .replace(/=\r?\n/g, '') // Remove soft line breaks
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }

  /**
   * Create minimal content from headers when full content unavailable
   */
  private createMinimalContent(record: SESRecord): string {
    const mail = record.ses.mail;
    let content = '';

    if (mail.commonHeaders?.subject) {
      content += `Subject: ${mail.commonHeaders.subject}\n\n`;
    }

    if (mail.source) {
      content += `From: ${mail.source}\n`;
    }

    const headers = mail.headers ?? [];
    ['Date', 'Message-ID'].forEach(headerName => {
      const header = headers.find(h => h.name === headerName);
      if (header) {
        content += `${header.name}: ${header.value}\n`;
      }
    });

    content += '\n[Note: Full message content could not be retrieved. Only headers are shown.]\n';

    return content;
  }

  /**
   * Extract headers from SES mail headers array
   */
  private extractHeaders(headers?: Array<{ name: string; value: string }>): Record<string, string> {
    if (!headers) return {};
    return headers.reduce(
      (acc, header) => {
        acc[header.name] = header.value;
        return acc;
      },
      {} as Record<string, string>
    );
  }

  /**
   * Check if input is an SES event
   */
  private isSESEvent(input: unknown): input is SESEvent {
    return (
      typeof input === 'object' &&
      input !== null &&
      'Records' in input &&
      Array.isArray((input as SESEvent).Records)
    );
  }

  /**
   * Convert various input types to string
   */
  private convertToString(input: unknown): string {
    if (typeof input === 'string') return input;
    if (Buffer.isBuffer(input)) return input.toString('utf8');
    if (typeof input === 'object') return JSON.stringify(input);
    return String(input);
  }

  /**
   * Extract relevant email data from message
   */
  extractEmailData(msg: EmailMessage): ExtractedEmailData {
    const emailData: ExtractedEmailData = {
      from_email: msg.from_email ?? '',
      subject: msg.subject ?? 'No Subject',
      text: msg.text ?? '',
      html: msg.html ?? '',
      headers: msg.headers ?? {},
      forwardedHeaders: {},
      attachments: msg.attachments ?? [],
      sender: msg.from_email ?? '',
      to: this.normalizeRecipients(msg.to),
      original_sender: msg.original_sender ?? '',
      originalForwarder: '',
      links: [],
    };

    emailData.originalForwarder = this.findOriginalForwarder(msg, emailData.headers);
    emailData.links = this.extractLinks(emailData.html || emailData.text);
    emailData.forwardedHeaders = this.extractForwardedHeaders(emailData.text);

    return emailData;
  }

  /**
   * Normalize recipient data to string
   */
  private normalizeRecipients(recipients: unknown): string {
    if (!recipients) return '';
    if (typeof recipients === 'string') return recipients;
    if (Array.isArray(recipients)) {
      return recipients
        .map(r => (typeof r === 'object' && r !== null ? (r as { email?: string }).email ?? '' : String(r)))
        .filter(Boolean)
        .join(', ');
    }
    return '';
  }

  /**
   * Find original forwarder from various sources
   */
  private findOriginalForwarder(
    msg: EmailMessage,
    headers: Record<string, string>
  ): string {
    // Check X-Forwarded-For header
    if (headers['X-Forwarded-For']) {
      return headers['X-Forwarded-For'];
    }

    // Parse from From header
    if (headers.From) {
      const email = extractEmailAddress(headers.From);
      if (email && this.isFromSafeDomain(email)) {
        return email;
      }
    }

    // Check to field
    if (typeof msg.to === 'string') {
      const email = extractEmailAddress(msg.to);
      if (email && this.isFromSafeDomain(email)) {
        return email;
      }
    }

    return '';
  }

  /**
   * Check if email is from a safe domain
   */
  private isFromSafeDomain(email: string): boolean {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return false;

    return this.safeDomains.some(
      safeDomain => domain === safeDomain || domain.endsWith('.' + safeDomain)
    );
  }

  /**
   * Extract links from content
   */
  private extractLinks(content: string): string[] {
    if (!content) return [];

    const links = new Set<string>();

    // Extract href URLs from HTML
    const hrefUrls = extractHrefUrls(content);
    hrefUrls.forEach(url => links.add(url));

    // Extract raw URLs
    const rawUrls = extractUrls(content);
    rawUrls.forEach(url => links.add(url));

    return Array.from(links);
  }

  /**
   * Extract essential headers for security analysis
   */
  extractEssentialHeaders(headers: Record<string, string>): Record<string, string> {
    const essential: Record<string, string> = {};

    for (const headerName of ESSENTIAL_HEADER_NAMES) {
      if (headers[headerName]) {
        essential[headerName] = headers[headerName];
      }
    }

    return essential;
  }

  /**
   * Extract original sender from headers
   */
  extractOriginalSender(headers: Record<string, string>): string | null {
    for (const header of ORIGINAL_SENDER_HEADERS) {
      if (headers[header]) {
        return headers[header];
      }
    }

    if (headers['Return-Path']) {
      const email = extractEmailAddress(headers['Return-Path']);
      if (email) return email;
    }

    return null;
  }

  /**
   * Extract headers from forwarded email content
   * Parses the embedded headers from "---------- Forwarded message ---------" sections
   */
  extractForwardedHeaders(emailText: string): Record<string, string> {
    const forwardedHeaders: Record<string, string> = {};

    if (!emailText) return forwardedHeaders;

    // Look for forwarded message markers
    const forwardedPatterns = [
      /---------- Forwarded message ---------\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n)/i,
      /-------- Original Message --------\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n)/i,
      /Begin forwarded message:\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n)/i,
      /From:.*\nSent:.*\nTo:.*\nSubject:/i, // Outlook style
    ];

    let headerBlock = '';

    for (const pattern of forwardedPatterns) {
      const match = emailText.match(pattern);
      if (match) {
        headerBlock = match[1] || match[0];
        break;
      }
    }

    if (!headerBlock) {
      // Try to extract inline headers at the start of forwarded content
      const inlineMatch = emailText.match(/^From:\s*(.+?)(?:\r?\n|$)/im);
      if (inlineMatch) {
        headerBlock = emailText.substring(0, 500); // Take first 500 chars
      }
    }

    if (!headerBlock) return forwardedHeaders;

    // Parse header lines
    const headerPatterns: Record<string, RegExp> = {
      'Original-From': /From:\s*(.+?)(?:\r?\n|$)/i,
      'Original-To': /To:\s*(.+?)(?:\r?\n|$)/i,
      'Original-Date': /Date:\s*(.+?)(?:\r?\n|$)/i,
      'Original-Subject': /Subject:\s*(.+?)(?:\r?\n|$)/i,
      'Original-Reply-To': /Reply-To:\s*(.+?)(?:\r?\n|$)/i,
      'Original-Sent': /Sent:\s*(.+?)(?:\r?\n|$)/i, // Outlook style
    };

    for (const [headerName, pattern] of Object.entries(headerPatterns)) {
      const match = headerBlock.match(pattern);
      if (match && match[1]) {
        // Clean up the value - remove HTML entities and extra whitespace
        let value = match[1].trim();
        value = value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        forwardedHeaders[headerName] = value;
      }
    }

    return forwardedHeaders;
  }
}

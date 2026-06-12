/**
 * Email Parser Service
 * Handles parsing of email messages from various sources
 */

import { simpleParser, ParsedMail, Attachment } from 'mailparser';
import { createHash } from 'crypto';
import { z } from 'zod';
import {
  EmailMessage,
  EmailAttachment,
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
import { buildLinkFacts, canonicalizeText, findAnchorMismatches } from '../../utils/canonicalize';

const logger = createLogger('email-parser');

/** Cap on attachment metadata entries carried per message */
const MAX_ATTACHMENTS = 20;

/**
 * Schema for events arriving from outside SES (API Gateway, tests).
 * Trust-bearing fields (authVerdicts, s3Location, s3Reference) are
 * deliberately absent — Zod strips unknown keys, so external callers
 * cannot inject them.
 */
const ExternalEmailMessageSchema = z.object({
  from_email: z.string().default(''),
  subject: z.string().default('No Subject'),
  text: z.string().default(''),
  html: z.string().nullable().default(null),
  headers: z.record(z.string(), z.string()).default({}),
  to: z.string().default(''),
  original_sender: z.string().optional(),
  messageId: z.string().optional(),
});

const ExternalEmailEventSchema = z.object({
  msg: ExternalEmailMessageSchema,
});

/**
 * Reduce a parsed attachment to safe metadata: name, type, size, and SHA-256.
 * Content is never carried forward, executed, or shown to the model.
 */
function toAttachmentMeta(attachment: Attachment): EmailAttachment {
  return {
    filename: attachment.filename ?? '(unnamed)',
    contentType: attachment.contentType,
    size: attachment.size,
    sha256: createHash('sha256').update(attachment.content).digest('hex'),
  };
}

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
const ORIGINAL_SENDER_HEADERS = ['X-Original-From', 'X-Sender', 'Original-From', 'X-Envelope-From'];

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
          return this.validateEventShapes(jsonBody);
        }

        if (jsonBody.Records && Array.isArray(jsonBody.Records)) {
          return await this.parseSESRecords(jsonBody.Records as SESRecord[]);
        }

        if (jsonBody.email_events) {
          const events = Array.isArray(jsonBody.email_events)
            ? jsonBody.email_events
            : JSON.parse(jsonBody.email_events as string);
          return Array.isArray(events) ? this.validateEventShapes(events) : [];
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
            return Array.isArray(events) ? this.validateEventShapes(events) : [];
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
   * Validate externally supplied event payloads against a schema instead of
   * blind-casting. Non-conforming entries are dropped with a warning rather
   * than crashing mid-pipeline.
   *
   * Only the allowed fields survive (Zod strips unknown keys): external
   * callers must not be able to supply trust-bearing fields like
   * `authVerdicts` (forged SPF/DKIM would defeat the email-command
   * authorization) or `s3Location` (would aim cleanup at arbitrary objects).
   * Those are only meaningful when derived from SES receipts.
   */
  private validateEventShapes(events: unknown[]): EmailEvent[] {
    const valid: EmailEvent[] = [];

    for (const event of events) {
      const result = ExternalEmailEventSchema.safeParse(event);
      if (result.success) {
        valid.push(result.data as EmailEvent);
      }
    }

    if (valid.length < events.length) {
      logger.warn('Dropped malformed email events from payload', {
        received: events.length,
        valid: valid.length,
      });
    }

    return valid;
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

          const forwarded = await this.parseRawEmail(content);

          const msg: EmailMessage = {
            from_email: record.ses.mail.source,
            subject: record.ses.mail.commonHeaders?.subject ?? 'No Subject',
            headers: this.extractHeaders(record.ses.mail.headers),
            text: forwarded.text || record.ses.mail.commonHeaders?.subject || 'No email content',
            html: forwarded.html,
            attachments: forwarded.attachments,
            to: record.ses.mail.destination?.join(', ') ?? '',
            original_sender: record.ses.mail.commonHeaders?.from?.[0] ?? '',
            messageId: record.ses.mail.messageId ?? '',
            sesMailTimestamp: record.ses.mail.timestamp ?? '',
            s3Reference: s3Location ? `s3://${s3Location.bucket}/${s3Location.key}` : null,
            s3Location: s3Location ?? undefined,
            authVerdicts: {
              spf: record.ses.receipt?.spfVerdict?.status,
              dkim: record.ses.receipt?.dkimVerdict?.status,
              dmarc: record.ses.receipt?.dmarcVerdict?.status,
            },
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

    // Fallback: create minimal content from headers. Report no S3 location —
    // every read above failed, and downstream uses the location for cleanup
    // and provenance, so a guessed-but-unread path would be misleading.
    return {
      content: this.createMinimalContent(record),
      s3Location: null,
    };
  }

  /**
   * Parse raw email content with a real MIME parser (mailparser). Handles
   * nested multiparts, all transfer encodings, charsets, and header folding —
   * the cases the previous regex-based parsing silently mangled.
   *
   * If the message carries a `message/rfc822` attachment ("forward as
   * attachment" — the one forwarding mode that preserves the original's full
   * headers), the inner message is parsed too and surfaced as a synthesized
   * forwarded block, so downstream forwarded-header extraction and analysis
   * see the original email rather than just the wrapper.
   */
  private async parseRawEmail(content: string): Promise<{
    text: string;
    html: string | null;
    attachments: EmailAttachment[];
  }> {
    const result: { text: string; html: string | null; attachments: EmailAttachment[] } = {
      text: '',
      html: null,
      attachments: [],
    };

    if (!content) return result;

    // Non-RFC822 payloads (plain pasted text, header-only fallbacks) skip the
    // MIME parser and are treated as a bare body
    const isRawEmail =
      content.includes('From:') &&
      (content.includes('Content-Type:') || content.includes('MIME-Version:'));

    if (!isRawEmail) {
      result.text = content;
      if (containsHtml(content)) {
        result.html = content;
      }
      return result;
    }

    let parsed: ParsedMail;
    try {
      parsed = await simpleParser(content);
    } catch (error) {
      logger.warn('MIME parsing failed — treating content as plain text', {
        error: error instanceof Error ? error.message : String(error),
      });
      result.text = content;
      return result;
    }

    result.text = parsed.text ?? '';
    result.html = typeof parsed.html === 'string' ? parsed.html : null;

    for (const attachment of parsed.attachments.slice(0, MAX_ATTACHMENTS)) {
      // Forward-as-attachment: parse the embedded original email
      if (attachment.contentType === 'message/rfc822') {
        const embedded = await this.parseEmbeddedMessage(attachment);
        if (embedded) {
          result.text = `${result.text.trim()}\n\n${embedded.forwardBlock}`.trim();
          if (!result.html && embedded.html) {
            result.html = embedded.html;
          }
          result.attachments.push(...embedded.attachments);
          continue;
        }
      }
      result.attachments.push(toAttachmentMeta(attachment));
    }

    if (parsed.attachments.length > MAX_ATTACHMENTS) {
      logger.warn('Attachment metadata truncated', {
        total: parsed.attachments.length,
        kept: MAX_ATTACHMENTS,
      });
    }

    // Generate text from HTML if needed
    if (result.html && (!result.text || result.text.length < 10)) {
      result.text = stripHtml(result.html);
    }

    return result;
  }

  /**
   * Parse a message/rfc822 attachment — the original email forwarded as an
   * attachment — into a synthesized forwarded block that downstream
   * forwarded-header extraction already understands, plus its attachments.
   */
  private async parseEmbeddedMessage(attachment: Attachment): Promise<{
    forwardBlock: string;
    html: string | null;
    attachments: EmailAttachment[];
  } | null> {
    try {
      const inner = await simpleParser(attachment.content);

      const headerLines: string[] = ['---------- Forwarded message ---------'];
      if (inner.from?.text) headerLines.push(`From: ${inner.from.text}`);
      if (inner.date) headerLines.push(`Date: ${inner.date.toUTCString()}`);
      if (inner.subject) headerLines.push(`Subject: ${inner.subject}`);
      const innerTo = Array.isArray(inner.to) ? inner.to[0] : inner.to;
      if (innerTo?.text) headerLines.push(`To: ${innerTo.text}`);
      const innerReplyTo = inner.replyTo;
      if (innerReplyTo?.text) headerLines.push(`Reply-To: ${innerReplyTo.text}`);
      const authResults = inner.headers.get('authentication-results');
      if (authResults) {
        headerLines.push(`Authentication-Results: ${String(authResults)}`);
      }

      const innerText = inner.text ?? (typeof inner.html === 'string' ? stripHtml(inner.html) : '');

      const innerAttachments = inner.attachments
        .slice(0, MAX_ATTACHMENTS)
        .map(a => toAttachmentMeta(a));

      logger.info('Parsed message/rfc822 attachment (forward-as-attachment)', {
        innerSubject: inner.subject?.substring(0, 50),
        innerAttachments: innerAttachments.length,
      });

      return {
        forwardBlock: `${headerLines.join('\n')}\n\n${innerText}`,
        html: typeof inner.html === 'string' ? inner.html : null,
        attachments: innerAttachments,
      };
    } catch (error) {
      logger.warn('Failed to parse message/rfc822 attachment', {
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
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
    emailData.forwardedHeaders = this.extractForwardedHeaders(emailData.text);

    // Canonicalize hostile content: links are unwrapped to their true
    // destinations (gateway wrappers removed), the body is normalized, and
    // every raw-vs-canonical divergence becomes a flag — obfuscation is
    // itself an indicator.
    const rawLinks = this.extractLinks(emailData.html || emailData.text);
    emailData.linkFacts = buildLinkFacts(rawLinks);
    emailData.links = emailData.linkFacts.map(f => f.canonical);

    const { canonical, flags } = canonicalizeText(emailData.text);
    emailData.canonicalText = canonical;
    emailData.contentFlags = [...flags, ...findAnchorMismatches(emailData.html)];

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
        .map(r =>
          typeof r === 'object' && r !== null ? ((r as { email?: string }).email ?? '') : String(r)
        )
        .filter(Boolean)
        .join(', ');
    }
    return '';
  }

  /**
   * Find original forwarder from various sources
   */
  private findOriginalForwarder(msg: EmailMessage, headers: Record<string, string>): string {
    // X-Forwarded-For is attacker-influenceable and often not an address at
    // all (proxies put IP chains here). The forwarder determines where the
    // analysis report is sent, so extract a real address and require a safe
    // domain — same bar as every other source below.
    if (headers['X-Forwarded-For']) {
      const email = extractEmailAddress(headers['X-Forwarded-For']);
      if (email && this.isFromSafeDomain(email)) {
        return email;
      }
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
      /---------- Forwarded message ---------\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n|$)/i,
      /-------- Original Message --------\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n|$)/i,
      /Begin forwarded message:\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n|$)/i,
      // Outlook style: no marker line — match through the end of the Subject
      // line so its value is part of the captured block
      /From:.*\r?\nSent:.*\r?\nTo:.*\r?\nSubject:.*/i,
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

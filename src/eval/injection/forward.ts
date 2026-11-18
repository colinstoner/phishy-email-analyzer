/**
 * Forward simulator for the injection eval.
 *
 * Phishy never sees the attacker's email directly: an employee forwards it.
 * This module plays the employee's mail client. It takes the original email
 * and produces the raw MIME message and the SES record Phishy would receive,
 * so the real parser does all the interpretation. It is test-harness code,
 * not a second implementation of anything in the pipeline.
 *
 * Styles:
 * - `inline`     Gmail-style marker block, the body pasted beneath it
 * - `outlook`    Outlook-style From/Sent/To/Subject block
 * - `attachment` forward-as-attachment (`message/rfc822`): the attacker's
 *                MIME reaches the parser byte for byte
 * - `unmarked`   a client whose forward header the parser does not recognize
 *                (a German-localized one), so the body carries no known marker
 */

import { simpleParser, AddressObject, ParsedMail } from 'mailparser';
import { SESRecord } from '../../types';
import { ForwardStyle } from './cases';

export interface ForwardOptions {
  caseId: string;
  style: ForwardStyle;
  note?: string;
  reporter: { name: string; address: string };
  /** The address Phishy receives reports at */
  phishyAddress?: string;
}

export interface ForwardedMessage {
  raw: string;
  subject: string;
  from: string;
  to: string;
  date: string;
  messageId: string;
}

const CRLF = '\r\n';
const DEFAULT_PHISHY_ADDRESS = 'phishy@example.com';
/** Used when the original carries no Date header, so output stays deterministic */
const FALLBACK_DATE = new Date('2026-11-09T09:14:00Z');
/** The employee forwards a few minutes after the email arrived */
const FORWARD_DELAY_MS = 7 * 60 * 1000;

function firstAddressText(value: AddressObject | AddressObject[] | undefined): string {
  const first = Array.isArray(value) ? value[0] : value;
  return first?.text ?? '';
}

function formatDate(date: Date, style: ForwardStyle): string {
  const part = (options: Intl.DateTimeFormatOptions): string =>
    new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', ...options }).format(date);
  const time = part({ hour: 'numeric', minute: '2-digit', hour12: true });
  if (style === 'outlook') {
    return `${part({ weekday: 'long' })}, ${part({ month: 'long' })} ${part({ day: 'numeric' })}, ${part({ year: 'numeric' })} ${time}`;
  }
  return `${part({ weekday: 'short' })}, ${part({ month: 'short' })} ${part({ day: 'numeric' })}, ${part({ year: 'numeric' })} at ${time}`;
}

/** The header block a mail client writes above forwarded content */
function forwardHeaderLines(
  style: ForwardStyle,
  fields: { from: string; to: string; subject: string; date: Date }
): string[] {
  const date = formatDate(fields.date, style);
  if (style === 'outlook') {
    return [
      '________________________________',
      `From: ${fields.from}`,
      `Sent: ${date}`,
      `To: ${fields.to}`,
      `Subject: ${fields.subject}`,
    ];
  }
  if (style === 'unmarked') {
    return [
      '-------- Weitergeleitete Nachricht --------',
      `Betreff: ${fields.subject}`,
      `Datum: ${date}`,
      `Von: ${fields.from}`,
      `An: ${fields.to}`,
    ];
  }
  return [
    '---------- Forwarded message ---------',
    `From: ${fields.from}`,
    `Date: ${date}`,
    `Subject: ${fields.subject}`,
    `To: ${fields.to}`,
  ];
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function singleLine(value: string): string {
  return value.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, ' ').trim();
}

function encodeHeaderText(value: string): string {
  const clean = singleLine(value);
  // eslint-disable-next-line no-control-regex
  return /^[\x00-\x7F]*$/.test(clean)
    ? clean
    : `=?UTF-8?B?${Buffer.from(clean, 'utf8').toString('base64')}?=`;
}

function base64Lines(content: Buffer): string {
  return (content.toString('base64').match(/.{1,76}/g) ?? []).join(CRLF);
}

function textPart(subtype: 'plain' | 'html', content: string): string {
  return [
    `Content-Type: text/${subtype}; charset=utf-8`,
    'Content-Transfer-Encoding: base64',
    '',
    base64Lines(Buffer.from(content, 'utf8')),
  ].join(CRLF);
}

function multipart(subtype: string, boundary: string, parts: string[]): string {
  return [
    `Content-Type: multipart/${subtype}; boundary="${boundary}"`,
    '',
    ...parts.map(part => `--${boundary}${CRLF}${part}`),
    `--${boundary}--`,
    '',
  ].join(CRLF);
}

/**
 * The text a mail client shows for an HTML body: what the employee sees and
 * what their client pastes into the forward. Comments are dropped; text
 * hidden with styling is kept, as it is in a real plain-text conversion.
 */
async function displayedText(original: ParsedMail): Promise<string> {
  if (typeof original.html !== 'string') {
    return original.text ?? '';
  }
  const rendered = await simpleParser(
    ['Content-Type: text/html; charset=utf-8', 'MIME-Version: 1.0', '', original.html].join(CRLF)
  );
  return rendered.text ?? original.text ?? '';
}

/**
 * Build the forward an employee's mail client would send to Phishy.
 */
export async function buildForward(
  originalRaw: string,
  options: ForwardOptions
): Promise<ForwardedMessage> {
  const original = await simpleParser(originalRaw);
  const originalSubject = singleLine(original.subject ?? '(no subject)');
  const reporter = `${options.reporter.name} <${options.reporter.address}>`;
  const originalDate = original.date ?? FALLBACK_DATE;
  const boundary = (name: string): string => `=_phishy_eval_${name}_${options.caseId}`;

  const subject = `${options.style === 'inline' ? 'Fwd' : options.style === 'unmarked' ? 'WG' : 'FW'}: ${originalSubject}`;
  const note = options.note?.trim() ?? '';

  let body: string;
  if (options.style === 'attachment') {
    body = multipart('mixed', boundary('mixed'), [
      textPart('plain', note),
      [
        'Content-Type: message/rfc822',
        'Content-Disposition: attachment; filename="original-message.eml"',
        '',
        originalRaw.replace(/\r?\n/g, CRLF),
      ].join(CRLF),
    ]);
  } else {
    const headerLines = forwardHeaderLines(options.style, {
      from: firstAddressText(original.from),
      to: firstAddressText(original.to) || reporter,
      subject: originalSubject,
      date: originalDate,
    });
    const text = `${note ? `${note}\n\n` : ''}${headerLines.join('\n')}\n\n\n${await displayedText(original)}\n`;

    let content = textPart('plain', text);
    if (typeof original.html === 'string') {
      const html = `<div dir="ltr">${note ? `${escapeHtml(note)}<br><br>` : ''}<div>${headerLines
        .map(escapeHtml)
        .join('<br>')}</div><br><br>${original.html}</div>`;
      content = multipart('alternative', boundary('alt'), [content, textPart('html', html)]);
    }

    // A forward carries the original's attachments along
    const attachments = original.attachments.map(attachment => {
      const filename = singleLine(attachment.filename ?? 'attachment').replace(/["\\]/g, '_');
      return [
        `Content-Type: ${attachment.contentType}`,
        `Content-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
        'Content-Transfer-Encoding: base64',
        '',
        base64Lines(attachment.content),
      ].join(CRLF);
    });
    body =
      attachments.length > 0
        ? multipart('mixed', boundary('mixed'), [content, ...attachments])
        : content;
  }

  const date = new Date(originalDate.getTime() + FORWARD_DELAY_MS).toUTCString();
  const to = options.phishyAddress ?? DEFAULT_PHISHY_ADDRESS;
  const messageId = `<injection-eval-${options.caseId}@example.com>`;
  const raw = [
    `From: ${reporter}`,
    `To: ${to}`,
    `Subject: ${encodeHeaderText(subject)}`,
    `Date: ${date}`,
    `Message-ID: ${messageId}`,
    'MIME-Version: 1.0',
    body,
  ].join(CRLF);

  return { raw, subject, from: reporter, to, date, messageId };
}

/**
 * The SES record for a forward: delivered inline (no S3 read), from the
 * reporter's own domain, with passing SPF/DKIM/DMARC on that hop.
 */
export function buildSesRecord(forward: ForwardedMessage, options: ForwardOptions): SESRecord {
  return {
    ses: {
      mail: {
        source: options.reporter.address,
        messageId: `injection-eval-${options.caseId}`,
        timestamp: new Date(forward.date).toISOString(),
        destination: [forward.to],
        headers: [
          { name: 'From', value: forward.from },
          { name: 'To', value: forward.to },
          { name: 'Subject', value: forward.subject },
          { name: 'Date', value: forward.date },
          { name: 'Message-ID', value: forward.messageId },
        ],
        commonHeaders: {
          from: [forward.from],
          subject: forward.subject,
          to: [forward.to],
        },
      },
      receipt: {
        action: { type: 'Lambda' },
        spfVerdict: { status: 'PASS' },
        dkimVerdict: { status: 'PASS' },
        dmarcVerdict: { status: 'PASS' },
      },
      content: forward.raw,
    },
  };
}

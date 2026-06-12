/**
 * Email Parser Service tests
 * Covers event payload parsing, SES record handling, MIME decoding,
 * forwarded-header extraction, and email data normalization.
 * All addresses/domains/names are invented (example.com style).
 */

import { EmailParserService } from '../../../../src/services/email/parser.service';
import type { S3Service } from '../../../../src/services/storage/s3.service';
import { EmailMessage, SESRecord } from '../../../../src/types';

type MockS3 = { getObject: jest.Mock };

function makeS3(impl?: (bucket: string, key: string) => Promise<string>): MockS3 {
  return {
    getObject: jest.fn(
      impl ??
        (async () => {
          throw new Error('S3 not available in test');
        })
    ),
  };
}

function makeParser(
  s3: MockS3 = makeS3(),
  safeDomains: string[] = ['example.com'],
  bucket = 'test-bucket'
): EmailParserService {
  return new EmailParserService(s3 as unknown as S3Service, safeDomains, bucket);
}

interface RecordOverrides {
  mail?: Record<string, unknown>;
  receipt?: Record<string, unknown>;
  content?: string;
}

function makeSESRecord(overrides: RecordOverrides = {}): SESRecord {
  const record = {
    ses: {
      mail: {
        source: 'sender@example.com',
        messageId: 'msg-001',
        timestamp: '2026-06-01T00:00:00.000Z',
        destination: ['reports@example.org'],
        headers: [
          { name: 'From', value: 'Sender <sender@example.com>' },
          { name: 'Date', value: 'Mon, 1 Jun 2026 09:00:00 -0500' },
          { name: 'Message-ID', value: '<msg-001@example.com>' },
        ],
        commonHeaders: {
          from: ['Sender <sender@example.com>'],
          subject: 'Test Subject',
        },
        ...overrides.mail,
      },
      receipt: overrides.receipt ?? { action: { type: 'Lambda' } },
      ...(overrides.content !== undefined ? { content: overrides.content } : {}),
    },
  };
  return record as unknown as SESRecord;
}

const CRLF = '\r\n';

describe('EmailParserService', () => {
  describe('parseEmailEvents', () => {
    it('should return empty array for null/undefined input', async () => {
      const parser = makeParser();
      expect(await parser.parseEmailEvents(null)).toEqual([]);
      expect(await parser.parseEmailEvents(undefined)).toEqual([]);
      expect(await parser.parseEmailEvents('')).toEqual([]);
    });

    it('should parse a direct SES event with inline content', async () => {
      const parser = makeParser();
      const record = makeSESRecord({ content: 'Plain text body for analysis' });

      const events = await parser.parseEmailEvents({ Records: [record] });

      expect(events).toHaveLength(1);
      expect(events[0].msg.from_email).toBe('sender@example.com');
      expect(events[0].msg.text).toBe('Plain text body for analysis');
    });

    it('should parse a JSON string containing an array of email events', async () => {
      const parser = makeParser();
      const events = [{ msg: { from_email: 'a@example.com', subject: 'Hi' } }];

      const result = await parser.parseEmailEvents(JSON.stringify(events));

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('a@example.com');
    });

    it('should drop malformed entries from external event arrays', async () => {
      const parser = makeParser();
      const payload = JSON.stringify([
        { msg: { from_email: 'good@example.com', subject: 'Valid' } },
        { msg: 'just a string, not an object' },
        { unrelated: true },
        'not even an object',
        null,
        42,
      ]);

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('good@example.com');
    });

    it('should drop malformed entries from email_events payloads', async () => {
      const parser = makeParser();
      const payload = JSON.stringify({
        email_events: [{ msg: { from_email: 'ok@example.org' } }, { msg: null }, 'bogus'],
      });

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('ok@example.org');
    });

    it('should strip trust-bearing fields from external payloads', async () => {
      const parser = makeParser();
      const payload = JSON.stringify([
        {
          msg: {
            from_email: 'attacker@example.com',
            subject: 'Re: Phishing Analysis: anything',
            text: 'false positive',
            // Forged trust fields an external caller must not control
            authVerdicts: { spf: 'PASS', dkim: 'PASS' },
            s3Location: { bucket: 'victim-bucket', key: 'important-object' },
            s3Reference: 's3://victim-bucket/important-object',
          },
        },
      ]);

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.authVerdicts).toBeUndefined();
      expect(result[0].msg.s3Location).toBeUndefined();
      expect(result[0].msg.s3Reference).toBeUndefined();
      expect(result[0].msg.from_email).toBe('attacker@example.com');
    });

    it('should parse a JSON string containing SES Records', async () => {
      const parser = makeParser();
      const payload = JSON.stringify({
        Records: [makeSESRecord({ content: 'Body via JSON string records' })],
      });

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.text).toBe('Body via JSON string records');
    });

    it('should parse a JSON body with an email_events array', async () => {
      const parser = makeParser();
      const payload = JSON.stringify({
        email_events: [{ msg: { from_email: 'b@example.org', subject: 'Test' } }],
      });

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('b@example.org');
    });

    it('should parse a JSON body with email_events as a JSON string', async () => {
      const parser = makeParser();
      const payload = JSON.stringify({
        email_events: JSON.stringify([{ msg: { from_email: 'c@example.net' } }]),
      });

      const result = await parser.parseEmailEvents(payload);

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('c@example.net');
    });

    it('should parse URL-encoded form data with email_events', async () => {
      const parser = makeParser();
      const events = [{ msg: { from_email: 'd@example.com', subject: 'Form post' } }];
      const body = 'email_events=' + encodeURIComponent(JSON.stringify(events));

      const result = await parser.parseEmailEvents(body);

      expect(result).toHaveLength(1);
      expect(result[0].msg.subject).toBe('Form post');
    });

    it('should accept Buffer input', async () => {
      const parser = makeParser();
      const events = [{ msg: { from_email: 'e@example.org' } }];

      const result = await parser.parseEmailEvents(Buffer.from(JSON.stringify(events), 'utf8'));

      expect(result).toHaveLength(1);
      expect(result[0].msg.from_email).toBe('e@example.org');
    });

    it('should return empty array for unparseable string payloads', async () => {
      const parser = makeParser();
      expect(await parser.parseEmailEvents('this is not json or form data')).toEqual([]);
    });

    it('should return empty array for JSON objects without recognized fields', async () => {
      const parser = makeParser();
      expect(await parser.parseEmailEvents({ some: 'object' })).toEqual([]);
    });

    it('should return empty array for malformed email_events form data', async () => {
      const parser = makeParser();
      expect(await parser.parseEmailEvents('email_events=not-valid-json')).toEqual([]);
    });

    it('should return empty array for primitive non-string input', async () => {
      const parser = makeParser();
      expect(await parser.parseEmailEvents(12345)).toEqual([]);
    });

    it('should return empty array when the payload cannot be serialized', async () => {
      const parser = makeParser();
      const circular: Record<string, unknown> = {};
      circular.self = circular;

      expect(await parser.parseEmailEvents(circular)).toEqual([]);
    });
  });

  describe('parseSESRecords', () => {
    it('should map SES mail fields onto the email message', async () => {
      const parser = makeParser();
      const record = makeSESRecord({ content: 'Hello from the test fixture content' });

      const events = await parser.parseSESRecords([record]);

      expect(events).toHaveLength(1);
      const msg = events[0].msg;
      expect(msg.from_email).toBe('sender@example.com');
      expect(msg.subject).toBe('Test Subject');
      expect(msg.to).toBe('reports@example.org');
      expect(msg.original_sender).toBe('Sender <sender@example.com>');
      expect(msg.messageId).toBe('msg-001');
      expect(msg.sesMailTimestamp).toBe('2026-06-01T00:00:00.000Z');
      expect(msg.headers).toEqual({
        From: 'Sender <sender@example.com>',
        Date: 'Mon, 1 Jun 2026 09:00:00 -0500',
        'Message-ID': '<msg-001@example.com>',
      });
      expect(msg.s3Reference).toBeNull();
    });

    it('should skip records without a ses.mail object', async () => {
      const parser = makeParser();
      const invalid = { ses: {} } as unknown as SESRecord;
      const valid = makeSESRecord({ content: 'Valid record content' });

      const events = await parser.parseSESRecords([invalid, valid]);

      expect(events).toHaveLength(1);
      expect(events[0].msg.text).toBe('Valid record content');
    });

    it('should default subject when commonHeaders are missing', async () => {
      const parser = makeParser();
      const record = makeSESRecord({
        mail: { commonHeaders: undefined },
        content: 'Content without common headers',
      });

      const events = await parser.parseSESRecords([record]);

      expect(events[0].msg.subject).toBe('No Subject');
      expect(events[0].msg.original_sender).toBe('');
    });

    it('should drop records that throw during processing', async () => {
      const parser = makeParser();
      // headers as a non-array object makes extractHeaders throw (no .reduce)
      const record = makeSESRecord({
        mail: { headers: { From: 'broken' } },
        content: 'Content for broken record',
      });

      const events = await parser.parseSESRecords([record]);

      expect(events).toEqual([]);
    });

    it('should prefer ses.content over other content sources', async () => {
      const s3 = makeS3();
      const parser = makeParser(s3);
      const record = makeSESRecord({ content: 'Direct ses content' });

      const events = await parser.parseSESRecords([record]);

      expect(events[0].msg.text).toBe('Direct ses content');
      expect(s3.getObject).not.toHaveBeenCalled();
    });

    it('should use ses.mail.content when ses.content is absent', async () => {
      const s3 = makeS3();
      const parser = makeParser(s3);
      const record = makeSESRecord({ mail: { content: 'Mail object content' } });

      const events = await parser.parseSESRecords([record]);

      expect(events[0].msg.text).toBe('Mail object content');
      expect(s3.getObject).not.toHaveBeenCalled();
    });

    it('should use receipt content when mail content is absent', async () => {
      const parser = makeParser();
      const record = makeSESRecord({
        receipt: { action: { type: 'Lambda' }, content: 'Receipt-level content' },
      });

      const events = await parser.parseSESRecords([record]);

      expect(events[0].msg.text).toBe('Receipt-level content');
    });

    it('should fetch content from S3 when the receipt action specifies a location', async () => {
      const s3 = makeS3(async () => 'Email body fetched from S3 storage');
      const parser = makeParser(s3);
      const record = makeSESRecord({
        receipt: { action: { type: 'S3', bucketName: 'mail-bucket', objectKey: 'emails/key-1' } },
      });

      const events = await parser.parseSESRecords([record]);

      expect(s3.getObject).toHaveBeenCalledWith('mail-bucket', 'emails/key-1');
      expect(events[0].msg.text).toBe('Email body fetched from S3 storage');
      expect(events[0].msg.s3Reference).toBe('s3://mail-bucket/emails/key-1');
      expect(events[0].msg.s3Location).toEqual({ bucket: 'mail-bucket', key: 'emails/key-1' });
    });

    it('should fall back to the standard S3 path when the action location fails', async () => {
      const s3 = makeS3(async (bucket: string) => {
        if (bucket === 'mail-bucket') throw new Error('access denied');
        return 'Content from standard path';
      });
      const parser = makeParser(s3, ['example.com'], 'default-bucket');
      const record = makeSESRecord({
        receipt: { action: { type: 'S3', bucketName: 'mail-bucket', objectKey: 'emails/key-2' } },
      });

      const events = await parser.parseSESRecords([record]);

      expect(s3.getObject).toHaveBeenCalledWith('mail-bucket', 'emails/key-2');
      expect(s3.getObject).toHaveBeenCalledWith('default-bucket', 'emails/msg-001');
      expect(events[0].msg.text).toBe('Content from standard path');
      expect(events[0].msg.s3Reference).toBe('s3://default-bucket/emails/msg-001');
    });

    it('should build minimal content from headers when no content can be retrieved', async () => {
      const s3 = makeS3();
      const parser = makeParser(s3, ['example.com'], 'default-bucket');
      const record = makeSESRecord();

      const events = await parser.parseSESRecords([record]);

      const msg = events[0].msg;
      expect(msg.text).toContain('Subject: Test Subject');
      expect(msg.text).toContain('From: sender@example.com');
      expect(msg.text).toContain('Date: Mon, 1 Jun 2026 09:00:00 -0500');
      expect(msg.text).toContain('Message-ID: <msg-001@example.com>');
      expect(msg.text).toContain('Full message content could not be retrieved');
      // No S3 reference is reported — every read failed, so a guessed path
      // would mislead cleanup and provenance
      expect(msg.s3Reference).toBeNull();
      expect(msg.s3Location).toBeUndefined();
    });

    it('should parse a message/rfc822 attachment (forward-as-attachment) into a forwarded block', async () => {
      const innerEmail = [
        'From: "Example Billing" <billing@examp1e-secure.test>',
        'To: victim@example.com',
        'Subject: Your account is suspended',
        'Reply-To: collect@example-evil.test',
        'Authentication-Results: spf=fail smtp.mailfrom=examp1e-secure.test',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Click https://examp1e-secure.test/verify within 24 hours.',
      ].join(CRLF);

      const outerEmail = [
        'From: employee@example.com',
        'To: phishy@example.com',
        'Subject: FW: found this in my inbox',
        'MIME-Version: 1.0',
        'Content-Type: multipart/mixed; boundary="outer-boundary"',
        '',
        '--outer-boundary',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'This looks fake to me, please check.',
        '--outer-boundary',
        'Content-Type: message/rfc822',
        '',
        innerEmail,
        '--outer-boundary--',
        '',
      ].join(CRLF);

      const parser = makeParser();
      const record = makeSESRecord({ content: outerEmail });

      const events = await parser.parseSESRecords([record]);
      const msg = events[0].msg;

      // The employee's note and the inner email both survive
      expect(msg.text).toContain('This looks fake to me');
      expect(msg.text).toContain('---------- Forwarded message ---------');
      expect(msg.text).toContain('Click https://examp1e-secure.test/verify');

      // The inner message's full headers are surfaced for analysis
      const forwarded = parser.extractForwardedHeaders(msg.text);
      expect(forwarded['Original-From']).toContain('billing@examp1e-secure.test');
      expect(forwarded['Original-Subject']).toBe('Your account is suspended');
      expect(forwarded['Original-Reply-To']).toContain('collect@example-evil.test');
    });

    it('should surface attachment metadata without carrying content', async () => {
      const pdfBytes = Buffer.from('%PDF-1.4 fake invoice payload');
      const rawEmail = [
        'From: sender@example-unknown.net',
        'To: victim@example.com',
        'Subject: Invoice attached',
        'MIME-Version: 1.0',
        'Content-Type: multipart/mixed; boundary="b1"',
        '',
        '--b1',
        'Content-Type: text/plain',
        '',
        'Please see the attached invoice.',
        '--b1',
        'Content-Type: application/pdf; name="invoice.pdf"',
        'Content-Disposition: attachment; filename="invoice.pdf"',
        'Content-Transfer-Encoding: base64',
        '',
        pdfBytes.toString('base64'),
        '--b1--',
        '',
      ].join(CRLF);

      const parser = makeParser();
      const record = makeSESRecord({ content: rawEmail });

      const events = await parser.parseSESRecords([record]);
      const attachments = events[0].msg.attachments ?? [];

      expect(attachments).toHaveLength(1);
      expect(attachments[0].filename).toBe('invoice.pdf');
      expect(attachments[0].contentType).toBe('application/pdf');
      expect(attachments[0].size).toBe(pdfBytes.length);
      expect(attachments[0].sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(attachments[0].content).toBeUndefined();
    });

    it('should still process records with very short content', async () => {
      const parser = makeParser();
      const record = makeSESRecord({ content: 'short' });

      const events = await parser.parseSESRecords([record]);

      expect(events).toHaveLength(1);
      expect(events[0].msg.text).toBe('short');
    });

    it('should ignore empty S3 content and keep falling back', async () => {
      const s3 = makeS3(async () => '');
      const parser = makeParser(s3);
      const record = makeSESRecord({
        receipt: { action: { type: 'S3', bucketName: 'mail-bucket', objectKey: 'emails/key-3' } },
      });

      const events = await parser.parseSESRecords([record]);

      expect(events[0].msg.text).toContain('Full message content could not be retrieved');
    });
  });

  describe('MIME and raw email content parsing', () => {
    it('should extract the body of a simple raw email', async () => {
      const parser = makeParser();
      const raw = [
        'From: alerts@example-notices.com',
        'To: user@example.com',
        'Subject: Hello',
        'MIME-Version: 1.0',
        '',
        'This is the plain message body.',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('This is the plain message body.');
      expect(events[0].msg.html).toBeNull();
    });

    it('should extract the text/plain part from a multipart email', async () => {
      const parser = makeParser();
      const raw = [
        'From: sender@example.com',
        'To: user@example.org',
        'Subject: Multipart test',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="XYZBOUNDARY"',
        '',
        '--XYZBOUNDARY',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Hello plain part from Example Team',
        '--XYZBOUNDARY',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><p>Hello HTML part</p></body></html>',
        '--XYZBOUNDARY--',
        '',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Hello plain part from Example Team');
      expect(events[0].msg.html).toBe('<html><body><p>Hello HTML part</p></body></html>');
    });

    it('should decode base64-encoded text parts', async () => {
      const parser = makeParser();
      const encoded = Buffer.from('Click here to verify your account', 'utf-8').toString('base64');
      const raw = [
        'From: alerts@example-notices.com',
        'To: user@example.com',
        'Subject: Action required',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="XYZBOUNDARY"',
        '',
        '--XYZBOUNDARY',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: base64',
        '',
        encoded,
        '--XYZBOUNDARY--',
        '',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Click here to verify your account');
    });

    it('should decode quoted-printable text parts including soft line breaks', async () => {
      const parser = makeParser();
      const raw = [
        'From: sender@example.com',
        'To: user@example.org',
        'Subject: QP test',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="XYZBOUNDARY"',
        '',
        '--XYZBOUNDARY',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        'Verify=20your=20account=',
        'now=2C please',
        '--XYZBOUNDARY--',
        '',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Verify your accountnow, please');
    });

    it('should fall back to a stripped HTML part when no text/plain part exists', async () => {
      const parser = makeParser();
      const raw = [
        'From: support@example-portal.net',
        'To: user@example.com',
        'Subject: HTML only',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="XYZBOUNDARY"',
        '',
        '--XYZBOUNDARY',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<html><body><p>Please review the notice from Example Support.</p></body></html>',
        '--XYZBOUNDARY--',
        '',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Please review the notice from Example Support.');
      expect(events[0].msg.html).toContain('<html>');
    });

    it('should strip tags from an HTML body in a non-multipart raw email', async () => {
      const parser = makeParser();
      const raw = [
        'From: news@example.org',
        'Content-Type: text/html',
        '',
        '<html><body><p>Hello from Example Corp newsletter</p></body></html>',
      ].join(CRLF);

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Hello from Example Corp newsletter');
      expect(events[0].msg.html).toBe(
        '<html><body><p>Hello from Example Corp newsletter</p></body></html>'
      );
    });

    it('should derive text from HTML when the raw email uses LF-only separators', async () => {
      const parser = makeParser();
      // No CRLF blank line, so the body index lookup fails and text is
      // generated from the extracted <html> block instead.
      const raw =
        'From: a@example.com\nContent-Type: text/html\n\n' +
        '<html><body>Welcome to Example Portal</body></html>';

      const events = await parser.parseSESRecords([makeSESRecord({ content: raw })]);

      expect(events[0].msg.text).toBe('Welcome to Example Portal');
    });

    it('should treat non-raw HTML content as both text and html', async () => {
      const parser = makeParser();
      const content = '<div>Click <a href="https://portal.example.org/login">here</a></div>';

      const events = await parser.parseSESRecords([makeSESRecord({ content })]);

      expect(events[0].msg.text).toBe(content);
      expect(events[0].msg.html).toBe(content);
    });
  });

  describe('extractEmailData', () => {
    function makeMessage(overrides: Partial<EmailMessage> = {}): EmailMessage {
      return {
        from_email: 'forwarder@example.com',
        subject: 'FYI: suspicious message',
        text: 'Please check this message.',
        html: null,
        headers: { From: 'Forwarder <forwarder@example.com>' },
        to: 'security@example.com',
        original_sender: 'odd-sender@example-unknown.net',
        ...overrides,
      };
    }

    it('should map message fields with defaults', () => {
      const parser = makeParser();
      const data = parser.extractEmailData(makeMessage());

      expect(data.from_email).toBe('forwarder@example.com');
      expect(data.sender).toBe('forwarder@example.com');
      expect(data.subject).toBe('FYI: suspicious message');
      expect(data.text).toBe('Please check this message.');
      expect(data.html).toBe('');
      expect(data.to).toBe('security@example.com');
      expect(data.original_sender).toBe('odd-sender@example-unknown.net');
      expect(data.attachments).toEqual([]);
    });

    it('should apply fallbacks for missing fields', () => {
      const parser = makeParser();
      const msg = {
        from_email: undefined,
        subject: undefined,
        text: undefined,
        html: undefined,
        headers: undefined,
        to: undefined,
      } as unknown as EmailMessage;

      const data = parser.extractEmailData(msg);

      expect(data.from_email).toBe('');
      expect(data.subject).toBe('No Subject');
      expect(data.text).toBe('');
      expect(data.headers).toEqual({});
      expect(data.to).toBe('');
      expect(data.links).toEqual([]);
    });

    it('should normalize recipient arrays of objects and strings', () => {
      const parser = makeParser();
      const msg = makeMessage({
        to: [{ email: 'one@example.com' }, 'two@example.org', { email: '' }] as unknown as string,
      });

      const data = parser.extractEmailData(msg);

      expect(data.to).toBe('one@example.com, two@example.org');
    });

    it('should return empty string for non-string non-array recipients', () => {
      const parser = makeParser();
      const msg = makeMessage({ to: { email: 'x@example.com' } as unknown as string });

      expect(parser.extractEmailData(msg).to).toBe('');
    });

    it('should extract links from HTML hrefs and raw URLs', () => {
      const parser = makeParser();
      const msg = makeMessage({
        html:
          '<html><body><a href="https://portal.example.org/verify">Click here to verify your account</a>' +
          ' Also see https://files.example.net/doc.pdf</body></html>',
      });

      const data = parser.extractEmailData(msg);

      expect(data.links).toContain('https://portal.example.org/verify');
      expect(data.links).toContain('https://files.example.net/doc.pdf');
      expect(data.links).toHaveLength(2);
    });

    it('should extract links from text when no HTML is present', () => {
      const parser = makeParser();
      const msg = makeMessage({ text: 'Go to https://login.example-verify.com/account now' });

      const data = parser.extractEmailData(msg);

      expect(data.links).toEqual(['https://login.example-verify.com/account']);
    });

    it('should use the X-Forwarded-For header as the original forwarder', () => {
      const parser = makeParser();
      const msg = makeMessage({
        headers: { 'X-Forwarded-For': 'employee@example.com' },
      });

      expect(parser.extractEmailData(msg).originalForwarder).toBe('employee@example.com');
    });

    it('should ignore X-Forwarded-For values that are not safe-domain addresses', () => {
      const parser = makeParser(makeS3(), ['example.com']);

      // Proxy-style IP chain — not an address at all
      const ipChain = makeMessage({
        headers: { 'X-Forwarded-For': '203.0.113.5, 198.51.100.7' },
        to: 'someone@outside.test',
      });
      expect(parser.extractEmailData(ipChain).originalForwarder).toBe('');

      // Attacker-supplied outside address must not receive the report
      const outside = makeMessage({
        headers: { 'X-Forwarded-For': 'attacker@evil.test' },
        to: 'someone@outside.test',
      });
      expect(parser.extractEmailData(outside).originalForwarder).toBe('');
    });

    it('should fall through to the From header when X-Forwarded-For is unusable', () => {
      const parser = makeParser(makeS3(), ['example.com']);
      const msg = makeMessage({
        headers: {
          'X-Forwarded-For': '203.0.113.5',
          From: 'Employee <employee@example.com>',
        },
      });

      expect(parser.extractEmailData(msg).originalForwarder).toBe('employee@example.com');
    });

    it('should use the From header when it belongs to a safe domain', () => {
      const parser = makeParser(makeS3(), ['example.com']);
      const msg = makeMessage({
        headers: { From: 'Employee Name <Employee@Example.com>' },
      });

      expect(parser.extractEmailData(msg).originalForwarder).toBe('employee@example.com');
    });

    it('should fall back to the to field for safe subdomain matches', () => {
      const parser = makeParser(makeS3(), ['example.com']);
      const msg = makeMessage({
        headers: { From: 'Stranger <stranger@example-other.net>' },
        to: 'analyst@mail.example.com',
      });

      expect(parser.extractEmailData(msg).originalForwarder).toBe('analyst@mail.example.com');
    });

    it('should return empty forwarder when no safe domain matches', () => {
      const parser = makeParser(makeS3(), ['example.com']);
      const msg = makeMessage({
        headers: { From: 'Stranger <stranger@example-other.net>' },
        to: 'someone@example-elsewhere.org',
      });

      expect(parser.extractEmailData(msg).originalForwarder).toBe('');
    });
  });

  describe('extractEssentialHeaders', () => {
    it('should keep only security-relevant headers', () => {
      const parser = makeParser();
      const headers = {
        From: 'Sender <sender@example.com>',
        'Return-Path': '<bounce@example.com>',
        'Reply-To': 'reply@example.com',
        'X-Originating-IP': '[192.0.2.10]',
        'Message-ID': '<abc@example.com>',
        'X-Mailer': 'ExampleMailer 1.0',
        Received: 'from mx.example.net',
        Subject: 'Hello',
      };

      const essential = parser.extractEssentialHeaders(headers);

      expect(essential).toEqual({
        From: 'Sender <sender@example.com>',
        'Return-Path': '<bounce@example.com>',
        'Reply-To': 'reply@example.com',
        'X-Originating-IP': '[192.0.2.10]',
        'Message-ID': '<abc@example.com>',
      });
    });

    it('should return empty object when no essential headers exist', () => {
      const parser = makeParser();
      expect(parser.extractEssentialHeaders({ 'X-Custom': 'value' })).toEqual({});
    });
  });

  describe('extractOriginalSender', () => {
    it('should prefer X-Original-From over other headers', () => {
      const parser = makeParser();
      const headers = {
        'X-Original-From': 'original@example.net',
        'X-Sender': 'other@example.org',
        'Return-Path': '<bounce@example.com>',
      };

      expect(parser.extractOriginalSender(headers)).toBe('original@example.net');
    });

    it('should use X-Sender when X-Original-From is absent', () => {
      const parser = makeParser();
      expect(parser.extractOriginalSender({ 'X-Sender': 'other@example.org' })).toBe(
        'other@example.org'
      );
    });

    it('should extract the address from Return-Path as a fallback', () => {
      const parser = makeParser();
      expect(parser.extractOriginalSender({ 'Return-Path': '<Bounce@Example.com>' })).toBe(
        'bounce@example.com'
      );
    });

    it('should return null when nothing matches', () => {
      const parser = makeParser();
      expect(parser.extractOriginalSender({})).toBeNull();
      expect(parser.extractOriginalSender({ 'Return-Path': 'not-an-email' })).toBeNull();
    });
  });

  describe('extractForwardedHeaders', () => {
    it('should return empty object for empty text', () => {
      const parser = makeParser();
      expect(parser.extractForwardedHeaders('')).toEqual({});
    });

    it('should parse a Gmail-style forwarded block with HTML entities', () => {
      const parser = makeParser();
      const text = [
        'FYI, see below.',
        '',
        '---------- Forwarded message ---------',
        'From: Alice Example &lt;alice@example.org&gt;',
        'Date: Mon, 1 Jun 2026 09:00:00 -0500',
        'Subject: Please verify your account',
        'To: Bob Example <bob@example.com>',
        '',
        'Click here to verify your account.',
      ].join('\n');

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-From']).toBe('Alice Example <alice@example.org>');
      expect(headers['Original-Date']).toBe('Mon, 1 Jun 2026 09:00:00 -0500');
      expect(headers['Original-Subject']).toBe('Please verify your account');
      expect(headers['Original-To']).toBe('Bob Example <bob@example.com>');
    });

    it('should parse an "Original Message" style block', () => {
      const parser = makeParser();
      const text = [
        '-------- Original Message --------',
        'Subject: Invoice 12345',
        'Date: Tue, 2 Jun 2026 10:30:00 +0000',
        'From: billing@example-billing.net',
        'To: user@example.com',
        '',
        'Your invoice is attached.',
      ].join('\n');

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-Subject']).toBe('Invoice 12345');
      expect(headers['Original-From']).toBe('billing@example-billing.net');
      expect(headers['Original-To']).toBe('user@example.com');
    });

    it('should parse an Apple-style "Begin forwarded message" block', () => {
      const parser = makeParser();
      const text = [
        'Begin forwarded message:',
        'From: Carol Example <carol@example.net>',
        'Subject: Updated payment details',
        'Date: Wed, 3 Jun 2026 14:00:00 +0100',
        'To: dave@example.com',
        '',
        'Please update the payment details.',
      ].join('\n');

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-From']).toBe('Carol Example <carol@example.net>');
      expect(headers['Original-Subject']).toBe('Updated payment details');
    });

    it('should parse Outlook-style From/Sent/To headers', () => {
      const parser = makeParser();
      const text = [
        'From: Alice Example <alice@example.org>',
        'Sent: Monday, June 1, 2026 9:00 AM',
        'To: bob@example.com',
        'Subject: Quarterly report',
        '',
        'See the report attached.',
      ].join('\n');

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-From']).toBe('Alice Example <alice@example.org>');
      expect(headers['Original-Sent']).toBe('Monday, June 1, 2026 9:00 AM');
      expect(headers['Original-To']).toBe('bob@example.com');
      expect(headers['Original-Subject']).toBe('Quarterly report');
    });

    it('should capture the Outlook subject with CRLF line endings', () => {
      const parser = makeParser();
      const text =
        'From: Alice Example <alice@example.org>\r\n' +
        'Sent: Monday, June 1, 2026 9:00 AM\r\n' +
        'To: bob@example.com\r\n' +
        'Subject: Re: Wire transfer approval\r\n\r\n' +
        'Please approve today.';

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-Subject']).toBe('Re: Wire transfer approval');
    });

    it('should fall back to inline From header at the start of text', () => {
      const parser = makeParser();
      const text = 'From: eve@example.org\nThanks for checking this message out.';

      const headers = parser.extractForwardedHeaders(text);

      expect(headers['Original-From']).toBe('eve@example.org');
    });

    it('should return empty object when no forwarded markers or From lines exist', () => {
      const parser = makeParser();
      const text = 'Just a normal message body with no forwarding markers.';

      expect(parser.extractForwardedHeaders(text)).toEqual({});
    });
  });
});

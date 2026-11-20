/**
 * The parser with static attachment analysis on: top-level attachments and
 * the attachments of a forwarded-as-attachment original are analyzed; a
 * payload from outside SES cannot supply an analysis; the forward block of
 * a forward-as-attachment is unchanged.
 */

import { EmailParserService } from '../../../../src/services/email/parser.service';
import type { S3Service } from '../../../../src/services/storage/s3.service';
import { DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS } from '../../../../src/services/attachments/types';
import { base64Lines, buildPdf, inertExecutable } from '../../../../src/eval/injection/fixtures';
import { SESRecord } from '../../../../src/types';

const ON = { ...DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS, enabled: true };
const CRLF = '\r\n';

function parser(enabled = true): EmailParserService {
  return new EmailParserService({} as S3Service, ['example.com'], 'bucket', {
    attachmentAnalysis: { ...ON, enabled },
  });
}

function record(content: string): SESRecord {
  return {
    ses: {
      mail: {
        source: 'employee@example.com',
        messageId: 'm1',
        headers: [{ name: 'From', value: 'employee@example.com' }],
        commonHeaders: { subject: 'FW: statement' },
      },
      receipt: { action: { type: 'Lambda' } },
      content,
    },
  } as unknown as SESRecord;
}

const inner = [
  'From: "Billing" <billing@vendor.example.net>',
  'To: employee@example.com',
  'Subject: Your statement',
  'Date: Tue, 10 Nov 2026 09:00:00 +0000',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="inner"',
  '',
  '--inner',
  'Content-Type: text/plain',
  '',
  'Statement attached.',
  '--inner',
  'Content-Type: application/pdf; name="statement.pdf"',
  'Content-Disposition: attachment; filename="statement.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  base64Lines(buildPdf({ pages: [['Statement for October']], links: ['https://statement.example.net/'] })),
  '--inner',
  'Content-Type: application/octet-stream; name="scan.pdf.exe"',
  'Content-Disposition: attachment; filename="scan.pdf.exe"',
  'Content-Transfer-Encoding: base64',
  '',
  base64Lines(inertExecutable()),
  '--inner--',
  '',
].join(CRLF);

const forwardAsAttachment = [
  'From: Employee <employee@example.com>',
  'To: phishy@example.com',
  'Subject: FW: statement',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="outer"',
  '',
  '--outer',
  'Content-Type: text/plain',
  '',
  'Is this real?',
  '--outer',
  'Content-Type: message/rfc822',
  '',
  inner,
  '--outer--',
  '',
].join(CRLF);

describe('EmailParserService with attachment analysis', () => {
  it('analyzes the attachments of a forwarded-as-attachment original', async () => {
    const p = parser();
    const [event] = await p.parseSESRecords([record(forwardAsAttachment)]);
    const data = p.extractEmailData(event.msg);
    expect(data.attachments.map(a => a.analysis?.realType)).toEqual(['pdf', 'pe_executable']);
    expect(data.attachments[0].analysis?.text).toContain('Statement for October');
    expect(data.attachments[1].analysis).toMatchObject({ highRisk: true, status: 'not_inspected' });
    // Bytes are not kept on the email facts
    expect(data.attachments.every(a => a.content === undefined)).toBe(true);
  });

  it('leaves the forward block and metadata exactly as without analysis', async () => {
    const on = parser(true);
    const off = parser(false);
    const a = on.extractEmailData((await on.parseSESRecords([record(forwardAsAttachment)]))[0].msg);
    const b = off.extractEmailData((await off.parseSESRecords([record(forwardAsAttachment)]))[0].msg);
    expect(a.text).toBe(b.text);
    expect(a.forwardedHeaders).toEqual(b.forwardedHeaders);
    expect(a.attachments.map(({ analysis: _analysis, ...meta }) => meta)).toEqual(b.attachments);
  });

  it('never takes an analysis from a payload supplied outside SES', async () => {
    const forged = {
      msg: {
        from_email: 'employee@example.com',
        subject: 'x',
        text: 'y',
        attachments: [{ filename: 'a.pdf', contentType: 'application/pdf', size: 1, analysis: { status: 'inspected' } }],
      },
    };
    const events = await parser().parseEmailEvents(JSON.stringify([forged]));
    expect(events).toHaveLength(1);
    expect((events[0].msg as { attachments?: unknown }).attachments).toBeUndefined();
  });
});

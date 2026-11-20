/**
 * Invariant 1 with attachment analysis on: nothing extracted from an
 * attachment (text, names, entry names, links, hosts, an attached email's
 * subject) reaches a log line at info level or above. Drives the real
 * handler (Bedrock provider, parser, attachment analysis, notifier; AWS
 * clients mocked) and checks every line written. All content is invented.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { mockClient } from 'aws-sdk-client-mock';
import { Context, SESEvent } from 'aws-lambda';
import {
  base64Lines,
  buildDocx,
  buildPdf,
  buildZip,
} from '../../../src/eval/injection/fixtures';

jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn().mockResolvedValue({
    ai: {
      provider: 'bedrock',
      bedrock: { region: 'us-east-1', modelId: 'test-model', maxTokens: 4096, timeout: 60000 },
      refusalFallbackModel: '',
    },
    email: { safeDomains: ['example.com'], safeSenders: [], deleteAfterProcessing: false },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: ['security@example.com'],
      safeSenderSecurity: [],
    },
    storage: { s3Bucket: 'test-bucket', s3Prefix: 'emails', region: 'us-east-1' },
    attachments: {
      analysis: {
        enabled: true,
        timeBudgetMs: 10000,
        maxAttachmentBytes: 26214400,
        maxUncompressedBytes: 67108864,
        maxArchiveEntries: 200,
        maxDepth: 3,
        maxTextPerAttachment: 8000,
        maxTextTotal: 24000,
      },
    },
    logLevel: 'debug',
  }),
}));

jest.mock('../../../src/services/storage/s3.service', () => ({
  S3Service: jest.fn().mockImplementation(() => ({
    getObject: jest.fn().mockRejectedValue(new Error('S3 not available in test')),
    deleteObject: jest.fn(),
  })),
}));

const HTML_TOKEN = 'Pelican-Turnstile-5521';
const PDF_TOKEN = 'Walrus-Abacus-7730';
const DOCX_TOKEN = 'Heron-Cascade-1148';
const ENTRY_NAME = 'Lobster-Quarry-3092.txt';
const FORM_HOST = 'gannet-harbor-6617.test';
const PDF_HOST = 'puffin-signal-2284.test';
const INNER_SUBJECT = 'Narwhal-Bellows-9035';
const SECRETS = [HTML_TOKEN, PDF_TOKEN, DOCX_TOKEN, ENTRY_NAME, FORM_HOST, PDF_HOST, INNER_SUBJECT];

const CRLF = '\r\n';
const VERDICT = JSON.stringify({
  summary: 'Credential phish.',
  verdict: 'phishing',
  riskScore: 90,
  verdictConfidence: 0.9,
  threatVectors: ['credential_harvest'],
  targeting: 'mass',
  indicators: ['Credential form attachment'],
  recommendations: ['Delete the email'],
});

const bedrockMock = mockClient(BedrockRuntimeClient);
const sesMock = mockClient(SESClient);
let lines: Array<{ level: string; raw: string }> = [];
const spies: jest.SpyInstance[] = [];

function capture(...args: unknown[]): void {
  const raw = args.map(String).join(' ');
  let level = 'unparsed';
  try {
    level = (JSON.parse(raw) as { level?: string }).level ?? 'unparsed';
  } catch {
    // Not a logger line; still checked
  }
  lines.push({ level, raw });
}

function part(name: string, type: string, data: Buffer): string[] {
  return [
    '--outer',
    `Content-Type: ${type}; name="${name}"`,
    `Content-Disposition: attachment; filename="${name}"`,
    'Content-Transfer-Encoding: base64',
    '',
    base64Lines(data),
  ];
}

function event(): SESEvent {
  const innerEmail = Buffer.from(
    `From: a@vendor.example.net${CRLF}To: b@example.com${CRLF}Subject: ${INNER_SUBJECT}${CRLF}${CRLF}inner body${CRLF}`
  );
  const raw = [
    'From: Employee <employee@example.com>',
    'To: phishy@example.com',
    'Subject: Fwd: statement',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Is this real?',
    ...part(
      'view.html',
      'text/html',
      Buffer.from(
        `<html><p>${HTML_TOKEN}</p><form action="https://${FORM_HOST}/p"><input type="password"></form></html>`
      )
    ),
    ...part(
      'statement.pdf',
      'application/pdf',
      buildPdf({ pages: [[PDF_TOKEN]], links: [`https://${PDF_HOST}/pay`], javascript: true })
    ),
    ...part('letter.docx', 'application/octet-stream', buildDocx({ paragraphs: [DOCX_TOKEN], macro: true })),
    ...part('files.zip', 'application/zip', buildZip([{ name: ENTRY_NAME, data: 'x' }])),
    ...part('note.dat', 'application/octet-stream', innerEmail),
    '--outer--',
    '',
  ].join(CRLF);

  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            source: 'employee@example.com',
            messageId: 'ses-attachment-logging',
            timestamp: '2026-11-10T14:02:11.000Z',
            destination: ['phishy@example.com'],
            headers: [{ name: 'From', value: 'Employee <employee@example.com>' }],
            commonHeaders: { from: ['Employee <employee@example.com>'], subject: 'Fwd: statement' },
          },
          receipt: {
            action: { type: 'Lambda' },
            spfVerdict: { status: 'PASS' },
            dkimVerdict: { status: 'PASS' },
          },
          content: raw,
        },
      },
    ],
  } as unknown as SESEvent;
}

describe('attachment content never logged at info or above', () => {
  let handler: (typeof import('../../../src/handlers/lambda.handler'))['handler'];

  beforeAll(async () => {
    process.env.LOG_LEVEL = 'debug';
    ({ handler } = await import('../../../src/handlers/lambda.handler'));
  });

  afterAll(() => {
    process.env.LOG_LEVEL = 'error';
  });

  beforeEach(() => {
    lines = [];
    bedrockMock.reset();
    sesMock.reset();
    sesMock.on(SendEmailCommand).resolves({ MessageId: 'out-1', $metadata: {} });
    for (const method of ['log', 'info', 'warn', 'error'] as const) {
      spies.push(jest.spyOn(console, method).mockImplementation(capture));
    }
  });

  afterEach(() => {
    while (spies.length) spies.pop()?.mockRestore();
  });

  it('analyzes the attachments, sends them to the model fenced, and logs none of their content', async () => {
    bedrockMock.on(InvokeModelCommand).resolves({
      body: new TextEncoder().encode(
        JSON.stringify({
          content: [{ type: 'text', text: VERDICT }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 100, output_tokens: 50 },
        })
      ) as never,
    });

    const result = await handler(event(), {} as Context);
    expect(result.statusCode).toBe(200);

    // The model saw the extracted content (inside the attachment fence)
    const call = bedrockMock.commandCalls(InvokeModelCommand)[0];
    const rawBody = call.args[0].input.body;
    const body = JSON.parse(
      typeof rawBody === 'string' ? rawBody : new TextDecoder().decode(rawBody as Uint8Array)
    ) as {
      messages: Array<{ content: string }>;
    };
    const prompt = body.messages[0].content;
    for (const token of [HTML_TOKEN, PDF_TOKEN, DOCX_TOKEN, ENTRY_NAME, INNER_SUBJECT]) {
      expect(prompt).toContain(token);
    }
    expect(prompt).toMatch(/<attachment-content-[0-9a-f]{12}>/);

    // The analysis step logged counts only
    const visible = lines.filter(l => l.level !== 'debug').map(l => l.raw);
    expect(visible.some(l => l.includes('Attachment analysis complete'))).toBe(true);
    for (const secret of SECRETS) {
      for (const line of visible) expect(line).not.toContain(secret);
    }
  });
});

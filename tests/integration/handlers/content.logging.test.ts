/**
 * Invariant 1: the suspicious email's content never reaches a log line at
 * info level or above. Drives the real handler (Bedrock provider, parser,
 * notifier; AWS clients mocked) and the Anthropic provider (HTTP mocked)
 * with a distinctive subject, body token and link, and checks every log
 * line they write. All addresses and content are invented.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { mockClient } from 'aws-sdk-client-mock';
import axios from 'axios';
import { Context, SESEvent } from 'aws-lambda';
import { ExtractedEmailData } from '../../../src/types';

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
    logLevel: 'debug',
  }),
}));

jest.mock('../../../src/services/storage/s3.service', () => ({
  S3Service: jest.fn().mockImplementation(() => ({
    getObject: jest.fn().mockRejectedValue(new Error('S3 not available in test')),
    deleteObject: jest.fn(),
  })),
}));

const SUBJECT = 'Quokka-Lantern-4417 payroll hold';
const BODY_TOKEN = 'Marmalade-Vortex-2290';
const LINK_HOST = 'otter-sprocket-8812.test';
const FILENAME = 'Halibut-Ledger-6604.pdf';
const SECRETS = [SUBJECT, BODY_TOKEN, LINK_HOST, FILENAME];

const CRLF = '\r\n';
const VERDICT = JSON.stringify({
  summary: 'Credential phish.',
  verdict: 'phishing',
  riskScore: 90,
  verdictConfidence: 0.9,
  threatVectors: ['credential_harvest'],
  targeting: 'mass',
  indicators: ['Lookalike link'],
  recommendations: ['Delete the email'],
});

const bedrockMock = mockClient(BedrockRuntimeClient);
const sesMock = mockClient(SESClient);

interface LogLine {
  level: string;
  raw: string;
}
let lines: LogLine[] = [];
const spies: jest.SpyInstance[] = [];

function capture(...args: unknown[]): void {
  const raw = args.map(String).join(' ');
  let level = 'unparsed';
  try {
    level = (JSON.parse(raw) as { level?: string }).level ?? 'unparsed';
  } catch {
    // Not a logger line; still checked below
  }
  lines.push({ level, raw });
}

/** Lines at info or above (anything not a debug line, including stray console output) */
function infoOrAbove(): string[] {
  return lines.filter(line => line.level !== 'debug').map(line => line.raw);
}

function expectNoContent(): void {
  const visible = infoOrAbove();
  expect(visible.length).toBeGreaterThan(0);
  for (const secret of SECRETS) {
    for (const line of visible) {
      expect(line).not.toContain(secret);
    }
  }
}

let sequence = 0;
function event(style: 'inline' | 'attachment'): SESEvent {
  sequence += 1;
  const inner = [
    'From: "Payroll" <payroll@lookalike-payroll.test>',
    'To: employee@example.com',
    `Subject: ${SUBJECT}`,
    'Content-Type: multipart/mixed; boundary="inner-boundary"',
    '',
    '--inner-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    `Your pay is on hold (${BODY_TOKEN}). Confirm at https://${LINK_HOST}/confirm today.`,
    '--inner-boundary',
    `Content-Type: application/pdf; name="${FILENAME}"`,
    `Content-Disposition: attachment; filename="${FILENAME}"`,
    'Content-Transfer-Encoding: base64',
    '',
    'cGxhY2Vob2xkZXI=',
    '--inner-boundary--',
  ].join(CRLF);

  const raw =
    style === 'attachment'
      ? [
          'From: Employee <employee@example.com>',
          'To: phishy@example.com',
          `Subject: FW: ${SUBJECT}`,
          'MIME-Version: 1.0',
          'Content-Type: multipart/mixed; boundary="outer-boundary"',
          '',
          '--outer-boundary',
          'Content-Type: text/plain; charset=utf-8',
          '',
          'Is this real?',
          '--outer-boundary',
          'Content-Type: message/rfc822',
          '',
          inner,
          '--outer-boundary--',
          '',
        ].join(CRLF)
      : [
          'From: Employee <employee@example.com>',
          'To: phishy@example.com',
          `Subject: Fwd: ${SUBJECT}`,
          'MIME-Version: 1.0',
          'Content-Type: text/plain; charset=utf-8',
          '',
          'Is this real?',
          '',
          '---------- Forwarded message ---------',
          'From: Payroll <payroll@lookalike-payroll.test>',
          'Date: Mon, 1 Jun 2026 at 14:02',
          `Subject: ${SUBJECT}`,
          'To: <employee@example.com>',
          '',
          `Your pay is on hold (${BODY_TOKEN}). Confirm at https://${LINK_HOST}/confirm today.`,
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
            messageId: `ses-content-${sequence}`,
            timestamp: '2026-06-01T14:02:11.000Z',
            destination: ['phishy@example.com'],
            headers: [{ name: 'From', value: 'Employee <employee@example.com>' }],
            commonHeaders: {
              from: ['Employee <employee@example.com>'],
              subject: `Fwd: ${SUBJECT}`,
            },
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

function bedrockReply(text: string): { body: never } {
  return {
    body: new TextEncoder().encode(
      JSON.stringify({
        content: [{ type: 'text', text }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 100, output_tokens: 50 },
      })
    ) as never,
  };
}

describe('content never logged at info or above', () => {
  let handler: (typeof import('../../../src/handlers/lambda.handler'))['handler'];
  let AnthropicProvider: (typeof import('../../../src/services/ai/anthropic.provider'))['AnthropicProvider'];

  beforeAll(async () => {
    // Module loggers take their level at import; debug lets the test see everything
    process.env.LOG_LEVEL = 'debug';
    ({ handler } = await import('../../../src/handlers/lambda.handler'));
    ({ AnthropicProvider } = await import('../../../src/services/ai/anthropic.provider'));
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

  it('handles an inline forward without logging its content', async () => {
    bedrockMock.on(InvokeModelCommand).resolves(bedrockReply(VERDICT));

    const result = await handler(event('inline'), {} as Context);

    expect(result.statusCode).toBe(200);
    expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
    expect(sesMock.commandCalls(SendEmailCommand)).toHaveLength(1);
    expectNoContent();
    // The facts that replaced the subject are there
    expect(infoOrAbove().some(line => line.includes('"subject":{"length":'))).toBe(true);
  });

  it('handles a forward-as-attachment with a failed analysis without logging its content', async () => {
    // No verdict object: the analysis fails and the error path logs
    bedrockMock.on(InvokeModelCommand).resolves(bedrockReply('I cannot decide.'));

    await handler(event('attachment'), {} as Context);

    expect(lines.some(line => line.raw.includes('Analysis could not be completed'))).toBe(true);
    expect(lines.some(line => line.raw.includes('innerSubject'))).toBe(true);
    expectNoContent();
  });

  it('runs the Anthropic provider without logging the subject', async () => {
    jest.spyOn(axios, 'post').mockResolvedValue({
      data: {
        content: [{ type: 'text', text: `${VERDICT}\nNote: ${BODY_TOKEN} was ignored.` }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 100, output_tokens: 50 },
      },
    });
    const email: ExtractedEmailData = {
      from_email: 'employee@example.com',
      subject: SUBJECT,
      text: `Your pay is on hold (${BODY_TOKEN}). https://${LINK_HOST}/confirm`,
      html: '',
      headers: {},
      forwardedHeaders: {},
      attachments: [],
      sender: 'employee@example.com',
      to: 'phishy@example.com',
      original_sender: 'payroll@lookalike-payroll.test',
      originalForwarder: 'employee@example.com',
      links: [`https://${LINK_HOST}/confirm`],
    };

    const provider = new AnthropicProvider({ apiKey: 'test-key' }, headers => headers);
    const result = await provider.analyzeEmail(email);

    expect(result.assessment?.verdict).toBe('phishing');
    expect(lines.some(line => line.raw.includes('Starting email analysis with Anthropic'))).toBe(
      true
    );
    expectNoContent();
  });
});

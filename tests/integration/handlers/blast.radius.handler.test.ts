/**
 * Blast radius in the handler: when the lookup runs, who gets its result.
 *
 * - Outlook Report-button phishing report: one email, to the security team
 *   only, carrying the section. The reporter is never emailed.
 * - Ordinary forward: the reporter's copy first, then the lookup, then the
 *   security team's own copy.
 * - Anything not malicious: no lookup.
 *
 * The lookup itself is mocked (no Graph, no network). All addresses,
 * identifiers and content are invented.
 */

const mockAnalyzeEmail = jest.fn();
const mockSendAnalysisReport = jest.fn();
const mockLookup = jest.fn();

jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn().mockResolvedValue({
    ai: {
      provider: 'bedrock',
      bedrock: { region: 'us-east-1', modelId: 'test-model', maxTokens: 4096, timeout: 60000 },
    },
    email: {
      safeDomains: ['example.com'],
      safeSenders: [],
      deleteAfterProcessing: false,
    },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: ['security@example.com', 'soc-lead@example.com'],
      safeSenderSecurity: [],
    },
    storage: { s3Bucket: 'test-bucket', s3Prefix: 'emails', region: 'us-east-1' },
    reportButton: { enabled: true },
    graph: {
      enabled: true,
      tenantId: '00000000-0000-0000-0000-000000000000',
      read: { clientId: '11111111-1111-1111-1111-111111111111', certificate: 'unused' },
      blastRadius: { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 },
    },
    logLevel: 'error',
  }),
}));

jest.mock('../../../src/services/ai/analysis.service', () => ({
  AnalysisService: jest.fn().mockImplementation(() => ({
    analyzeEmail: mockAnalyzeEmail,
    setProfile: jest.fn(),
  })),
}));

jest.mock('../../../src/services/ai/bedrock.provider', () => ({
  BedrockProvider: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('../../../src/services/notification/ses.notifier', () => ({
  SESNotifier: jest.fn().mockImplementation(() => ({
    sendAnalysisReport: mockSendAnalysisReport,
  })),
}));

jest.mock('../../../src/services/storage/s3.service', () => ({
  S3Service: jest.fn().mockImplementation(() => ({
    getObject: jest.fn().mockRejectedValue(new Error('S3 not available in test')),
    deleteObject: jest.fn(),
  })),
}));

jest.mock('../../../src/services/graph/blast-radius.service', () => ({
  createBlastRadiusService: jest.fn(() => ({ lookup: mockLookup })),
}));

import { handler } from '../../../src/handlers/lambda.handler';
import { Context, SESEvent } from 'aws-lambda';

const CRLF = '\r\n';
const NMID = '11111111-2222-4333-8444-555555555555';
const context = {} as Context;
const SECTION = {
  status: 'complete',
  route: 'trace',
  totals: { recipients: 2, read: 1, replied: 0, forwarded: 0 },
  lookedUpAt: '2026-11-17T12:00:00.000Z',
};

let sequence = 0;

function sesEvent(subject: string, raw: string): SESEvent {
  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            source: 'employee@example.com',
            messageId: `ses-blast-${sequence}`,
            timestamp: '2026-06-01T14:02:11.000Z',
            destination: ['phishy@example.com'],
            headers: [{ name: 'From', value: 'Employee <employee@example.com>' }],
            commonHeaders: { from: ['Employee <employee@example.com>'], subject },
          },
          receipt: { action: { type: 'Lambda' } },
          content: raw,
        },
      },
    ],
  } as unknown as SESEvent;
}

/** An SES event shaped like an Outlook Report-button phishing submission */
function reportEvent(): SESEvent {
  sequence += 1;
  const subject = `Phishing:${NMID}|billing@examp1e-secure.test|(Your account is suspended) 06/01/2026 14:02:${String(sequence).padStart(2, '0')}`;
  const inner = [
    'From: "Example Billing" <billing@examp1e-secure.test>',
    'To: employee@example.com',
    'Subject: Your account is suspended',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Click https://examp1e-secure.test/verify within 24 hours.',
  ].join(CRLF);
  const raw = [
    'From: Employee <employee@example.com>',
    'To: phishy@example.com',
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="report-boundary"',
    '',
    '--report-boundary',
    'Content-Type: text/plain; charset=utf-8',
    '',
    '# Questionable URLs detected in message:',
    'None',
    '--report-boundary',
    'Content-Type: message/rfc822',
    '',
    inner,
    '--report-boundary--',
    '',
  ].join(CRLF);
  return sesEvent(subject, raw);
}

/** An ordinary forward of the same email */
function forwardEvent(): SESEvent {
  sequence += 1;
  const subject = `FW: Your account is suspended (${sequence})`;
  const raw = [
    'From: Employee <employee@example.com>',
    'To: phishy@example.com',
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Is this real?',
    '',
    '---------- Forwarded message ---------',
    'From: Example Billing <billing@examp1e-secure.test>',
    'Date: Mon, 1 Jun 2026 13:00:00 +0000',
    'Subject: Your account is suspended',
    'To: employee@example.com',
    '',
    'Click https://examp1e-secure.test/verify within 24 hours.',
    '',
  ].join(CRLF);
  return sesEvent(subject, raw);
}

function verdict(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    summary: 'Credential phishing impersonating a billing notice.',
    isPhishing: true,
    confidence: 'High',
    indicators: ['Lookalike sender domain'],
    recommendations: ['Do not click'],
    provider: 'bedrock',
    model: 'test-model',
    ...overrides,
  };
}

describe('blast radius in the handler', () => {
  let events: string[];

  beforeEach(() => {
    events = [];
    mockAnalyzeEmail.mockReset();
    mockSendAnalysisReport.mockReset();
    mockLookup.mockReset();
    mockSendAnalysisReport.mockImplementation((to: string) => {
      events.push(`send:${to}`);
      return Promise.resolve({ success: true, messageId: `out-${events.length}` });
    });
    mockLookup.mockImplementation(() => {
      events.push('lookup');
      return Promise.resolve(SECTION);
    });
  });

  describe('Outlook Report-button phishing report', () => {
    it('sends one email, to the security team only, carrying the section', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict());

      await handler(reportEvent(), context);

      // The lookup runs before the single email; there is no second email
      expect(events).toEqual(['lookup', 'send:security@example.com']);
      const [recipient, , , cc, options] = mockSendAnalysisReport.mock.calls[0];
      expect(cc).toEqual(['soc-lead@example.com']);
      expect([recipient, ...cc]).not.toContain('employee@example.com');
      expect(options.silentReport).toEqual({ reporter: 'employee@example.com' });
      expect(options.blastRadius).toBe(SECTION);

      // Keyed on the reported email, which the model never authored into a query
      const [emailData] = mockLookup.mock.calls[0];
      expect(emailData.forwardedHeaders['Original-From']).toContain('billing@examp1e-secure.test');
      expect(emailData.subject).toBe('Your account is suspended');
    });

    it('still sends the email, with the note, when the lookup has no result', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict());
      const failed = {
        status: 'unavailable',
        note: 'Blast radius lookup could not be completed: it ran out of time before any result.',
        lookedUpAt: '2026-11-17T12:00:00.000Z',
      };
      mockLookup.mockResolvedValueOnce(failed);

      await handler(reportEvent(), context);

      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [recipient, , , , options] = mockSendAnalysisReport.mock.calls[0];
      expect(recipient).toBe('security@example.com');
      expect(options.blastRadius).toBe(failed);
      expect(options.silentReport).toEqual({ reporter: 'employee@example.com' });
    });

    it('still sends the email, with a note, if the lookup throws', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict());
      mockLookup.mockRejectedValueOnce(new Error('unexpected'));

      await handler(reportEvent(), context);

      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [recipient, , , cc, options] = mockSendAnalysisReport.mock.calls[0];
      expect([recipient, ...cc]).toEqual(['security@example.com', 'soc-lead@example.com']);
      expect(options.blastRadius).toMatchObject({
        status: 'unavailable',
        note: 'Blast radius lookup could not be completed.',
      });
    });

    it('does not look up, or email anyone, when the report turns out benign', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict({ isPhishing: false, indicators: [] }));

      await handler(reportEvent(), context);

      expect(mockLookup).not.toHaveBeenCalled();
      expect(mockSendAnalysisReport).not.toHaveBeenCalled();
    });

    it('does not look up when the analysis failed, but still tells the security team', async () => {
      mockAnalyzeEmail.mockResolvedValue(
        verdict({ isPhishing: false, analysisFailed: true, failureReason: 'provider unreachable' })
      );

      await handler(reportEvent(), context);

      expect(mockLookup).not.toHaveBeenCalled();
      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      expect(mockSendAnalysisReport.mock.calls[0][4]).not.toHaveProperty('blastRadius');
    });
  });

  describe('ordinary forward', () => {
    it('tells the reporter first, then looks up, then sends the security copy', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict());

      await handler(forwardEvent(), context);

      expect(events).toEqual(['send:employee@example.com', 'lookup', 'send:security@example.com']);
      const [reporterCall, securityCall] = mockSendAnalysisReport.mock.calls;
      expect(reporterCall[3]).toEqual([]);
      expect(reporterCall[4]).not.toHaveProperty('blastRadius');
      expect(securityCall[3]).toEqual(['soc-lead@example.com']);
      expect(securityCall[4].blastRadius).toBe(SECTION);
      expect(mockLookup.mock.calls[0][1]).toMatchObject({
        reporterAddress: 'employee@example.com',
      });
    });

    it('sends the one combined email, with no lookup, for a benign verdict', async () => {
      mockAnalyzeEmail.mockResolvedValue(verdict({ isPhishing: false, indicators: [] }));

      await handler(forwardEvent(), context);

      expect(mockLookup).not.toHaveBeenCalled();
      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [recipient, , , cc, options] = mockSendAnalysisReport.mock.calls[0];
      expect(recipient).toBe('employee@example.com');
      // undefined Cc: the notifier's default security-team distribution, as on main
      expect(cc).toBeUndefined();
      expect(options).not.toHaveProperty('blastRadius');
    });
  });
});

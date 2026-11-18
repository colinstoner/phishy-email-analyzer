/**
 * Sender-relationship check in the handler: when the lookup runs, and which
 * copy of the report carries how much of its result.
 *
 * - Runs before analysis on a campaign-cache miss, for forwards and for
 *   Outlook Report-button phishing submissions; never for safelist users.
 * - Combined email (reporter + security team in Cc): counts, no IPs.
 * - Split emails (blast radius on, malicious verdict): the reporter's copy
 *   has no detail; the security team's own copy has all of it, IPs included.
 * - Silent Report-button report: one security-team email, full detail.
 *
 * The lookups are mocked (no Graph, no network); the report templates are
 * real. All addresses, identifiers and content are invented.
 */

const mockAnalyzeEmail = jest.fn();
const mockSendAnalysisReport = jest.fn();
const mockBlastLookup = jest.fn();
const mockSenderLookup = jest.fn();

jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn().mockResolvedValue({
    ai: {
      provider: 'bedrock',
      bedrock: { region: 'us-east-1', modelId: 'test-model', maxTokens: 4096, timeout: 60000 },
    },
    email: {
      safeDomains: ['example.com'],
      safeSenders: ['outsider@partner.example.org'],
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
      senderHistory: {
        enabled: true,
        lookbackDays: 30,
        burstWindowHours: 24,
        budgetMs: 8000,
        fanoutMinRecipients: 10,
        fanoutMultiplier: 3,
      },
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
  createBlastRadiusService: jest.fn(() => ({ lookup: mockBlastLookup })),
}));

jest.mock('../../../src/services/graph/sender.history', () => ({
  createSenderHistoryService: jest.fn(() => ({ lookupForEmail: mockSenderLookup })),
}));

import { handler } from '../../../src/handlers/lambda.handler';
import { buildEmailHtml, buildPlainTextReport } from '../../../src/templates/report.html';
import { SenderHistoryFacts } from '../../../src/types';
import { Context, SESEvent } from 'aws-lambda';

const CRLF = '\r\n';
const NMID = '11111111-2222-4333-8444-555555555555';
const context = {} as Context;
const BURST_IP = '198.51.100.7';
const FAN_OUT_SENTENCE = 'far more people than usual';

const exact = (count: number): { count: number; atLeast: boolean } => ({ count, atLeast: false });

const FACTS: SenderHistoryFacts = {
  classification: 'established_with_anomalous_fanout',
  lookbackDays: 30,
  burstWindowHours: 24,
  history: { messages: exact(12), recipients: exact(3), firstSeen: '2026-05-04' },
  twoWay: { messages: exact(5), internalSenders: exact(2) },
  burst: { messages: exact(41), recipients: exact(40), newRecipients: exact(38) },
  sendingIps: {
    burst: 1,
    seenInHistory: 0,
    historyComplete: true,
    burstIps: [{ ip: BURST_IP, seenInHistory: false }],
  },
  truncated: false,
};

const BLAST_SECTION = {
  status: 'complete',
  route: 'trace',
  totals: { recipients: 2, read: 1, replied: 0, forwarded: 0 },
  lookedUpAt: '2026-11-17T12:00:00.000Z',
};

let sequence = 0;

function sesEvent(subject: string, raw: string, source = 'employee@example.com'): SESEvent {
  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            source,
            messageId: `ses-sender-history-${sequence}`,
            timestamp: '2026-06-01T14:02:11.000Z',
            destination: ['phishy@example.com'],
            headers: [{ name: 'From', value: `Reporter <${source}>` }],
            commonHeaders: { from: [`Reporter <${source}>`], subject },
          },
          receipt: { action: { type: 'Lambda' } },
          content: raw,
        },
      },
    ],
  } as unknown as SESEvent;
}

/** An ordinary forward of an RFQ from a known supplier's address */
function forwardEvent(source = 'employee@example.com'): SESEvent {
  sequence += 1;
  const subject = `FW: RFQ 1001 (${sequence})`;
  const raw = [
    `From: Reporter <${source}>`,
    'To: phishy@example.com',
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Is this real?',
    '',
    '---------- Forwarded message ---------',
    'From: Pat Doe <pat@supplier.example.net>',
    'Date: Mon, 1 Jun 2026 13:00:00 +0000',
    'Subject: RFQ 1001',
    'To: employee@example.com',
    '',
    'Please review the RFQ at https://files.example.org/rfq-1001.',
    '',
  ].join(CRLF);
  return sesEvent(subject, raw, source);
}

/** The same email submitted with the Outlook Report button */
function reportEvent(): SESEvent {
  sequence += 1;
  const subject = `Phishing:${NMID}|pat@supplier.example.net|(RFQ 1001) 06/01/2026 14:02:${String(sequence).padStart(2, '0')}`;
  const inner = [
    'From: "Pat Doe" <pat@supplier.example.net>',
    'To: employee@example.com',
    'Subject: RFQ 1001',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Please review the RFQ at https://files.example.org/rfq-1001.',
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

function verdict(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    summary: 'Credential phishing behind a shared-file lure.',
    isPhishing: true,
    confidence: 'High',
    indicators: ['Unexpected file-share link'],
    recommendations: ['Do not click'],
    provider: 'bedrock',
    model: 'test-model',
    ...overrides,
  };
}

/** Render one sent email with the real templates, exactly as the notifier would */
function rendered(call: unknown[]): string {
  type TemplateArgs = Parameters<typeof buildEmailHtml>;
  const analysis = call[1] as TemplateArgs[0];
  const emailData = call[2] as TemplateArgs[1];
  const options = call[4] as TemplateArgs[2];
  return `${buildEmailHtml(analysis, emailData, options)}\n${buildPlainTextReport(analysis, emailData, options)}`;
}

describe('sender-relationship check in the handler', () => {
  let events: string[];

  beforeEach(() => {
    events = [];
    mockAnalyzeEmail.mockReset();
    mockSendAnalysisReport.mockReset();
    mockBlastLookup.mockReset();
    mockSenderLookup.mockReset();
    mockSenderLookup.mockImplementation(() => {
      events.push('sender-history');
      return Promise.resolve(FACTS);
    });
    mockAnalyzeEmail.mockImplementation(() => {
      events.push('analyze');
      return Promise.resolve(verdict());
    });
    mockBlastLookup.mockImplementation(() => {
      events.push('blast-radius');
      return Promise.resolve(BLAST_SECTION);
    });
    mockSendAnalysisReport.mockImplementation((to: string) => {
      events.push(`send:${to}`);
      return Promise.resolve({ success: true, messageId: `out-${events.length}` });
    });
  });

  describe('gating', () => {
    it('runs before analysis and hands the facts to the model input', async () => {
      await handler(forwardEvent(), context);

      expect(events.slice(0, 2)).toEqual(['sender-history', 'analyze']);
      expect(mockSenderLookup).toHaveBeenCalledTimes(1);
      const [lookedUp] = mockSenderLookup.mock.calls[0];
      expect(lookedUp.forwardedHeaders['Original-From']).toContain('pat@supplier.example.net');
      expect(mockAnalyzeEmail.mock.calls[0][0].senderHistory).toBe(FACTS);
    });

    it('runs for an Outlook Report-button phishing submission too', async () => {
      await handler(reportEvent(), context);

      expect(events.slice(0, 2)).toEqual(['sender-history', 'analyze']);
      const [lookedUp] = mockSenderLookup.mock.calls[0];
      expect(lookedUp.forwardedHeaders['Original-From']).toContain('pat@supplier.example.net');
      expect(mockAnalyzeEmail.mock.calls[0][0].senderHistory).toBe(FACTS);
    });

    it('never runs for a safelist user', async () => {
      await handler(forwardEvent('outsider@partner.example.org'), context);

      expect(mockSenderLookup).not.toHaveBeenCalled();
      expect(mockAnalyzeEmail).toHaveBeenCalledTimes(1);
      expect(mockAnalyzeEmail.mock.calls[0][0].senderHistory).toBeUndefined();
    });

    it('changes nothing when the lookup has no facts', async () => {
      mockSenderLookup.mockResolvedValueOnce(undefined);
      mockAnalyzeEmail.mockResolvedValueOnce(verdict({ isPhishing: false, indicators: [] }));

      await handler(forwardEvent(), context);

      expect(mockAnalyzeEmail.mock.calls[0][0].senderHistory).toBeUndefined();
      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [call] = mockSendAnalysisReport.mock.calls;
      expect(call[4].risk.verdict).toBe('legitimate');
      expect(rendered(call)).not.toContain('Sender Relationship');
    });
  });

  describe('which email shows what', () => {
    it('combined email: raised to suspicious, counts in the IT-review part, no IPs', async () => {
      // The model saw nothing wrong; the fan-out alone lifts it
      mockAnalyzeEmail.mockResolvedValueOnce(verdict({ isPhishing: false, indicators: [] }));

      await handler(forwardEvent(), context);

      expect(mockBlastLookup).not.toHaveBeenCalled();
      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [call] = mockSendAnalysisReport.mock.calls;
      expect(call[0]).toBe('employee@example.com');
      expect(call[3]).toBeUndefined(); // the notifier's default: security team in Cc
      expect(call[4]).not.toHaveProperty('audience');
      expect(call[4].risk).toMatchObject({ verdict: 'suspicious', riskScore: 35 });

      const body = rendered(call);
      expect(body).toContain('Sender Relationship (organization mail-flow records)');
      expect(body).toContain('established_with_anomalous_fanout');
      expect(body).toContain(FAN_OUT_SENTENCE);
      expect(body).not.toContain(BURST_IP);
    });

    it('split emails: nothing for the reporter, everything for the security team', async () => {
      await handler(forwardEvent(), context);

      expect(events).toEqual([
        'sender-history',
        'analyze',
        'send:employee@example.com',
        'blast-radius',
        'send:security@example.com',
      ]);
      const [reporterCall, securityCall] = mockSendAnalysisReport.mock.calls;

      expect(reporterCall[3]).toEqual([]);
      expect(reporterCall[4].audience).toBe('reporter');
      const reporterBody = rendered(reporterCall);
      expect(reporterBody).not.toContain('Sender Relationship');
      expect(reporterBody).not.toContain(BURST_IP);
      expect(reporterBody).not.toContain('established');
      expect(reporterBody).toContain(FAN_OUT_SENTENCE);

      expect(securityCall[3]).toEqual(['soc-lead@example.com']);
      expect(securityCall[4].audience).toBe('security');
      const securityBody = rendered(securityCall);
      expect(securityBody).toContain('security team only');
      expect(securityBody).toContain('established_with_anomalous_fanout');
      expect(securityBody).toContain(`${BURST_IP} (not seen in the history period)`);
    });

    it('silent Report-button report: one security-team email with the full detail', async () => {
      await handler(reportEvent(), context);

      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [call] = mockSendAnalysisReport.mock.calls;
      expect([call[0], ...call[3]]).toEqual(['security@example.com', 'soc-lead@example.com']);
      expect(call[4].silentReport).toEqual({ reporter: 'employee@example.com' });
      expect(call[4].audience).toBe('security');

      const body = rendered(call);
      expect(body).toContain(
        'Sender Relationship (organization mail-flow records; security team only)'
      );
      expect(body).toContain(`${BURST_IP} (not seen in the history period)`);
    });

    it('silent Report-button report raised only by fan-out still reaches the team with the detail', async () => {
      mockAnalyzeEmail.mockResolvedValueOnce(verdict({ isPhishing: false, indicators: [] }));

      await handler(reportEvent(), context);

      // Not malicious, so no blast-radius lookup; suspicious, so the team is told
      expect(mockBlastLookup).not.toHaveBeenCalled();
      expect(mockSendAnalysisReport).toHaveBeenCalledTimes(1);
      const [call] = mockSendAnalysisReport.mock.calls;
      expect(call[0]).toBe('security@example.com');
      expect(call[4].risk.verdict).toBe('suspicious');
      expect(rendered(call)).toContain(BURST_IP);
    });
  });
});

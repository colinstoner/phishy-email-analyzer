/**
 * Regression: the indicator feedback loop.
 *
 * Before the fix, indicators were stored whenever the FUSED decision said
 * phishing, any stored indicator matched any later email, and each match
 * floored the score at 60 + timesSeen * 8. A graymail newsletter sharing a
 * bulk-mail click tracker with one earlier phish was therefore lifted over
 * the phishing threshold, its own indicators were stored, and every re-report
 * pushed the shared indicators' times_seen (and the next floor) higher.
 *
 * This drives the real handler (parser, IOC extraction, risk fusion, storage
 * gating, report options) against an in-memory intelligence store that
 * mirrors the upsert's SQL semantics. Nothing connects anywhere; the model is
 * mocked. All addresses, domains and content are invented.
 */

const mockAnalyzeEmail = jest.fn();
const mockSendAnalysisReport = jest.fn();

interface MockRow {
  indicatorType: string;
  indicatorValue: string;
  indicatorHash: string;
  confidenceScore: number;
  severity: string;
  timesSeen: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  isActive: boolean;
  metadata: Record<string, unknown>;
}

const mockStore = new Map<string, MockRow>();
let mockAnalysisSeq = 0;

/**
 * Mirrors IntelligenceDatabaseService.upsertIndicator's ON CONFLICT clause:
 * times_seen counts distinct report keys; a row without report keys (legacy)
 * restarts at 1; provenance fills in when missing; a sender/payload role is
 * never downgraded.
 */
function mockUpsert(indicator: MockRow, options: { reportKey?: string } = {}): Promise<string> {
  const key = `${indicator.indicatorType}:${indicator.indicatorValue.toLowerCase()}`;
  const reportKey = options.reportKey ?? `unkeyed:${Math.random()}`;
  const existing = mockStore.get(key);
  if (!existing) {
    mockStore.set(key, {
      ...indicator,
      metadata: { ...indicator.metadata, reportKeys: [reportKey] },
    });
    return Promise.resolve(key);
  }
  const old = existing.metadata ?? {};
  const keys = Array.isArray(old.reportKeys) ? (old.reportKeys as string[]) : undefined;
  existing.timesSeen = !keys
    ? 1
    : keys.includes(reportKey)
      ? existing.timesSeen
      : existing.timesSeen + 1;
  const keepRole = old.role === 'sender' || old.role === 'payload';
  existing.metadata = {
    ...old,
    provenance: old.provenance ?? indicator.metadata.provenance,
    sourceVerdict: old.sourceVerdict ?? indicator.metadata.sourceVerdict,
    role: keepRole ? old.role : (indicator.metadata.role ?? old.role),
    reportKeys: keys ? (keys.includes(reportKey) ? keys : [...keys, reportKey]) : [reportKey],
  };
  return Promise.resolve(key);
}

const mockDb = {
  initialize: jest.fn().mockResolvedValue(undefined),
  findCampaignVerdict: jest.fn().mockResolvedValue(null),
  lookupIndicators: jest.fn((type: string, values: string[]) =>
    Promise.resolve(
      values
        .map(v => mockStore.get(`${type}:${v.toLowerCase()}`))
        .filter((r): r is MockRow => !!r && r.isActive)
        .map(r => ({ ...r, metadata: { ...r.metadata } }))
    )
  ),
  getCampaignBySignature: jest.fn().mockResolvedValue(null),
  storeAnalysis: jest.fn(() => Promise.resolve(`analysis-${++mockAnalysisSeq}`)),
  storeAIUsage: jest.fn().mockResolvedValue('usage'),
  setReportMessageId: jest.fn().mockResolvedValue(undefined),
  upsertIndicator: jest.fn(mockUpsert),
};

jest.mock('../../../src/services/intelligence/database.service', () => {
  const actual = jest.requireActual('../../../src/services/intelligence/database.service');
  return { ...actual, IntelligenceDatabaseService: jest.fn(() => mockDb) };
});

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
      securityTeamDistribution: ['security@example.com'],
      safeSenderSecurity: [],
    },
    storage: { s3Bucket: 'test-bucket', s3Prefix: 'emails', region: 'us-east-1' },
    intelligence: { enabled: true, connectionString: 'postgresql://unused.invalid/phishy' },
    campaignCache: { enabled: true, ttlHours: 24 },
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

import { handler } from '../../../src/handlers/lambda.handler';
import { VERDICT_SCORE_BANDS } from '../../../src/services/intelligence/risk.fusion';
import { AnalysisResult, ThreatVerdict } from '../../../src/types';
import { Context, SESEvent } from 'aws-lambda';

const CRLF = '\r\n';
const context = {} as Context;

/** A bulk-mail click tracker that both an attacker and a legitimate sender use */
const TRACKER = 'click.mailer.example.org';
const PHISH_LINK = `https://${TRACKER}/r?url=https%3A%2F%2Flanding.phish.example.net%2Flogin`;
const NEWSLETTER_LINK = `https://${TRACKER}/r?url=https%3A%2F%2Fshop.example.org%2Fsale`;

let sequence = 0;

function forward(options: {
  reporter: string;
  subject: string;
  from: string;
  body: string;
}): SESEvent {
  sequence += 1;
  const outerSubject = `FW: ${options.subject}`;
  const raw = [
    `From: Reporter <${options.reporter}>`,
    'To: phishy@example.com',
    `Subject: ${outerSubject}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Is this real?',
    '',
    '---------- Forwarded message ---------',
    `From: ${options.from}`,
    'Date: Mon, 2 Nov 2026 13:00:00 +0000',
    `Subject: ${options.subject}`,
    `To: ${options.reporter}`,
    '',
    options.body,
    '',
  ].join(CRLF);
  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            source: options.reporter,
            messageId: `ses-loop-${sequence}`,
            timestamp: '2026-11-02T14:02:11.000Z',
            destination: ['phishy@example.com'],
            headers: [{ name: 'From', value: `Reporter <${options.reporter}>` }],
            commonHeaders: { from: [`Reporter <${options.reporter}>`], subject: outerSubject },
          },
          receipt: { action: { type: 'Lambda' } },
          content: raw,
        },
      },
    ],
  } as unknown as SESEvent;
}

function phishReport(reporter: string, subject = 'Your mailbox is full'): SESEvent {
  return forward({
    reporter,
    subject,
    from: 'IT Desk <helpdesk@phish.example.net>',
    body: `Sign in to keep your mail: ${PHISH_LINK}`,
  });
}

function newsletterReport(reporter: string, subject = 'Autumn sale ends Friday'): SESEvent {
  return forward({
    reporter,
    subject,
    from: 'Shop News <news@shop.example.org>',
    body: `Our autumn sale ends Friday. See the offers: ${NEWSLETTER_LINK}`,
  });
}

function modelResult(verdict: ThreatVerdict, riskScore: number): AnalysisResult {
  const malicious = ['bec', 'phishing', 'malware_delivery'].includes(verdict);
  return {
    summary: `Model says ${verdict}.`,
    isPhishing: malicious,
    confidence: 'High',
    indicators: [],
    recommendations: [],
    provider: 'bedrock',
    model: 'test-model',
    assessment: {
      verdict,
      riskScore,
      verdictConfidence: 0.9,
      threatVectors: malicious ? ['credential_harvest'] : [],
      targeting: 'mass',
    },
  };
}

/** The fused risk the handler passed to the report for the most recent send */
function lastReportRisk(): { verdict: string; riskScore: number; reasons: string[] } {
  const calls = mockSendAnalysisReport.mock.calls;
  return (
    calls[calls.length - 1][4] as {
      risk: { verdict: string; riskScore: number; reasons: string[] };
    }
  ).risk;
}

function lastReportAnalysis(): AnalysisResult {
  const calls = mockSendAnalysisReport.mock.calls;
  return calls[calls.length - 1][1] as AnalysisResult;
}

function stored(type: string, value: string): MockRow | undefined {
  return mockStore.get(`${type}:${value}`);
}

describe('indicator feedback loop (regression)', () => {
  beforeEach(() => {
    mockStore.clear();
    mockAnalyzeEmail.mockReset();
    mockSendAnalysisReport.mockReset();
    mockSendAnalysisReport.mockResolvedValue({ success: true, messageId: 'out-1' });
    mockDb.upsertIndicator.mockClear();
    mockDb.findCampaignVerdict.mockReset();
    mockDb.findCampaignVerdict.mockResolvedValue(null);
  });

  it('keeps a graymail newsletter graymail, re-report after re-report, and stores nothing from it', async () => {
    // An earlier, genuinely malicious report through the shared tracker
    mockAnalyzeEmail.mockResolvedValueOnce(modelResult('phishing', 90));
    await handler(phishReport('alex@example.com'), context);
    expect(stored('domain', TRACKER)?.metadata.role).toBe('infrastructure');
    expect(stored('domain', 'landing.phish.example.net')?.metadata.provenance).toBe(
      'model_malicious'
    );
    const indicatorsAfterPhish = mockStore.size;

    // The newsletter shares only the tracker; it is reported again and again,
    // including as a reply in its thread
    const reports = [
      newsletterReport('blair@example.com'),
      newsletterReport('casey@example.com'),
      newsletterReport('devon@example.com', 'RE: Autumn sale ends Friday'),
      newsletterReport('emery@example.com'),
      newsletterReport('blair@example.com', 'Re: RE: Autumn sale ends Friday'),
    ];
    for (const report of reports) {
      mockAnalyzeEmail.mockResolvedValueOnce(modelResult('graymail', 15));
      await handler(report, context);

      const risk = lastReportRisk();
      expect(risk.verdict).toBe('graymail');
      expect(risk.riskScore).toBeGreaterThanOrEqual(VERDICT_SCORE_BANDS.graymail.min);
      expect(risk.riskScore).toBeLessThanOrEqual(VERDICT_SCORE_BANDS.graymail.max);
      expect(lastReportAnalysis().isPhishing).toBe(false);
      // The weak match is disclosed, not used as evidence
      expect(risk.reasons.join(' ')).toMatch(/not treated as evidence of an attack/);
    }

    // No indicator was added, and the shared tracker was not counted again
    expect(mockStore.size).toBe(indicatorsAfterPhish);
    expect(stored('domain', 'shop.example.org')).toBeUndefined();
    expect(stored('email', 'news@shop.example.org')).toBeUndefined();
    expect(stored('domain', TRACKER)?.timesSeen).toBe(1);
  });

  it('counts distinct reported emails: repeat reports and thread replies count once', async () => {
    for (const [reporter, subject] of [
      ['alex@example.com', 'Your mailbox is full'],
      ['blair@example.com', 'Your mailbox is full'],
      ['casey@example.com', 'RE: Your mailbox is full'],
    ]) {
      mockAnalyzeEmail.mockResolvedValueOnce(modelResult('phishing', 90));
      await handler(phishReport(reporter, subject), context);
    }
    expect(stored('domain', 'landing.phish.example.net')?.timesSeen).toBe(1);

    // A different phishing email reusing the same landing page is a new sighting
    mockAnalyzeEmail.mockResolvedValueOnce(modelResult('phishing', 90));
    await handler(phishReport('devon@example.com', 'Password expires today'), context);
    expect(stored('domain', 'landing.phish.example.net')?.timesSeen).toBe(2);
  });

  it('does not store or count on a campaign-cache hit', async () => {
    mockDb.findCampaignVerdict.mockResolvedValueOnce({
      analysisId: 'analysis-source',
      analysisResult: modelResult('phishing', 90),
      analyzedAt: new Date('2026-11-02T12:00:00Z'),
    });

    await handler(phishReport('alex@example.com'), context);

    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
    expect(mockDb.upsertIndicator).not.toHaveBeenCalled();
    expect(lastReportRisk().verdict).toBe('phishing');
  });

  it('lets a strong match flag a benign-looking email as suspicious, saying why, without storing it', async () => {
    mockAnalyzeEmail.mockResolvedValueOnce(modelResult('phishing', 90));
    await handler(phishReport('alex@example.com'), context);
    const before = mockStore.size;

    // A "graymail" that links straight to the confirmed landing page
    mockAnalyzeEmail.mockResolvedValueOnce(modelResult('graymail', 15));
    await handler(
      forward({
        reporter: 'blair@example.com',
        subject: 'Weekly digest',
        from: 'Digest <digest@news.example.org>',
        body: 'Read more: https://landing.phish.example.net/login',
      }),
      context
    );

    const risk = lastReportRisk();
    expect(risk.verdict).toBe('suspicious');
    expect(risk.riskScore).toBeLessThanOrEqual(VERDICT_SCORE_BANDS.suspicious.max);
    expect(risk.reasons.join(' ')).toMatch(/treating it as suspicious/);
    expect(lastReportAnalysis().isPhishing).toBe(true);
    // The model did not call it malicious, so nothing new is stored
    expect(mockStore.size).toBe(before);
    expect(stored('domain', 'news.example.org')).toBeUndefined();
  });

  it('records provenance and passes the model confidence to the report', async () => {
    mockAnalyzeEmail.mockResolvedValueOnce(modelResult('phishing', 90));
    await handler(phishReport('alex@example.com'), context);

    const landing = stored('domain', 'landing.phish.example.net');
    expect(landing?.metadata).toMatchObject({
      provenance: 'model_malicious',
      sourceVerdict: 'phishing',
      role: 'payload',
    });
    expect(landing?.metadata.sourceAnalysisId).toMatch(/^analysis-/);
    const options = mockSendAnalysisReport.mock.calls[0][4] as {
      risk: { confidence: string; confidenceBasis: string };
    };
    expect(options.risk).toMatchObject({ confidence: 'Very High', confidenceBasis: 'model' });
  });
});

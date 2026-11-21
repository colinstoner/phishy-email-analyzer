/**
 * Campaign response in the handler.
 *
 * - Flag off: the campaign alert runs exactly as before (processDetection,
 *   no campaign response, no tracking-only call).
 * - Flag on: the detection is only counted before the reports; after the
 *   reporter's copy and the security copy have gone, campaign response gets
 *   the same blast-radius result the security copy carried. The security
 *   copy says how to reply with a verdict.
 * - An incident email reply that fails authentication is not analyzed as a
 *   phishing report.
 * - notification.securityTeamMembers: a member who is not on the distribution
 *   may record a verdict and approve a warning (with SPF/DKIM PASS only), is
 *   never sent security email, and a member off the safe domains is ignored.
 *
 * Everything external is mocked. Invented example.com data only.
 */

const mockAnalyzeEmail = jest.fn();
const mockSendAnalysisReport = jest.fn();
const mockLookup = jest.fn();
const mockProcessDetection = jest.fn();
const mockTrackDetection = jest.fn();
const mockHandleCampaignReport = jest.fn();
const mockResponseCtor = jest.fn();
const mockHandleApprovals = jest.fn();
const mockHandleBareWarningApproval = jest.fn();
const mockSendEmail = jest.fn();
const mockNotifierCtor = jest.fn();
let mockConfig: Record<string, unknown> = {};

const mockDb = {
  initialize: jest.fn().mockResolvedValue(undefined),
  findCampaignVerdict: jest.fn().mockResolvedValue(null),
  lookupIndicators: jest.fn().mockResolvedValue([]),
  getCampaignBySignature: jest.fn().mockResolvedValue(null),
  storeAnalysis: jest.fn().mockResolvedValue('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b'),
  storeAIUsage: jest.fn().mockResolvedValue('usage'),
  setReportMessageId: jest.fn().mockResolvedValue(undefined),
  upsertIndicator: jest.fn().mockResolvedValue('id'),
  runQuery: jest.fn().mockResolvedValue({ rows: [] }),
  findAnalysisIdByReportMessageId: jest.fn().mockResolvedValue(null),
  recordFeedback: jest.fn().mockResolvedValue(undefined),
  applyFeedbackToIndicators: jest.fn().mockResolvedValue(2),
};

jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn(() => Promise.resolve(mockConfig)),
}));

jest.mock('../../../src/services/intelligence/database.service', () => {
  const actual = jest.requireActual('../../../src/services/intelligence/database.service');
  return { ...actual, IntelligenceDatabaseService: jest.fn(() => mockDb) };
});

jest.mock('../../../src/services/intelligence/campaign.service', () => ({
  CampaignAlertService: jest.fn().mockImplementation(() => ({
    processDetection: mockProcessDetection,
    trackDetection: mockTrackDetection,
    sendLegacyAlert: jest.fn(),
    markAlerted: jest.fn(),
  })),
}));

jest.mock('../../../src/services/response/campaign.response.service', () => ({
  CampaignResponseService: jest.fn().mockImplementation((deps: unknown) => {
    mockResponseCtor(deps);
    return {
      handleCampaignReport: mockHandleCampaignReport,
      handleApprovals: mockHandleApprovals,
      handleBareWarningApproval: mockHandleBareWarningApproval,
      onVerdict: jest.fn().mockResolvedValue(undefined),
    };
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
  SESNotifier: jest.fn().mockImplementation((options: unknown) => {
    mockNotifierCtor(options);
    return {
      sendAnalysisReport: mockSendAnalysisReport,
      sendEmail: mockSendEmail,
      sendThreadedEmail: jest.fn().mockResolvedValue({ success: true }),
    };
  }),
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

import type { Context, SESEvent } from 'aws-lambda';

const CRLF = '\r\n';
const SECTION = {
  status: 'complete',
  route: 'trace',
  totals: { recipients: 2, read: 1, replied: 0, forwarded: 0 },
  recipients: [{ address: 'colleague@example.com', mailbox: 'found', folder: 'inbox' }],
  lookedUpAt: '2026-11-17T12:00:00.000Z',
};
let sequence = 0;

function config(campaignResponse?: Record<string, unknown>): Record<string, unknown> {
  return {
    ai: {
      provider: 'bedrock',
      bedrock: { region: 'us-east-1', modelId: 'test-model', maxTokens: 4096, timeout: 60000 },
    },
    email: { safeDomains: ['example.com'], safeSenders: [], deleteAfterProcessing: false },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: ['security@example.com', 'soc@example.com'],
      safeSenderSecurity: [],
    },
    storage: { s3Bucket: 'test-bucket', s3Prefix: 'emails', region: 'us-east-1' },
    intelligence: { enabled: true, connectionString: 'postgresql://unused.invalid/phishy' },
    campaignAlerts: { enabled: true, distributionList: 'everyone@example.com' },
    commands: { enabled: true },
    graph: {
      enabled: true,
      tenantId: '00000000-0000-0000-0000-000000000000',
      read: { clientId: '11111111-1111-1111-1111-111111111111', certificate: 'unused' },
      blastRadius: { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 },
    },
    ...(campaignResponse ? { campaignResponse } : {}),
    logLevel: 'error',
  };
}

function event(
  subject: string,
  body: string,
  from = 'employee@example.com',
  auth = 'PASS',
  inReplyTo?: string
): SESEvent {
  sequence += 1;
  const raw = [
    `From: Employee <${from}>`,
    'To: phishy@example.com',
    `Subject: ${subject}`,
    ...(inReplyTo ? [`In-Reply-To: ${inReplyTo}`] : []),
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
    '',
  ].join(CRLF);
  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            source: from,
            messageId: `ses-campaign-${sequence}`,
            timestamp: '2026-11-17T09:21:00.000Z',
            destination: ['phishy@example.com'],
            headers: [
              { name: 'From', value: `Employee <${from}>` },
              ...(inReplyTo ? [{ name: 'In-Reply-To', value: inReplyTo }] : []),
            ],
            commonHeaders: { from: [`Employee <${from}>`], subject },
          },
          receipt: {
            action: { type: 'Lambda' },
            spfVerdict: { status: auth },
            dkimVerdict: { status: auth },
          },
          content: raw,
        },
      },
    ],
  } as unknown as SESEvent;
}

function forward(): SESEvent {
  return event(
    `FW: Invoice 2291 overdue (${sequence})`,
    [
      'Is this real?',
      '',
      '---------- Forwarded message ---------',
      'From: Accounts Team <billing@examp1e-billing.test>',
      'Date: Tue, 17 Nov 2026 09:14:00 +0000',
      'Subject: Invoice 2291 overdue',
      'To: employee@example.com',
      '',
      'Pay at https://pay.examp1e-billing.test/now today.',
    ].join(CRLF)
  );
}

/** An Outlook Report-button phishing submission (the original attached as message/rfc822) */
function reportButtonEvent(): SESEvent {
  sequence += 1;
  const subject = `Phishing:11111111-2222-4333-8444-55555555555${sequence % 10}|billing@examp1e-billing.test|(Invoice 2291 overdue) 11/17/2026 09:14:00`;
  const inner = [
    'From: "Accounts Team" <billing@examp1e-billing.test>',
    'To: employee@example.com',
    'Subject: Invoice 2291 overdue',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Pay at https://pay.examp1e-billing.test/now today.',
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
    'Reported by the Outlook Report button.',
    '--report-boundary',
    'Content-Type: message/rfc822',
    '',
    inner,
    '--report-boundary--',
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
            messageId: `ses-button-${sequence}`,
            timestamp: '2026-11-17T09:21:00.000Z',
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

const PHISH = {
  summary: 'Credential phishing behind a fake invoice.',
  isPhishing: true,
  confidence: 'High',
  indicators: ['Lookalike sender domain'],
  recommendations: [],
  provider: 'bedrock',
  model: 'test-model',
};

const TRACKED = {
  match: {
    campaignId: 'campaign-1',
    signature: 'abcdef0123456789',
    detectionCount: 3,
    uniqueRecipientCount: 3,
    hoursActive: 0.2,
    shouldAlert: true,
  },
  campaign: { id: 'campaign-1', uniqueRecipients: ['employee@example.com'] },
};

function loadHandler(): (e: SESEvent, c: Context) => Promise<unknown> {
  let handler!: (e: SESEvent, c: Context) => Promise<unknown>;
  jest.isolateModules(() => {
    ({ handler } = jest.requireActual('../../../src/handlers/lambda.handler'));
  });
  return handler;
}

beforeEach(() => {
  for (const mock of [
    mockAnalyzeEmail,
    mockSendAnalysisReport,
    mockLookup,
    mockProcessDetection,
    mockTrackDetection,
    mockHandleCampaignReport,
    mockResponseCtor,
    mockHandleApprovals,
    mockHandleBareWarningApproval,
    mockSendEmail,
    mockNotifierCtor,
  ]) {
    mock.mockReset();
  }
  mockSendEmail.mockResolvedValue({ success: true });
  mockHandleApprovals.mockResolvedValue({ heading: 'Done: approval carried out', body: [] });
  mockHandleBareWarningApproval.mockResolvedValue({
    heading: 'Done: approval carried out',
    body: [],
  });
  mockAnalyzeEmail.mockResolvedValue(PHISH);
  mockSendAnalysisReport.mockResolvedValue({ success: true, messageId: 'out-1' });
  mockLookup.mockResolvedValue(SECTION);
  mockProcessDetection.mockResolvedValue(false);
  mockTrackDetection.mockResolvedValue(TRACKED);
  mockHandleCampaignReport.mockResolvedValue('opened');
});

describe('campaign response off (the default)', () => {
  it('runs the campaign alert exactly as before', async () => {
    mockConfig = config();
    await loadHandler()(forward(), {} as Context);

    expect(mockProcessDetection).toHaveBeenCalledTimes(1);
    expect(mockProcessDetection.mock.calls[0].slice(2, 4)).toEqual([
      'employee@example.com',
      'high',
    ]);
    expect(mockTrackDetection).not.toHaveBeenCalled();
    expect(mockResponseCtor).not.toHaveBeenCalled();
    expect(mockHandleCampaignReport).not.toHaveBeenCalled();
  });

  it('is off when the section is present but not enabled', async () => {
    mockConfig = config({ enabled: false, audience: 'recipients' });
    await loadHandler()(forward(), {} as Context);
    expect(mockProcessDetection).toHaveBeenCalledTimes(1);
    expect(mockResponseCtor).not.toHaveBeenCalled();
  });

  it('still needs a distribution list for the campaign alert', async () => {
    mockConfig = { ...config(), campaignAlerts: { enabled: true } };
    await loadHandler()(forward(), {} as Context);
    expect(mockProcessDetection).not.toHaveBeenCalled();
  });
});

describe('campaign response on', () => {
  const on = {
    enabled: true,
    audience: 'recipients',
    employeeWarning: 'approve',
    distributionWarning: 'auto',
    approvalTtlHours: 4,
    maxWarningsPerCampaign: 100,
    maxRemovalMailboxes: 500,
    maxRemovalMessages: 1000,
    updateIntervalMinutes: 30,
    alreadyClickedInstructions: 'Call the service desk.',
    timeZone: 'UTC',
  };

  it('counts the detection, sends the reports, then responds with the same blast radius', async () => {
    mockConfig = config(on);
    const order: string[] = [];
    mockSendAnalysisReport.mockImplementation((to: string) => {
      order.push(`send:${to}`);
      return Promise.resolve({ success: true, messageId: `out-${order.length}` });
    });
    mockHandleCampaignReport.mockImplementation(() => {
      order.push('respond');
      return Promise.resolve('opened');
    });

    await loadHandler()(forward(), {} as Context);

    expect(mockProcessDetection).not.toHaveBeenCalled();
    expect(mockTrackDetection).toHaveBeenCalledTimes(1);
    expect(order).toEqual(['send:employee@example.com', 'send:security@example.com', 'respond']);
    const input = mockHandleCampaignReport.mock.calls[0][0];
    expect(input.match).toEqual(TRACKED.match);
    expect(input.blastRadius).toBe(SECTION);
    expect(input.blastRadiusEnabled).toBe(true);
    expect(input.analysisId).toBe('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b');
    expect(input.risk.verdict).toBeDefined();
    // The reporter's analysis went out, so the incident email may say so
    expect(input.reporterReply).toBe('emailed');

    const deps = mockResponseCtor.mock.calls[0][0];
    expect(deps.safeDomains).toEqual(['example.com']);
    expect(deps.securityTeam).toEqual(['security@example.com', 'soc@example.com']);
    expect(deps.commandsEnabled).toBe(true);

    // The security copy says how to reply with a verdict; the reporter's does not
    const [, securityOptions] = [
      mockSendAnalysisReport.mock.calls[0][4],
      mockSendAnalysisReport.mock.calls[1][4],
    ];
    expect(securityOptions.replyCommands).toBe(true);
    expect(securityOptions.audience).toBe('security');
  });

  it('works without a distribution list when the audience is the recipients', async () => {
    mockConfig = { ...config(on), campaignAlerts: { enabled: true } };
    await loadHandler()(forward(), {} as Context);
    expect(mockTrackDetection).toHaveBeenCalledTimes(1);
    expect(mockHandleCampaignReport).toHaveBeenCalledTimes(1);
  });

  it('does nothing for a benign verdict', async () => {
    mockConfig = config(on);
    mockAnalyzeEmail.mockResolvedValue({ ...PHISH, isPhishing: false, indicators: [] });
    await loadHandler()(forward(), {} as Context);
    expect(mockTrackDetection).not.toHaveBeenCalled();
    expect(mockHandleCampaignReport).not.toHaveBeenCalled();
  });

  it('hands a Report-button report to campaign response after its single security email, with its blast radius', async () => {
    mockConfig = { ...config({ ...on, reachThreshold: 1 }), reportButton: { enabled: true } };
    const order: string[] = [];
    mockSendAnalysisReport.mockImplementation((to: string) => {
      order.push(`send:${to}`);
      return Promise.resolve({ success: true, messageId: 'out-1' });
    });
    mockHandleCampaignReport.mockImplementation(() => {
      order.push('respond');
      return Promise.resolve('opened');
    });

    await loadHandler()(reportButtonEvent(), {} as Context);

    expect(mockTrackDetection).toHaveBeenCalledTimes(1);
    expect(mockLookup).toHaveBeenCalledTimes(1);
    // Silent: the reporter is never emailed; one email to the security team, then the response
    expect(order).toEqual(['send:security@example.com', 'respond']);
    const input = mockHandleCampaignReport.mock.calls[0][0];
    expect(input.blastRadius).toBe(SECTION);
    expect(input.risk.verdict).toBeDefined();
    expect(input.analysis.analysisFailed).toBeFalsy();
    // Campaign response is told the reporter was not emailed
    expect(input.reporterReply).toBe('silent');
    expect(mockResponseCtor.mock.calls[0][0].config.reachThreshold).toBe(1);
  });

  it('tells campaign response when the reporter could not be sent their analysis', async () => {
    mockConfig = config(on);
    mockSendAnalysisReport.mockResolvedValue({ success: false, error: 'SES refused' });
    await loadHandler()(forward(), {} as Context);
    expect(mockHandleCampaignReport).toHaveBeenCalledTimes(1);
    expect(mockHandleCampaignReport.mock.calls[0][0].reporterReply).toBe('not_sent');
  });

  it('never tracks or responds to a report from a safelist user', async () => {
    const base = config(on);
    mockConfig = {
      ...base,
      email: { ...(base.email as Record<string, unknown>), safeSenders: ['employee@example.com'] },
    };
    await loadHandler()(forward(), {} as Context);
    expect(mockTrackDetection).not.toHaveBeenCalled();
    expect(mockHandleCampaignReport).not.toHaveBeenCalled();
  });

  it('does not analyze an unauthenticated reply to an incident email as a phishing report', async () => {
    mockConfig = config(on);
    await loadHandler()(
      event(
        'Re: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"',
        'APPROVE WARNING PHY-AAAA-BBBB-CCCC-DDDD',
        'security@example.com',
        'FAIL'
      ),
      {} as Context
    );
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
    expect(mockSendAnalysisReport).not.toHaveBeenCalled();
  });

  it('still analyzes an email with an incident-style subject from someone outside the security team', async () => {
    mockConfig = config(on);
    await loadHandler()(
      event(
        'FW: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"',
        'Please see the forwarded message.',
        'employee@example.com',
        'PASS'
      ),
      {} as Context
    );
    expect(mockAnalyzeEmail).toHaveBeenCalledTimes(1);
  });
});

describe('security-team members (notification.securityTeamMembers)', () => {
  const on = {
    enabled: true,
    audience: 'recipients',
    employeeWarning: 'approve',
    distributionWarning: 'auto',
    approvalTtlHours: 4,
    maxWarningsPerCampaign: 100,
    maxRemovalMailboxes: 500,
    maxRemovalMessages: 1000,
    updateIntervalMinutes: 30,
    alreadyClickedInstructions: 'Call the service desk.',
    timeZone: 'UTC',
  };
  const MEMBER = 'alice@example.com';
  const OUTSIDE_MEMBER = 'mallory@outside.test';
  const ANALYSIS_ID = '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b';
  const INCIDENT_SUBJECT =
    'Re: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"';
  const INCIDENT_MESSAGE = '<ses-incident-1@email.amazonses.com>';

  /**
   * The handler's config is mocked (loadConfig is bypassed), so the outside
   * member reaching the handler here also proves the safe-domain filter
   * applies at use, not only at load.
   */
  function withMembers(): Record<string, unknown> {
    const base = config(on);
    return {
      ...base,
      notification: {
        ...(base.notification as Record<string, unknown>),
        securityTeamMembers: [MEMBER, OUTSIDE_MEMBER],
      },
    };
  }

  function verdictReply(from: string, auth: string): SESEvent {
    return event(
      'Re: Phishing Analysis: Invoice 2291 overdue',
      ['Confirmed phishing.', '', `Analysis ID: ${ANALYSIS_ID}`].join(CRLF),
      from,
      auth
    );
  }

  beforeEach(() => {
    mockDb.recordFeedback.mockClear();
    mockDb.applyFeedbackToIndicators.mockClear();
  });

  it('lets a member who is not on the distribution record a verdict, and replies to that member', async () => {
    mockConfig = withMembers();
    await loadHandler()(verdictReply(MEMBER, 'PASS'), {} as Context);

    expect(mockDb.recordFeedback).toHaveBeenCalledWith(
      expect.objectContaining({
        analysisId: ANALYSIS_ID,
        verdict: 'confirmed_phishing',
        submittedBy: MEMBER,
      })
    );
    expect(mockSendEmail).toHaveBeenCalledTimes(1);
    expect(mockSendEmail.mock.calls[0][0]).toBe(MEMBER);
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
  });

  it('refuses a member verdict without SPF/DKIM PASS', async () => {
    mockConfig = withMembers();
    await loadHandler()(verdictReply(MEMBER, 'FAIL'), {} as Context);
    expect(mockDb.recordFeedback).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  it('lets a member approve a warning with the full line', async () => {
    mockConfig = withMembers();
    await loadHandler()(
      event(INCIDENT_SUBJECT, 'APPROVE WARNING PHY-AAAA-BBBB-CCCC-DDDD', MEMBER, 'PASS'),
      {} as Context
    );
    expect(mockHandleApprovals).toHaveBeenCalledTimes(1);
    expect(mockHandleApprovals.mock.calls[0][0]).toEqual([
      { verb: 'WARNING', reference: 'PHY-AAAA-BBBB-CCCC-DDDD' },
    ]);
    expect(mockHandleApprovals.mock.calls[0][1]).toBe(MEMBER);
    expect(mockSendEmail.mock.calls[0][0]).toBe(MEMBER);
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
  });

  it('lets a member approve with a bare APPROVE WARNING reply to the incident email', async () => {
    mockConfig = withMembers();
    await loadHandler()(
      event(INCIDENT_SUBJECT, 'APPROVE WARNING', MEMBER, 'PASS', INCIDENT_MESSAGE),
      {} as Context
    );
    expect(mockHandleBareWarningApproval).toHaveBeenCalledWith(['ses-incident-1'], MEMBER);
    expect(mockSendEmail.mock.calls[0][0]).toBe(MEMBER);
  });

  it('acts on no member approval without SPF/DKIM PASS, and does not analyze it either', async () => {
    mockConfig = withMembers();
    for (const body of ['APPROVE WARNING PHY-AAAA-BBBB-CCCC-DDDD', 'APPROVE WARNING']) {
      await loadHandler()(
        event(INCIDENT_SUBJECT, body, MEMBER, 'FAIL', INCIDENT_MESSAGE),
        {} as Context
      );
    }
    expect(mockHandleApprovals).not.toHaveBeenCalled();
    expect(mockHandleBareWarningApproval).not.toHaveBeenCalled();
    // The team's own incident-thread correspondence is skipped, not analyzed
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
  });

  it('refuses an address on neither list exactly as before', async () => {
    mockConfig = withMembers();
    await loadHandler()(verdictReply('employee@example.com', 'PASS'), {} as Context);
    await loadHandler()(
      event(INCIDENT_SUBJECT, 'APPROVE WARNING PHY-AAAA-BBBB-CCCC-DDDD', 'employee@example.com'),
      {} as Context
    );
    expect(mockDb.recordFeedback).not.toHaveBeenCalled();
    expect(mockHandleApprovals).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  it('ignores a member off the safe domains, even with SPF/DKIM PASS', async () => {
    mockConfig = withMembers();
    await loadHandler()(verdictReply(OUTSIDE_MEMBER, 'PASS'), {} as Context);
    await loadHandler()(
      event(INCIDENT_SUBJECT, 'APPROVE WARNING PHY-AAAA-BBBB-CCCC-DDDD', OUTSIDE_MEMBER),
      {} as Context
    );
    expect(mockDb.recordFeedback).not.toHaveBeenCalled();
    expect(mockHandleApprovals).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
    const approvers = mockResponseCtor.mock.calls[0][0].approvers as string[];
    expect(approvers).toContain(MEMBER);
    expect(approvers).not.toContain(OUTSIDE_MEMBER);
  });

  it('sends members no security email: report Cc and incident recipients stay the distribution', async () => {
    mockConfig = withMembers();
    await loadHandler()(forward(), {} as Context);

    expect(mockSendAnalysisReport).toHaveBeenCalled();
    expect(JSON.stringify(mockSendAnalysisReport.mock.calls)).not.toContain(MEMBER);
    expect(mockNotifierCtor.mock.calls[0][0].securityTeamDistribution).toEqual([
      'security@example.com',
      'soc@example.com',
    ]);
    const deps = mockResponseCtor.mock.calls[0][0];
    expect(deps.securityTeam).toEqual(['security@example.com', 'soc@example.com']);
    expect(deps.approvers).toEqual(['security@example.com', 'soc@example.com', MEMBER]);
    expect(mockSendEmail).not.toHaveBeenCalled();
  });
});

/**
 * The scheduled-task path of the main function, through the deployed entry
 * point (the unified handler): strict dispatch between schedule and email
 * events, the fan-out scan in broker mode end to end on the main side (the
 * Lambda API, SES and the database are stand-ins), alerts to the security
 * team only, and no change at all with the feature off. No Graph, no
 * network, no model. Invented data only.
 */

/* eslint-disable @typescript-eslint/no-require-imports */

const mockState: {
  config: Record<string, unknown>;
  db: unknown;
  invoke: jest.Mock;
} = { config: {}, db: undefined, invoke: jest.fn() };
const mockSendEmail = jest.fn();
const mockSendAnalysisReport = jest.fn();
const mockAnalyzeEmail = jest.fn();

jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn(() => Promise.resolve(mockState.config)),
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
    sendEmail: mockSendEmail,
    sendAnalysisReport: mockSendAnalysisReport,
  })),
}));
jest.mock('../../../src/services/storage/s3.service', () => ({
  S3Service: jest.fn().mockImplementation(() => ({
    getObject: jest.fn().mockRejectedValue(new Error('S3 not available in test')),
    deleteObject: jest.fn(),
  })),
}));
jest.mock('../../../src/services/intelligence/database.service', () => {
  const actual = jest.requireActual('../../../src/services/intelligence/database.service');
  return {
    ...actual,
    IntelligenceDatabaseService: jest.fn().mockImplementation(() => ({
      initialize: jest.fn().mockResolvedValue(undefined),
      featureStore: () => mockState.db,
    })),
  };
});
jest.mock('@aws-sdk/client-lambda', () => ({
  LambdaClient: jest.fn().mockImplementation(() => ({
    send: (command: { input: unknown }) => mockState.invoke(command.input),
  })),
  InvokeCommand: jest.fn().mockImplementation((input: unknown) => ({ input })),
}));

import type { APIGatewayProxyResult, Context } from 'aws-lambda';
import type { FakeFanoutDb } from '../../mocks/fanout.db';

const context = { getRemainingTimeInMillis: () => 170_000 } as unknown as Context;
const SCHEDULE = { phishyScheduledTask: 'graph_fanout_scan', version: 1 };
const SECURITY_TEAM = ['security@example.com', 'soc-lead@example.com'];
const SENDER = 'pat@supplier.example.net';
const NOW = Date.parse('2026-11-17T12:00:00Z');

const exact = (count: number): { count: number; atLeast: boolean } => ({ count, atLeast: false });

const FLAG = {
  senderAddress: SENDER,
  subject: 'Updated remittance details',
  firstSeen: '2026-11-17T11:58:00.000Z',
  lastSeen: '2026-11-17T11:59:00.000Z',
  windowRecipients: 30,
  windowMessages: 1,
  statuses: { delivered: 25, junk: 2, quarantined: 3, failed: 0, other: 0 },
  recipients: [
    { address: 'person1@example.com', status: 'delivered' },
    // Not one of the organization's domains: dropped on the main side
    { address: 'outsider@example.org', status: 'delivered' },
  ],
  recipientsOmitted: 28,
  facts: {
    classification: 'established_with_anomalous_fanout',
    lookbackDays: 30,
    burstWindowHours: 25,
    history: { messages: exact(3), recipients: exact(2) },
    twoWay: { messages: exact(1), internalSenders: exact(1) },
    burst: {
      messages: exact(1),
      recipients: exact(30),
      newRecipients: exact(29),
      sameSubject: { recipients: exact(30), newRecipients: exact(29) },
    },
    sendingIps: { burst: 1, seenInHistory: 0, historyComplete: true },
    truncated: false,
  },
};

const SCAN_RESULT = {
  outcome: 'ok',
  rowsScanned: 400,
  inboundRows: 120,
  pages: 1,
  requestsUsed: 7,
  forbiddenRetries: 0,
  filterMismatch: false,
  candidates: 1,
  candidatesChecked: 1,
  incomplete: false,
  incompleteReasons: [],
  flagged: [FLAG],
};

function baseConfig(fanoutEnabled: boolean): Record<string, unknown> {
  return {
    ai: {
      provider: 'bedrock',
      bedrock: { region: 'us-east-1', modelId: 'test-model', maxTokens: 4096, timeout: 60000 },
    },
    email: { safeDomains: ['example.com'], safeSenders: [], deleteAfterProcessing: false },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: SECURITY_TEAM,
      safeSenderSecurity: [],
    },
    storage: { s3Bucket: 'test-bucket', s3Prefix: 'emails', region: 'us-east-1' },
    intelligence: {
      enabled: true,
      type: 'postgres',
      connectionString: 'postgresql://phishy@db.example.com/phishy',
    },
    graph: {
      enabled: true,
      mode: 'broker',
      brokerFunctionName: 'phishy-graph-broker',
      ...(fanoutEnabled
        ? {
            fanoutScan: {
              enabled: true,
              overlapMinutes: 10,
              maxWindowMinutes: 60,
              maxPages: 4,
              maxCandidates: 3,
              requestAllowancePer5Min: 20,
              budgetMs: 60000,
              dedupeHours: 24,
            },
          }
        : {}),
    },
    logLevel: 'error',
  };
}

type Unified = typeof import('../../../src/handlers/unified.handler');
type Ses = typeof import('../../../src/handlers/lambda.handler');

/** A fresh main function (its services are cached per instance) */
function loadMain(fanoutEnabled: boolean): { unified: Unified; ses: Ses; db: FakeFanoutDb } {
  const { FakeFanoutDb: FakeDb } =
    require('../../mocks/fanout.db') as typeof import('../../mocks/fanout.db');
  const db = new FakeDb();
  mockState.config = baseConfig(fanoutEnabled);
  mockState.db = db;
  let unified: Unified | undefined;
  let ses: Ses | undefined;
  jest.isolateModules(() => {
    unified = require('../../../src/handlers/unified.handler') as Unified;
    ses = require('../../../src/handlers/lambda.handler') as Ses;
  });
  return { unified: unified!, ses: ses!, db };
}

const SES_EVENT = {
  Records: [
    {
      eventSource: 'aws:ses',
      eventVersion: '1.0',
      ses: {
        mail: {
          messageId: 'ses-inbound-1',
          source: 'reporter@example.com',
          timestamp: '2026-11-17T12:00:00.000Z',
          destination: ['phishy@example.com'],
          commonHeaders: {
            from: ['Reporter <reporter@example.com>'],
            to: ['phishy@example.com'],
            subject: 'FW: Updated remittance details',
          },
          headers: [],
        },
        receipt: {
          spfVerdict: { status: 'PASS' },
          dkimVerdict: { status: 'PASS' },
          action: { type: 'Lambda' },
        },
      },
    },
  ],
};

beforeEach(() => {
  jest.useFakeTimers({
    now: NOW,
    doNotFake: [
      'nextTick',
      'setImmediate',
      'setTimeout',
      'clearTimeout',
      'setInterval',
      'clearInterval',
      'queueMicrotask',
    ],
  });
  mockState.invoke = jest.fn().mockResolvedValue({
    StatusCode: 200,
    Payload: Buffer.from(JSON.stringify({ ok: true, result: SCAN_RESULT })),
  });
  mockSendEmail.mockReset().mockResolvedValue({ success: true, messageId: 'ses-alert-1' });
  mockSendAnalysisReport
    .mockReset()
    .mockResolvedValue({ success: true, messageId: 'ses-report-1' });
  mockAnalyzeEmail.mockReset();
  // The email path's own failure (no real analysis here) is not what these tests check
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

function body(response: APIGatewayProxyResult): Record<string, unknown> {
  return JSON.parse(response.body) as Record<string, unknown>;
}

describe('scheduled fan-out scan through the entry point', () => {
  it('runs the scan in the broker and alerts the security team only', async () => {
    const { unified, db } = loadMain(true);
    const response = await unified.handler(SCHEDULE as never, context);

    expect(response.statusCode).toBe(200);
    expect(body(response)).toMatchObject({
      success: true,
      task: 'graph_fanout_scan',
      outcome: 'ok',
      flagged: 1,
      alertsSent: 1,
    });
    expect(mockState.invoke).toHaveBeenCalledTimes(1);
    const invocation = mockState.invoke.mock.calls[0][0] as {
      Payload: Uint8Array;
      FunctionName: string;
    };
    expect(invocation.FunctionName).toBe('phishy-graph-broker');
    const sent = JSON.parse(Buffer.from(invocation.Payload).toString('utf8')) as {
      operation: string;
      params: Record<string, unknown>;
    };
    expect(sent.operation).toBe('fanout_scan');
    expect(sent.params.internalDomains).toEqual(['example.com']);
    expect(sent.params.maxRequests).toBe(20);

    expect(mockSendEmail).toHaveBeenCalledTimes(1);
    const [to, subject, html, , cc] = mockSendEmail.mock.calls[0] as [
      string,
      string,
      string,
      string,
      string[],
    ];
    expect([to, ...cc]).toEqual(SECURITY_TEAM);
    expect(subject).not.toContain(SENDER);
    expect(html).toContain('person1@example.com');
    expect(html).not.toContain('outsider@example.org');
    // No email analysis, no report to anyone
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
    expect(mockSendAnalysisReport).not.toHaveBeenCalled();
    expect(db.waves).toHaveLength(1);
    expect(db.waves[0].report_message_id).toBe('ses-alert-1');
  });

  it('refuses anything that only resembles a schedule event, and treats it as nothing else', async () => {
    const { unified } = loadMain(true);
    for (const event of [
      { phishyScheduledTask: 'graph_fanout_scan' },
      { ...SCHEDULE, version: 2 },
      { ...SCHEDULE, phishyScheduledTask: 'graph_purge' },
      { ...SCHEDULE, extra: true },
      { ...SCHEDULE, Records: SES_EVENT.Records },
      { phishyScheduledTask: 'graph_fanout_scan', version: 1, httpMethod: 'POST' },
    ]) {
      const response = await unified.handler(event as never, context);
      expect(response.statusCode).toBe(400);
    }
    expect(mockState.invoke).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
    expect(mockSendAnalysisReport).not.toHaveBeenCalled();
  });

  it('never treats an email event as a schedule event', async () => {
    const { unified } = loadMain(true);
    await unified.handler(SES_EVENT as never, context);
    // It went down the email path, and only that
    expect(mockAnalyzeEmail).toHaveBeenCalledTimes(1);
    expect(mockState.invoke).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });

  it('refuses a schedule event that reaches the email handler directly', async () => {
    const { ses } = loadMain(true);
    const response = await ses.handler(SCHEDULE as never, context);
    expect(response.statusCode).toBe(400);
    expect(mockState.invoke).not.toHaveBeenCalled();
    expect(mockAnalyzeEmail).not.toHaveBeenCalled();
  });

  it('does nothing on a schedule event with the feature off, and leaves email handling as it was', async () => {
    const { unified, db } = loadMain(false);
    const response = await unified.handler(SCHEDULE as never, context);
    expect(response.statusCode).toBe(200);
    expect(body(response)).toMatchObject({ outcome: 'disabled' });
    expect(mockState.invoke).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
    expect(db.statements).toHaveLength(0);

    await unified.handler(SES_EVENT as never, context);
    expect(mockAnalyzeEmail).toHaveBeenCalledTimes(1);
    expect(mockState.invoke).not.toHaveBeenCalled();
  });

  it('runs no scan without the intelligence database', async () => {
    mockState.config = { ...baseConfig(true), intelligence: { enabled: false, type: 'postgres' } };
    let fresh: Unified | undefined;
    jest.isolateModules(() => {
      fresh = require('../../../src/handlers/unified.handler') as Unified;
    });
    const response = await fresh!.handler(SCHEDULE as never, context);
    expect(body(response)).toMatchObject({ outcome: 'no_database' });
    expect(mockState.invoke).not.toHaveBeenCalled();
    expect(mockSendEmail).not.toHaveBeenCalled();
  });
});

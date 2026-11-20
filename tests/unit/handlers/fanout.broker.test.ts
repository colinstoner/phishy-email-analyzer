/**
 * The `fanout_scan` broker operation end to end: the main function's scan
 * source in broker mode on one side, the broker handler on the other, joined
 * by an in-process stand-in for Lambda `Invoke` that carries JSON both ways.
 * Plus the wire format's strictness and re-bounding for the new operation.
 *
 * Microsoft Graph is a fake (a real GraphClient over a mocked fetch). No
 * network, no AWS. Invented data only.
 */

import type { InvokeCommand } from '@aws-sdk/client-lambda';
import type { FakeGraph } from '../../mocks/graph.fake';
import type { FanoutTenant } from '../../mocks/fanout.tenant';

jest.mock('../../../src/services/graph/graph.credential', () => ({
  createGraphReadClient: jest.fn(),
}));
// The broker never parses email, sends mail or opens the database
jest.mock('mailparser', () => {
  throw new Error('the Graph broker loaded mailparser');
});
jest.mock('pg', () => {
  throw new Error('the Graph broker loaded pg');
});
jest.mock('@aws-sdk/client-ses', () => {
  throw new Error('the Graph broker loaded the SES client');
});

type Broker = typeof import('../../../src/handlers/graph.broker.handler');
type SourceModule = typeof import('../../../src/services/graph/fanout.source');
type Protocol = typeof import('../../../src/services/graph/broker.protocol');
type FakeModule = typeof import('../../mocks/graph.fake');
type TenantModule = typeof import('../../mocks/fanout.tenant');

const BROKER_ENV: Record<string, string> = {
  PHISHY_GRAPH_ENABLED: 'true',
  PHISHY_GRAPH_TENANT_ID: 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb',
  PHISHY_GRAPH_READ_CLIENT_ID: 'cccccccc-4444-4555-8666-dddddddddddd',
  PHISHY_GRAPH_READ_CERTIFICATE:
    'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf',
  PHISHY_GRAPH_FANOUT_SCAN_ENABLED: 'true',
};

const MAIN_CONFIG = {
  graph: {
    enabled: true,
    mode: 'broker' as const,
    brokerFunctionName: 'phishy-graph-broker',
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
  },
};

describe('fanout_scan through the Graph broker', () => {
  const savedEnv: Record<string, string | undefined> = {};
  let broker: Broker;
  let sourceModule: SourceModule;
  let protocol: Protocol;
  let fakeModule: FakeModule;
  let tenantModule: TenantModule;
  let createGraphReadClient: jest.Mock;
  let fake: FakeGraph;
  let tenant: FanoutTenant;
  let lines: string[];
  let invoked: unknown[];

  beforeAll(async () => {
    for (const name of [...Object.keys(BROKER_ENV), 'LOG_LEVEL', 'PHISHY_CONFIG_S3']) {
      savedEnv[name] = process.env[name];
      delete process.env[name];
    }
    Object.assign(process.env, BROKER_ENV, { LOG_LEVEL: 'info' });
    jest.resetModules();
    fakeModule = await import('../../mocks/graph.fake');
    tenantModule = await import('../../mocks/fanout.tenant');
    ({ createGraphReadClient } =
      (await import('../../../src/services/graph/graph.credential')) as unknown as {
        createGraphReadClient: jest.Mock;
      });
    broker = await import('../../../src/handlers/graph.broker.handler');
    sourceModule = await import('../../../src/services/graph/fanout.source');
    protocol = await import('../../../src/services/graph/broker.protocol');
  });

  afterAll(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
    jest.useRealTimers();
    jest.resetModules();
  });

  beforeEach(() => {
    // Only the clock is fixed: the invented tenant lives on 2026-11-17
    jest.useFakeTimers({
      now: tenantModule.NOW,
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
    Object.assign(process.env, BROKER_ENV);
    broker.resetGraphBroker();
    tenant = tenantModule.takeoverTenant();
    fake = fakeModule.fakeGraph([tenantModule.fanoutResponder(tenant)]);
    createGraphReadClient.mockReset();
    createGraphReadClient.mockImplementation((config?: { enabled?: boolean }) =>
      config?.enabled ? fake.client : undefined
    );
    invoked = [];
    lines = [];
    const capture = (...args: unknown[]): void => {
      lines.push(args.map(String).join(' '));
    };
    jest.spyOn(console, 'log').mockImplementation(capture);
    jest.spyOn(console, 'warn').mockImplementation(capture);
    jest.spyOn(console, 'error').mockImplementation(capture);
    jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  function lambda(): import('../../../src/services/graph/broker.client').LambdaInvoker {
    const send = async (command: InvokeCommand): Promise<unknown> => {
      const request = JSON.parse(
        Buffer.from(command.input.Payload as Uint8Array).toString('utf8')
      ) as unknown;
      invoked.push(request);
      const response = await broker.handler(request, { getRemainingTimeInMillis: () => 170_000 });
      return { StatusCode: 200, Payload: Buffer.from(JSON.stringify(response)) };
    };
    return { send } as unknown as import('../../../src/services/graph/broker.client').LambdaInvoker;
  }

  const request = (): import('../../../src/services/graph/fanout.scan').FanoutScanRequest => ({
    ...tenantModule.WINDOW,
    internalDomains: tenantModule.INTERNAL_DOMAINS,
    maxPages: 4,
    maxCandidates: 3,
    maxRequests: 20,
    budgetMs: 60_000,
  });

  it('runs the scan in the broker and returns validated flags to the main function', async () => {
    const source = sourceModule.createFanoutScanSource(MAIN_CONFIG, { lambda: lambda() });
    expect(source?.mode).toBe('broker');
    const call = await source!.scan(request(), 60_000);

    expect(call.ok).toBe(true);
    if (!call.ok) return;
    expect(call.result.flagged).toHaveLength(1);
    expect(call.result.flagged[0].senderAddress).toBe(tenantModule.SENDER);
    expect(call.result.flagged[0].facts.classification).toBe('established_with_anomalous_fanout');
    expect(call.result.requestsUsed).toBe(7);

    // What crossed: one typed request, with the organization's domains and the budgets only
    expect(invoked).toHaveLength(1);
    expect(invoked[0]).toEqual({
      version: 1,
      operation: 'fanout_scan',
      params: {
        receivedFrom: tenantModule.WINDOW.receivedFrom.toISOString(),
        receivedTo: tenantModule.WINDOW.receivedTo.toISOString(),
        internalDomains: ['example.com'],
        maxPages: 4,
        maxCandidates: 3,
        maxRequests: 20,
        budgetMs: 59_000,
      },
    });
    expect(fake.requests.every(r => r.method === 'GET')).toBe(true);
  });

  it('logs counts and outcomes only in the broker', async () => {
    const source = sourceModule.createFanoutScanSource(MAIN_CONFIG, { lambda: lambda() });
    await source!.scan(request(), 60_000);
    const logged = lines.join('\n');
    expect(logged).toContain('Graph broker request finished');
    expect(logged).not.toContain(tenantModule.SENDER);
    expect(logged).not.toContain(tenantModule.SUBJECT);
    expect(logged).not.toContain('person1@example.com');
  });

  it('is refused when the broker’s own configuration has the scan off', async () => {
    process.env.PHISHY_GRAPH_FANOUT_SCAN_ENABLED = 'false';
    broker.resetGraphBroker();
    const source = sourceModule.createFanoutScanSource(MAIN_CONFIG, { lambda: lambda() });
    const call = await source!.scan(request(), 60_000);
    expect(call).toEqual({ ok: false, failure: 'unavailable' });
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses malformed scan requests before touching Graph', async () => {
    const valid = {
      version: 1,
      operation: 'fanout_scan',
      params: {
        receivedFrom: '2026-11-17T11:45:00.000Z',
        receivedTo: '2026-11-17T12:00:00.000Z',
        internalDomains: ['example.com'],
        maxPages: 4,
        maxCandidates: 3,
        maxRequests: 20,
        budgetMs: 59_000,
      },
    };
    expect(protocol.GraphBrokerRequestSchema.safeParse(valid).success).toBe(true);
    for (const params of [
      { ...valid.params, receivedFrom: '2026-11-17T09:00:00.000Z' }, // wider than two hours
      { ...valid.params, receivedFrom: valid.params.receivedTo }, // empty
      { ...valid.params, internalDomains: [] },
      { ...valid.params, internalDomains: ["example.com' or 1 eq 1"] },
      { ...valid.params, maxPages: 11 },
      { ...valid.params, maxRequests: 101 },
      { ...valid.params, maxCandidates: 0 },
      { ...valid.params, filter: 'receivedDateTime ge 2020-01-01' },
      { ...valid.params, senderAddress: 'pat@supplier.example.net' },
    ]) {
      expect(await broker.handler({ ...valid, params })).toEqual({
        ok: false,
        reason: 'invalid_request',
      });
    }
    expect(fake.requests).toHaveLength(0);
  });

  it('re-bounds a broker answer as hostile data', () => {
    const facts = {
      classification: 'established_with_anomalous_fanout',
      lookbackDays: 30,
      burstWindowHours: 24,
      history: {
        messages: { count: 3, atLeast: false },
        recipients: { count: 2, atLeast: false },
      },
      twoWay: {
        messages: { count: 1, atLeast: false },
        internalSenders: { count: 1, atLeast: false },
      },
      burst: {
        messages: { count: 1, atLeast: false },
        recipients: { count: 150, atLeast: false },
        newRecipients: { count: 150, atLeast: false },
        sameSubject: {
          recipients: { count: 150, atLeast: false },
          newRecipients: { count: 150, atLeast: false },
        },
      },
      sendingIps: {
        burst: 30,
        seenInHistory: 0,
        historyComplete: true,
        burstIps: [
          ...Array.from({ length: 25 }, (_, i) => ({
            ip: `198.51.100.${i}`,
            seenInHistory: false,
          })),
          { ip: '<script>', seenInHistory: false },
        ],
      },
      truncated: false,
    };
    const flag = {
      senderAddress: 'pat@supplier.example.net',
      subject: 'Hello',
      firstSeen: '2026-11-17T11:58:00.000Z',
      lastSeen: '2026-11-17T11:59:00.000Z',
      windowRecipients: 150,
      windowMessages: 1,
      statuses: { delivered: 150, junk: 0, quarantined: 0, failed: 0, other: 0 },
      recipients: Array.from({ length: 150 }, (_, i) => ({
        address: `person${i}@example.com`,
        status: 'delivered',
      })),
      recipientsOmitted: 0,
      facts,
    };
    const base = {
      outcome: 'ok',
      rowsScanned: 150,
      inboundRows: 150,
      pages: 1,
      requestsUsed: 7,
      forbiddenRetries: 0,
      filterMismatch: false,
      candidates: 12,
      candidatesChecked: 12,
      incomplete: false,
      incompleteReasons: [],
      flagged: Array.from({ length: 12 }, () => flag),
    };
    const parsed = protocol.FanoutScanResultSchema.parse(base);
    expect(parsed.flagged).toHaveLength(10);
    expect(parsed.flagged[0].recipients).toHaveLength(100);
    expect(parsed.flagged[0].recipientsOmitted).toBe(50);
    expect(parsed.flagged[0].facts.sendingIps.burstIps).toHaveLength(20);
    expect(parsed.flagged[0].facts.sendingIps.burstIpsOmitted).toBe(6);
    // Why paging stopped early is carried when present, and optional
    expect(parsed.windowUnread).toBeUndefined();
    expect(
      protocol.FanoutScanResultSchema.parse({ ...base, windowUnread: 'request_allowance' })
        .windowUnread
    ).toBe('request_allowance');

    for (const broken of [
      { ...base, extra: 1 },
      { ...base, outcome: 'great' },
      { ...base, flagged: [{ ...flag, senderAddress: 'not an address' }] },
      { ...base, flagged: [{ ...flag, subject: 'x'.repeat(256) }] },
      {
        ...base,
        flagged: [{ ...flag, recipients: [{ address: 'a b@example.com', status: 'delivered' }] }],
      },
      { ...base, incompleteReasons: ['because'] },
      { ...base, windowUnread: 'candidate_limit' },
    ]) {
      expect(protocol.FanoutScanResultSchema.safeParse(broken).success).toBe(false);
    }
  });

  it('drops flags and recipients the main function cannot accept', () => {
    const flag = (sender: string): never =>
      ({
        senderAddress: sender,
        subject: 'Hello',
        firstSeen: '2026-11-17T11:58:00.000Z',
        lastSeen: '2026-11-17T11:59:00.000Z',
        windowRecipients: 2,
        windowMessages: 1,
        statuses: { delivered: 2, junk: 0, quarantined: 0, failed: 0, other: 0 },
        recipients: [
          { address: 'a@example.com', status: 'delivered' },
          { address: 'outsider@example.org', status: 'delivered' },
        ],
        recipientsOmitted: 0,
        facts: {},
      }) as never;
    const result = sourceModule.reboundFanoutResult(
      {
        outcome: 'ok',
        rowsScanned: 0,
        inboundRows: 0,
        pages: 1,
        requestsUsed: 1,
        forbiddenRetries: 0,
        filterMismatch: false,
        candidates: 2,
        candidatesChecked: 2,
        incomplete: false,
        incompleteReasons: [],
        flagged: [flag('pat@supplier.example.net'), flag('insider@example.com')],
      },
      ['example.com']
    );
    expect(result.flagged).toHaveLength(1);
    expect(result.flagged[0].recipients).toEqual([
      { address: 'a@example.com', status: 'delivered' },
    ]);
    expect(result.flagged[0].recipientsOmitted).toBe(1);
  });
});

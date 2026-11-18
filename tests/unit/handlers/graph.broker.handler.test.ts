/**
 * The Graph broker function, and each operation end to end: the main
 * function's gateway on one side, the broker handler on the other, joined by
 * an in-process stand-in for Lambda `Invoke` that carries JSON both ways.
 *
 * Microsoft Graph is a fake (a real GraphClient over a mocked fetch, handed
 * out in place of the credential-backed client). No network, no AWS.
 * Invented data only.
 *
 * Loggers capture their level at module load, so everything is loaded fresh
 * with LOG_LEVEL=info to check what the broker writes to its log.
 */

import type { InvokeCommand } from '@aws-sdk/client-lambda';
import type { FakeGraph, FakeResponder, RecordedRequest } from '../../mocks/graph.fake';
import type { EmailMessage, ExtractedEmailData } from '../../../src/types';

jest.mock('../../../src/services/graph/graph.credential', () => ({
  createGraphReadClient: jest.fn(),
}));
// The broker never parses email, calls a model, sends mail or opens the
// database: loading any of these while loading the broker fails the test
jest.mock('mailparser', () => {
  throw new Error('the Graph broker loaded mailparser');
});
jest.mock('pg', () => {
  throw new Error('the Graph broker loaded pg');
});
jest.mock('@aws-sdk/client-bedrock-runtime', () => {
  throw new Error('the Graph broker loaded the Bedrock client');
});
jest.mock('@aws-sdk/client-ses', () => {
  throw new Error('the Graph broker loaded the SES client');
});

type Broker = typeof import('../../../src/handlers/graph.broker.handler');
type GatewayModule = typeof import('../../../src/services/graph/graph.gateway');
type FakeModule = typeof import('../../mocks/graph.fake');
type Metrics = typeof import('../../../src/utils/metrics');

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const REPORTER = 'reporter@example.com';
const BILLING = 'billing-alerts@example.org';
const SUPPLIER = 'pat@supplier.example.net';
const SUBJECT = 'Invoice 7731 overdue';
const GRAPH_ID = 'AAMkAG-original-7731';
const HEADER_MARKER = 'HEADER-VALUE-MARKER-93cd';
const TRACE_PATH = '/admin/exchange/tracing/messageTraces';
const SAFE_DOMAINS = ['example.com'];

const BROKER_ENV: Record<string, string> = {
  PHISHY_GRAPH_ENABLED: 'true',
  PHISHY_GRAPH_TENANT_ID: 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb',
  PHISHY_GRAPH_READ_CLIENT_ID: 'cccccccc-4444-4555-8666-dddddddddddd',
  PHISHY_GRAPH_READ_CERTIFICATE:
    'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf',
  PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED: 'true',
  PHISHY_GRAPH_BLAST_RADIUS_ENABLED: 'true',
  PHISHY_GRAPH_SENDER_HISTORY_ENABLED: 'true',
};
/** Settings the main function needs and the broker must not */
const MAIN_ONLY_ENV = [
  'ANTHROPIC_API_KEY',
  'PHISHY_AI_PROVIDER',
  'SENDER_EMAIL',
  'SECURITY_TEAM_DISTRIBUTION',
  'SAFE_DOMAINS',
  'SAFE_SENDERS',
  'S3_BUCKET_NAME',
  'PHISHY_DB_CONNECTION',
  'PHISHY_INTELLIGENCE_ENABLED',
  'PHISHY_CONFIG_S3',
  'PHISHY_GRAPH_MODE',
  'PHISHY_GRAPH_BROKER_FUNCTION',
];

const MAIN_CONFIG = {
  graph: {
    enabled: true,
    mode: 'broker' as const,
    brokerFunctionName: 'phishy-graph-broker',
    originalFetch: { enabled: true },
    blastRadius: { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 },
    senderHistory: {
      enabled: true,
      lookbackDays: 30,
      burstWindowHours: 24,
      budgetMs: 8000,
      fanoutMinRecipients: 15,
      fanoutMultiplier: 3,
    },
  },
  email: { safeDomains: SAFE_DOMAINS, safeSenders: [], deleteAfterProcessing: false },
};

function forwarded(headers: Record<string, string>): ExtractedEmailData {
  return {
    from_email: REPORTER,
    subject: `FW: ${SUBJECT}`,
    text: 'body',
    html: '',
    headers: { From: `Reporter <${REPORTER}>` },
    forwardedHeaders: headers,
    attachments: [],
    sender: REPORTER,
    to: 'phishy@example.com',
    original_sender: REPORTER,
    originalForwarder: REPORTER,
    links: [],
  };
}

const AUTHENTICATED = { authVerdicts: { spf: 'PASS', dkim: 'PASS' } } as EmailMessage;

describe('Graph broker', () => {
  const savedEnv: Record<string, string | undefined> = {};
  let broker: Broker;
  let gatewayModule: GatewayModule;
  let fakeModule: FakeModule;
  let metrics: Metrics;
  let createGraphReadClient: jest.Mock;
  let fake: FakeGraph;
  let respond: FakeResponder;
  let lines: string[];
  /** Requests the broker received, as parsed JSON */
  let invoked: unknown[];

  beforeAll(async () => {
    for (const name of [...Object.keys(BROKER_ENV), ...MAIN_ONLY_ENV, 'LOG_LEVEL']) {
      savedEnv[name] = process.env[name];
      delete process.env[name];
    }
    Object.assign(process.env, BROKER_ENV, { LOG_LEVEL: 'info' });

    jest.resetModules();
    fakeModule = await import('../../mocks/graph.fake');
    metrics = await import('../../../src/utils/metrics');
    ({ createGraphReadClient } =
      (await import('../../../src/services/graph/graph.credential')) as unknown as {
        createGraphReadClient: jest.Mock;
      });
    broker = await import('../../../src/handlers/graph.broker.handler');
    gatewayModule = await import('../../../src/services/graph/graph.gateway');
  });

  afterAll(() => {
    for (const [name, value] of Object.entries(savedEnv)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
    jest.resetModules();
  });

  beforeEach(() => {
    Object.assign(process.env, BROKER_ENV);
    broker.resetGraphBroker();
    respond = (): Response | undefined => undefined;
    fake = fakeModule.fakeGraph([(request): Response | undefined => respond(request)]);
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
  });

  /** Lambda `Invoke`, in process: JSON in, the handler, JSON out */
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

  const gateway = (): import('../../../src/services/graph/graph.gateway').GraphGateway =>
    gatewayModule.createGraphGateway(MAIN_CONFIG, { lambda: lambda() });

  const mailboxTenant = (): FakeResponder => request => {
    const { collection, jsonResponse } = fakeModule;
    const stored = {
      id: GRAPH_ID,
      internetMessageId: '<msg-7731@mail.example.org>',
      subject: SUBJECT,
      from: { emailAddress: { name: 'Billing', address: BILLING } },
      receivedDateTime: '2026-11-16T16:00:07Z',
      parentFolderId: 'folder-inbox',
      hasAttachments: false,
      body: { content: 'BODY-MUST-NOT-SURFACE' },
    };
    if (request.path === '/users/reporter%40example.com/messages') {
      return collection([stored]);
    }
    if (
      request.path ===
      '/users/reporter%40example.com/mailFolders/recoverableitemsdeletions/messages'
    ) {
      return collection([]);
    }
    if (request.path === `/users/reporter%40example.com/messages/${GRAPH_ID}`) {
      return jsonResponse({
        internetMessageHeaders: [
          { name: 'Received', value: 'from mx.example.com by mailbox.example.com' },
          { name: 'Authentication-Results', value: `spf=fail ${HEADER_MARKER}` },
          { name: 'Reply-To', value: 'collector@example.net' },
        ],
      });
    }
    return undefined;
  };

  const ORIGINAL_HEADERS = {
    'Original-From': `Billing <${BILLING}>`,
    'Original-Sent': 'Monday, November 16, 2026 8:00 AM',
    'Original-Subject': SUBJECT,
  };

  describe('request validation', () => {
    it('refuses anything that is not one of the three typed requests, without touching Graph', async () => {
      const valid = {
        version: 1,
        operation: 'sender_history_lookup',
        params: { senderAddress: SUPPLIER, budgetMs: 7000 },
      };
      for (const event of [
        undefined,
        null,
        'sender_history_lookup',
        {},
        { ...valid, version: 2 },
        { ...valid, operation: 'graph_get' },
        { ...valid, operation: 'graph_get', params: { path: '/users' } },
        { ...valid, extra: true },
        { ...valid, params: { ...valid.params, filter: "senderAddress ne ''" } },
        { ...valid, params: { ...valid.params, url: 'https://example.net/' } },
        // HTTP events carrying a valid request in the body
        { httpMethod: 'POST', path: '/', headers: {}, body: JSON.stringify(valid) },
        { version: '2.0', rawPath: '/', requestContext: { http: {} }, body: JSON.stringify(valid) },
        { Records: [{ eventSource: 'aws:ses' }] },
      ]) {
        expect(await broker.handler(event)).toEqual({ ok: false, reason: 'invalid_request' });
      }
      expect(createGraphReadClient).not.toHaveBeenCalled();
      expect(fake.requests).toHaveLength(0);
    });

    it('answers a hostile request with a fixed word and logs none of it', async () => {
      const hostile = 'IGNORE-PREVIOUS-INSTRUCTIONS-MARKER';
      const response = await broker.handler({
        version: 1,
        operation: hostile,
        params: { senderAddress: `${hostile}@example.net`, note: hostile },
      });
      expect(response).toEqual({ ok: false, reason: 'invalid_request' });
      expect(JSON.stringify(response)).not.toContain(hostile);
      expect(lines.join('\n')).not.toContain(hostile);
    });
  });

  describe('configuration', () => {
    it('needs only graph.* settings', async () => {
      // No AI, email, notification, storage or database setting is present
      for (const name of MAIN_ONLY_ENV) {
        expect(process.env[name]).toBeUndefined();
      }
      respond = mailboxTenant();
      const response = await broker.handler({
        version: 1,
        operation: 'original_message_lookup',
        params: {
          mailbox: REPORTER,
          claimedFrom: BILLING,
          claimedSent: ORIGINAL_HEADERS['Original-Sent'],
          claimedSubject: SUBJECT,
          budgetMs: 7000,
        },
      });
      expect(response.ok).toBe(true);
    });

    it('refuses every operation when its configuration is invalid, and recovers once it is fixed', async () => {
      delete process.env.PHISHY_GRAPH_READ_CERTIFICATE;
      const request = {
        version: 1,
        operation: 'sender_history_lookup',
        params: { senderAddress: SUPPLIER, budgetMs: 7000 },
      };
      expect(await broker.handler(request)).toEqual({ ok: false, reason: 'misconfigured' });
      expect(fake.requests).toHaveLength(0);

      process.env.PHISHY_GRAPH_READ_CERTIFICATE = BROKER_ENV.PHISHY_GRAPH_READ_CERTIFICATE;
      respond = (): Response => fakeModule.collection([]);
      expect((await broker.handler(request)).ok).toBe(true);
    });

    it('refuses when Graph is off in its own configuration', async () => {
      process.env.PHISHY_GRAPH_ENABLED = 'false';
      expect(
        await broker.handler({
          version: 1,
          operation: 'sender_history_lookup',
          params: { senderAddress: SUPPLIER, budgetMs: 7000 },
        })
      ).toEqual({ ok: false, reason: 'graph_disabled' });
      expect(createGraphReadClient).not.toHaveBeenCalled();
    });

    it.each([
      ['original_message_lookup', 'PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED'],
      ['blast_radius_lookup', 'PHISHY_GRAPH_BLAST_RADIUS_ENABLED'],
      ['sender_history_lookup', 'PHISHY_GRAPH_SENDER_HISTORY_ENABLED'],
    ])('refuses %s when its feature flag is off here', async (operation, flag) => {
      process.env[flag] = 'false';
      const params: Record<string, unknown> = {
        original_message_lookup: {
          mailbox: REPORTER,
          claimedFrom: BILLING,
          claimedSent: ORIGINAL_HEADERS['Original-Sent'],
          budgetMs: 7000,
        },
        blast_radius_lookup: {
          key: {
            senderAddress: BILLING,
            receivedFrom: new Date(Date.now() - 2 * DAY).toISOString(),
            receivedTo: new Date().toISOString(),
          },
          budgetMs: 40000,
        },
        sender_history_lookup: { senderAddress: SUPPLIER, budgetMs: 7000 },
      };
      expect(await broker.handler({ version: 1, operation, params: params[operation] })).toEqual({
        ok: false,
        reason: 'feature_disabled',
      });
      expect(fake.requests).toHaveLength(0);
    });

    it('reports a failure to build its services as a fixed word, without the detail', async () => {
      createGraphReadClient.mockImplementation(() => {
        throw new Error(`secret detail about ${REPORTER}`);
      });
      const response = await broker.handler({
        version: 1,
        operation: 'sender_history_lookup',
        params: { senderAddress: SUPPLIER, budgetMs: 7000 },
      });
      expect(response).toEqual({ ok: false, reason: 'misconfigured' });
      expect(lines.join('\n')).not.toContain('secret detail');
    });

    it('never throws: a defect in an operation is a fixed word too', async () => {
      const { SenderHistoryService } = await import('../../../src/services/graph/sender.history');
      jest.spyOn(SenderHistoryService.prototype, 'lookupSender').mockImplementation(() => {
        throw new Error(`secret detail about ${SUPPLIER}`);
      });
      const response = await broker.handler({
        version: 1,
        operation: 'sender_history_lookup',
        params: { senderAddress: SUPPLIER, budgetMs: 7000 },
      });
      expect(response).toEqual({ ok: false, reason: 'internal_error' });
      const output = lines.join('\n');
      expect(output).not.toContain('secret detail');
      expect(output).not.toContain(SUPPLIER);
    });
  });

  describe('original_message_lookup, end to end', () => {
    it('reads the original from the reporter’s mailbox and attaches its headers', async () => {
      respond = mailboxTenant();
      const fetchMetric = jest
        .spyOn(metrics, 'emitOriginalFetchMetric')
        .mockImplementation(() => undefined);
      const emailData = forwarded(ORIGINAL_HEADERS);
      const sink = {
        attachRetrievedOriginal: (data: ExtractedEmailData, original: unknown): void => {
          data.retrievedOriginal = original as ExtractedEmailData['retrievedOriginal'];
        },
      };

      const result = await gateway().enrichWithOriginalMessage(
        sink,
        AUTHENTICATED,
        emailData,
        SAFE_DOMAINS
      );

      expect(result.outcome).toBe('found');
      expect(emailData.retrievedOriginal?.location).toBe('mailbox');
      expect(emailData.retrievedOriginal?.receivedAt).toBe('2026-11-16T16:00:07.000Z');
      expect(emailData.retrievedOriginal?.headers.map(header => header.name)).toEqual([
        'Received',
        'Authentication-Results',
        'Reply-To',
      ]);
      expect(fetchMetric).toHaveBeenCalledTimes(1);
      expect(fetchMetric.mock.calls[0][0]).toBe('found');

      // What crossed: the confirmed mailbox, the bare claimed address, time, subject
      expect(invoked).toEqual([
        {
          version: 1,
          operation: 'original_message_lookup',
          params: {
            mailbox: REPORTER,
            claimedFrom: BILLING,
            claimedSent: ORIGINAL_HEADERS['Original-Sent'],
            claimedSubject: SUBJECT,
            budgetMs: 7000,
          },
        },
      ]);
      // And the same three GETs a direct lookup makes
      expect(fake.requests.map(request => request.method)).toEqual(['GET', 'GET', 'GET']);
    });

    it('does not ask the broker when the reporter is not confirmed or nothing is usable', async () => {
      respond = mailboxTenant();
      const sink = { attachRetrievedOriginal: jest.fn() };

      const unconfirmed = await gateway().enrichWithOriginalMessage(
        sink,
        {} as EmailMessage,
        forwarded(ORIGINAL_HEADERS),
        SAFE_DOMAINS
      );
      const noTime = await gateway().enrichWithOriginalMessage(
        sink,
        AUTHENTICATED,
        forwarded({ 'Original-From': BILLING, 'Original-Sent': '11/16/2026 8:00' }),
        SAFE_DOMAINS
      );

      expect(unconfirmed).toEqual({ outcome: 'skipped', reason: 'reporter_not_confirmed' });
      expect(noTime).toEqual({ outcome: 'skipped', reason: 'no_claimed_time' });
      expect(invoked).toHaveLength(0);
      expect(sink.attachRetrievedOriginal).not.toHaveBeenCalled();
    });

    it('logs counts and outcomes only', async () => {
      respond = mailboxTenant();
      const emailData = forwarded(ORIGINAL_HEADERS);
      await gateway().enrichWithOriginalMessage(
        { attachRetrievedOriginal: jest.fn() },
        AUTHENTICATED,
        emailData,
        SAFE_DOMAINS
      );

      const output = lines.join('\n');
      expect(output).toContain('Graph broker request finished');
      expect(output).toContain('"operation":"original_message_lookup"');
      for (const hostile of [REPORTER, BILLING, SUBJECT, HEADER_MARKER, 'collector@example.net']) {
        expect(output).not.toContain(hostile);
      }
    });
  });

  describe('sender_history_lookup, end to end', () => {
    const traceTenant = (): FakeResponder => request => {
      if (decodeURIComponent(request.path) !== TRACE_PATH) {
        return undefined;
      }
      const filter = request.query.$filter ?? '';
      const now = Date.now();
      if (filter.includes(`senderAddress eq '${SUPPLIER}'`)) {
        return fakeModule.collection(
          [5, 6, 7, 8].map(daysAgo => ({
            id: `in-${daysAgo}`,
            messageId: `<m${daysAgo}@supplier.example.net>`,
            senderAddress: SUPPLIER,
            recipientAddress: 'alice@example.com',
            subject: 'RFQ 1001',
            receivedDateTime: new Date(now - daysAgo * DAY).toISOString(),
            fromIP: '192.0.2.10',
            status: 'Delivered',
          }))
        );
      }
      if (filter.includes(`recipientAddress eq '${SUPPLIER}'`)) {
        return fakeModule.collection([
          {
            id: 'out-1',
            messageId: '<reply-1@example.com>',
            senderAddress: 'alice@example.com',
            recipientAddress: SUPPLIER,
            receivedDateTime: new Date(now - 4 * DAY).toISOString(),
            status: 'Delivered',
          },
        ]);
      }
      return fakeModule.collection([]);
    };

    it('returns the facts and emits the feature metric once, on the main side', async () => {
      respond = traceTenant();
      const historyMetric = jest
        .spyOn(metrics, 'emitSenderHistoryMetric')
        .mockImplementation(() => undefined);

      const facts = await gateway().lookupSenderHistory(
        forwarded({
          'Original-From': `Pat Doe <${SUPPLIER}>`,
          'Original-Date': new Date(Date.now() - HOUR).toUTCString(),
        })
      );

      expect(facts?.classification).toBe('established');
      expect(facts?.history.messages).toEqual({ count: 4, atLeast: false });
      expect(facts?.twoWay.messages).toEqual({ count: 1, atLeast: false });
      expect(historyMetric).toHaveBeenCalledTimes(1);
      expect(historyMetric.mock.calls[0][0]).toMatchObject({
        outcome: 'ok',
        classification: 'established',
        truncated: false,
        forbiddenRetries: 0,
      });

      const [request] = invoked as Array<{ operation: string; params: Record<string, unknown> }>;
      expect(request.operation).toBe('sender_history_lookup');
      expect(Object.keys(request.params).sort()).toEqual([
        'budgetMs',
        'claimedDate',
        'senderAddress',
      ]);
      expect(request.params.senderAddress).toBe(SUPPLIER);
      expect(request.params.budgetMs).toBe(7000);
      expect(fake.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
    });

    it('answers a repeat from the broker’s cache: the cache lives where the requests are made', async () => {
      respond = traceTenant();
      const historyMetric = jest
        .spyOn(metrics, 'emitSenderHistoryMetric')
        .mockImplementation(() => undefined);
      const emailData = forwarded({ 'Original-From': SUPPLIER });

      // Two separate main-function instances, one broker instance
      const first = await gateway().lookupSenderHistory(emailData);
      const graphRequests = fake.requests.length;
      const second = await gateway().lookupSenderHistory(emailData);

      expect(second).toEqual(first);
      expect(fake.requests).toHaveLength(graphRequests);
      expect(
        historyMetric.mock.calls.map(call => (call[0] as { outcome: string }).outcome)
      ).toEqual(['ok', 'cache_hit']);
    });

    it('does not ask about the organization’s own addresses, or anything that is not one address', async () => {
      respond = traceTenant();
      const historyMetric = jest
        .spyOn(metrics, 'emitSenderHistoryMetric')
        .mockImplementation(() => undefined);

      for (const from of ['Colleague <colleague@example.com>', 'a@x.example, b@y.example', '']) {
        expect(
          await gateway().lookupSenderHistory(forwarded({ 'Original-From': from }))
        ).toBeUndefined();
      }
      expect(invoked).toHaveLength(0);
      expect(
        historyMetric.mock.calls.map(call => (call[0] as { outcome: string }).outcome)
      ).toEqual(['skipped', 'skipped', 'skipped']);
    });

    it('carries a Graph failure back as the same outcome a direct lookup has', async () => {
      respond = (request: RecordedRequest): Response | undefined =>
        decodeURIComponent(request.path) === TRACE_PATH
          ? fakeModule.graphErrorResponse(500, 'ServiceUnavailable')
          : undefined;
      const historyMetric = jest
        .spyOn(metrics, 'emitSenderHistoryMetric')
        .mockImplementation(() => undefined);

      const facts = await gateway().lookupSenderHistory(
        forwarded({ 'Original-From': 'someone@other-supplier.example.net' })
      );

      expect(facts).toBeUndefined();
      expect(historyMetric).toHaveBeenCalledTimes(1);
      expect((historyMetric.mock.calls[0][0] as { outcome: string }).outcome).toBe('error');
    });
  });

  describe('blast_radius_lookup, end to end', () => {
    const user = (name: string): Record<string, unknown> => ({
      id: `id-${name}`,
      userPrincipalName: `${name}@example.com`,
      mail: `${name}@example.com`,
      userType: 'Member',
      accountEnabled: true,
      assignedPlans: [{ service: 'exchange', capabilityStatus: 'Enabled' }],
    });

    const tenant = (): FakeResponder => request => {
      const { collection, jsonResponse } = fakeModule;
      const path = decodeURIComponent(request.path);
      if (path === TRACE_PATH) {
        return collection([
          { recipientAddress: 'Alice@example.com', status: 'Delivered' },
          { recipientAddress: 'bob@example.com', status: 'FilteredAsSpam' },
        ]);
      }
      if (path === '/users') {
        return collection([user('alice'), user('bob'), user('carol')]);
      }
      const match = path.match(/^\/users\/id-([a-z]+)\/(.+)$/);
      if (!match) {
        return undefined;
      }
      const [, name, rest] = match;
      if (rest === 'messages') {
        return collection(
          name === 'alice'
            ? [
                {
                  id: 'msg-alice',
                  internetMessageId: '<m1@mail.example.org>',
                  subject: SUBJECT,
                  from: { emailAddress: { address: BILLING } },
                  receivedDateTime: new Date(Date.now() - DAY).toISOString(),
                  parentFolderId: 'folder-inbox',
                  isRead: true,
                },
              ]
            : []
        );
      }
      if (rest === 'mailFolders/recoverableitemsdeletions/messages') {
        return collection([]);
      }
      const folder = rest.match(/^mailFolders\/(inbox|junkemail|deleteditems)$/);
      if (folder) {
        return jsonResponse({
          id: `folder-${folder[1].replace('email', '').replace('items', '')}`,
        });
      }
      if (rest.startsWith('messages/')) {
        return jsonResponse({ id: 'msg-alice', singleValueExtendedProperties: undefined });
      }
      return undefined;
    };

    const malicious = (): ExtractedEmailData =>
      forwarded({
        'Original-From': `Billing <${BILLING}>`,
        'Original-Subject': SUBJECT,
        'Original-Date': new Date(Date.now() - DAY).toUTCString(),
      });

    it('returns the report, marks the reporter on the main side and emits the metric once', async () => {
      respond = tenant();
      const blastMetric = jest
        .spyOn(metrics, 'emitBlastRadiusMetric')
        .mockImplementation(() => undefined);

      const report = await gateway().lookupBlastRadius(malicious(), {
        remainingMs: 120_000,
        reporterAddress: 'Alice@example.com',
      });

      expect(report.status).toBe('complete');
      expect(report.route).toBe('trace');
      expect(report.matchedBy).toBe('senderSubject');
      expect(report.totals).toMatchObject({ recipients: 2, read: 1 });
      expect(report.recipients?.map(recipient => recipient.address)).toEqual([
        'alice@example.com',
        'bob@example.com',
      ]);
      expect(report.reporterAddress).toBe('alice@example.com');
      expect(blastMetric).toHaveBeenCalledTimes(1);
      expect(blastMetric.mock.calls[0][0]).toMatchObject({
        route: 'trace',
        outcome: 'complete',
        recipientsFound: 2,
        errors: 0,
        cached: false,
      });

      // The key and a budget cross; the reporter's address does not
      const [request] = invoked as Array<{ operation: string; params: Record<string, unknown> }>;
      expect(request.operation).toBe('blast_radius_lookup');
      expect(Object.keys(request.params).sort()).toEqual(['budgetMs', 'key']);
      expect(request.params.key).toMatchObject({ senderAddress: BILLING, subject: SUBJECT });
      // min(45 s budget, 120 s remaining - 20 s send reserve) - 1 s invocation overhead
      expect(request.params.budgetMs).toBe(44_000);
      expect(JSON.stringify(invoked)).not.toContain('alice@example.com');
      expect(fake.requests.every(r => r.method === 'GET')).toBe(true);
    });

    it('shrinks the budget to the time the main function has left, and does not ask without enough', async () => {
      respond = tenant();
      jest.spyOn(metrics, 'emitBlastRadiusMetric').mockImplementation(() => undefined);

      await gateway().lookupBlastRadius(malicious(), { remainingMs: 30_000 });
      const [request] = invoked as Array<{ params: { budgetMs: number } }>;
      expect(request.params.budgetMs).toBe(9000);

      const none = await gateway().lookupBlastRadius(malicious(), { remainingMs: 22_500 });
      expect(none.status).toBe('unavailable');
      expect(none.note).toContain('not enough processing time remained');
      expect(invoked).toHaveLength(1);
    });

    it('reports an unidentifiable message without asking', async () => {
      const blastMetric = jest
        .spyOn(metrics, 'emitBlastRadiusMetric')
        .mockImplementation(() => undefined);
      const report = await gateway().lookupBlastRadius(forwarded({}), { remainingMs: 120_000 });

      expect(report.status).toBe('unavailable');
      expect(report.note).toContain('could not be identified');
      expect(invoked).toHaveLength(0);
      expect(blastMetric.mock.calls[0][0]).toMatchObject({ route: 'none', outcome: 'unavailable' });
    });

    it('logs counts and outcomes only', async () => {
      respond = tenant();
      await gateway().lookupBlastRadius(malicious(), { remainingMs: 120_000 });

      const output = lines.join('\n');
      expect(output).toContain('"operation":"blast_radius_lookup"');
      for (const hostile of [BILLING, SUBJECT, 'alice@example.com', 'bob@example.com']) {
        expect(output).not.toContain(hostile);
      }
    });
  });

  describe('a broker that refuses', () => {
    it('leaves each feature as it is when Graph fails', async () => {
      process.env.PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED = 'false';
      process.env.PHISHY_GRAPH_BLAST_RADIUS_ENABLED = 'false';
      process.env.PHISHY_GRAPH_SENDER_HISTORY_ENABLED = 'false';
      const fetchMetric = jest
        .spyOn(metrics, 'emitOriginalFetchMetric')
        .mockImplementation(() => undefined);
      const historyMetric = jest
        .spyOn(metrics, 'emitSenderHistoryMetric')
        .mockImplementation(() => undefined);
      const blastMetric = jest
        .spyOn(metrics, 'emitBlastRadiusMetric')
        .mockImplementation(() => undefined);
      const callMetric = jest
        .spyOn(metrics, 'emitGraphBrokerCallMetric')
        .mockImplementation(() => undefined);
      const emailData = forwarded({
        ...ORIGINAL_HEADERS,
        'Original-Date': new Date(Date.now() - DAY).toUTCString(),
      });
      const sink = { attachRetrievedOriginal: jest.fn() };
      const main = gateway();

      const original = await main.enrichWithOriginalMessage(
        sink,
        AUTHENTICATED,
        emailData,
        SAFE_DOMAINS
      );
      const facts = await main.lookupSenderHistory(emailData);
      const report = await main.lookupBlastRadius(emailData, { remainingMs: 120_000 });

      expect(original).toEqual({ outcome: 'error', reason: 'broker_refused' });
      expect(sink.attachRetrievedOriginal).not.toHaveBeenCalled();
      expect(emailData.retrievedOriginal).toBeUndefined();
      expect(fetchMetric.mock.calls[0][0]).toBe('error');

      expect(facts).toBeUndefined();
      expect((historyMetric.mock.calls[0][0] as { outcome: string }).outcome).toBe('error');

      expect(report.status).toBe('unavailable');
      expect(report.note).toBe(
        'Blast radius lookup could not be completed: the Graph broker function did not return a usable answer.'
      );
      expect(blastMetric.mock.calls[0][0]).toMatchObject({
        route: 'none',
        outcome: 'unavailable',
        errors: 1,
      });

      expect(callMetric.mock.calls.map(call => call.slice(0, 2))).toEqual([
        ['original_message_lookup', 'refused'],
        ['sender_history_lookup', 'refused'],
        ['blast_radius_lookup', 'refused'],
      ]);
      expect(fake.requests).toHaveLength(0);
    });
  });
});

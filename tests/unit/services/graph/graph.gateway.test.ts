/**
 * The Graph gateway: which implementation configuration selects, that the
 * direct one only delegates, and that every way a broker call can fail is
 * the feature's ordinary failure, with the feature's own metric.
 *
 * No Graph, no AWS: the broker client is a stub. Invented data only.
 */

import { BrokerGraphGateway } from '../../../../src/services/graph/broker.gateway';
import {
  GraphBrokerCallFailure,
  GraphBrokerClient,
} from '../../../../src/services/graph/broker.client';
import * as credential from '../../../../src/services/graph/graph.credential';
import {
  DirectGraphGateway,
  createGraphGateway,
} from '../../../../src/services/graph/graph.gateway';
import { EmailMessage, ExtractedEmailData } from '../../../../src/types';
import * as metrics from '../../../../src/utils/metrics';

const REPORTER = 'reporter@example.com';
const SENDER = 'pat@supplier.example.net';
const SAFE_DOMAINS = ['example.com'];
const EMAIL = { safeDomains: SAFE_DOMAINS, safeSenders: [], deleteAfterProcessing: false };
const AUTHENTICATED = { authVerdicts: { spf: 'PASS' } } as EmailMessage;

const FAILURES: GraphBrokerCallFailure[] = [
  'timeout',
  'throttled',
  'invoke_error',
  'function_error',
  'oversized',
  'malformed',
  'refused',
  'invalid_request',
];

function email(): ExtractedEmailData {
  return {
    from_email: REPORTER,
    subject: 'FW: RFQ 1001',
    text: '',
    html: '',
    headers: { From: `Reporter <${REPORTER}>` },
    forwardedHeaders: {
      'Original-From': `Pat Doe <${SENDER}>`,
      'Original-Sent': 'Monday, November 16, 2026 8:00 AM',
      'Original-Subject': 'RFQ 1001',
    },
    attachments: [],
    sender: REPORTER,
    to: 'phishy@example.com',
    original_sender: REPORTER,
    originalForwarder: REPORTER,
    links: [],
  };
}

function stubBroker(answer: unknown): { broker: GraphBrokerClient; call: jest.Mock } {
  const call = jest.fn().mockResolvedValue(answer);
  return { broker: { call } as unknown as GraphBrokerClient, call };
}

function brokerGateway(broker: GraphBrokerClient): BrokerGraphGateway {
  return new BrokerGraphGateway(broker, {
    originalFetch: true,
    senderHistoryBudgetMs: 8000,
    blastRadiusTimeBudgetMs: 45000,
    safeDomains: SAFE_DOMAINS,
    safeSenders: [],
  });
}

describe('createGraphGateway', () => {
  it('is direct by default and has nothing on while Graph is off', () => {
    const build = jest.spyOn(credential, 'createGraphReadClient');
    const gateway = createGraphGateway({ graph: undefined, email: EMAIL });

    expect(gateway).toBeInstanceOf(DirectGraphGateway);
    expect(gateway.mode).toBe('direct');
    expect([gateway.originalFetch, gateway.senderHistory, gateway.blastRadius]).toEqual([
      false,
      false,
      false,
    ]);
    expect(build.mock.results.every(result => result.value === undefined)).toBe(true);
  });

  it('builds a client per enabled feature in direct mode', () => {
    const gateway = createGraphGateway({
      graph: {
        enabled: true,
        tenantId: 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb',
        read: { clientId: 'cccccccc-4444-4555-8666-dddddddddddd', certificate: 'unused' },
        originalFetch: { enabled: true },
        blastRadius: { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 },
      },
      email: EMAIL,
    });

    expect(gateway.mode).toBe('direct');
    expect([gateway.originalFetch, gateway.senderHistory, gateway.blastRadius]).toEqual([
      true,
      false,
      true,
    ]);
  });

  it('builds no Graph client in broker mode, whatever is enabled', () => {
    const readClient = jest.spyOn(credential, 'createGraphReadClient');
    const anyClient = jest.spyOn(credential, 'createGraphClient');
    const gateway = createGraphGateway({
      graph: {
        enabled: true,
        mode: 'broker',
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
      email: EMAIL,
    });

    expect(gateway).toBeInstanceOf(BrokerGraphGateway);
    expect(gateway.mode).toBe('broker');
    expect([gateway.originalFetch, gateway.senderHistory, gateway.blastRadius]).toEqual([
      true,
      true,
      true,
    ]);
    expect(readClient).not.toHaveBeenCalled();
    expect(anyClient).not.toHaveBeenCalled();
  });

  it('follows the feature flags in broker mode, and has nothing on while Graph is off', () => {
    const some = createGraphGateway({
      graph: {
        enabled: true,
        mode: 'broker',
        brokerFunctionName: 'phishy-graph-broker',
        originalFetch: { enabled: false },
        blastRadius: { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 },
      },
      email: EMAIL,
    });
    expect([some.originalFetch, some.senderHistory, some.blastRadius]).toEqual([
      false,
      false,
      true,
    ]);

    const off = createGraphGateway({
      graph: { enabled: false, mode: 'broker', originalFetch: { enabled: true } },
      email: EMAIL,
    });
    expect(off.mode).toBe('broker');
    expect([off.originalFetch, off.senderHistory, off.blastRadius]).toEqual([false, false, false]);
  });
});

describe('DirectGraphGateway', () => {
  it('hands each call to the existing service, unchanged', async () => {
    const lookupForEmail = jest.fn().mockResolvedValue({ classification: 'established' });
    const lookup = jest.fn().mockResolvedValue({ status: 'complete' });
    const gateway = new DirectGraphGateway({
      senderHistory: { lookupForEmail },
      blastRadius: { lookup },
    });
    const emailData = email();
    const options = { remainingMs: 90_000, reporterAddress: REPORTER };

    expect(await gateway.lookupSenderHistory(emailData)).toEqual({ classification: 'established' });
    expect(await gateway.lookupBlastRadius(emailData, options)).toEqual({ status: 'complete' });

    expect(lookupForEmail).toHaveBeenCalledWith(emailData);
    expect(lookup).toHaveBeenCalledWith(emailData, options);
    expect(gateway.originalFetch).toBe(false);
  });

  it('does nothing for a feature that is off', async () => {
    const gateway = new DirectGraphGateway({});
    const sink = { attachRetrievedOriginal: jest.fn() };

    expect(
      await gateway.enrichWithOriginalMessage(sink, AUTHENTICATED, email(), SAFE_DOMAINS)
    ).toEqual({ outcome: 'skipped', reason: 'feature_off' });
    expect(await gateway.lookupSenderHistory(email())).toBeUndefined();
    expect((await gateway.lookupBlastRadius(email(), {})).status).toBe('unavailable');
    expect(sink.attachRetrievedOriginal).not.toHaveBeenCalled();
  });
});

describe('BrokerGraphGateway when the broker call fails', () => {
  let fetchMetric: jest.SpyInstance;
  let historyMetric: jest.SpyInstance;
  let blastMetric: jest.SpyInstance;

  beforeEach(() => {
    fetchMetric = jest
      .spyOn(metrics, 'emitOriginalFetchMetric')
      .mockImplementation(() => undefined);
    historyMetric = jest
      .spyOn(metrics, 'emitSenderHistoryMetric')
      .mockImplementation(() => undefined);
    blastMetric = jest.spyOn(metrics, 'emitBlastRadiusMetric').mockImplementation(() => undefined);
  });

  it.each(FAILURES)(
    'original-message lookup: %s is an error outcome, nothing attached',
    async failure => {
      const { broker, call } = stubBroker({ ok: false, failure });
      const sink = { attachRetrievedOriginal: jest.fn() };
      const emailData = email();

      const result = await brokerGateway(broker).enrichWithOriginalMessage(
        sink,
        AUTHENTICATED,
        emailData,
        SAFE_DOMAINS
      );

      expect(result).toEqual({ outcome: 'error', reason: `broker_${failure}` });
      expect(sink.attachRetrievedOriginal).not.toHaveBeenCalled();
      expect(emailData.retrievedOriginal).toBeUndefined();
      expect(fetchMetric).toHaveBeenCalledTimes(1);
      expect(fetchMetric.mock.calls[0][0]).toBe('error');
      // The whole 8 s budget is the wait; the broker is asked for 1 s less
      expect(call).toHaveBeenCalledWith(
        'original_message_lookup',
        expect.objectContaining({ mailbox: REPORTER, claimedFrom: SENDER, budgetMs: 7000 }),
        8000
      );
    }
  );

  it.each(FAILURES)(
    'sender history: %s yields no facts and a timeout or error metric',
    async failure => {
      const { broker, call } = stubBroker({ ok: false, failure });

      expect(await brokerGateway(broker).lookupSenderHistory(email())).toBeUndefined();

      expect(historyMetric).toHaveBeenCalledTimes(1);
      expect(historyMetric.mock.calls[0][0].outcome).toBe(
        failure === 'timeout' ? 'timeout' : 'error'
      );
      expect(call).toHaveBeenCalledWith(
        'sender_history_lookup',
        { senderAddress: SENDER, claimedDate: 'Monday, November 16, 2026 8:00 AM', budgetMs: 7000 },
        8000
      );
    }
  );

  it.each(FAILURES)('blast radius: %s is an unavailable report with a note', async failure => {
    const { broker, call } = stubBroker({ ok: false, failure });

    const report = await brokerGateway(broker).lookupBlastRadius(email(), {
      remainingMs: 50_000,
      reporterAddress: 'Reporter@Example.com',
    });

    expect(report.status).toBe('unavailable');
    expect(report.note).toBe(
      failure === 'timeout'
        ? 'Blast radius lookup could not be completed: it ran out of time before any result.'
        : 'Blast radius lookup could not be completed: the Graph broker function did not return a usable answer.'
    );
    expect(report.recipients).toBeUndefined();
    expect(report.reporterAddress).toBe(REPORTER);
    expect(blastMetric).toHaveBeenCalledTimes(1);
    expect(blastMetric.mock.calls[0][0]).toMatchObject({
      route: 'none',
      outcome: 'unavailable',
      errors: 1,
      cached: false,
    });
    // 50 s remaining - 20 s send reserve = 30 s to wait; the broker gets 29 s
    expect(call).toHaveBeenCalledWith(
      'blast_radius_lookup',
      expect.objectContaining({ budgetMs: 29_000 }),
      30_000
    );
  });

  it('never throws, even when the broker client does', async () => {
    const call = jest.fn().mockRejectedValue(new Error('defect'));
    const gateway = brokerGateway({ call } as unknown as GraphBrokerClient);
    const sink = { attachRetrievedOriginal: jest.fn() };

    expect(
      (await gateway.enrichWithOriginalMessage(sink, AUTHENTICATED, email(), SAFE_DOMAINS)).outcome
    ).toBe('error');
    expect(await gateway.lookupSenderHistory(email())).toBeUndefined();
    expect((await gateway.lookupBlastRadius(email(), { remainingMs: 60_000 })).status).toBe(
      'unavailable'
    );
    expect(historyMetric.mock.calls[0][0]).toEqual({ outcome: 'error', durationMs: 0 });
    expect(blastMetric.mock.calls[0][0]).toMatchObject({ outcome: 'unavailable', errors: 1 });
  });

  it('uses what the broker returned only as validated by the client', async () => {
    // The gateway is handed a parsed result; here: a cached sender-history answer
    const facts = {
      classification: 'established',
      lookbackDays: 30,
      burstWindowHours: 24,
      truncated: true,
    };
    const { broker } = stubBroker({
      ok: true,
      result: { outcome: 'cache_hit', facts, forbiddenRetries: 2, filterMismatch: false },
    });

    expect(await brokerGateway(broker).lookupSenderHistory(email())).toBe(facts);
    expect(historyMetric.mock.calls[0][0]).toMatchObject({
      outcome: 'cache_hit',
      classification: 'established',
      truncated: true,
      forbiddenRetries: 2,
      filterMismatch: false,
    });
  });
});

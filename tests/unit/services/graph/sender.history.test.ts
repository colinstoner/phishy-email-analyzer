/**
 * Sender-relationship check: address validation, windowing, fact computation,
 * classification, and the bounded lookup (a real GraphClient over a mocked
 * fetch; no network). Invented data only.
 */

import {
  CACHE_TTL_MS,
  FORBIDDEN_COOLDOWN_MS,
  FORBIDDEN_RETRIES,
  FORBIDDEN_RETRY_DELAY_MS,
  GraphAccessTokenProvider,
  GraphClient,
  MAX_REPORTED_BURST_IPS,
  MessageTrace,
  REQUEST_ALLOWANCE_PER_5_MIN,
  SenderHistoryService,
  SenderHistorySettings,
  TRACE_MAX_WINDOW_MS,
  TraceRows,
  claimedSenderAddress,
  classifySenderRelationship,
  computeSenderHistoryFacts,
  createSenderHistoryService,
  listMessageTracesByRecipient,
  listMessageTracesBySenderDomain,
  resolveEmailTime,
  splitTraceWindows,
} from '../../../../src/services/graph';
import { ExtractedEmailData } from '../../../../src/types';
import * as metrics from '../../../../src/utils/metrics';
import {
  FakeResponder,
  RecordedRequest,
  collection,
  fakeGraph,
  graphErrorResponse,
} from '../../../mocks/graph.fake';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const NOW = Date.parse('2026-11-17T12:00:00Z');
const SENDER = 'pat@supplier.example.net';
const TRACE_PATH = '/admin/exchange/tracing/messageTraces';

const SETTINGS: SenderHistorySettings = {
  lookbackDays: 30,
  burstWindowHours: 24,
  budgetMs: 8000,
  includeDomain: true,
  freeMailDomains: [],
  fanoutMinRecipients: 10,
  fanoutMultiplier: 3,
  safeDomains: ['example.com'],
  safeSenders: ['partner@safelisted.example.org'],
};

function email(from: string | undefined, extra: Record<string, string> = {}): ExtractedEmailData {
  return {
    from_email: 'reporter@example.com',
    subject: 'FW: RFQ 1001',
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: { ...(from === undefined ? {} : { 'Original-From': from }), ...extra },
    attachments: [],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: 'reporter@example.com',
    originalForwarder: 'reporter@example.com',
    links: [],
  };
}

let rowSeq = 0;
function inboundRow(
  atMs: number,
  recipient: string,
  extra: Partial<MessageTrace> = {}
): MessageTrace {
  rowSeq++;
  return {
    id: `row-${rowSeq}`,
    messageId: `<m${rowSeq}@supplier.example.net>`,
    senderAddress: SENDER,
    recipientAddress: recipient,
    receivedDateTime: new Date(atMs).toISOString(),
    fromIP: '192.0.2.10',
    status: 'delivered',
    ...extra,
  };
}

function rows(list: MessageTrace[], truncated: Partial<TraceRows> = {}): TraceRows {
  return { rows: list, historyTruncated: false, burstTruncated: false, ...truncated };
}

const BASE = {
  startMs: NOW - 30 * DAY,
  burstStartMs: NOW - DAY,
  nowMs: NOW,
  lookbackDays: 30,
  fanoutMinRecipients: 10,
  fanoutMultiplier: 3,
};

/** A blast inside the burst window to `count` distinct recipients, as one message each */
function blast(count: number, extra: Partial<MessageTrace> = {}): MessageTrace[] {
  return Array.from({ length: count }, (_, i) =>
    inboundRow(NOW - HOUR, `person${i}@example.com`, extra)
  );
}

describe('claimedSenderAddress', () => {
  it('extracts one ordinary address, lower-cased', () => {
    expect(claimedSenderAddress('Pat Doe <Pat@Supplier.Example.NET>')).toBe(SENDER);
    expect(claimedSenderAddress(SENDER)).toBe(SENDER);
    expect(claimedSenderAddress(`Pat Doe [mailto:${SENDER}]`)).toBe(SENDER);
    expect(claimedSenderAddress(`Pat Doe <${SENDER}<mailto:${SENDER}>>`)).toBe(SENDER);
    expect(claimedSenderAddress(`From ${SENDER}.`)).toBe(SENDER);
  });

  it('takes the bracketed address when the display name looks like one', () => {
    expect(claimedSenderAddress('"ceo@example.com" <intruder@evil.example.org>')).toBe(
      'intruder@evil.example.org'
    );
  });

  it('refuses anything that is not exactly one plain ASCII address', () => {
    for (const value of [
      undefined,
      42,
      '',
      'Pat Doe',
      'a@example.net, b@example.net',
      '<a@example.net> <b@example.net>',
      "<x' or senderAddress ne '@example.net>",
      '<pаt@supplier.example.net>', // Cyrillic "а"
      '<pat@localhost>',
      '<pat@-bad-.example.net>',
      `<${'a'.repeat(65)}@example.net>`,
      `<pat@${'a'.repeat(250)}.example.net>`,
      'x'.repeat(1001),
    ]) {
      expect(claimedSenderAddress(value)).toBeUndefined();
    }
  });

  it('takes only the address out of surrounding junk', () => {
    expect(claimedSenderAddress('<pat@supplier.example.net) or (1 eq 1>')).toBe(SENDER);
  });

  it('keeps a quote that is legal in a local part (escaping is the filter helper’s job)', () => {
    expect(claimedSenderAddress("<o'neil@supplier.example.net>")).toBe(
      "o'neil@supplier.example.net"
    );
  });
});

describe('resolveEmailTime', () => {
  it('uses a parseable claimed date within the last 7 days', () => {
    expect(resolveEmailTime('Mon, 16 Nov 2026 09:00:00 +0000', NOW)).toBe(
      Date.parse('2026-11-16T09:00:00Z')
    );
  });

  it('clamps a hostile date: never in the future, never more than 7 days back', () => {
    expect(resolveEmailTime('Tue, 01 Dec 2037 09:00:00 +0000', NOW)).toBe(NOW);
    expect(resolveEmailTime('Thu, 01 Jan 2015 09:00:00 +0000', NOW)).toBe(NOW - 7 * DAY);
  });

  it('falls back to now for anything unparseable', () => {
    expect(resolveEmailTime('yesterday-ish', NOW)).toBe(NOW);
    expect(resolveEmailTime(undefined, NOW)).toBe(NOW);
    expect(resolveEmailTime('2'.repeat(200), NOW)).toBe(NOW);
  });
});

describe('splitTraceWindows', () => {
  it('covers the range in windows of at most 10 days, newest first', () => {
    const windows = splitTraceWindows(NOW - 30 * DAY, NOW);
    expect(windows).toHaveLength(3);
    expect(windows[0].receivedTo.getTime()).toBe(NOW);
    expect(windows[2].receivedFrom.getTime()).toBe(NOW - 30 * DAY);
    for (const window of windows) {
      expect(window.receivedTo.getTime() - window.receivedFrom.getTime()).toBeLessThanOrEqual(
        TRACE_MAX_WINDOW_MS
      );
    }
    expect(splitTraceWindows(NOW - 14 * DAY, NOW)).toHaveLength(2);
    expect(splitTraceWindows(NOW - 90 * DAY, NOW)).toHaveLength(9);
  });
});

describe('computeSenderHistoryFacts', () => {
  it('reports no_history when nothing was exchanged', () => {
    const facts = computeSenderHistoryFacts({ ...BASE, inbound: rows([]), outbound: rows([]) });
    expect(facts.classification).toBe('no_history');
    expect(facts.history.messages).toEqual({ count: 0, atLeast: false });
    expect(facts.burst.newRecipients).toEqual({ count: 0, atLeast: false });
    expect(facts.history.firstSeen).toBeUndefined();
    expect(facts.domain).toBeUndefined();
    expect(facts.truncated).toBe(false);
    expect(facts.burstWindowHours).toBe(24);
  });

  it('counts messages, distinct recipients and first-seen in the history period', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([
        inboundRow(NOW - 20 * DAY, 'alex@example.com', { messageId: '<a@x>' }),
        inboundRow(NOW - 20 * DAY, 'sam@example.com', { messageId: '<a@x>' }),
        inboundRow(NOW - 10 * DAY, 'Alex@Example.com', { messageId: '<b@x>' }),
        inboundRow(NOW - 5 * DAY, 'alex@example.com', { messageId: '<c@x>' }),
      ]),
      outbound: rows([]),
    });
    expect(facts.history.messages.count).toBe(3);
    expect(facts.history.recipients.count).toBe(2);
    expect(facts.history.firstSeen).toBe('2026-10-28');
    expect(facts.classification).toBe('established');
  });

  it('is limited_history below the thresholds, established once there is two-way contact', () => {
    const one = [inboundRow(NOW - 5 * DAY, 'alex@example.com')];
    expect(
      computeSenderHistoryFacts({ ...BASE, inbound: rows(one), outbound: rows([]) }).classification
    ).toBe('limited_history');

    const reply = inboundRow(NOW - 4 * DAY, SENDER, { senderAddress: 'alex@example.com' });
    const twoWay = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows(one),
      outbound: rows([reply]),
    });
    expect(twoWay.classification).toBe('established');
    expect(twoWay.twoWay.internalSenders.count).toBe(1);

    // Mail to the address with nothing coming back is a relationship, but a thin one
    expect(
      computeSenderHistoryFacts({ ...BASE, inbound: rows([]), outbound: rows([reply]) })
        .classification
    ).toBe('limited_history');
  });

  it('ignores replies sent during the burst when judging two-way contact', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([inboundRow(NOW - 5 * DAY, 'alex@example.com')]),
      outbound: rows([inboundRow(NOW - HOUR, SENDER, { senderAddress: 'alex@example.com' })]),
    });
    expect(facts.twoWay.messages.count).toBe(0);
    expect(facts.classification).toBe('limited_history');
  });

  it('flags anomalous fan-out from an established sender', () => {
    const history = [
      inboundRow(NOW - 20 * DAY, 'person0@example.com'),
      inboundRow(NOW - 12 * DAY, 'person0@example.com'),
      inboundRow(NOW - 6 * DAY, 'person1@example.com'),
    ];
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([...history, ...blast(40, { fromIP: '198.51.100.7' })]),
      outbound: rows([]),
    });
    expect(facts.classification).toBe('established_with_anomalous_fanout');
    expect(facts.burst.recipients).toEqual({ count: 40, atLeast: false });
    expect(facts.burst.newRecipients).toEqual({ count: 38, atLeast: false });
    expect(facts.sendingIps).toEqual({
      burst: 1,
      seenInHistory: 0,
      historyComplete: true,
      burstIps: [{ ip: '198.51.100.7', seenInHistory: false }],
    });
  });

  it('carries the burst IPs for the security copy: unseen first, capped, shape-checked', () => {
    const history = [
      inboundRow(NOW - 5 * DAY, 'a@example.com', { fromIP: '192.0.2.10' }),
      inboundRow(NOW - 6 * DAY, 'a@example.com', { fromIP: '2001:db8::10' }),
    ];
    const burst = [
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: '192.0.2.10' }),
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: '2001:db8::10' }),
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: '203.0.113.9' }),
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: '<img src=x onerror=1>' }),
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: 'not an ip' }),
    ];
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([...history, ...burst]),
      outbound: rows([]),
    });
    expect(facts.sendingIps).toEqual({
      burst: 5,
      seenInHistory: 2,
      historyComplete: true,
      burstIps: [
        { ip: '203.0.113.9', seenInHistory: false },
        { ip: '192.0.2.10', seenInHistory: true },
        { ip: '2001:db8::10', seenInHistory: true },
      ],
      // Counted, but never carried as text: they are not shaped like an IP
      burstIpsOmitted: 2,
    });

    const many = Array.from({ length: MAX_REPORTED_BURST_IPS + 7 }, (_, i) =>
      inboundRow(NOW - HOUR, 'a@example.com', { fromIP: `198.51.100.${i + 1}` })
    );
    const capped = computeSenderHistoryFacts({ ...BASE, inbound: rows(many), outbound: rows([]) });
    expect(capped.sendingIps.burst).toBe(MAX_REPORTED_BURST_IPS + 7);
    expect(capped.sendingIps.burstIps).toHaveLength(MAX_REPORTED_BURST_IPS);
    expect(capped.sendingIps.burstIpsOmitted).toBe(7);
  });

  it('carries no IP list when the burst recorded none', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([inboundRow(NOW - HOUR, 'a@example.com', { fromIP: undefined })]),
      outbound: rows([]),
    });
    expect(facts.sendingIps).toEqual({ burst: 0, seenInHistory: 0, historyComplete: true });
  });

  it('does not flag fan-out that reaches the sender’s usual recipients', () => {
    const history = blast(12).map((row, i) => ({
      ...row,
      id: `h-${i}`,
      receivedDateTime: new Date(NOW - 10 * DAY).toISOString(),
    }));
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([...history, ...blast(12)]),
      outbound: rows([]),
    });
    expect(facts.classification).toBe('established');
    expect(facts.burst.newRecipients?.count).toBe(0);
    expect(facts.sendingIps.seenInHistory).toBe(1);
  });

  it('counts a distribution-list expansion as a message, not a recipient', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([
        inboundRow(NOW - HOUR, 'all-staff@example.com', { messageId: '<dl@x>', status: 'expanded' }),
        inboundRow(NOW - HOUR, 'alex@example.com', { messageId: '<dl@x>' }),
        inboundRow(NOW - HOUR, 'sam@example.com', { messageId: '<dl@x>', status: 'failed' }),
      ]),
      outbound: rows([]),
    });
    expect(facts.burst.messages.count).toBe(1);
    expect(facts.burst.recipients.count).toBe(2);
  });

  it('drops duplicate rows, rows outside the lookback and rows without a usable date', () => {
    const row = inboundRow(NOW - 5 * DAY, 'alex@example.com');
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([
        row,
        { ...row },
        inboundRow(NOW - 40 * DAY, 'old@example.com'),
        inboundRow(NOW - 5 * DAY, 'nodate@example.com', { receivedDateTime: 'not a date' }),
        inboundRow(NOW - 5 * DAY, 'nodate2@example.com', { receivedDateTime: undefined }),
      ]),
      outbound: rows([]),
    });
    expect(facts.history.messages.count).toBe(1);
    expect(facts.history.recipients.count).toBe(1);
  });

  it('never presents a truncated count as exact, and never calls recipients new against a truncated history', () => {
    const history = Array.from({ length: 5 }, (_, i) => inboundRow(NOW - (i + 3) * DAY, 'a@example.com'));
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([...history, ...blast(40)], { historyTruncated: true }),
      outbound: rows([], { historyTruncated: true }),
      domain: rows(history, { historyTruncated: true }),
    });
    expect(facts.truncated).toBe(true);
    expect(facts.history.messages).toEqual({ count: 5, atLeast: true });
    expect(facts.history.recipients.atLeast).toBe(true);
    expect(facts.twoWay.messages.atLeast).toBe(true);
    expect(facts.domain?.messages).toEqual({ count: 5, atLeast: true });
    expect(facts.burst.newRecipients).toBeNull();
    expect(facts.sendingIps.historyComplete).toBe(false);
    // Fan-out cannot be judged, so the class stays at what is known
    expect(facts.classification).toBe('established');
  });

  it('marks burst counts as minimums when the burst window was cut short', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows(blast(20), { burstTruncated: true }),
      outbound: rows([]),
    });
    expect(facts.burst.recipients).toEqual({ count: 20, atLeast: true });
    expect(facts.burst.newRecipients).toEqual({ count: 20, atLeast: true });
    expect(facts.history.messages.atLeast).toBe(false);
  });

  it('computes domain-level history from the history period only', () => {
    const facts = computeSenderHistoryFacts({
      ...BASE,
      inbound: rows([]),
      outbound: rows([]),
      domain: rows([
        inboundRow(NOW - 9 * DAY, 'alex@example.com', { senderAddress: 'kim@supplier.example.net' }),
        inboundRow(NOW - HOUR, 'sam@example.com', { senderAddress: 'kim@supplier.example.net' }),
      ]),
    });
    expect(facts.domain).toEqual({
      messages: { count: 1, atLeast: false },
      recipients: { count: 1, atLeast: false },
      firstSeen: '2026-11-08',
    });
    expect(facts.classification).toBe('no_history');
  });
});

describe('classifySenderRelationship thresholds', () => {
  const established = {
    historyMessages: 5,
    historyRecipients: 3,
    historyTruncated: false,
    twoWayMessages: 0,
    burstRecipients: 10,
    newRecipients: 5,
    fanoutMinRecipients: 10,
    fanoutMultiplier: 3,
  };

  it('needs all three fan-out conditions', () => {
    expect(classifySenderRelationship(established)).toBe('established_with_anomalous_fanout');
    expect(classifySenderRelationship({ ...established, burstRecipients: 9 })).toBe('established');
    expect(classifySenderRelationship({ ...established, historyRecipients: 4 })).toBe(
      'established'
    );
    expect(classifySenderRelationship({ ...established, newRecipients: 4 })).toBe('established');
  });

  it('honours configured thresholds', () => {
    expect(
      classifySenderRelationship({
        ...established,
        burstRecipients: 6,
        newRecipients: 6,
        fanoutMinRecipients: 5,
        fanoutMultiplier: 2,
      })
    ).toBe('established_with_anomalous_fanout');
  });

  it('never calls a sender without history anomalous', () => {
    expect(
      classifySenderRelationship({ ...established, historyMessages: 0, historyRecipients: 0 })
    ).toBe('no_history');
    expect(
      classifySenderRelationship({ ...established, historyMessages: 2, historyRecipients: 1 })
    ).toBe('limited_history');
  });
});

describe('new trace operations', () => {
  const window = {
    receivedFrom: new Date('2026-11-10T00:00:00Z'),
    receivedTo: new Date('2026-11-17T00:00:00Z'),
    now: new Date(NOW),
  };
  const range =
    'receivedDateTime ge 2026-11-10T00:00:00Z and receivedDateTime le 2026-11-17T00:00:00Z';

  it('traces by recipient and by sender domain, escaping the value', async () => {
    const graph = fakeGraph([() => collection([])]);
    await listMessageTracesByRecipient(graph.client, {
      ...window,
      recipientAddress: "o'neil@supplier.example.net",
      maxPages: 2,
    });
    await listMessageTracesBySenderDomain(graph.client, {
      ...window,
      senderDomain: 'supplier.example.net',
    });
    expect(graph.requests.map(r => r.query.$filter)).toEqual([
      `${range} and recipientAddress eq 'o''neil@supplier.example.net'`,
      `${range} and endswith(senderAddress, '@supplier.example.net')`,
    ]);
    expect(graph.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
  });

  it('refuses a bad page cap or a domain that is not bare', async () => {
    const graph = fakeGraph([() => collection([])]);
    await expect(
      listMessageTracesByRecipient(graph.client, { ...window, recipientAddress: SENDER, maxPages: 6 })
    ).rejects.toThrow('maxPages');
    await expect(
      listMessageTracesBySenderDomain(graph.client, { ...window, senderDomain: 'a@example.net' })
    ).rejects.toThrow('bare domain');
    expect(graph.requests).toHaveLength(0);
  });

  it('stops at the caller’s deadline without sending anything further', async () => {
    const graph = fakeGraph([() => collection([])]);
    const controller = new AbortController();
    controller.abort();
    const error = await listMessageTracesByRecipient(graph.client, {
      ...window,
      recipientAddress: SENDER,
      signal: controller.signal,
    }).catch((e: unknown) => e);
    expect(error).toMatchObject({ name: 'GraphError', kind: 'timeout' });
    expect(graph.requests).toHaveLength(0);
  });
});

describe('SenderHistoryService', () => {
  let metricSpy: jest.SpyInstance;
  let clock: number;
  const now = (): number => clock;

  beforeEach(() => {
    clock = NOW + 400; // not on a whole second, on purpose
    metricSpy = jest.spyOn(metrics, 'emitSenderHistoryMetric').mockImplementation(() => undefined);
  });

  const outcomes = (): string[] =>
    metricSpy.mock.calls.map(call => (call[0] as metrics.SenderHistoryMetric).outcome);

  /** Answer by query type: inbound by sender, outbound by recipient, domain-level */
  function traceResponder(data: {
    inbound?: MessageTrace[];
    outbound?: MessageTrace[];
    domain?: MessageTrace[];
  }): FakeResponder {
    return (request: RecordedRequest) => {
      const filter = request.query.$filter ?? '';
      const newest = filter.includes('receivedDateTime le 2026-11-17T12:00:00Z');
      if (filter.includes('senderAddress eq')) {
        return collection(newest ? (data.inbound ?? []) : []);
      }
      if (filter.includes('recipientAddress eq')) {
        return collection(newest ? (data.outbound ?? []) : []);
      }
      return collection(newest ? (data.domain ?? []) : []);
    };
  }

  it('makes 9 GET requests for a 30-day lookup with domain history, all code-built', async () => {
    const graph = fakeGraph([traceResponder({ inbound: blast(3) })]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });

    const facts = await service.lookupForEmail(email(`Pat <${SENDER}>`));

    expect(facts?.burst.recipients.count).toBe(3);
    expect(graph.requests).toHaveLength(9);
    expect(graph.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
    expect(graph.requests.every(r => r.query.$top === '2000')).toBe(true);

    const filters = graph.requests.map(r => r.query.$filter);
    const windows = [
      'receivedDateTime ge 2026-11-07T12:00:00Z and receivedDateTime le 2026-11-17T12:00:00Z',
      'receivedDateTime ge 2026-10-28T12:00:00Z and receivedDateTime le 2026-11-07T12:00:00Z',
      'receivedDateTime ge 2026-10-18T12:00:00Z and receivedDateTime le 2026-10-28T12:00:00Z',
    ];
    for (const window of windows) {
      expect(filters).toContain(`${window} and senderAddress eq '${SENDER}'`);
      expect(filters).toContain(`${window} and recipientAddress eq '${SENDER}'`);
      expect(filters).toContain(`${window} and endswith(senderAddress, '@supplier.example.net')`);
    }
    expect(outcomes()).toEqual(['ok']);
  });

  it('skips domain history for free-mail domains, built in or configured', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(
      graph.client,
      { ...SETTINGS, freeMailDomains: ['Freemail.Example.org'] },
      { now }
    );

    const gmail = await service.lookupForEmail(email('someone@gmail.com'));
    await service.lookupForEmail(email('someone@freemail.example.org'));

    expect(gmail?.domain).toBeUndefined();
    expect(graph.requests).toHaveLength(12);
    expect(graph.requests.some(r => r.query.$filter.includes('endswith'))).toBe(false);
  });

  it('skips domain history when it is switched off', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(
      graph.client,
      { ...SETTINGS, includeDomain: false },
      { now }
    );
    await service.lookupForEmail(email(SENDER));
    expect(graph.requests).toHaveLength(6);
  });

  it('caps the lookback inside the trace horizon', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(
      graph.client,
      { ...SETTINGS, lookbackDays: 90, includeDomain: false },
      { now }
    );
    const facts = await service.lookupForEmail(email(SENDER));
    expect(facts?.lookbackDays).toBe(90);
    expect(graph.requests).toHaveLength(18);
  });

  it('detects the takeover pattern end to end', async () => {
    const history = [
      inboundRow(NOW - 3 * DAY, 'person0@example.com'),
      inboundRow(NOW - 4 * DAY, 'person0@example.com'),
      inboundRow(NOW - 5 * DAY, 'person1@example.com'),
    ];
    const graph = fakeGraph([
      traceResponder({
        inbound: [...history, ...blast(30)],
        outbound: [inboundRow(NOW - 4 * DAY, SENDER, { senderAddress: 'person0@example.com' })],
      }),
    ]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });

    const facts = await service.lookupForEmail(email(SENDER));

    expect(facts?.classification).toBe('established_with_anomalous_fanout');
    expect(facts?.twoWay.internalSenders.count).toBe(1);
    expect(metricSpy.mock.calls[0][0]).toMatchObject({
      outcome: 'ok',
      classification: 'established_with_anomalous_fanout',
    });
    // No address anywhere in the result; IPs only in the list kept for the
    // security team's copy of the report
    expect(JSON.stringify(facts)).not.toContain('@');
    expect(facts?.sendingIps.burstIps).toEqual([{ ip: '192.0.2.10', seenInHistory: true }]);
    const withoutIpList = { ...facts, sendingIps: { ...facts?.sendingIps, burstIps: undefined } };
    expect(JSON.stringify(withoutIpList)).not.toContain('192.0.2');
  });

  it('widens the burst window back to a late report’s claimed date', async () => {
    const graph = fakeGraph([traceResponder({ inbound: [inboundRow(NOW - 3 * DAY, 'a@example.com')] })]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    const facts = await service.lookupForEmail(
      email(SENDER, { 'Original-Date': 'Sat, 14 Nov 2026 12:00:00 +0000' })
    );
    expect(facts?.burstWindowHours).toBe(96);
    expect(facts?.burst.messages.count).toBe(1);
    expect(facts?.history.messages.count).toBe(0);
  });

  it('reports a row cap as truncation', async () => {
    const graph = fakeGraph([
      request =>
        // A follow-up page carries only the service's own paging token
        (request.query.$filter ?? 'senderAddress eq').includes('senderAddress eq')
          ? collection(blast(5), 'https://graph.microsoft.com/v1.0/admin/exchange/tracing/messageTraces?$skiptoken=next')
          : collection([]),
    ]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    const facts = await service.lookupForEmail(email(SENDER));
    expect(facts?.truncated).toBe(true);
    expect(facts?.history.messages.atLeast).toBe(true);
    expect(facts?.burst.recipients.atLeast).toBe(true);
    expect(facts?.burst.newRecipients).toBeNull();
    // Two pages per inbound window, one for every other query
    expect(graph.requests).toHaveLength(12);
  });

  it('does not query for an internal, safelisted, missing or malformed sender', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    for (const from of [
      'colleague@example.com',
      'colleague@mail.example.com',
      'partner@safelisted.example.org',
      undefined,
      'Pat Doe',
      "<x' or 1 eq 1 or '@example.net>",
    ]) {
      expect(await service.lookupForEmail(email(from))).toBeUndefined();
    }
    expect(graph.requests).toHaveLength(0);
    expect(new Set(outcomes())).toEqual(new Set(['skipped']));
  });

  it('reuses a result for the same sender, then refreshes it', async () => {
    const graph = fakeGraph([traceResponder({ inbound: blast(2) })]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });

    const first = await service.lookupForEmail(email(SENDER));
    const second = await service.lookupForEmail(email(`Pat <${SENDER.toUpperCase()}>`));
    expect(second).toBe(first);
    expect(graph.requests).toHaveLength(9);

    clock += CACHE_TTL_MS + 1000;
    await service.lookupForEmail(email(SENDER));
    expect(graph.requests).toHaveLength(18);
    expect(outcomes()).toEqual(['ok', 'cache_hit', 'ok']);
  });

  describe('intermittent 403 from message trace', () => {
    const NEWEST = 'receivedDateTime le 2026-11-17T12:00:00Z';
    let delays: number[];
    const sleep = (ms: number): Promise<void> => {
      delays.push(ms);
      return Promise.resolve();
    };
    const denied = (): Response =>
      graphErrorResponse(403, 'Forbidden', `service principal not found for ${SENDER}`);
    const retriesReported = (): number[] =>
      metricSpy.mock.calls.map(
        call => (call[0] as metrics.SenderHistoryMetric).forbiddenRetries ?? -1
      );

    beforeEach(() => {
      delays = [];
    });

    it('retries a request that got a 403 and still returns facts', async () => {
      let calls = 0;
      const data = traceResponder({ inbound: blast(3) });
      const graph = fakeGraph([request => (calls++ % 4 === 0 ? denied() : data(request))]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now, sleep });

      const facts = await service.lookupForEmail(email(SENDER));

      expect(facts?.burst.recipients.count).toBe(3);
      expect(outcomes()).toEqual(['ok']);
      const [retries] = retriesReported();
      expect(retries).toBeGreaterThanOrEqual(2);
      expect(graph.requests).toHaveLength(9 + retries);
      expect(delays).toHaveLength(retries);
      expect(delays.every(ms => ms === FORBIDDEN_RETRY_DELAY_MS)).toBe(true);
      expect(graph.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
    });

    it('backs off a little more on each retry of the same request', async () => {
      const attempts = new Map<string, number>();
      const graph = fakeGraph([
        request => {
          const seen = (attempts.get(request.query.$filter) ?? 0) + 1;
          attempts.set(request.query.$filter, seen);
          return seen <= FORBIDDEN_RETRIES ? denied() : collection([]);
        },
      ]);
      const service = new SenderHistoryService(
        graph.client,
        { ...SETTINGS, lookbackDays: 14, includeDomain: false },
        { now, sleep }
      );

      expect(await service.lookupForEmail(email(SENDER))).toBeDefined();
      // 4 requests, each succeeding on its last allowed attempt
      expect(graph.requests).toHaveLength(4 * (FORBIDDEN_RETRIES + 1));
      expect(retriesReported()).toEqual([4 * FORBIDDEN_RETRIES]);
      expect(new Set(delays)).toEqual(new Set([250, 500, 750]));
    });

    it('is forbidden, with a cooldown, only when nothing in the lookup succeeded', async () => {
      const graph = fakeGraph([denied]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now, sleep });

      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      const afterFirst = graph.requests.length;
      // Every request that started was tried once and retried three times
      expect(afterFirst).toBeGreaterThanOrEqual(FORBIDDEN_RETRIES + 1);
      expect(afterFirst).toBeLessThanOrEqual(9 * (FORBIDDEN_RETRIES + 1));

      expect(await service.lookupForEmail(email('other@supplier.example.net'))).toBeUndefined();
      expect(graph.requests).toHaveLength(afterFirst);

      clock += FORBIDDEN_COOLDOWN_MS + 1000;
      await service.lookupForEmail(email('other@supplier.example.net'));
      expect(graph.requests.length).toBeGreaterThan(afterFirst);
      expect(outcomes()).toEqual(['forbidden', 'cooldown', 'forbidden']);
      expect(retriesReported()[0]).toBeGreaterThanOrEqual(FORBIDDEN_RETRIES);
    });

    it('is an ordinary error, with no cooldown, when one request stays 403 while others work', async () => {
      const stuck = (request: RecordedRequest): boolean =>
        request.query.$filter.includes('recipientAddress eq') &&
        request.query.$filter.includes(NEWEST);
      const graph = fakeGraph([request => (stuck(request) ? denied() : collection([]))]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now, sleep });

      // All-or-nothing: eight good windows are not turned into partial counts
      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      expect(graph.requests.filter(stuck)).toHaveLength(FORBIDDEN_RETRIES + 1);
      const afterFirst = graph.requests.length;

      expect(await service.lookupForEmail(email('other@supplier.example.net'))).toBeUndefined();
      expect(graph.requests.length).toBeGreaterThan(afterFirst);
      expect(outcomes()).toEqual(['error', 'error']);
      expect(retriesReported()).toEqual([FORBIDDEN_RETRIES, FORBIDDEN_RETRIES]);
    });

    it('stops retrying at the deadline', async () => {
      const graph = fakeGraph([denied]);
      // Real timers: the 250 ms retry delay outlasts the 60 ms budget
      const service = new SenderHistoryService(graph.client, { ...SETTINGS, budgetMs: 60 }, { now });

      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      const atDeadline = graph.requests.length;
      expect(atDeadline).toBeLessThanOrEqual(6); // one attempt per request in flight

      await new Promise(resolve => setTimeout(resolve, 400));
      expect(graph.requests).toHaveLength(atDeadline);
      expect(outcomes()).toEqual(['timeout']);
      expect(retriesReported()).toEqual([0]);

      // Not a verdict on permissions: the next report tries again
      await service.lookupForEmail(email('other@supplier.example.net'));
      expect(graph.requests.length).toBeGreaterThan(atDeadline);
    });

    it('stops retrying when the instance allowance is used up', async () => {
      const graph = fakeGraph([denied]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now, sleep });
      for (let i = 0; i < 4; i++) {
        clock += FORBIDDEN_COOLDOWN_MS / 10; // stay inside one 5-minute allowance window
        (service as unknown as { forbiddenUntil: number }).forbiddenUntil = 0;
        await service.lookupForEmail(email(`sender${i}@supplier.example.net`));
      }
      expect(graph.requests.length).toBeLessThanOrEqual(REQUEST_ALLOWANCE_PER_5_MIN);
    });
  });

  it('returns nothing when any window fails, rather than partial counts', async () => {
    let calls = 0;
    const graph = fakeGraph([
      () => (++calls === 4 ? graphErrorResponse(500, 'ServiceUnavailable') : collection(blast(1))),
    ]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
    expect(outcomes()).toEqual(['error']);
  });

  it('gives up at the time budget and cancels what is in flight', async () => {
    const signals: AbortSignal[] = [];
    const tokenProvider: GraphAccessTokenProvider = {
      label: 'read',
      getToken: () => Promise.resolve('token'),
      invalidate: () => undefined,
    };
    const client = new GraphClient({
      tokenProvider,
      maxAttempts: 1,
      fetchImpl: ((_input: unknown, init?: RequestInit) => {
        const signal = init?.signal as AbortSignal;
        signals.push(signal);
        return new Promise<Response>((_, reject) => {
          signal.addEventListener('abort', () => reject(new Error('aborted')));
        });
      }) as unknown as typeof fetch,
    });
    const service = new SenderHistoryService(client, { ...SETTINGS, budgetMs: 30 });

    const started = Date.now();
    expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();

    expect(Date.now() - started).toBeLessThan(2000);
    expect(outcomes()).toEqual(['timeout']);
    expect(signals.length).toBeGreaterThan(0);
    expect(signals.length).toBeLessThanOrEqual(6); // the concurrency cap
    expect(signals.every(signal => signal.aborted)).toBe(true);
  });

  it('stops spending trace requests once this instance’s allowance is used', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    for (let i = 0; i < 8; i++) {
      await service.lookupForEmail(email(`sender${i}@supplier.example.net`));
    }
    // 6 lookups x 9 requests fit in the allowance of 60; the 7th and 8th do not
    expect(graph.requests).toHaveLength(54);
    expect(outcomes().slice(6)).toEqual(['rate_limited', 'rate_limited']);

    clock += 5 * 60 * 1000 + 1000;
    expect(await service.lookupForEmail(email('later@supplier.example.net'))).toBeDefined();
  });

  it('never logs the sender address or a sending IP, at any level', async () => {
    const written: string[] = [];
    const capture = (...args: unknown[]): void => {
      written.push(args.map(String).join(' '));
    };
    const spies = [
      jest.spyOn(console, 'log').mockImplementation(capture),
      jest.spyOn(console, 'warn').mockImplementation(capture),
      jest.spyOn(console, 'error').mockImplementation(capture),
    ];
    const ok = fakeGraph([traceResponder({ inbound: blast(2) })]);
    const denied = fakeGraph([() => graphErrorResponse(403, 'Forbidden', `denied for ${SENDER}`)]);

    await new SenderHistoryService(ok.client, SETTINGS, { now }).lookupForEmail(email(SENDER));
    await new SenderHistoryService(denied.client, SETTINGS, { now }).lookupForEmail(email(SENDER));
    spies.forEach(spy => spy.mockRestore());

    const all = written.join('\n');
    expect(all).not.toContain(SENDER);
    expect(all).not.toContain('supplier.example.net');
    expect(all).not.toContain('person0@example.com');
    expect(all).not.toContain('192.0.2.10');
  });
});

describe('SenderHistoryService failure containment', () => {
  it('never throws, even on input it was not built for', async () => {
    const metricSpy = jest
      .spyOn(metrics, 'emitSenderHistoryMetric')
      .mockImplementation(() => undefined);
    const graph = fakeGraph([() => collection([])]);
    const service = new SenderHistoryService(graph.client, SETTINGS);
    const hostile = new Proxy(email(SENDER), {
      get: (target, property) => {
        if (property === 'forwardedHeaders') {
          throw new Error('boom');
        }
        return Reflect.get(target, property);
      },
    });
    await expect(service.lookupForEmail(hostile)).resolves.toBeUndefined();
    expect(metricSpy).toHaveBeenCalledWith({ outcome: 'error', durationMs: 0 });
    expect(graph.requests).toHaveLength(0);
  });
});

describe('createSenderHistoryService', () => {
  const email = { safeDomains: ['example.com'], safeSenders: [], deleteAfterProcessing: false };
  const senderHistory = {
    enabled: true,
    lookbackDays: 30,
    burstWindowHours: 24,
    budgetMs: 8000,
    includeDomain: true,
    freeMailDomains: [],
    fanoutMinRecipients: 10,
    fanoutMultiplier: 3,
  };
  const graph = fakeGraph([() => collection([])]);

  it('is off unless both Graph and the feature are enabled', () => {
    expect(createSenderHistoryService({ email }, graph.client)).toBeUndefined();
    expect(
      createSenderHistoryService({ email, graph: { enabled: false, senderHistory } }, graph.client)
    ).toBeUndefined();
    expect(
      createSenderHistoryService(
        { email, graph: { enabled: true, senderHistory: { ...senderHistory, enabled: false } } },
        graph.client
      )
    ).toBeUndefined();
    expect(createSenderHistoryService({ email, graph: { enabled: true } }, graph.client)).toBeUndefined();
  });

  it('builds the service when both are on', () => {
    expect(
      createSenderHistoryService({ email, graph: { enabled: true, senderHistory } }, graph.client)
    ).toBeInstanceOf(SenderHistoryService);
  });
});

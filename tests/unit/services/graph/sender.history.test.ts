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
  assertTraceRowsMatch,
  DEFAULT_FANOUT_MIN_RECIPIENTS,
  DEFAULT_FANOUT_MULTIPLIER,
  FANOUT_MIN_NEW_RECIPIENT_SHARE,
  FANOUT_MIN_TWO_WAY_MESSAGES,
  claimedSenderAddress,
  classifySenderRelationship,
  computeSenderHistoryFacts,
  createSenderHistoryService,
  listMessageTracesByRecipient,
  listMessageTracesBySender,
  resolveEmailTime,
  splitTraceWindows,
  subjectGroupKey,
} from '../../../../src/services/graph';
import * as graphModule from '../../../../src/services/graph';
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
  fanoutMinRecipients: 15,
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
  fanoutMinRecipients: 15,
  fanoutMultiplier: 3,
};

/** A blast inside the burst window: one subject to `count` distinct recipients, a row each */
function blast(count: number, extra: Partial<MessageTrace> = {}): MessageTrace[] {
  return Array.from({ length: count }, (_, i) =>
    inboundRow(NOW - HOUR, `person${i}@example.com`, { subject: 'RFQ 1001', ...extra })
  );
}

/** Mail the organization sent to the sender in the history period: two-way contact */
function reply(daysAgo = 4): MessageTrace {
  return inboundRow(NOW - daysAgo * DAY, SENDER, { senderAddress: 'person0@example.com' });
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
    expect(facts).not.toHaveProperty('domain');
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

  describe('anomalous fan-out', () => {
    const history = (): MessageTrace[] => [
      inboundRow(NOW - 20 * DAY, 'person0@example.com'),
      inboundRow(NOW - 12 * DAY, 'person0@example.com'),
      inboundRow(NOW - 6 * DAY, 'person1@example.com'),
    ];

    it('flags one subject sent far beyond the usual reach of a sender we correspond with', () => {
      const facts = computeSenderHistoryFacts({
        ...BASE,
        inbound: rows([...history(), ...blast(40, { fromIP: '198.51.100.7' })]),
        outbound: rows([reply()]),
      });
      expect(facts.classification).toBe('established_with_anomalous_fanout');
      expect(facts.burst.recipients).toEqual({ count: 40, atLeast: false });
      expect(facts.burst.newRecipients).toEqual({ count: 38, atLeast: false });
      expect(facts.burst.sameSubject).toEqual({
        recipients: { count: 40, atLeast: false },
        newRecipients: { count: 38, atLeast: false },
      });
      expect(facts.sendingIps).toEqual({
        burst: 1,
        seenInHistory: 0,
        historyComplete: true,
        burstIps: [{ ip: '198.51.100.7', seenInHistory: false }],
      });
    });

    it('requires two-way contact: a bulk sender nobody writes to stays established', () => {
      const facts = computeSenderHistoryFacts({
        ...BASE,
        inbound: rows([...history(), ...blast(40)]),
        outbound: rows([]),
      });
      expect(facts.classification).toBe('established');
      // The fan-out is still reported as a fact
      expect(facts.burst.sameSubject.recipients.count).toBe(40);
    });

    it('does not count mail sent to the sender during the burst as two-way contact', () => {
      const facts = computeSenderHistoryFacts({
        ...BASE,
        inbound: rows([...history(), ...blast(40)]),
        outbound: rows([inboundRow(NOW - HOUR, SENDER, { senderAddress: 'person5@example.com' })]),
      });
      expect(facts.classification).toBe('established');
    });

    it('measures fan-out per subject: a transactional system sending many different messages is not flagged', () => {
      const transactional = Array.from({ length: 120 }, (_, i) =>
        inboundRow(NOW - HOUR, `person${i}@example.com`, { subject: `Order ${1000 + i} shipped` })
      );
      const facts = computeSenderHistoryFacts({
        ...BASE,
        inbound: rows([...history(), ...transactional]),
        outbound: rows([reply()]),
      });
      expect(facts.burst.recipients.count).toBe(120);
      expect(facts.burst.newRecipients?.count).toBe(118);
      expect(facts.burst.sameSubject).toEqual({
        recipients: { count: 1, atLeast: false },
        newRecipients: { count: 1, atLeast: false },
      });
      expect(facts.classification).toBe('established');
    });

    it('does not flag one email to a project team below the minimum, and does at the minimum', () => {
      const classify = (teamSize: number): string =>
        computeSenderHistoryFacts({
          ...BASE,
          inbound: rows([...history(), ...blast(teamSize)]),
          outbound: rows([reply()]),
        }).classification;
      expect(classify(14)).toBe('established');
      expect(classify(15)).toBe('established_with_anomalous_fanout');
    });

    it('groups subjects ignoring case and spacing, and keeps no subject text', () => {
      const variants = ['RFQ 1001', '  rfq   1001 ', 'Rfq\t1001'];
      const sameMessage = Array.from({ length: 18 }, (_, i) =>
        inboundRow(NOW - HOUR, `person${i}@example.com`, { subject: variants[i % 3] })
      );
      const facts = computeSenderHistoryFacts({
        ...BASE,
        inbound: rows([...history(), ...sameMessage]),
        outbound: rows([reply()]),
      });
      expect(facts.burst.sameSubject.recipients.count).toBe(18);
      expect(facts.classification).toBe('established_with_anomalous_fanout');
      expect(JSON.stringify(facts).toLowerCase()).not.toContain('rfq');
      expect(subjectGroupKey('  RFQ \n 1001 ')).toBe('rfq 1001');
      expect(subjectGroupKey(undefined)).toBe('');
    });

    it('takes the new-recipient share from the same subject group, not the whole burst', () => {
      const known = Array.from({ length: 16 }, (_, i) => `known${i}@example.com`);
      const usual = known.map(recipient => inboundRow(NOW - 8 * DAY, recipient));
      // The usual newsletter to the usual 16 people plus 4 new ones ...
      const newsletter = [...known, 'n1@example.com', 'n2@example.com', 'n3@example.com', 'n4@example.com'].map(
        recipient => inboundRow(NOW - HOUR, recipient, { subject: 'Monthly update' })
      );
      // ... and unrelated one-off messages to 30 other new people
      const oneOffs = Array.from({ length: 30 }, (_, i) =>
        inboundRow(NOW - HOUR, `other${i}@example.com`, { subject: `Ticket ${i}` })
      );
      const facts = computeSenderHistoryFacts({
        ...BASE,
        fanoutMultiplier: 1,
        inbound: rows([...usual, ...newsletter, ...oneOffs]),
        outbound: rows([reply()]),
      });
      expect(facts.burst.recipients.count).toBe(50);
      expect(facts.burst.newRecipients?.count).toBe(34);
      expect(facts.burst.sameSubject).toEqual({
        recipients: { count: 20, atLeast: false },
        newRecipients: { count: 4, atLeast: false },
      });
      expect(facts.classification).toBe('established');
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
      outbound: rows([reply()], { historyTruncated: true }),
    });
    expect(facts.truncated).toBe(true);
    expect(facts.history.messages).toEqual({ count: 5, atLeast: true });
    expect(facts.history.recipients.atLeast).toBe(true);
    expect(facts.twoWay.messages.atLeast).toBe(true);
    expect(facts.burst.newRecipients).toBeNull();
    expect(facts.burst.sameSubject).toEqual({
      recipients: { count: 40, atLeast: false },
      newRecipients: null,
    });
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

});

describe('classifySenderRelationship thresholds', () => {
  const anomalous = {
    historyMessages: 5,
    historyRecipients: 5,
    historyTruncated: false,
    twoWayMessages: 1,
    sameSubjectRecipients: 15,
    sameSubjectNewRecipients: 8,
    fanoutMinRecipients: 15,
    fanoutMultiplier: 3,
  };

  it('needs every fan-out condition', () => {
    expect(classifySenderRelationship(anomalous)).toBe('established_with_anomalous_fanout');
    // two-way contact
    expect(classifySenderRelationship({ ...anomalous, twoWayMessages: 0 })).toBe('established');
    // enough recipients of one subject
    expect(classifySenderRelationship({ ...anomalous, sameSubjectRecipients: 14 })).toBe(
      'established'
    );
    // three times the usual reach
    expect(classifySenderRelationship({ ...anomalous, historyRecipients: 6 })).toBe('established');
    // half of them new
    expect(classifySenderRelationship({ ...anomalous, sameSubjectNewRecipients: 7 })).toBe(
      'established'
    );
    // a complete history to compare against
    expect(classifySenderRelationship({ ...anomalous, historyTruncated: true })).toBe(
      'established'
    );
    expect(classifySenderRelationship({ ...anomalous, sameSubjectNewRecipients: null })).toBe(
      'established'
    );
  });

  it('ships the documented defaults', () => {
    expect(DEFAULT_FANOUT_MIN_RECIPIENTS).toBe(15);
    expect(DEFAULT_FANOUT_MULTIPLIER).toBe(3);
    expect(FANOUT_MIN_NEW_RECIPIENT_SHARE).toBe(0.5);
    expect(FANOUT_MIN_TWO_WAY_MESSAGES).toBe(1);
  });

  it('honours configured thresholds', () => {
    expect(
      classifySenderRelationship({
        ...anomalous,
        historyRecipients: 3,
        sameSubjectRecipients: 6,
        sameSubjectNewRecipients: 6,
        fanoutMinRecipients: 5,
        fanoutMultiplier: 2,
      })
    ).toBe('established_with_anomalous_fanout');
  });

  it('keeps `established` as it was: history alone, or one message with two-way contact', () => {
    const quiet = { ...anomalous, sameSubjectRecipients: 0, sameSubjectNewRecipients: 0 };
    expect(classifySenderRelationship({ ...quiet, historyMessages: 3, twoWayMessages: 0 })).toBe(
      'established'
    );
    expect(classifySenderRelationship({ ...quiet, historyMessages: 1, twoWayMessages: 1 })).toBe(
      'established'
    );
    expect(classifySenderRelationship({ ...quiet, historyMessages: 2, twoWayMessages: 0 })).toBe(
      'limited_history'
    );
  });

  it('never calls a sender without history anomalous', () => {
    expect(
      classifySenderRelationship({
        ...anomalous,
        historyMessages: 0,
        historyRecipients: 0,
        twoWayMessages: 0,
      })
    ).toBe('no_history');
    expect(
      classifySenderRelationship({
        ...anomalous,
        historyMessages: 0,
        historyRecipients: 0,
      })
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

  it('traces by recipient, escaping the value', async () => {
    const graph = fakeGraph([() => collection([])]);
    await listMessageTracesByRecipient(graph.client, {
      ...window,
      recipientAddress: "o'neil@supplier.example.net",
      maxPages: 2,
    });
    expect(graph.requests.map(r => r.query.$filter)).toEqual([
      `${range} and recipientAddress eq 'o''neil@supplier.example.net'`,
    ]);
    expect(graph.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
  });

  it('refuses a bad page cap', async () => {
    const graph = fakeGraph([() => collection([])]);
    await expect(
      listMessageTracesByRecipient(graph.client, { ...window, recipientAddress: SENDER, maxPages: 6 })
    ).rejects.toThrow('maxPages');
    expect(graph.requests).toHaveLength(0);
  });

  it('has no domain-level trace query: the service ignores endswith/contains on addresses', () => {
    expect(graphModule).not.toHaveProperty('listMessageTracesBySenderDomain');
  });

  describe('rows the filter did not select', () => {
    const at = '2026-11-12T00:00:00Z';
    const good = { senderAddress: SENDER, recipientAddress: 'a@example.com', receivedDateTime: at };
    const other = {
      senderAddress: 'newsletter@bulk.example.org',
      recipientAddress: 'b@example.com',
      receivedDateTime: at,
    };

    it('accepts rows that all carry the requested address, whatever the case', async () => {
      const graph = fakeGraph([
        () => collection([good, { ...good, senderAddress: SENDER.toUpperCase() }]),
      ]);
      const bySender = await listMessageTracesBySender(graph.client, {
        ...window,
        senderAddress: SENDER,
      });
      expect(bySender.items).toHaveLength(2);

      const toSender = { ...other, recipientAddress: 'Pat@Supplier.Example.net' };
      const byRecipient = await listMessageTracesByRecipient(
        fakeGraph([() => collection([toSender])]).client,
        { ...window, recipientAddress: SENDER }
      );
      expect(byRecipient.items).toHaveLength(1);
    });

    it('lets a row with no address through the operation, but not through the strict check', async () => {
      const graph = fakeGraph([() => collection([good, { ...good, senderAddress: null }])]);
      const result = await listMessageTracesBySender(graph.client, {
        ...window,
        senderAddress: SENDER,
      });
      expect(result.items).toHaveLength(2);
      expect(() =>
        assertTraceRowsMatch(graph.client, result.items, 'senderAddress', SENDER)
      ).toThrow('1 of 2 rows do not match the senderAddress');
      expect(() =>
        assertTraceRowsMatch(graph.client, result.items, 'senderAddress', SENDER, {
          allowMissing: true,
        })
      ).not.toThrow();
    });

    it('fails a by-sender query on a row from another sender', async () => {
      const graph = fakeGraph([() => collection([good, other])]);
      for (const subject of [undefined, 'RFQ']) {
        const error = await listMessageTracesBySender(graph.client, {
          ...window,
          senderAddress: SENDER,
          subject,
        }).catch((e: unknown) => e);
        expect(error).toMatchObject({ name: 'GraphError', kind: 'filter_not_applied' });
        // What went wrong, never whose mail it was
        expect((error as Error).message).toContain('1 of 2 rows do not match the senderAddress');
        expect((error as Error).message).not.toContain('@');
      }
    });

    it('fails a by-recipient query on a row to someone else', async () => {
      const graph = fakeGraph([() => collection([good, other])]);
      const error = await listMessageTracesByRecipient(graph.client, {
        ...window,
        recipientAddress: SENDER,
      }).catch((e: unknown) => e);
      expect(error).toMatchObject({ name: 'GraphError', kind: 'filter_not_applied' });
      expect((error as Error).message).not.toContain('@');
    });
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

  /** Answer by query type: inbound by sender, outbound by recipient */
  function traceResponder(data: {
    inbound?: MessageTrace[];
    outbound?: MessageTrace[];
  }): FakeResponder {
    return (request: RecordedRequest) => {
      const filter = request.query.$filter ?? '';
      const newest = filter.includes('receivedDateTime le 2026-11-17T12:00:00Z');
      if (filter.includes('senderAddress eq')) {
        return collection(newest ? (data.inbound ?? []) : []);
      }
      return collection(newest ? (data.outbound ?? []) : []);
    };
  }

  it('makes 6 GET requests for a 30-day lookup, all code-built and filtered with eq only', async () => {
    const graph = fakeGraph([traceResponder({ inbound: blast(3) })]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });

    const facts = await service.lookupForEmail(email(`Pat <${SENDER}>`));

    expect(facts?.burst.recipients.count).toBe(3);
    expect(graph.requests).toHaveLength(6);
    expect(graph.requests.every(r => r.method === 'GET' && r.path === TRACE_PATH)).toBe(true);
    expect(graph.requests.every(r => r.query.$top === '2000')).toBe(true);

    const filters = graph.requests.map(r => r.query.$filter);
    const windows = [
      'receivedDateTime ge 2026-11-07T12:00:00Z and receivedDateTime le 2026-11-17T12:00:00Z',
      'receivedDateTime ge 2026-10-28T12:00:00Z and receivedDateTime le 2026-11-07T12:00:00Z',
      'receivedDateTime ge 2026-10-18T12:00:00Z and receivedDateTime le 2026-10-28T12:00:00Z',
    ];
    expect([...filters].sort()).toEqual(
      windows
        .flatMap(window => [
          `${window} and senderAddress eq '${SENDER}'`,
          `${window} and recipientAddress eq '${SENDER}'`,
        ])
        .sort()
    );
    // Predicates message trace accepts but does not apply to addresses
    expect(filters.join(' ')).not.toMatch(/endswith|contains|startswith/i);
    expect(outcomes()).toEqual(['ok']);
  });

  it('discards a lookup whose rows carry no address to confirm', async () => {
    const graph = fakeGraph([
      traceResponder({ inbound: [inboundRow(NOW - HOUR, 'a@example.com', { senderAddress: undefined })] }),
    ]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
    expect(metricSpy.mock.calls[0][0]).toMatchObject({ outcome: 'error', filterMismatch: true });
  });

  it('makes the same 6 requests for a free-mail sender: there is no domain query to skip', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    const facts = await service.lookupForEmail(email('someone@gmail.com'));
    expect(facts).not.toHaveProperty('domain');
    expect(graph.requests).toHaveLength(6);
  });

  describe('when message trace does not apply the address filter', () => {
    /** The whole tenant's mail flow, whatever was asked: what a dropped predicate looks like */
    const unfiltered = (): Response =>
      collection(
        Array.from({ length: 50 }, (_, i) =>
          inboundRow(NOW - HOUR, `staff${i}@example.com`, {
            senderAddress: `bulk${i % 7}@newsletter.example.org`,
          })
        )
      );

    it('discards the lookup: no facts, an error outcome, a metric, no cooldown, nothing cached', async () => {
      const graph = fakeGraph([unfiltered]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now });

      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      expect(metricSpy.mock.calls[0][0]).toMatchObject({ outcome: 'error', filterMismatch: true });
      const afterFirst = graph.requests.length;

      // Asked again at once: not cached, not in cooldown
      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      expect(graph.requests.length).toBeGreaterThan(afterFirst);
      expect(outcomes()).toEqual(['error', 'error']);
    });

    it('discards it even when only one of the six queries came back unfiltered', async () => {
      const honest = traceResponder({ inbound: blast(30) });
      const graph = fakeGraph([
        request =>
          request.query.$filter.includes('recipientAddress eq') &&
          request.query.$filter.includes('ge 2026-10-18T12:00:00Z')
            ? unfiltered()
            : honest(request),
      ]);
      const service = new SenderHistoryService(graph.client, SETTINGS, { now });

      expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
      expect(metricSpy.mock.calls[0][0]).toMatchObject({ outcome: 'error', filterMismatch: true });
    });

    it('is not retried, and is reported without any address', async () => {
      const written: string[] = [];
      const capture = (...args: unknown[]): void => {
        written.push(args.map(String).join(' '));
      };
      const spies = [
        jest.spyOn(console, 'log').mockImplementation(capture),
        jest.spyOn(console, 'warn').mockImplementation(capture),
        jest.spyOn(console, 'error').mockImplementation(capture),
      ];
      const graph = fakeGraph([unfiltered]);
      const sleep = jest.fn(() => Promise.resolve());
      await new SenderHistoryService(graph.client, SETTINGS, { now, sleep }).lookupForEmail(
        email(SENDER)
      );
      spies.forEach(spy => spy.mockRestore());

      expect(sleep).not.toHaveBeenCalled();
      expect(graph.requests.length).toBeLessThanOrEqual(6);
      expect(metricSpy.mock.calls[0][0]).toMatchObject({ forbiddenRetries: 0 });
      expect(written.join('\n')).not.toContain('@');
    });

    it('reports no mismatch on an ordinary lookup', async () => {
      const graph = fakeGraph([traceResponder({ inbound: blast(2) })]);
      await new SenderHistoryService(graph.client, SETTINGS, { now }).lookupForEmail(email(SENDER));
      expect(metricSpy.mock.calls[0][0].filterMismatch).toBeUndefined();
    });
  });

  it('caps the lookback inside the trace horizon', async () => {
    const graph = fakeGraph([traceResponder({})]);
    const service = new SenderHistoryService(
      graph.client,
      { ...SETTINGS, lookbackDays: 90 },
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
    expect(graph.requests).toHaveLength(9);
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
    expect(graph.requests).toHaveLength(6);

    clock += CACHE_TTL_MS + 1000;
    await service.lookupForEmail(email(SENDER));
    expect(graph.requests).toHaveLength(12);
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
      expect(graph.requests).toHaveLength(6 + retries);
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
        { ...SETTINGS, lookbackDays: 14 },
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
      expect(afterFirst).toBeLessThanOrEqual(6 * (FORBIDDEN_RETRIES + 1));

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
      request =>
        ++calls === 4
          ? graphErrorResponse(500, 'ServiceUnavailable')
          : traceResponder({ inbound: blast(1) })(request),
    ]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now });
    expect(await service.lookupForEmail(email(SENDER))).toBeUndefined();
    expect(outcomes()).toEqual(['error']);
    expect(metricSpy.mock.calls[0][0].filterMismatch).toBeUndefined();
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
    for (let i = 0; i < 12; i++) {
      await service.lookupForEmail(email(`sender${i}@supplier.example.net`));
    }
    // 10 distinct senders x 6 requests use the allowance of 60; the 11th and 12th wait
    expect(graph.requests).toHaveLength(60);
    expect(outcomes().slice(0, 10)).toEqual(Array(10).fill('ok'));
    expect(outcomes().slice(10)).toEqual(['rate_limited', 'rate_limited']);

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
    fanoutMinRecipients: 15,
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

describe('fan-out judged on one chosen subject (the fan-out scan)', () => {
  const history = (): MessageTrace[] => [
    inboundRow(NOW - 20 * DAY, 'person0@example.com'),
    inboundRow(NOW - 12 * DAY, 'person0@example.com'),
    inboundRow(NOW - 6 * DAY, 'person1@example.com'),
  ];

  it('measures only the focused subject group, however wide another subject is', () => {
    const team = Array.from({ length: 40 }, (_, i) =>
      inboundRow(NOW - HOUR, `person${i}@example.com`, { subject: 'Quarterly newsletter' })
    );
    const input = {
      ...BASE,
      inbound: rows([...history(), ...team, ...blast(16)]),
      outbound: rows([reply()]),
    };
    expect(computeSenderHistoryFacts(input).burst.sameSubject.recipients.count).toBe(40);
    const focused = computeSenderHistoryFacts({ ...input, focusSubjectKey: 'rfq 1001' });
    expect(focused.burst.sameSubject.recipients.count).toBe(16);
    expect(focused.classification).toBe('established_with_anomalous_fanout');
    const absent = computeSenderHistoryFacts({ ...input, focusSubjectKey: 'no such subject' });
    expect(absent.burst.sameSubject.recipients.count).toBe(0);
    expect(absent.classification).toBe('established');
  });

  it('caches a focused lookup apart from an unfocused one, and honours a smaller allowance', async () => {
    const graph = fakeGraph([() => collection([])]);
    const service = new SenderHistoryService(
      graph.client,
      { ...SETTINGS, requestAllowancePer5Min: 12 },
      { now: () => NOW }
    );
    await service.lookupSender(() => ({ claimedFrom: SENDER, claimedDate: undefined }));
    await service.lookupSender(() => ({
      claimedFrom: SENDER,
      claimedDate: undefined,
      focusSubject: 'RFQ 1001',
    }));
    expect(graph.requests).toHaveLength(12);
    expect(service.requestsUsed()).toBe(12);
    const third = await service.lookupSender(() => ({
      claimedFrom: SENDER,
      claimedDate: undefined,
      focusSubject: 'Another subject',
    }));
    expect(third.metric.outcome).toBe('rate_limited');
    expect(graph.requests).toHaveLength(12);
  });
});

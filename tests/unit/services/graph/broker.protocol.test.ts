/**
 * Graph broker wire format: a closed allow-list of requests, and responses
 * that are validated and re-bounded as hostile data. Invented data only.
 */

import {
  BlastRadiusLookupResultSchema,
  GRAPH_BROKER_OPERATIONS,
  GraphBrokerRequestSchema,
  GraphBrokerResponseSchema,
  OriginalMessageLookupResultSchema,
  SenderHistoryLookupResultSchema,
  brokerBudgetMs,
} from '../../../../src/services/graph/broker.protocol';

const ORIGINAL = {
  version: 1,
  operation: 'original_message_lookup',
  params: {
    mailbox: 'reporter@example.com',
    claimedFrom: 'billing-alerts@example.org',
    claimedSent: 'Monday, November 16, 2026 8:00 AM',
    claimedSubject: 'Invoice 7731 overdue',
    budgetMs: 7000,
  },
};

const BLAST = {
  version: 1,
  operation: 'blast_radius_lookup',
  params: {
    key: {
      internetMessageId: '<m1@mail.example.org>',
      senderAddress: 'billing-alerts@example.org',
      subject: 'Invoice 7731 overdue',
      receivedFrom: '2026-11-15T08:00:00.000Z',
      receivedTo: '2026-11-17T08:00:00.000Z',
    },
    budgetMs: 44000,
  },
};

const SENDER = {
  version: 1,
  operation: 'sender_history_lookup',
  params: {
    senderAddress: 'pat@supplier.example.net',
    claimedDate: 'Mon, 16 Nov 2026 08:00:00 +0000',
    budgetMs: 7000,
  },
};

const accepts = (value: unknown): boolean => GraphBrokerRequestSchema.safeParse(value).success;

describe('Graph broker requests', () => {
  it('has exactly four operations', () => {
    expect([...GRAPH_BROKER_OPERATIONS].sort()).toEqual([
      'blast_radius_lookup',
      'fanout_scan',
      'original_message_lookup',
      'sender_history_lookup',
    ]);
  });

  it.each([
    ['original_message_lookup', ORIGINAL],
    ['blast_radius_lookup', BLAST],
    ['sender_history_lookup', SENDER],
  ])('accepts a well-formed %s request', (_name, request) => {
    expect(accepts(request)).toBe(true);
  });

  it('accepts the optional fields being absent', () => {
    const { claimedSubject: _subject, ...original } = ORIGINAL.params;
    expect(accepts({ ...ORIGINAL, params: original })).toBe(true);
    expect(accepts({ ...SENDER, params: { senderAddress: 'a@example.net', budgetMs: 1 } })).toBe(
      true
    );
    expect(
      accepts({
        ...BLAST,
        params: {
          key: {
            senderAddress: 'a@example.net',
            receivedFrom: BLAST.params.key.receivedFrom,
            receivedTo: BLAST.params.key.receivedTo,
          },
          budgetMs: 5000,
        },
      })
    ).toBe(true);
  });

  it.each([
    'graph_get',
    'call_graph',
    'get',
    'list_users',
    'message_trace',
    'ORIGINAL_MESSAGE_LOOKUP',
    '',
  ])('refuses the unknown operation %p', operation => {
    expect(accepts({ ...ORIGINAL, operation })).toBe(false);
    expect(accepts({ version: 1, operation, params: {} })).toBe(false);
  });

  it('has no way to pass a path, URL, filter or query', () => {
    for (const extra of [
      { path: '/users' },
      { url: 'https://graph.microsoft.com/v1.0/users' },
      { filter: "senderAddress ne ''" },
      { query: { $filter: 'true' } },
      { select: ['body'] },
      { method: 'POST' },
    ]) {
      expect(accepts({ ...ORIGINAL, ...extra })).toBe(false);
      expect(accepts({ ...ORIGINAL, params: { ...ORIGINAL.params, ...extra } })).toBe(false);
      expect(accepts({ ...SENDER, params: { ...SENDER.params, ...extra } })).toBe(false);
      expect(accepts({ ...BLAST, params: { ...BLAST.params, ...extra } })).toBe(false);
      expect(
        accepts({ ...BLAST, params: { ...BLAST.params, key: { ...BLAST.params.key, ...extra } } })
      ).toBe(false);
    }
  });

  it.each([[2], [0], ['1'], [undefined], [null], [1.5]])('refuses version %p', version => {
    expect(accepts({ ...ORIGINAL, version })).toBe(false);
  });

  it('refuses params that belong to another operation', () => {
    expect(accepts({ ...ORIGINAL, params: SENDER.params })).toBe(false);
    expect(accepts({ ...SENDER, params: BLAST.params })).toBe(false);
    expect(accepts({ ...BLAST, params: ORIGINAL.params })).toBe(false);
  });

  it('refuses anything that is not a request object', () => {
    for (const value of [undefined, null, 'original_message_lookup', 42, [], [ORIGINAL], {}]) {
      expect(accepts(value)).toBe(false);
    }
    expect(accepts({ version: 1, operation: 'original_message_lookup' })).toBe(false);
  });

  it('refuses HTTP events and event-source records', () => {
    const body = JSON.stringify(ORIGINAL);
    // API Gateway (REST), API Gateway (HTTP) / function URL, load balancer, SES
    expect(accepts({ httpMethod: 'POST', path: '/', headers: {}, body })).toBe(false);
    expect(
      accepts({ version: '2.0', routeKey: '$default', rawPath: '/', requestContext: {}, body })
    ).toBe(false);
    expect(accepts({ requestContext: { elb: {} }, httpMethod: 'POST', body })).toBe(false);
    expect(accepts({ Records: [{ eventSource: 'aws:ses' }] })).toBe(false);
    // A real request with HTTP trimmings is still not a request
    expect(accepts({ ...ORIGINAL, headers: {}, requestContext: {} })).toBe(false);
  });

  it('bounds every string and number', () => {
    const original = (params: Record<string, unknown>): unknown => ({
      ...ORIGINAL,
      params: { ...ORIGINAL.params, ...params },
    });
    expect(accepts(original({ claimedSubject: 'x'.repeat(256) }))).toBe(false);
    expect(accepts(original({ claimedSent: 'x'.repeat(121) }))).toBe(false);
    expect(accepts(original({ claimedSent: '' }))).toBe(false);
    expect(accepts(original({ mailbox: `${'a'.repeat(250)}@example.com` }))).toBe(false);
    expect(accepts(original({ mailbox: 'not an address' }))).toBe(false);
    expect(accepts(original({ mailbox: 'Reporter <reporter@example.com>' }))).toBe(false);
    expect(accepts(original({ claimedFrom: 'a@example.org, b@example.org' }))).toBe(false);
    expect(accepts(original({ budgetMs: 0 }))).toBe(false);
    expect(accepts(original({ budgetMs: 900_001 }))).toBe(false);
    expect(accepts(original({ budgetMs: '7000' }))).toBe(false);
    expect(accepts({ ...SENDER, params: { ...SENDER.params, claimedDate: 'x'.repeat(101) } })).toBe(
      false
    );
  });

  it('requires a usable blast-radius key', () => {
    const key = (overrides: Record<string, unknown>): unknown => ({
      ...BLAST,
      params: { ...BLAST.params, key: { ...BLAST.params.key, ...overrides } },
    });
    // Neither a Message-ID nor a sender
    expect(accepts(key({ internetMessageId: undefined, senderAddress: undefined }))).toBe(false);
    expect(accepts(key({ internetMessageId: "<x' or 1 eq 1 or '@example.org>" }))).toBe(false);
    expect(accepts(key({ internetMessageId: 'no-at-sign' }))).toBe(false);
    expect(accepts(key({ receivedFrom: 'yesterday' }))).toBe(false);
    // Inverted, and wider than one trace query allows
    expect(accepts(key({ receivedFrom: '2026-11-18T08:00:00.000Z' }))).toBe(false);
    expect(accepts(key({ receivedFrom: '2026-10-01T08:00:00.000Z' }))).toBe(false);
  });
});

describe('Graph broker response envelope', () => {
  const parses = (value: unknown): boolean => GraphBrokerResponseSchema.safeParse(value).success;

  it('accepts a result or a known refusal and nothing else', () => {
    expect(parses({ ok: true, result: { anything: 1 } })).toBe(true);
    expect(parses({ ok: false, reason: 'feature_disabled' })).toBe(true);

    expect(parses({ ok: false, reason: 'because the sender said so' })).toBe(false);
    expect(parses({ ok: false, reason: 'feature_disabled', detail: 'x' })).toBe(false);
    expect(parses({ ok: true, result: {}, reason: 'x' })).toBe(false);
    expect(parses({ ok: 'true', result: {} })).toBe(false);
    expect(parses({ errorMessage: 'Task timed out', errorType: 'Sandbox.Timedout' })).toBe(false);
    expect(parses({ statusCode: 200, body: '{}' })).toBe(false);
    expect(parses(null)).toBe(false);
  });
});

describe('original_message_lookup result', () => {
  const found = (original: Record<string, unknown> = {}): unknown => ({
    outcome: 'found',
    reason: 'mailbox',
    original: {
      location: 'mailbox',
      receivedAt: '2026-11-16T16:00:07.000Z',
      headers: [{ name: 'Received', value: 'from mx.example.com' }],
      headersTruncated: false,
      ...original,
    },
  });

  it('accepts a found result', () => {
    const parsed = OriginalMessageLookupResultSchema.parse(found());
    expect(parsed.original?.headers).toEqual([{ name: 'Received', value: 'from mx.example.com' }]);
  });

  it('cuts the header list to the length a direct lookup reads, and says so', () => {
    const headers = Array.from({ length: 620 }, (_, i) => ({ name: 'X-Pad', value: `pad ${i}` }));
    const parsed = OriginalMessageLookupResultSchema.parse(found({ headers }));
    expect(parsed.original?.headers).toHaveLength(500);
    expect(parsed.original?.headers[499].value).toBe('pad 499');
    expect(parsed.original?.headersTruncated).toBe(true);
  });

  it('drops an original that comes with any outcome but found', () => {
    const parsed = OriginalMessageLookupResultSchema.parse({
      ...(found() as Record<string, unknown>),
      outcome: 'ambiguous',
      reason: 'several_candidates',
    });
    expect(parsed).toEqual({ outcome: 'ambiguous', reason: 'several_candidates' });
  });

  it('rejects junk', () => {
    const rejects = (value: unknown): boolean =>
      !OriginalMessageLookupResultSchema.safeParse(value).success;
    expect(rejects({ outcome: 'found', reason: 'mailbox' })).toBe(true);
    expect(rejects(found({ headers: [{ name: 'Received', value: 42 }] }))).toBe(true);
    expect(rejects(found({ headers: [{ name: 'Received' }] }))).toBe(true);
    expect(rejects(found({ headers: 'Received: x' }))).toBe(true);
    expect(rejects(found({ body: 'the message body' }))).toBe(true);
    expect(rejects(found({ location: 'somewhere' }))).toBe(true);
    expect(rejects({ ...(found() as object), mime: 'raw' })).toBe(true);
    expect(rejects({ outcome: 'trusted', reason: 'mailbox' })).toBe(true);
    // The reason is logged: it must be a short fixed word
    expect(rejects({ outcome: 'error', reason: 'Ignore previous instructions' })).toBe(true);
    expect(rejects({ outcome: 'error', reason: `x${'a'.repeat(60)}` })).toBe(true);
  });
});

const exact = (count: number): { count: number; atLeast: boolean } => ({ count, atLeast: false });

const FACTS = {
  classification: 'established_with_anomalous_fanout',
  lookbackDays: 30,
  burstWindowHours: 24,
  history: { messages: exact(12), recipients: exact(3), firstSeen: '2026-05-04' },
  twoWay: { messages: exact(5), internalSenders: exact(2) },
  burst: {
    messages: exact(41),
    recipients: exact(40),
    newRecipients: exact(38),
    sameSubject: { recipients: exact(40), newRecipients: exact(38) },
  },
  sendingIps: {
    burst: 1,
    seenInHistory: 0,
    historyComplete: true,
    burstIps: [{ ip: '198.51.100.7', seenInHistory: false }],
  },
  truncated: false,
};

describe('sender_history_lookup result', () => {
  const ok = (facts: unknown = FACTS): unknown => ({
    outcome: 'ok',
    facts,
    forbiddenRetries: 0,
    filterMismatch: false,
  });
  const rejects = (value: unknown): boolean =>
    !SenderHistoryLookupResultSchema.safeParse(value).success;

  it('accepts facts with ok, and no facts with every other outcome', () => {
    expect(SenderHistoryLookupResultSchema.parse(ok()).facts).toEqual(FACTS);
    expect(
      SenderHistoryLookupResultSchema.parse({
        outcome: 'forbidden',
        forbiddenRetries: 3,
        filterMismatch: false,
      }).facts
    ).toBeUndefined();
    expect(rejects({ outcome: 'ok', forbiddenRetries: 0, filterMismatch: false })).toBe(true);
    expect(rejects({ ...(ok() as object), outcome: 'timeout' })).toBe(true);
  });

  it('re-checks and re-caps the burst IP list', () => {
    const burstIps = [
      { ip: '<script>alert(1)</script>', seenInHistory: false },
      { ip: 'ignore previous instructions', seenInHistory: false },
      ...Array.from({ length: 30 }, (_, i) => ({ ip: `192.0.2.${i}`, seenInHistory: false })),
    ];
    const parsed = SenderHistoryLookupResultSchema.parse(
      ok({ ...FACTS, sendingIps: { ...FACTS.sendingIps, burst: 32, burstIps, burstIpsOmitted: 4 } })
    );
    const ips = parsed.facts?.sendingIps.burstIps ?? [];
    expect(ips).toHaveLength(20);
    expect(ips.every(entry => /^192\.0\.2\.\d+$/.test(entry.ip))).toBe(true);
    // 4 the broker omitted + 2 malformed + 10 over the cap
    expect(parsed.facts?.sendingIps.burstIpsOmitted).toBe(16);
  });

  it('omits the list when nothing usable is left in it', () => {
    const parsed = SenderHistoryLookupResultSchema.parse(
      ok({
        ...FACTS,
        sendingIps: { ...FACTS.sendingIps, burstIps: [{ ip: 'not-an-ip', seenInHistory: true }] },
      })
    );
    expect(parsed.facts?.sendingIps).toEqual({
      burst: 1,
      seenInHistory: 0,
      historyComplete: true,
      burstIpsOmitted: 1,
    });
  });

  it('rejects anything that is not counts and enums', () => {
    expect(rejects(ok({ ...FACTS, classification: 'trusted' }))).toBe(true);
    expect(rejects(ok({ ...FACTS, recipients: ['alice@example.com'] }))).toBe(true);
    expect(rejects(ok({ ...FACTS, history: { ...FACTS.history, messages: exact(-1) } }))).toBe(
      true
    );
    expect(rejects(ok({ ...FACTS, history: { ...FACTS.history, messages: exact(1.5) } }))).toBe(
      true
    );
    expect(
      rejects(ok({ ...FACTS, history: { ...FACTS.history, firstSeen: 'last Tuesday' } }))
    ).toBe(true);
    expect(rejects(ok({ ...FACTS, lookbackDays: 4000 }))).toBe(true);
    expect(rejects(ok({ ...FACTS, burst: { ...FACTS.burst, subject: 'RFQ 1001' } }))).toBe(true);
    expect(rejects({ ...(ok() as object), senderAddress: 'pat@supplier.example.net' })).toBe(true);
  });
});

describe('blast_radius_lookup result', () => {
  const recipient = (name: string, extra: Record<string, unknown> = {}): unknown => ({
    address: `${name}@example.com`,
    mailbox: 'found',
    folder: 'inbox',
    isRead: true,
    response: 'none',
    ...extra,
  });
  const result = (report: Record<string, unknown> = {}): unknown => ({
    report: {
      status: 'complete',
      route: 'trace',
      matchedBy: 'messageId',
      criteria: {
        senderAddress: 'billing-alerts@example.org',
        subject: 'Invoice 7731 overdue',
        receivedFrom: '2026-11-15T08:00:00.000Z',
        receivedTo: '2026-11-17T08:00:00.000Z',
      },
      totals: { recipients: 2, read: 1, replied: 0, forwarded: 0, notDelivered: 0 },
      recipients: [recipient('alice'), recipient('bob', { deliveryStatus: 'Delivered' })],
      coverage: {
        mailboxesChecked: 2,
        mailboxesEligible: 2,
        eligibleIsLowerBound: false,
        recoverableChecked: 0,
        recoverableCandidates: 0,
        detailUnavailable: 0,
      },
      caveats: ['Recipients come from Exchange message trace.'],
      lookedUpAt: '2026-11-17T12:00:00.000Z',
      ...report,
    },
    errors: 0,
    cached: false,
  });
  const rejects = (value: unknown): boolean =>
    !BlastRadiusLookupResultSchema.safeParse(value).success;

  it('accepts a report and an unavailable note', () => {
    expect(BlastRadiusLookupResultSchema.parse(result()).report.recipients).toHaveLength(2);
    expect(
      BlastRadiusLookupResultSchema.parse({
        report: {
          status: 'unavailable',
          note: 'Blast radius lookup could not be completed: it ran out of time before any result.',
          lookedUpAt: '2026-11-17T12:00:00.000Z',
        },
        errors: 1,
        cached: false,
      }).report.status
    ).toBe('unavailable');
  });

  it('cuts the recipient list to the length a direct lookup lists', () => {
    const recipients = Array.from({ length: 140 }, (_, i) => recipient(`person${i}`));
    const parsed = BlastRadiusLookupResultSchema.parse(result({ recipients }));
    expect(parsed.report.recipients).toHaveLength(100);
    expect(parsed.report.recipients?.[99].address).toBe('person99@example.com');
  });

  it('rejects junk', () => {
    // The reporter is marked by the main function, never by the broker
    expect(rejects(result({ reporterAddress: 'ceo@example.com' }))).toBe(true);
    expect(rejects(result({ status: 'safe' }))).toBe(true);
    expect(rejects(result({ recipients: [recipient('alice', { folder: 'archive' })] }))).toBe(true);
    expect(rejects(result({ recipients: [recipient('alice', { body: 'text' })] }))).toBe(true);
    expect(
      rejects(result({ recipients: [{ address: 'alice@example.com\nBcc: x', mailbox: 'found' }] }))
    ).toBe(true);
    expect(
      rejects(
        result({ recipients: [{ address: `${'a'.repeat(400)}@example.com`, mailbox: 'found' }] })
      )
    ).toBe(true);
    expect(
      rejects(result({ recipients: [recipient('alice', { deliveryStatus: '<b>Delivered</b>' })] }))
    ).toBe(true);
    expect(rejects(result({ note: 'x'.repeat(601) }))).toBe(true);
    expect(rejects(result({ caveats: Array.from({ length: 31 }, () => 'caveat') }))).toBe(true);
    expect(
      rejects(
        result({ criteria: { subject: 'x'.repeat(300), receivedFrom: 'a', receivedTo: 'b' } })
      )
    ).toBe(true);
    expect(rejects(result({ totals: { recipients: -1, read: 0, replied: 0, forwarded: 0 } }))).toBe(
      true
    );
    expect(rejects({ ...(result() as object), errors: 'many' })).toBe(true);
    expect(rejects({ ...(result() as object), raw: {} })).toBe(true);
  });
});

describe('brokerBudgetMs', () => {
  it('asks the broker to finish before the caller stops waiting', () => {
    expect(brokerBudgetMs(8000)).toBe(7000);
    expect(brokerBudgetMs(45000)).toBe(44000);
    // A short budget keeps three quarters of itself
    expect(brokerBudgetMs(1000)).toBe(750);
    expect(brokerBudgetMs(1)).toBe(1);
  });
});

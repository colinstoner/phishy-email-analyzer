/**
 * Blast radius lookup: route choice, request shape, coverage honesty and
 * failure behaviour. A real GraphClient over a mocked fetch; no network.
 * Invented data only.
 */

import {
  BlastRadiusService,
  createBlastRadiusService,
  deriveBlastRadiusKey,
  describeLastVerb,
} from '../../../../src/services/graph';
import { ExtractedEmailData } from '../../../../src/types';
import {
  FakeResponder,
  RecordedRequest,
  collection,
  fakeGraph,
  graphErrorResponse,
  jsonResponse,
} from '../../../mocks/graph.fake';

const NOW = new Date('2026-11-17T12:00:00Z');
const SENDER = 'billing-alerts@example.org';
const SUBJECT = "Invoice 7731 overdue - it's urgent";
const TRACE_PATH = '/admin/exchange/tracing/messageTraces';

function email(overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData {
  return {
    from_email: 'alice@example.com',
    subject: 'FW: ' + SUBJECT,
    text: 'body',
    html: '',
    headers: {},
    forwardedHeaders: {
      'Original-From': `Billing <${SENDER}>`,
      'Original-Subject': SUBJECT,
      'Original-Date': 'Mon, 16 Nov 2026 08:00:00 +0000',
    },
    attachments: [],
    sender: 'alice@example.com',
    to: 'phishy@example.com',
    original_sender: 'alice@example.com',
    originalForwarder: 'alice@example.com',
    links: [],
    ...overrides,
  };
}

function user(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: `id-${name}`,
    userPrincipalName: `${name}@example.com`,
    mail: `${name}@example.com`,
    userType: 'Member',
    accountEnabled: true,
    assignedPlans: [{ service: 'exchange', capabilityStatus: 'Enabled' }],
    ...extra,
  };
}

function message(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: `msg-${name}`,
    internetMessageId: '<m1@mail.example.org>',
    subject: SUBJECT,
    from: { emailAddress: { address: SENDER } },
    receivedDateTime: '2026-11-16T08:00:00Z',
    parentFolderId: 'folder-inbox',
    isRead: false,
    body: { content: 'BODY-MUST-NOT-SURFACE' },
    ...extra,
  };
}

interface Tenant {
  users?: Record<string, unknown>[];
  /** Trace answer: rows, or an HTTP status to fail with */
  trace?: Record<string, unknown>[] | number;
  /** Messages in each user's mailbox, by user name */
  mailboxes?: Record<string, Record<string, unknown>[]>;
  /** Messages in each user's Recoverable Items */
  recoverable?: Record<string, Record<string, unknown>[]>;
  /** Raw last-verb value per message id */
  verbs?: Record<string, string>;
}

function tenant(config: Tenant): FakeResponder[] {
  const users = config.users ?? [user('alice'), user('bob'), user('carol')];
  return [
    (request: RecordedRequest): Response | undefined => {
      const path = decodeURIComponent(request.path);
      if (path === TRACE_PATH) {
        return typeof config.trace === 'number'
          ? graphErrorResponse(config.trace, 'Forbidden')
          : collection(config.trace ?? []);
      }
      if (path === '/users') {
        return collection(users);
      }
      const match = path.match(/^\/users\/id-([a-z0-9]+)\/(.+)$/);
      if (!match) {
        return undefined;
      }
      const [, name, rest] = match;
      // A Message-ID filter returns only the messages with that ID
      const wantedId = request.query.$filter?.match(/^internetMessageId eq '(.+)'$/)?.[1];
      const matching = (messages: Record<string, unknown>[] = []): Record<string, unknown>[] =>
        wantedId ? messages.filter(item => item.internetMessageId === wantedId) : messages;
      if (rest === 'messages') {
        return collection(matching(config.mailboxes?.[name]));
      }
      if (rest === 'mailFolders/recoverableitemsdeletions/messages') {
        return collection(matching(config.recoverable?.[name]));
      }
      const folder = rest.match(/^mailFolders\/(inbox|junkemail|deleteditems)$/);
      if (folder) {
        return jsonResponse({
          id: `folder-${folder[1].replace('email', '').replace('items', '')}`,
        });
      }
      const single = rest.match(/^messages\/(.+)$/);
      if (single) {
        const value = config.verbs?.[single[1]];
        return jsonResponse({
          id: single[1],
          singleValueExtendedProperties:
            value === undefined ? undefined : [{ id: 'Integer 0x1081', value }],
        });
      }
      return undefined;
    },
  ];
}

function service(
  responders: FakeResponder[],
  options: { maxMailboxes?: number; timeBudgetMs?: number; now?: () => number } = {}
): {
  service: BlastRadiusService;
  requests: RecordedRequest[];
  graph: ReturnType<typeof fakeGraph>;
} {
  const graph = fakeGraph(responders);
  return {
    service: new BlastRadiusService({
      client: graph.client,
      now: options.now ?? ((): number => NOW.getTime()),
      maxMailboxes: options.maxMailboxes,
      timeBudgetMs: options.timeBudgetMs,
      concurrency: 2,
    }),
    requests: graph.requests,
    graph,
  };
}

describe('deriveBlastRadiusKey', () => {
  it('uses the claimed sender, quoted subject and a window around the claimed date', () => {
    const key = deriveBlastRadiusKey(email(), NOW);
    expect(key).toEqual({
      internetMessageId: undefined,
      senderAddress: SENDER,
      subject: SUBJECT,
      receivedFrom: new Date('2026-11-15T08:00:00Z'),
      receivedTo: new Date('2026-11-17T08:00:00Z'),
    });
  });

  it('prefers a Message-ID when the parsed email has one', () => {
    const key = deriveBlastRadiusKey(
      email({ forwardedHeaders: { 'Original-Message-ID': 'm1@mail.example.org' } }),
      NOW
    );
    expect(key?.internetMessageId).toBe('<m1@mail.example.org>');
  });

  it('ignores a malformed Message-ID', () => {
    const key = deriveBlastRadiusKey(
      email({
        forwardedHeaders: { 'Original-Message-ID': '<a b@x> or 1 eq 1', 'Original-From': SENDER },
      }),
      NOW
    );
    expect(key?.internetMessageId).toBeUndefined();
    expect(key?.senderAddress).toBe(SENDER);
  });

  it('falls back to the forward subject without its prefixes, and to a lookback window', () => {
    const key = deriveBlastRadiusKey(
      email({
        subject: 'FW: Fwd:  Payroll update',
        forwardedHeaders: { 'Original-From': `x [mailto:${SENDER}]`, 'Original-Date': 'garbage' },
      }),
      NOW
    );
    expect(key?.subject).toBe('Payroll update');
    expect(key?.receivedTo).toEqual(NOW);
    expect(key?.receivedFrom).toEqual(new Date('2026-11-10T12:00:00Z'));
  });

  it('does not believe a date far in the past or the future', () => {
    for (const date of ['Mon, 16 Nov 2020 08:00:00 +0000', 'Mon, 16 Nov 2031 08:00:00 +0000']) {
      const key = deriveBlastRadiusKey(
        email({ forwardedHeaders: { 'Original-From': SENDER, 'Original-Date': date } }),
        NOW
      );
      expect(key?.receivedTo).toEqual(NOW);
    }
  });

  it('drops an over-long subject and returns nothing without sender or Message-ID', () => {
    const long = deriveBlastRadiusKey(
      email({ forwardedHeaders: { 'Original-From': SENDER, 'Original-Subject': 'x'.repeat(300) } }),
      NOW
    );
    expect(long?.subject).toBeUndefined();
    expect(
      deriveBlastRadiusKey(email({ forwardedHeaders: { 'Original-From': 'A Colleague' } }), NOW)
    ).toBeUndefined();
  });
});

describe('describeLastVerb', () => {
  it('reports only the MAPI reply and forward verbs as actions', () => {
    expect(describeLastVerb(102)).toEqual({ response: 'replied' });
    expect(describeLastVerb(103)).toEqual({ response: 'replied' });
    expect(describeLastVerb(104)).toEqual({ response: 'forwarded' });
    expect(describeLastVerb(undefined)).toEqual({ response: 'none' });
    expect(describeLastVerb(261)).toEqual({ response: 'unknown', lastVerbCode: 261 });
    expect(describeLastVerb(262)).toEqual({ response: 'unknown', lastVerbCode: 262 });
  });
});

describe('BlastRadiusService', () => {
  it('uses message trace, then reads the recipients that are user mailboxes', async () => {
    const { service: blast, requests } = service(
      tenant({
        trace: [
          { recipientAddress: 'Alice@example.com', status: 'Delivered' },
          { recipientAddress: 'bob@example.com', status: 'FilteredAsSpam' },
          { recipientAddress: 'bob@example.com', status: 'FilteredAsSpam' },
          { recipientAddress: 'all-staff@example.com', status: '<script>' },
          { recipientAddress: 'not an address' },
        ],
        mailboxes: {
          alice: [message('alice', { isRead: true })],
          bob: [message('bob', { parentFolderId: 'folder-junk' })],
        },
        verbs: { 'msg-alice': '104' },
      })
    );

    const report = await blast.lookup(email(), { reporterAddress: 'Alice@example.com' });

    expect(report.route).toBe('trace');
    expect(report.matchedBy).toBe('senderSubject');
    expect(report.reporterAddress).toBe('alice@example.com');
    expect(report.totals).toEqual({
      recipients: 3,
      read: 1,
      replied: 0,
      forwarded: 1,
      notDelivered: 0,
    });
    expect(report.recipients).toEqual([
      expect.objectContaining({
        address: 'alice@example.com',
        deliveryStatus: 'Delivered',
        mailbox: 'found',
        folder: 'inbox',
        isRead: true,
        response: 'forwarded',
      }),
      expect.objectContaining({
        address: 'bob@example.com',
        deliveryStatus: 'FilteredAsSpam',
        mailbox: 'found',
        folder: 'junk',
        isRead: false,
        response: 'none',
      }),
      { address: 'all-staff@example.com', mailbox: 'not_checked', deliveryStatus: undefined },
    ]);
    // The group address is not a readable mailbox: coverage says so
    expect(report.status).toBe('partial');
    expect(report.coverage).toMatchObject({ mailboxesChecked: 2, mailboxesEligible: 3 });

    // carol was not a recipient: her mailbox is never touched
    expect(requests.some(request => request.path.includes('id-carol'))).toBe(false);
    expect(requests.every(request => request.method === 'GET')).toBe(true);
    expect(JSON.stringify(report)).not.toContain('BODY-MUST-NOT-SURFACE');
  });

  it('reads mailboxes by the Message-IDs trace recorded, however the trace was keyed', async () => {
    const { service: blast, requests } = service(
      tenant({
        trace: [
          // Two distinct messages in the campaign; trace gives one ID bare
          {
            recipientAddress: 'alice@example.com',
            status: 'delivered',
            messageId: '<m1@mail.example.org>',
          },
          {
            recipientAddress: 'bob@example.com',
            status: 'delivered',
            messageId: 'm2@mail.example.org',
          },
          {
            recipientAddress: 'carol@example.com',
            status: 'delivered',
            messageId: '<m1@mail.example.org>',
          },
          {
            recipientAddress: 'carol@example.com',
            status: 'delivered',
            messageId: '<m2@mail.example.org>',
          },
          { recipientAddress: 'carol@example.com', status: 'delivered', messageId: "x' or 1 eq 1" },
        ],
        mailboxes: {
          alice: [message('alice')],
          bob: [message('bob', { internetMessageId: '<m2@mail.example.org>', isRead: true })],
          carol: [
            message('carol-1'),
            message('carol-2', { internetMessageId: '<m2@mail.example.org>' }),
          ],
        },
        verbs: { 'msg-bob': '103' },
      })
    );

    // The key is sender + subject: only the trace query may use it
    const report = await blast.lookup(email());

    const searches = requests.filter(request => /\/messages$/.test(request.path));
    expect(searches.length).toBeGreaterThan(0);
    for (const search of searches) {
      expect(search.query.$filter).toMatch(/^internetMessageId eq '<m[12]@mail\.example\.org>'$/);
      expect(search.query.$orderby).toBeUndefined();
    }
    const filtersFor = (name: string): string[] =>
      requests
        .filter(request => request.path === `/users/id-${name}/messages`)
        .map(request => request.query.$filter);
    expect(filtersFor('alice')).toEqual(["internetMessageId eq '<m1@mail.example.org>'"]);
    expect(filtersFor('bob')).toEqual(["internetMessageId eq '<m2@mail.example.org>'"]);
    expect(filtersFor('carol')).toEqual([
      "internetMessageId eq '<m1@mail.example.org>'",
      "internetMessageId eq '<m2@mail.example.org>'",
    ]);

    expect(report.status).toBe('complete');
    expect(report.matchedBy).toBe('senderSubject');
    expect(report.totals).toMatchObject({ recipients: 3, read: 1, replied: 1 });
    expect(report.recipients?.[0]).toMatchObject({
      address: 'bob@example.com',
      folder: 'inbox',
      response: 'replied',
    });
    expect(report.recipients?.find(row => row.address === 'carol@example.com')).toMatchObject({
      mailbox: 'found',
      copies: 2,
    });
    expect(report.coverage).toMatchObject({ mailboxesChecked: 3, mailboxesEligible: 3 });
  });

  it('caps the Message-IDs looked up per mailbox and says so', async () => {
    const ids = [1, 2, 3, 4, 5].map(n => `<many-${n}@mail.example.org>`);
    const { service: blast, requests } = service(
      tenant({
        trace: ids.map(messageId => ({
          recipientAddress: 'alice@example.com',
          status: 'Delivered',
          messageId,
        })),
      })
    );
    const report = await blast.lookup(email());
    expect(requests.filter(request => request.path === '/users/id-alice/messages')).toHaveLength(3);
    expect(report.caveats).toContain(
      '1 recipient(s) received more than 3 matching messages; only 3 were looked up in each of their mailboxes.'
    );
  });

  it('never presents expanded or failed trace rows as a delivered mailbox copy', async () => {
    const { service: blast, requests } = service(
      tenant({
        trace: [
          {
            recipientAddress: 'all-staff@example.com',
            status: 'expanded',
            messageId: '<m1@mail.example.org>',
          },
          {
            recipientAddress: 'alice@example.com',
            status: 'delivered',
            messageId: '<m1@mail.example.org>',
          },
          {
            recipientAddress: 'bob@example.com',
            status: 'Failed',
            messageId: '<m1@mail.example.org>',
          },
          // A failed attempt followed by a delivery is a delivery
          {
            recipientAddress: 'carol@example.com',
            status: 'failed',
            messageId: '<m1@mail.example.org>',
          },
          {
            recipientAddress: 'carol@example.com',
            status: 'delivered',
            messageId: '<m1@mail.example.org>',
          },
        ],
        // Even if a copy were somehow there, a failed delivery is not searched
        mailboxes: { alice: [message('alice')], bob: [message('bob')], carol: [message('carol')] },
      })
    );

    const report = await blast.lookup(email());

    expect(report.totals).toMatchObject({ recipients: 2, notDelivered: 1 });
    expect(report.recipients?.map(row => [row.address, row.mailbox, row.deliveryStatus])).toEqual([
      ['alice@example.com', 'found', 'delivered'],
      ['carol@example.com', 'found', 'delivered'],
      ['bob@example.com', 'not_delivered', 'Failed'],
    ]);
    expect(JSON.stringify(report.recipients)).not.toContain('all-staff');
    expect(report.caveats?.join(' ')).toContain(
      '1 distribution-list address(es) that message trace shows as expanded are not listed'
    );
    expect(requests.some(request => request.path.includes('id-bob'))).toBe(false);
    // Neither kind counts against mailbox coverage
    expect(report.coverage).toMatchObject({ mailboxesChecked: 2, mailboxesEligible: 2 });
    expect(report.status).toBe('complete');
  });

  it('falls back on an intermittent trace 403 and uses trace again once it answers', async () => {
    let traceCalls = 0;
    const rows = [
      {
        recipientAddress: 'alice@example.com',
        status: 'delivered',
        messageId: '<m1@mail.example.org>',
      },
    ];
    const { service: blast } = service([
      request => {
        if (request.path !== TRACE_PATH) {
          return undefined;
        }
        traceCalls += 1;
        return traceCalls === 1 ? graphErrorResponse(403, 'Forbidden') : collection(rows);
      },
      ...tenant({ mailboxes: { alice: [message('alice')] } }),
    ]);

    const refused = await blast.lookup(email());
    expect(refused.route).toBe('mailbox');
    expect(refused.status).not.toBe('unavailable');
    expect(refused.totals?.recipients).toBe(1);
    expect(refused.caveats).toContain(
      'Message trace was not available, so mailboxes were searched directly.'
    );

    // A different message, so the first result is not reused
    const answered = await blast.lookup(
      email({ forwardedHeaders: { 'Original-From': SENDER, 'Original-Subject': 'Another one' } })
    );
    expect(answered.route).toBe('trace');
    expect(answered.caveats?.join(' ')).not.toContain('Message trace was not available');
  });

  it('has full detail for every mailbox it reached when time runs out', async () => {
    // The clock passes the deadline as soon as the first mailbox has matched
    let late = false;
    const { service: blast, graph } = service(
      tenant({
        trace: 403,
        mailboxes: {
          alice: [message('alice', { isRead: true })],
          bob: [message('bob')],
          carol: [message('carol')],
        },
        verbs: { 'msg-alice': '102', 'msg-bob': '104' },
      }),
      { now: () => NOW.getTime() + (late ? 60_000 : 0) }
    );
    const original = graph.fetchMock.getMockImplementation()!;
    graph.fetchMock.mockImplementation((input, init) => {
      if (/\/messages\?/.test(String(input))) {
        late = true;
      }
      return original(input, init);
    });

    const report = await blast.lookup(email());

    expect(report.status).toBe('partial');
    expect(report.coverage?.mailboxesChecked).toBeLessThan(3);
    expect(report.recipients?.length).toBeGreaterThan(0);
    for (const row of report.recipients ?? []) {
      expect(row.folder).toBe('inbox');
      expect(['replied', 'forwarded']).toContain(row.response);
    }
    expect(report.coverage?.detailUnavailable).toBe(0);
  });

  it('sends hostile strings only as escaped filter literals', async () => {
    const { service: blast, requests } = service(tenant({ trace: 403, mailboxes: {} }));
    await blast.lookup(email());

    const trace = requests.find(request => request.path === TRACE_PATH);
    expect(trace?.query.$filter).toBe(
      "receivedDateTime ge 2026-11-15T08:00:00Z and receivedDateTime le 2026-11-17T08:00:00Z and senderAddress eq 'billing-alerts@example.org' and contains(subject, 'Invoice 7731 overdue - it''s urgent')"
    );
    const mailbox = requests.find(request => request.path === '/users/id-alice/messages');
    expect(mailbox?.query.$filter).toBe(
      "receivedDateTime ge 2026-11-15T08:00:00.000Z and receivedDateTime lt 2026-11-17T08:00:00.000Z and from/emailAddress/address eq 'billing-alerts@example.org' and subject eq 'Invoice 7731 overdue - it''s urgent'"
    );
    expect(mailbox?.query.$search).toBeUndefined();
  });

  it('falls back to searching mailboxes when trace is refused', async () => {
    const { service: blast, requests } = service(
      tenant({
        trace: 403,
        users: [
          user('alice'),
          user('bob'),
          user('carol'),
          user('guest', { userType: 'Guest' }),
          user('shared', { assignedPlans: [] }),
          user('leaver', { accountEnabled: false }),
        ],
        mailboxes: { bob: [message('bob', { isRead: true, parentFolderId: 'folder-deleted' })] },
        recoverable: { carol: [message('carol', { isRead: true })] },
        verbs: { 'msg-bob': '102', 'msg-carol': '999' },
      })
    );

    const report = await blast.lookup(email());

    expect(report.status).toBe('complete');
    expect(report.route).toBe('mailbox');
    expect(report.coverage).toEqual({
      mailboxesChecked: 3,
      mailboxesEligible: 3,
      eligibleIsLowerBound: false,
      recoverableChecked: 2,
      recoverableCandidates: 2,
      detailUnavailable: 0,
    });
    expect(report.totals).toEqual({ recipients: 2, read: 2, replied: 1, forwarded: 0 });
    expect(report.recipients).toEqual([
      expect.objectContaining({
        address: 'bob@example.com',
        folder: 'deleted',
        response: 'replied',
      }),
      expect.objectContaining({
        address: 'carol@example.com',
        folder: 'recoverable',
        response: 'unknown',
        lastVerbCode: 999,
      }),
    ]);
    expect(report.caveats?.join(' ')).toContain('Message trace was not available');
    for (const skipped of ['id-guest', 'id-shared', 'id-leaver']) {
      expect(requests.some(request => request.path.includes(skipped))).toBe(false);
    }
    expect(requests.every(request => request.method === 'GET')).toBe(true);
  });

  it('falls back when trace answers with no rows, and says so', async () => {
    const { service: blast } = service(
      tenant({ trace: [], mailboxes: { alice: [message('alice')] } })
    );
    const report = await blast.lookup(email());
    expect(report.route).toBe('mailbox');
    expect(report.totals?.recipients).toBe(1);
    expect(report.caveats?.join(' ')).toContain('Message trace returned no rows');
  });

  it('looks up by Message-ID in both trace forms and in mailboxes', async () => {
    const { service: blast, requests } = service(
      tenant({ trace: [], mailboxes: { alice: [message('alice')] } })
    );
    const report = await blast.lookup(
      email({ forwardedHeaders: { 'Original-Message-ID': '<m1@mail.example.org>' } })
    );

    const traces = requests.filter(request => request.path === TRACE_PATH);
    expect(traces.map(request => request.query.$filter)).toEqual([
      expect.stringContaining("messageId eq '<m1@mail.example.org>'"),
      expect.stringContaining("messageId eq 'm1@mail.example.org'"),
    ]);
    const mailbox = requests.find(request => request.path === '/users/id-alice/messages');
    expect(mailbox?.query.$filter).toBe("internetMessageId eq '<m1@mail.example.org>'");
    expect(report.matchedBy).toBe('messageId');
    expect(report.caveats?.join(' ')).toContain('only copies of this exact message');
  });

  it('reports partial coverage when the mailbox cap is reached', async () => {
    const { service: blast } = service(
      tenant({ trace: 403, mailboxes: { alice: [message('alice')] } }),
      { maxMailboxes: 2 }
    );
    const report = await blast.lookup(email());
    expect(report.status).toBe('partial');
    expect(report.coverage).toMatchObject({ mailboxesChecked: 2, mailboxesEligible: 3 });
    expect(report.caveats).toContain('The mailbox cap (2) was reached.');
  });

  it('stops at the deadline and reports what it covered', async () => {
    // A clock that jumps past the deadline once the first mailbox was searched
    let late = false;
    const { service: blast, graph } = service(tenant({ trace: 403, mailboxes: {} }), {
      now: () => NOW.getTime() + (late ? 60_000 : 0),
    });
    const original = graph.fetchMock.getMockImplementation()!;
    graph.fetchMock.mockImplementation((input, init) => {
      const response = original(input, init);
      if (String(input).includes('/messages')) {
        late = true;
      }
      return response;
    });

    const report = await blast.lookup(email());
    expect(report.status).toBe('partial');
    expect(report.coverage?.mailboxesChecked).toBeLessThan(3);
    expect(report.coverage?.mailboxesEligible).toBe(3);
  });

  it('gives up at the hard time budget when Graph never answers', async () => {
    jest.useFakeTimers();
    try {
      const { service: blast, graph } = service([], {
        timeBudgetMs: 5000,
        now: () => Date.now(),
      });
      graph.fetchMock.mockImplementation(() => new Promise<Response>(() => undefined));
      const pending = blast.lookup(email());
      await jest.advanceTimersByTimeAsync(5001);
      const report = await pending;
      expect(report.status).toBe('unavailable');
      expect(report.note).toContain('ran out of time');
    } finally {
      jest.useRealTimers();
    }
  });

  it('keeps the trace recipients when the budget ends during mailbox reads', async () => {
    jest.useFakeTimers();
    try {
      const { service: blast, graph } = service(
        tenant({ trace: [{ recipientAddress: 'bob@example.com', status: 'Delivered' }] }),
        { timeBudgetMs: 5000, now: () => Date.now() }
      );
      const original = graph.fetchMock.getMockImplementation()!;
      graph.fetchMock.mockImplementation((input, init) =>
        String(input).includes('/messages')
          ? new Promise<Response>(() => undefined)
          : original(input, init)
      );
      const pending = blast.lookup(email());
      await jest.advanceTimersByTimeAsync(5001);
      const report = await pending;
      expect(report.status).toBe('partial');
      expect(report.recipients).toEqual([
        { address: 'bob@example.com', mailbox: 'not_checked', deliveryStatus: 'Delivered' },
      ]);
      expect(report.caveats).toContain('The lookup stopped at its time budget.');
    } finally {
      jest.useRealTimers();
    }
  });

  it('stops on throttling and is unavailable when nothing was read', async () => {
    const { service: blast, requests } = service([
      request =>
        request.path.endsWith('/messages') ? graphErrorResponse(429, 'TooManyRequests') : undefined,
      ...tenant({ trace: 403 }),
    ]);
    const report = await blast.lookup(email());
    expect(report.status).toBe('unavailable');
    expect(report.note).toBe(
      'Blast radius lookup could not be completed: Microsoft Graph throttled the requests.'
    );
    // Two workers each got one refusal; nobody carried on
    expect(requests.filter(request => request.path.endsWith('/messages')).length).toBeLessThan(3);
  });

  it('is unavailable when mailbox reads are refused', async () => {
    const many = Array.from({ length: 8 }, (_, index) => user(`u${index}`));
    const { service: blast, requests } = service([
      request =>
        request.path.endsWith('/messages')
          ? graphErrorResponse(403, 'ErrorAccessDenied')
          : undefined,
      ...tenant({ trace: 403, users: many }),
    ]);
    const report = await blast.lookup(email());
    expect(report.status).toBe('unavailable');
    expect(report.note).toContain('refused');
    expect(requests.filter(request => request.path.endsWith('/messages')).length).toBeLessThan(8);
  });

  it('is unavailable when neither trace nor the directory can be read', async () => {
    const { service: blast } = service([() => graphErrorResponse(500, 'ServiceUnavailable')]);
    const report = await blast.lookup(email());
    expect(report).toMatchObject({ status: 'unavailable' });
    expect(report.recipients).toBeUndefined();
  });

  it('reports "unknown" rather than guessing when folder and verb cannot be read', async () => {
    const { service: blast } = service([
      request =>
        /mailFolders\/(inbox|junkemail|deleteditems)$/.test(request.path) ||
        /\/messages\/msg-/.test(request.path)
          ? graphErrorResponse(403, 'ErrorAccessDenied')
          : undefined,
      ...tenant({
        trace: 403,
        mailboxes: { alice: [message('alice', { parentFolderId: 'folder-archive' })] },
      }),
    ]);
    const report = await blast.lookup(email());
    expect(report.recipients?.[0]).toMatchObject({ folder: 'unknown', response: 'unknown' });
    // The failure is counted and disclosed, not silently shown as "unknown"
    expect(report.status).toBe('partial');
    expect(report.coverage?.detailUnavailable).toBe(1);
    expect(report.caveats).toContain(
      'Folder or replied/forwarded detail could not be read for 1 recipient(s); it is shown as Unknown.'
    );
    expect(report.caveats?.join(' ')).toContain('4 Microsoft Graph request(s) failed');
  });

  it('counts a mailbox whose detail was never read when the budget ends first', async () => {
    jest.useFakeTimers();
    try {
      const { service: blast, graph } = service(
        tenant({ trace: 403, mailboxes: { alice: [message('alice')] } }),
        { timeBudgetMs: 5000, now: () => Date.now() }
      );
      const original = graph.fetchMock.getMockImplementation()!;
      graph.fetchMock.mockImplementation((input, init) =>
        /mailFolders\/|messages\/msg-/.test(String(input))
          ? new Promise<Response>(() => undefined)
          : original(input, init)
      );
      const pending = blast.lookup(email());
      await jest.advanceTimersByTimeAsync(5001);
      const report = await pending;
      expect(report.status).toBe('partial');
      expect(report.recipients?.[0]).toMatchObject({ folder: 'unknown', response: 'unknown' });
      expect(report.coverage?.detailUnavailable).toBe(1);
      expect(report.caveats?.join(' ')).toContain('detail could not be read for 1 recipient(s)');
    } finally {
      jest.useRealTimers();
    }
  });

  it('does not start without an identifiable message or without time', async () => {
    const { service: blast, requests } = service(tenant({}));
    const noKey = await blast.lookup(email({ forwardedHeaders: {} }));
    expect(noKey.note).toContain('could not be identified');
    const noTime = await blast.lookup(email(), { remainingMs: 21_000 });
    expect(noTime.note).toContain('not enough processing time');
    expect(requests).toHaveLength(0);
  });

  it('reuses a recent result for the same message instead of sweeping again', async () => {
    const { service: blast, requests } = service(
      tenant({ trace: 403, mailboxes: { alice: [message('alice')] } })
    );
    const first = await blast.lookup(email());
    const count = requests.length;
    const second = await blast.lookup(email(), { reporterAddress: 'bob@example.com' });
    expect(requests).toHaveLength(count);
    expect(second.recipients).toEqual(first.recipients);
    expect(second.reporterAddress).toBe('bob@example.com');
    expect(first.reporterAddress).toBeUndefined();
  });
});

describe('createBlastRadiusService', () => {
  const graph = {
    enabled: true,
    tenantId: '00000000-0000-0000-0000-000000000000',
    read: {
      clientId: '11111111-1111-1111-1111-111111111111',
      certificate: 'unused-until-first-call',
    },
  };
  const blastRadius = { enabled: true, timeBudgetMs: 45000, maxMailboxes: 2000 };

  it('needs both graph.enabled and graph.blastRadius.enabled', () => {
    expect(createBlastRadiusService(undefined)).toBeUndefined();
    expect(createBlastRadiusService(graph)).toBeUndefined();
    expect(createBlastRadiusService({ ...graph, enabled: false, blastRadius })).toBeUndefined();
    expect(
      createBlastRadiusService({ ...graph, blastRadius: { ...blastRadius, enabled: false } })
    ).toBeUndefined();
    expect(createBlastRadiusService({ ...graph, blastRadius })).toBeInstanceOf(BlastRadiusService);
  });
});

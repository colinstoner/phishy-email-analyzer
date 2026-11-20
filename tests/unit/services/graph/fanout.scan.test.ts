/**
 * Fan-out scan (the broker-side core): grouping and normalization, the full
 * rule end to end through a real GraphClient over a mocked fetch, row
 * statuses, paging limits and incomplete scans, 403 retries, request
 * budgets and their separation from the on-report check. No network.
 * Invented data only.
 */

import {
  FANOUT_INSTANCE_ALLOWANCE_PER_5_MIN,
  FanoutScanRequest,
  FanoutScanService,
  FanoutScanSettings,
  SenderHistoryService,
  createFanoutScanService,
  groupInboundRows,
  isInternalAddress,
  listMessageTracePage,
  selectCandidates,
  statusBucket,
} from '../../../../src/services/graph';
import { graphPath } from '../../../../src/services/graph/graph.request';
import { collection, fakeGraph, jsonResponse } from '../../../mocks/graph.fake';
import {
  INTERNAL_DOMAINS,
  NOW,
  SENDER,
  SUBJECT,
  WINDOW,
  establishedHistory,
  fanoutResponder,
  takeoverTenant,
  traceRow,
  wave,
} from '../../../mocks/fanout.tenant';

const SETTINGS: FanoutScanSettings = {
  lookbackDays: 30,
  burstWindowHours: 24,
  fanoutMinRecipients: 15,
  fanoutMultiplier: 3,
};

const REQUEST: FanoutScanRequest = {
  ...WINDOW,
  internalDomains: INTERNAL_DOMAINS,
  maxPages: 4,
  maxCandidates: 3,
  maxRequests: 20,
  budgetMs: 60_000,
};

const deps = { now: (): number => NOW, sleep: (): Promise<void> => Promise.resolve() };

function service(tenant = takeoverTenant()): {
  scan: FanoutScanService;
  graph: ReturnType<typeof fakeGraph>;
  responder: ReturnType<typeof fanoutResponder>;
} {
  const responder = fanoutResponder(tenant);
  const graph = fakeGraph([responder]);
  return { scan: new FanoutScanService(graph.client, SETTINGS, deps), graph, responder };
}

describe('grouping', () => {
  it('knows internal addresses by domain and subdomain only', () => {
    expect(isInternalAddress('a@example.com', INTERNAL_DOMAINS)).toBe(true);
    expect(isInternalAddress('a@mail.example.com', INTERNAL_DOMAINS)).toBe(true);
    expect(isInternalAddress('a@example.com.example.net', INTERNAL_DOMAINS)).toBe(false);
    expect(isInternalAddress('a@notexample.com', INTERNAL_DOMAINS)).toBe(false);
    expect(isInternalAddress('example.com', INTERNAL_DOMAINS)).toBe(false);
  });

  it('maps trace statuses to the alert’s buckets', () => {
    expect(statusBucket('Delivered')).toBe('delivered');
    expect(statusBucket('FilteredAsSpam')).toBe('junk');
    expect(statusBucket('Quarantined')).toBe('quarantined');
    expect(statusBucket('Failed')).toBe('failed');
    expect(statusBucket('Pending')).toBe('other');
    expect(statusBucket(undefined)).toBe('other');
  });

  it('groups inbound rows by sender and normalized subject, case and spacing ignored', () => {
    const rows = [
      traceRow('Pat@Supplier.Example.NET', 'a@example.com', NOW - 60_000, {
        subject: 'Hello  World',
      }),
      traceRow(SENDER, 'b@example.com', NOW - 50_000, { subject: ' hello world ' }),
      traceRow(SENDER, 'c@example.com', NOW - 40_000, { subject: 'Something else' }),
    ];
    const { inboundRows, groups } = groupInboundRows(rows, INTERNAL_DOMAINS);
    expect(inboundRows).toBe(3);
    expect(groups.size).toBe(2);
    const hello = [...groups.values()].find(group => group.subjectKey === 'hello world');
    expect(hello?.recipients.size).toBe(2);
    expect(hello?.senderAddress).toBe(SENDER);
    // The subject shown is the earliest row's, as the sender wrote it
    expect(hello?.subject).toBe('Hello  World');
  });

  it('ignores outbound, internal-to-internal and external-to-external rows', () => {
    const rows = [
      traceRow('alex@example.com', SENDER, NOW - 1000),
      traceRow('alex@example.com', 'sam@example.com', NOW - 1000),
      traceRow(SENDER, 'someone@example.org', NOW - 1000),
      traceRow(SENDER, 'kim@example.com', NOW - 1000, { senderAddress: undefined }),
      traceRow(SENDER, 'kim@example.com', NOW - 1000, { receivedDateTime: undefined }),
    ];
    const { inboundRows, groups } = groupInboundRows(rows, INTERNAL_DOMAINS);
    expect(inboundRows).toBe(0);
    expect(groups.size).toBe(0);
  });

  it('counts an expanded row (distribution list) as no recipient, and failed or filtered rows as recipients', () => {
    const rows = [
      traceRow(SENDER, 'all-staff@example.com', NOW - 1000, { status: 'Expanded' }),
      traceRow(SENDER, 'a@example.com', NOW - 900, { status: 'Failed' }),
      traceRow(SENDER, 'b@example.com', NOW - 800, { status: 'Quarantined' }),
      traceRow(SENDER, 'c@example.com', NOW - 700, { status: 'FilteredAsSpam' }),
    ];
    const [group] = groupInboundRows(rows, INTERNAL_DOMAINS).groups.values();
    expect([...group.recipients.keys()].sort()).toEqual([
      'a@example.com',
      'b@example.com',
      'c@example.com',
    ]);
    expect(group.recipients.get('a@example.com')).toBe('failed');
  });

  it('keeps each recipient’s best delivery state and counts a repeated row once', () => {
    const delivered = traceRow(SENDER, 'a@example.com', NOW - 500, { status: 'Delivered' });
    const rows = [
      traceRow(SENDER, 'a@example.com', NOW - 900, { status: 'Quarantined' }),
      delivered,
      { ...delivered },
    ];
    const { inboundRows, groups } = groupInboundRows(rows, INTERNAL_DOMAINS);
    expect(inboundRows).toBe(2);
    const [group] = groups.values();
    expect(group.recipients.get('a@example.com')).toBe('delivered');
  });

  it('selects groups at the minimum, most recipients first', () => {
    const rows = [
      ...wave(16, { sender: 'one@supplier.example.net' }),
      ...wave(25, { sender: 'two@supplier.example.net' }),
      ...wave(14, { sender: 'three@supplier.example.net' }),
    ];
    const selected = selectCandidates(groupInboundRows(rows, INTERNAL_DOMAINS).groups, 15);
    expect(selected.map(group => group.senderAddress)).toEqual([
      'two@supplier.example.net',
      'one@supplier.example.net',
    ]);
  });
});

describe('listMessageTracePage', () => {
  it('asks for the window with no address predicate, at $top 5000', async () => {
    const graph = fakeGraph([() => collection([])]);
    await listMessageTracePage(graph.client, { ...WINDOW, now: new Date(NOW) });
    expect(graph.requests).toHaveLength(1);
    expect(graph.requests[0].method).toBe('GET');
    expect(graph.requests[0].query.$top).toBe('5000');
    expect(graph.requests[0].query.$filter).toBe(
      'receivedDateTime ge 2026-11-17T11:45:00Z and receivedDateTime le 2026-11-17T12:00:00Z'
    );
  });

  it('rejects a page with rows outside the window: the date filter was not applied', async () => {
    const graph = fakeGraph([
      () => collection([traceRow(SENDER, 'a@example.com', NOW - 3 * 60 * 60 * 1000)]),
    ]);
    await expect(
      listMessageTracePage(graph.client, { ...WINDOW, now: new Date(NOW) })
    ).rejects.toMatchObject({ kind: 'filter_not_applied' });
  });

  it('refuses a window the service would refuse, before any request', async () => {
    const graph = fakeGraph([() => collection([])]);
    await expect(
      listMessageTracePage(graph.client, {
        receivedFrom: new Date(NOW - 11 * 24 * 60 * 60 * 1000),
        receivedTo: new Date(NOW),
        now: new Date(NOW),
      })
    ).rejects.toThrow('10 days');
    expect(graph.requests).toHaveLength(0);
  });
});

describe('GraphClient.getPage cursors', () => {
  const PATH = graphPath`/admin/exchange/tracing/messageTraces`;
  const OTHER = graphPath`/users`;

  it('follows a next link only through its own cursor, on the same path', async () => {
    const graph = fakeGraph([
      request =>
        request.query.$skiptoken
          ? collection([{ id: 'second' }])
          : collection(
              [{ id: 'first' }],
              'https://graph.microsoft.com/v1.0/admin/exchange/tracing/messageTraces?$skiptoken=2'
            ),
    ]);
    const first = await graph.client.getPage(PATH);
    expect(first.next).toBeDefined();
    await expect(graph.client.getPage(OTHER, { cursor: first.next })).rejects.toMatchObject({
      kind: 'invalid_request',
    });
    const forged = Object.freeze({}) as typeof first.next;
    await expect(graph.client.getPage(PATH, { cursor: forged })).rejects.toMatchObject({
      kind: 'invalid_request',
    });
    const second = await graph.client.getPage(PATH, { cursor: first.next });
    expect(second.items).toEqual([{ id: 'second' }]);
    expect(second.next).toBeUndefined();
  });

  it('refuses a next link off the Graph origin', async () => {
    const graph = fakeGraph([
      () => collection([], 'https://graph.example.net/v1.0/admin/exchange/tracing/messageTraces'),
    ]);
    await expect(graph.client.getPage(PATH)).rejects.toMatchObject({ kind: 'unsafe_next_link' });
  });

  it('refuses a response with no value array', async () => {
    const graph = fakeGraph([() => jsonResponse({ nothing: true })]);
    await expect(graph.client.getPage(PATH)).rejects.toMatchObject({ kind: 'invalid_response' });
  });
});

describe('FanoutScanService', () => {
  it('flags an established two-way contact sending one subject to many new people, end to end', async () => {
    const { scan, graph } = service();
    const result = await scan.scan(REQUEST);

    expect(result.outcome).toBe('ok');
    expect(result.incomplete).toBe(false);
    expect(result.candidates).toBe(1);
    expect(result.candidatesChecked).toBe(1);
    expect(result.flagged).toHaveLength(1);
    const [flag] = result.flagged;
    expect(flag.senderAddress).toBe(SENDER);
    expect(flag.subject).toBe(SUBJECT);
    expect(flag.windowRecipients).toBe(20);
    expect(flag.windowMessages).toBe(1);
    expect(flag.statuses).toEqual({ delivered: 20, junk: 0, quarantined: 0, failed: 0, other: 0 });
    expect(flag.recipients).toHaveLength(20);
    expect(flag.facts.classification).toBe('established_with_anomalous_fanout');
    expect(flag.facts.burst.sameSubject.recipients.count).toBe(20);
    expect(flag.facts.history.recipients.count).toBe(2);

    // 1 window page + 3 windows x 2 history queries; all GET, all code-built
    expect(graph.requests).toHaveLength(7);
    expect(result.requestsUsed).toBe(7);
    expect(graph.requests.every(r => r.method === 'GET')).toBe(true);
    const filters = graph.requests.map(r => r.query.$filter ?? '');
    expect(filters.some(f => /endswith|contains/i.test(f))).toBe(false);
  });

  it('does not flag a bulk sender nobody in the organization writes to', async () => {
    const tenant = takeoverTenant();
    tenant.outbound = {};
    const result = await service(tenant).scan.scan(REQUEST);
    expect(result.candidates).toBe(1);
    expect(result.flagged).toHaveLength(0);
  });

  it('does not flag a wave below the minimum, and spends nothing on history for it', async () => {
    const { scan, graph } = service(takeoverTenant(14));
    const result = await scan.scan(REQUEST);
    expect(result.candidates).toBe(0);
    expect(result.flagged).toHaveLength(0);
    expect(graph.requests).toHaveLength(1);
  });

  it('judges the rule on the subject it found, not on another, wider subject of the sender', async () => {
    const history = establishedHistory();
    const flagged = wave(20, { subject: 'Wave subject' });
    // A different subject to many people earlier in the burst, outside the window
    const other = wave(40, { subject: 'Quarterly newsletter', atMs: NOW - 3 * 60 * 60 * 1000 });
    const result = await service({
      windowPages: [flagged],
      inbound: { [SENDER]: [...history.inbound, ...flagged, ...other] },
      outbound: { [SENDER]: history.outbound },
    }).scan.scan(REQUEST);
    expect(result.flagged).toHaveLength(1);
    expect(result.flagged[0].facts.burst.sameSubject.recipients.count).toBe(20);
  });

  it('reports delivery states, including what the filter already quarantined or junked', async () => {
    const history = establishedHistory();
    const statuses = ['Delivered', 'Quarantined', 'FilteredAsSpam', 'Failed'];
    const burst = wave(20, { status: i => statuses[i % 4] });
    const expanded = traceRow(SENDER, 'all-staff@example.com', NOW - 60_000, {
      status: 'Expanded',
      subject: SUBJECT,
    });
    const result = await service({
      windowPages: [[...burst, expanded]],
      inbound: { [SENDER]: [...history.inbound, ...burst, expanded] },
      outbound: { [SENDER]: history.outbound },
    }).scan.scan(REQUEST);
    const [flag] = result.flagged;
    expect(flag.windowRecipients).toBe(20);
    expect(flag.statuses).toEqual({ delivered: 5, junk: 5, quarantined: 5, failed: 5, other: 0 });
    expect(flag.recipients.some(r => r.address === 'all-staff@example.com')).toBe(false);
  });

  it('checks candidates most recipients first, up to the cap, and says the rest were not checked', async () => {
    const senders = ['a', 'b', 'c', 'd'].map(name => `${name}@supplier.example.net`);
    const windowRows = senders.flatMap((sender, i) => wave(16 + i, { sender }));
    const { scan } = service({ windowPages: [windowRows] });
    const result = await scan.scan({ ...REQUEST, maxCandidates: 2, maxRequests: 40 });
    expect(result.candidates).toBe(4);
    expect(result.candidatesChecked).toBe(2);
    expect(result.incomplete).toBe(true);
    expect(result.incompleteReasons).toContain('candidate_limit');
  });

  describe('paging', () => {
    it('reads pages up to the cap and then says the scan is incomplete', async () => {
      const tenant = takeoverTenant();
      tenant.windowPages = [tenant.windowPages[0], [], [], [], []];
      const { scan, responder } = service(tenant);
      const result = await scan.scan({ ...REQUEST, maxPages: 2 });
      expect(responder.windowRequests).toBe(2);
      expect(result.pages).toBe(2);
      expect(result.incomplete).toBe(true);
      expect(result.incompleteReasons).toEqual(['page_limit']);
      // What was read is still judged
      expect(result.flagged).toHaveLength(1);
    });

    it('is complete when the last page has no next link', async () => {
      const tenant = takeoverTenant();
      tenant.windowPages = [tenant.windowPages[0].slice(0, 10), tenant.windowPages[0].slice(10)];
      const result = await service(tenant).scan.scan(REQUEST);
      expect(result.pages).toBe(2);
      expect(result.incomplete).toBe(false);
      expect(result.flagged[0].windowRecipients).toBe(20);
    });

    it('keeps earlier pages when a later one fails, and says so', async () => {
      const tenant = takeoverTenant();
      tenant.windowPages = [tenant.windowPages[0], []];
      tenant.laterPageStatus = 503;
      const result = await service(tenant).scan.scan(REQUEST);
      expect(result.outcome).toBe('ok');
      expect(result.incompleteReasons).toContain('page_error');
      expect(result.flagged).toHaveLength(1);
    });

    it('fails the scan when the first page fails', async () => {
      const tenant = takeoverTenant();
      tenant.windowPages = [];
      const graph = fakeGraph([() => jsonResponse({ error: { code: 'Boom' } }, 500)]);
      const result = await new FanoutScanService(graph.client, SETTINGS, deps).scan(REQUEST);
      expect(result.outcome).toBe('error');
      expect(result.flagged).toHaveLength(0);
    });

    it('uses nothing when a page carries rows outside the window', async () => {
      const tenant = takeoverTenant(20, [
        traceRow(SENDER, 'z@example.com', NOW - 5 * 60 * 60 * 1000),
      ]);
      const result = await service(tenant).scan.scan(REQUEST);
      expect(result.outcome).toBe('error');
      expect(result.filterMismatch).toBe(true);
      expect(result.flagged).toHaveLength(0);
    });
  });

  describe('intermittent 403', () => {
    it('retries a window page that answered 403, counting each retry as a request', async () => {
      const tenant = takeoverTenant();
      tenant.windowForbidden = 2;
      const { scan, responder } = service(tenant);
      const result = await scan.scan(REQUEST);
      expect(result.outcome).toBe('ok');
      expect(result.forbiddenRetries).toBe(2);
      expect(responder.windowRequests).toBe(3);
      expect(result.requestsUsed).toBe(9);
      expect(result.flagged).toHaveLength(1);
    });

    it('is forbidden when the first page keeps answering 403', async () => {
      const tenant = takeoverTenant();
      tenant.windowForbidden = 10;
      const result = await service(tenant).scan.scan(REQUEST);
      expect(result.outcome).toBe('forbidden');
      expect(result.forbiddenRetries).toBe(3);
      expect(result.requestsUsed).toBe(4);
    });
  });

  describe('request budget', () => {
    it('never spends more than the scan was given, and says what it could not check', async () => {
      const { scan, graph } = service();
      // 1 page + 6 history requests would be needed
      const result = await scan.scan({ ...REQUEST, maxRequests: 5 });
      expect(graph.requests.length).toBeLessThanOrEqual(5);
      expect(result.requestsUsed).toBeLessThanOrEqual(5);
      expect(result.incompleteReasons).toContain('request_allowance');
      expect(result.flagged).toHaveLength(0);
    });

    it('spends a one-request budget on the window and starts no history lookup', async () => {
      const { scan, graph } = service();
      const result = await scan.scan({ ...REQUEST, maxRequests: 1 });
      expect(result.outcome).toBe('ok');
      expect(graph.requests).toHaveLength(1);
      expect(result.candidates).toBe(1);
      expect(result.candidatesChecked).toBe(0);
      expect(result.incompleteReasons).toEqual(['request_allowance']);
    });

    it('keeps its own per-instance cap across scans, whatever callers ask', async () => {
      const { scan } = service();
      let spent = 0;
      for (let i = 0; i < 10; i++) {
        spent += (await scan.scan({ ...REQUEST, maxRequests: 100 })).requestsUsed;
      }
      expect(spent).toBeLessThanOrEqual(FANOUT_INSTANCE_ALLOWANCE_PER_5_MIN);
      const after = await scan.scan({ ...REQUEST, maxRequests: 100 });
      expect(after.outcome).toBe('rate_limited');
    });

    it('does not touch the on-report sender-history allowance', async () => {
      const tenant = takeoverTenant();
      const graph = fakeGraph([fanoutResponder(tenant)]);
      const onReport = new SenderHistoryService(
        graph.client,
        {
          lookbackDays: 30,
          burstWindowHours: 24,
          budgetMs: 8000,
          fanoutMinRecipients: 15,
          fanoutMultiplier: 3,
          safeDomains: INTERNAL_DOMAINS,
          safeSenders: [],
        },
        deps
      );
      const scan = new FanoutScanService(graph.client, SETTINGS, deps);
      for (let i = 0; i < 5; i++) {
        await scan.scan({ ...REQUEST, maxRequests: 40 });
      }
      expect(onReport.requestsUsed()).toBe(0);
      const { metric } = await onReport.lookupSender(() => ({
        claimedFrom: SENDER,
        claimedDate: undefined,
      }));
      expect(metric.outcome).toBe('ok');
    });
  });

  it('stops checking candidates at the time budget and says so', async () => {
    let clock = NOW;
    const tenant = takeoverTenant();
    const graph = fakeGraph([
      request => {
        clock += 10_000;
        return fanoutResponder(tenant)(request);
      },
    ]);
    const scan = new FanoutScanService(graph.client, SETTINGS, {
      now: () => clock,
      sleep: () => Promise.resolve(),
    });
    const result = await scan.scan({ ...REQUEST, budgetMs: 11_000 });
    expect(result.incompleteReasons).toContain('time_budget');
    expect(result.flagged).toHaveLength(0);
  });

  it('never throws, and logs no address or subject at any level', async () => {
    const lines: string[] = [];
    const capture = (...args: unknown[]): void => {
      lines.push(args.map(String).join(' '));
    };
    const spies = [
      jest.spyOn(console, 'log').mockImplementation(capture),
      jest.spyOn(console, 'warn').mockImplementation(capture),
      jest.spyOn(console, 'error').mockImplementation(capture),
      jest.spyOn(console, 'debug').mockImplementation(capture),
    ];
    const savedLevel = process.env.LOG_LEVEL;
    try {
      // Loggers capture their level at module load: load the scan afresh at debug level
      process.env.LOG_LEVEL = 'debug';
      let fresh: typeof import('../../../../src/services/graph') | undefined;
      let freshFake: typeof import('../../../mocks/graph.fake') | undefined;
      jest.isolateModules(() => {
        /* eslint-disable @typescript-eslint/no-require-imports */
        fresh = require('../../../../src/services/graph');
        freshFake = require('../../../mocks/graph.fake');
        /* eslint-enable @typescript-eslint/no-require-imports */
      });
      const tenant = takeoverTenant();
      tenant.windowPages = [tenant.windowPages[0], []];
      tenant.laterPageStatus = 503;
      const graph = freshFake!.fakeGraph([fanoutResponder(tenant)]);
      const result = await new fresh!.FanoutScanService(graph.client, SETTINGS, deps).scan(REQUEST);
      expect(result.flagged).toHaveLength(1);
      const broken = new fresh!.FanoutScanService(
        { getPage: () => Promise.reject(new TypeError('boom')) } as never,
        SETTINGS,
        deps
      );
      await expect(broken.scan(REQUEST)).resolves.toMatchObject({ outcome: 'error' });
    } finally {
      process.env.LOG_LEVEL = savedLevel;
      spies.forEach(spy => spy.mockRestore());
    }
    const logged = lines.join('\n');
    expect(logged).toContain('Fan-out scan finished');
    expect(logged).not.toContain(SENDER);
    expect(logged).not.toContain('Updated remittance');
    expect(logged).not.toContain('person1@example.com');
  });
});

describe('createFanoutScanService', () => {
  const graph = fakeGraph([]);
  it('is off unless both Graph and the feature are on', () => {
    expect(createFanoutScanService(undefined, graph.client)).toBeUndefined();
    expect(createFanoutScanService({ enabled: true }, graph.client)).toBeUndefined();
    expect(
      createFanoutScanService(
        { enabled: false, fanoutScan: { enabled: true } as never },
        graph.client
      )
    ).toBeUndefined();
    expect(
      createFanoutScanService(
        { enabled: true, fanoutScan: { enabled: true } as never },
        graph.client
      )
    ).toBeInstanceOf(FanoutScanService);
  });
});

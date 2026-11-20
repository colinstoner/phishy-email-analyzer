/**
 * The scheduled fan-out job in the main function: the lock, the window and
 * its overlap, dedupe and growth updates across invocations, the shared
 * request allowance, who gets the alert, and how it degrades without the
 * database or its migration. The scan runs for real in direct mode over a
 * fake Graph; the database is an in-memory stand-in for migration 005's
 * tables. No network, no AWS. Invented data only.
 */

import type { FanoutScanSource } from '../../../../src/services/graph';
import type { BlastRadiusReport } from '../../../../src/services/graph/blast-radius.service';
import type { FanoutJobDeps } from '../../../../src/services/hunting/fanout.job';
import type { FakeFanoutDb } from '../../../mocks/fanout.db';
import type { FanoutTenant } from '../../../mocks/fanout.tenant';
import type { FakeGraph } from '../../../mocks/graph.fake';

// Loggers capture their level at module load: everything is loaded fresh at
// debug level, so the no-hostile-text-in-logs checks see every line
type Graph = typeof import('../../../../src/services/graph');
type Job = typeof import('../../../../src/services/hunting/fanout.job');
type Store = typeof import('../../../../src/services/hunting/fanout.store');
type Db = typeof import('../../../mocks/fanout.db');
type Tenant = typeof import('../../../mocks/fanout.tenant');
type Fake = typeof import('../../../mocks/graph.fake');
type Response = typeof import('../../../../src/services/response/campaign.response.service');
type FakeStoreModule = typeof import('../response/fake.store');
type Intel = typeof import('../../../../src/services/intelligence/database.service');
type Schema = typeof import('../../../../src/config/schema');

const savedLevel = process.env.LOG_LEVEL;
process.env.LOG_LEVEL = 'debug';
jest.resetModules();
/* eslint-disable @typescript-eslint/no-require-imports */
const { createFanoutScanSource } = require('../../../../src/services/graph') as Graph;
const { blastRadiusEmailFor, fanoutWindow, likelyReporterDomain, runFanoutScan } =
  require('../../../../src/services/hunting/fanout.job') as Job;
const { CampaignResponseService } =
  require('../../../../src/services/response/campaign.response.service') as Response;
const { FakeResponseStore } = require('../response/fake.store') as FakeStoreModule;
const { computeCampaignSignature } =
  require('../../../../src/services/intelligence/database.service') as Intel;
const { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } = require('../../../../src/config/schema') as Schema;
const { isMaterialGrowth } = require('../../../../src/services/hunting/fanout.store') as Store;
const { FakeFanoutDb: FakeDb } = require('../../../mocks/fanout.db') as Db;
const {
  NOW,
  SENDER,
  SUBJECT,
  establishedHistory,
  fanoutResponder,
  takeoverTenant,
  traceRow,
  wave,
  wideWindowTenant,
} = require('../../../mocks/fanout.tenant') as Tenant;
const { fakeGraph } = require('../../../mocks/graph.fake') as Fake;
/* eslint-enable @typescript-eslint/no-require-imports */
process.env.LOG_LEVEL = savedLevel;

const MINUTE = 60 * 1000;
const SECURITY_TEAM = ['security@example.com', 'soc@example.com'];

const FANOUT = {
  enabled: true,
  overlapMinutes: 10,
  maxWindowMinutes: 60,
  maxPages: 4,
  maxCandidates: 3,
  requestAllowancePer5Min: 20,
  budgetMs: 60000,
  dedupeHours: 24,
};

function config(fanout: Partial<typeof FANOUT> = {}): FanoutJobDeps['config'] {
  return {
    graph: { enabled: true, mode: 'direct', fanoutScan: { ...FANOUT, ...fanout } },
    email: { safeDomains: ['example.com'], safeSenders: [], deleteAfterProcessing: false },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: SECURITY_TEAM,
      safeSenderSecurity: [],
    },
  };
}

interface Harness {
  db: FakeFanoutDb;
  graph: FakeGraph;
  tenant: FanoutTenant;
  sendEmail: jest.Mock;
  source: FanoutScanSource;
  metrics: Array<Record<string, unknown>>;
  logs: string[];
  run: (overrides?: Partial<FanoutJobDeps>) => ReturnType<typeof runFanoutScan>;
}

function harness(tenant: FanoutTenant = takeoverTenant()): Harness {
  const db = new FakeDb();
  const holder = { tenant };
  const graph = fakeGraph([request => fanoutResponder(holder.tenant)(request)]);
  const cfg = config();
  const source = createFanoutScanSource(cfg, { client: graph.client })!;
  const sendEmail = jest.fn().mockResolvedValue({ success: true, messageId: 'ses-message-1' });
  const h: Harness = {
    db,
    graph,
    get tenant() {
      return holder.tenant;
    },
    set tenant(value: FanoutTenant) {
      holder.tenant = value;
    },
    sendEmail,
    source,
    metrics: [],
    logs: [],
    run: overrides =>
      runFanoutScan(
        {
          config: cfg,
          source,
          db,
          notifier: { sendEmail },
          now: () => Date.now(),
          ...overrides,
        },
        { remainingMs: () => 170_000 }
      ),
  };
  return h;
}

let current: Harness;
let writes: string[];
let logLines: string[];

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
  writes = [];
  logLines = [];
  jest.spyOn(process.stdout, 'write').mockImplementation(chunk => {
    writes.push(String(chunk));
    return true;
  });
  const capture = (...args: unknown[]): void => {
    logLines.push(args.map(String).join(' '));
  };
  jest.spyOn(console, 'log').mockImplementation(capture);
  jest.spyOn(console, 'warn').mockImplementation(capture);
  jest.spyOn(console, 'error').mockImplementation(capture);
  delete process.env.PHISHY_DISABLE_METRICS;
  current = harness();
});

afterEach(() => {
  process.env.PHISHY_DISABLE_METRICS = 'true';
  jest.useRealTimers();
  jest.restoreAllMocks();
});

function scanMetrics(): Array<Record<string, unknown>> {
  return writes
    .map(line => JSON.parse(line) as Record<string, unknown>)
    .filter(line => line.FanoutScans === 1);
}

describe('fanoutWindow', () => {
  const settings = { overlapMinutes: 10, maxWindowMinutes: 60 };

  it('starts the first scan overlap plus five minutes back', () => {
    const window = fanoutWindow(NOW, undefined, settings);
    expect(window.from.getTime()).toBe(NOW - 15 * MINUTE);
    expect(window.to.getTime()).toBe(NOW);
  });

  it('starts each later scan the overlap before the previous end', () => {
    const window = fanoutWindow(NOW, new Date(NOW - 5 * MINUTE), settings);
    expect(window.from.getTime()).toBe(NOW - 15 * MINUTE);
    expect(window.gapSkipped).toBe(false);
  });

  it('caps the window after a long gap and says so', () => {
    const window = fanoutWindow(NOW, new Date(NOW - 5 * 60 * MINUTE), settings);
    expect(window.from.getTime()).toBe(NOW - 60 * MINUTE);
    expect(window.gapSkipped).toBe(true);
  });

  it('ignores a previous end in the future', () => {
    const window = fanoutWindow(NOW, new Date(NOW + 60 * MINUTE), settings);
    expect(window.from.getTime()).toBe(NOW - 15 * MINUTE);
  });
});

describe('isMaterialGrowth', () => {
  it('needs at least double and at least the minimum more', () => {
    expect(isMaterialGrowth(20, 39, 15)).toBe(false);
    expect(isMaterialGrowth(20, 40, 15)).toBe(true);
    expect(isMaterialGrowth(5, 10, 15)).toBe(false);
    expect(isMaterialGrowth(5, 20, 15)).toBe(true);
  });
});

describe('runFanoutScan', () => {
  it('alerts the security team, and nobody else, about a takeover wave', async () => {
    const summary = await current.run();

    expect(summary).toMatchObject({ outcome: 'ok', flagged: 1, alertsSent: 1, traceRequests: 7 });
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    const [to, subject, html, text, cc] = current.sendEmail.mock.calls[0] as [
      string,
      string,
      string,
      string,
      string[],
    ];
    expect([to, ...cc]).toEqual(SECURITY_TEAM);
    // No address from mail flow is ever a recipient
    expect([to, ...cc].some(address => address.startsWith('person'))).toBe(false);
    expect(subject).toMatch(/^Phishy fan-out alert FANOUT-[0-9A-F]{10}: /);
    expect(subject).not.toContain(SENDER);
    expect(html).toContain(SENDER);
    expect(text).toContain('Reference: FANOUT-');

    expect(current.db.waves).toHaveLength(1);
    expect(current.db.waves[0].alerted_recipients).toBe(20);
    expect(current.db.waves[0].report_message_id).toBe('ses-message-1');
    expect(current.db.state?.last_window_end?.getTime()).toBe(NOW);
    expect(current.db.state?.lock_token).toBeNull();
    expect(current.db.state?.recent_requests).toEqual([
      { at: new Date(NOW).toISOString(), requests: 7 },
    ]);

    const [metric] = scanMetrics();
    expect(metric).toMatchObject({
      Outcome: 'ok',
      FanoutScanRowsScanned: 20,
      FanoutScanCandidates: 1,
      FanoutScanFlags: 1,
      FanoutScanAlertsSent: 1,
      FanoutScanIncomplete: 0,
      FanoutScanTraceRequests: 7,
    });
    expect((metric._aws as { CloudWatchMetrics: unknown[] }).CloudWatchMetrics).toHaveLength(1);
  });

  it('overlaps windows and does not alert twice for the same wave, even for a late row', async () => {
    await current.run();
    expect(current.sendEmail).toHaveBeenCalledTimes(1);

    // Five minutes later: the same rows are still in the overlapping
    // window, plus one that message trace recorded late
    jest.setSystemTime(NOW + 5 * MINUTE);
    const late = traceRow(SENDER, 'latecomer@example.com', NOW - 3 * MINUTE, {
      subject: current.tenant.windowPages[0][0].subject,
    });
    const tenant = takeoverTenant();
    tenant.windowPages = [[...current.tenant.windowPages[0], late]];
    tenant.inbound = {
      [SENDER]: [...(current.tenant.inbound?.[SENDER] ?? []), late],
    };
    tenant.outbound = current.tenant.outbound;
    current.tenant = tenant;

    const summary = await current.run();
    expect(summary).toMatchObject({ outcome: 'ok', flagged: 1, alertsSent: 0 });
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    expect(current.db.waves).toHaveLength(1);
    expect(current.db.waves[0].max_recipients).toBe(21);

    // The window started the overlap before the previous end
    const windowRequest = current.graph.requests.filter(
      r => !(r.query.$filter ?? '').includes(' eq ')
    );
    expect(windowRequest.at(-1)?.query.$filter).toBe(
      'receivedDateTime ge 2026-11-17T11:50:00Z and receivedDateTime le 2026-11-17T12:05:00Z'
    );
  });

  it('sends one update when the wave grows materially, and no more until it doubles again', async () => {
    await current.run();
    const history = establishedHistory();

    jest.setSystemTime(NOW + 5 * MINUTE);
    const bigger = wave(45);
    current.tenant = {
      windowPages: [bigger],
      inbound: { [SENDER]: [...history.inbound, ...bigger] },
      outbound: { [SENDER]: history.outbound },
    };
    await current.run();
    expect(current.sendEmail).toHaveBeenCalledTimes(2);
    const [, subject, html] = current.sendEmail.mock.calls[1] as string[];
    expect(subject).toContain('(update)');
    expect(subject).toContain(current.db.waves[0].reference);
    expect(html).toContain('the previous alert for this wave reported 20; it has now reached 45');
    expect(current.db.waves).toHaveLength(1);
    expect(current.db.waves[0].alerted_recipients).toBe(45);
    expect(current.db.waves[0].alerts_sent).toBe(2);

    jest.setSystemTime(NOW + 10 * MINUTE);
    const more = wave(60);
    current.tenant = {
      windowPages: [more],
      inbound: { [SENDER]: [...history.inbound, ...more] },
      outbound: { [SENDER]: history.outbound },
    };
    await current.run();
    expect(current.sendEmail).toHaveBeenCalledTimes(2);
  });

  it('alerts again for the same sender and subject after the wave has been quiet past the dedupe period', async () => {
    await current.run();
    jest.setSystemTime(NOW + 25 * 60 * MINUTE);
    const history = establishedHistory();
    const later = wave(20, { atMs: NOW + 25 * 60 * MINUTE - 2 * MINUTE });
    current.tenant = {
      windowPages: [later],
      inbound: { [SENDER]: [...history.inbound, ...later] },
      outbound: { [SENDER]: history.outbound },
    };
    await current.run();
    expect(current.sendEmail).toHaveBeenCalledTimes(2);
    expect(current.db.waves).toHaveLength(2);
    expect(current.db.waves[0].reference).not.toBe(current.db.waves[1].reference);
  });

  it('does nothing while the previous scan holds the lock, and runs once it has expired', async () => {
    current.db.state = {
      lock_token: 'another-scan',
      lock_until: new Date(NOW + MINUTE),
      last_window_end: null,
      last_started_at: new Date(NOW - MINUTE),
      recent_requests: [],
    };
    const skipped = await current.run();
    expect(skipped.outcome).toBe('skipped_running');
    expect(current.graph.requests).toHaveLength(0);
    expect(current.sendEmail).not.toHaveBeenCalled();
    expect(current.db.state.lock_token).toBe('another-scan');
    expect(scanMetrics()[0]).toMatchObject({ Outcome: 'skipped_running' });

    jest.setSystemTime(NOW + 2 * MINUTE);
    const ran = await current.run();
    expect(ran.outcome).toBe('ok');
  });

  describe('the shared request allowance', () => {
    it('gives the scan only what other scans left in the last five minutes', async () => {
      current.db.state = {
        lock_token: null,
        lock_until: null,
        last_window_end: null,
        last_started_at: null,
        recent_requests: [
          { at: new Date(NOW - 2 * MINUTE).toISOString(), requests: 17 },
          // Older than five minutes: no longer counts
          { at: new Date(NOW - 6 * MINUTE).toISOString(), requests: 20 },
        ],
      };
      const summary = await current.run();
      expect(summary.outcome).toBe('ok');
      expect(summary.incomplete).toBe(true);
      expect(summary.traceRequests).toBeLessThanOrEqual(3);
      expect(current.graph.requests.length).toBeLessThanOrEqual(3);
      expect(current.sendEmail).not.toHaveBeenCalled();
      expect(current.db.state.recent_requests).toEqual([
        { at: new Date(NOW - 2 * MINUTE).toISOString(), requests: 17 },
        { at: new Date(NOW).toISOString(), requests: summary.traceRequests },
      ]);
    });

    it('does not scan at all when the allowance is spent', async () => {
      current.db.state = {
        lock_token: null,
        lock_until: null,
        last_window_end: new Date(NOW - 5 * MINUTE),
        last_started_at: null,
        recent_requests: [{ at: new Date(NOW - MINUTE).toISOString(), requests: 20 }],
      };
      const summary = await current.run();
      expect(summary.outcome).toBe('rate_limited');
      expect(current.graph.requests).toHaveLength(0);
      // The window is not advanced: the next scan covers it
      expect(current.db.state.last_window_end?.getTime()).toBe(NOW - 5 * MINUTE);
      expect(current.db.state.lock_token).toBeNull();
    });

    describe('over a wide window', () => {
      const traceRequests = (): number =>
        current.graph.requests.filter(r => r.path === '/admin/exchange/tracing/messageTraces')
          .length;

      function afterGap(recent: Array<{ at: string; requests: number }> = []): void {
        current.db.state = {
          lock_token: null,
          lock_until: null,
          // Fifty minutes ago: the window reaches back the full hour
          last_window_end: new Date(NOW - 50 * MINUTE),
          last_started_at: null,
          recent_requests: recent,
        };
      }

      it('spends no more than the allowance, records exactly that, and advances past what it read', async () => {
        current = harness(wideWindowTenant());
        afterGap();
        const summary = await current.run();

        expect(summary).toMatchObject({
          outcome: 'ok',
          rowsScanned: 4497,
          candidates: 6,
          flagged: 1,
          alertsSent: 1,
        });
        expect(summary.incomplete).toBe(true);
        // The alert for the wave it could judge says the scan was incomplete, and why
        const text = current.sendEmail.mock.calls[0][3] as string;
        expect(text).toContain(
          'Scan incomplete: more senders reached the threshold than one scan checks; the scan used its share of the message-trace request limit.'
        );
        expect(traceRequests()).toBe(20);
        expect(summary.traceRequests).toBe(20);
        expect(current.db.state?.recent_requests).toEqual([
          { at: new Date(NOW).toISOString(), requests: 20 },
        ]);
        // Every row was read; only candidate checks were cut short, and
        // reading the window again would check the same candidates first
        expect(current.db.state?.last_window_end?.getTime()).toBe(NOW);
        expect(scanMetrics()[0]).toMatchObject({
          FanoutScanTraceRequests: 20,
          FanoutScanIncomplete: 1,
        });
      });

      it('reads the window again when the allowance ended the read before its last page', async () => {
        // Rows from 45 minutes back, so the next (wider) window still holds them all
        current = harness(wideWindowTenant({ windowPages: 3, startMs: NOW - 45 * MINUTE }));
        afterGap([{ at: new Date(NOW - 2 * MINUTE).toISOString(), requests: 18 }]);
        const cut = await current.run();

        expect(cut).toMatchObject({ outcome: 'ok', incomplete: true, traceRequests: 2 });
        expect(traceRequests()).toBe(2);
        // Not advanced: the unread rows are not skipped
        expect(current.db.state?.last_window_end?.getTime()).toBe(NOW - 50 * MINUTE);
        expect(logLines.join('\n')).toContain('the next scan reads this window again');

        // Six minutes later the other scans' requests have aged out
        jest.setSystemTime(NOW + 6 * MINUTE);
        const again = await current.run();
        expect(again.outcome).toBe('ok');
        expect(again.traceRequests).toBeLessThanOrEqual(18);
        expect(current.db.state?.last_window_end?.getTime()).toBe(NOW + 6 * MINUTE);
      });

      it('still advances a window cut short by the page cap, saying it was incomplete', async () => {
        current = harness(wideWindowTenant({ windowPages: 6 }));
        afterGap();
        const summary = await current.run();
        expect(summary).toMatchObject({ outcome: 'ok', incomplete: true });
        expect(traceRequests()).toBeLessThanOrEqual(20);
        expect(current.db.state?.last_window_end?.getTime()).toBe(NOW);
      });
    });

    it('charges the whole allowance when the scan did not answer', async () => {
      const silent: FanoutScanSource = {
        mode: 'broker',
        scan: () => Promise.resolve({ ok: false, failure: 'timeout' }),
      };
      const summary = await current.run({ source: silent });
      expect(summary).toMatchObject({ outcome: 'timeout', traceRequests: 20 });
      expect(current.db.state?.last_window_end).toBeNull();
    });
  });

  it('does not advance the window when Graph refused the scan', async () => {
    current.tenant = { ...takeoverTenant(), windowForbidden: 100 };
    const summary = await current.run();
    expect(summary.outcome).toBe('forbidden');
    expect(current.db.state?.last_window_end).toBeNull();
    expect(current.sendEmail).not.toHaveBeenCalled();
  });

  it('undoes the claim when the alert cannot be sent, so the next scan alerts', async () => {
    current.sendEmail.mockResolvedValueOnce({ success: false, error: 'Throttling' });
    const failed = await current.run();
    expect(failed.alertsSent).toBe(0);
    expect(failed.outcome).toBe('error');
    expect(current.db.waves).toHaveLength(0);
    // The window is held, so the wave is read again however long the retry takes
    expect(current.db.state?.last_window_end).toBeNull();

    jest.setSystemTime(NOW + 5 * MINUTE);
    const retried = await current.run();
    expect(retried.alertsSent).toBe(1);
    expect(current.db.waves).toHaveLength(1);
  });

  it('includes the blast radius when that feature is on', async () => {
    const report: BlastRadiusReport = {
      status: 'complete',
      route: 'trace',
      totals: { recipients: 20, read: 4, replied: 1, forwarded: 0 },
      recipients: [
        {
          address: 'person1@example.com',
          mailbox: 'found',
          folder: 'inbox',
          isRead: true,
          response: 'replied',
        },
      ],
      lookedUpAt: new Date(NOW).toISOString(),
    };
    const lookupBlastRadius = jest.fn().mockResolvedValue(report);
    const summary = await current.run({ graph: { blastRadius: true, lookupBlastRadius } });
    expect(summary.traceRequests).toBe(9);
    expect(lookupBlastRadius).toHaveBeenCalledTimes(1);
    const [email] = lookupBlastRadius.mock.calls[0] as [
      { forwardedHeaders: Record<string, string> },
    ];
    expect(email.forwardedHeaders['Original-From']).toBe(SENDER);
    const html = current.sendEmail.mock.calls[0][2] as string;
    expect(html).toContain('Blast radius (security team only)');
    expect(html).toContain('replied to by 1');
  });

  it('builds the blast-radius key from the flag, a day either side of the first sighting', () => {
    const email = blastRadiusEmailFor(
      { senderAddress: SENDER, subject: 'Hello' } as never,
      '2026-11-17T11:58:00.000Z'
    );
    expect(email.forwardedHeaders).toEqual({
      'Original-From': SENDER,
      'Original-Subject': 'Hello',
      'Original-Date': '2026-11-17T11:58:00.000Z',
    });
  });

  describe('without its state', () => {
    it('does not run without the intelligence database, and says what to configure', async () => {
      const summary = await current.run({ db: undefined });
      expect(summary.outcome).toBe('no_database');
      expect(current.graph.requests).toHaveLength(0);
      expect(current.sendEmail).not.toHaveBeenCalled();
      expect(logLines.join('\n')).toContain('PHISHY_INTELLIGENCE_ENABLED');
      expect(scanMetrics()[0]).toMatchObject({ Outcome: 'no_database' });
    });

    it.each(['42P01', '42703'])(
      'does not run without migration 005 (%s), and names the file to apply',
      async code => {
        current.db.failWith = code;
        const summary = await current.run();
        expect(summary.outcome).toBe('migration_missing');
        expect(current.graph.requests).toHaveLength(0);
        expect(current.sendEmail).not.toHaveBeenCalled();
        expect(logLines.join('\n')).toContain('migrations/005_fanout_scan.sql');
      }
    );

    it('reports any other database failure as an error without scanning', async () => {
      current.db.failWith = '57P01';
      const summary = await current.run();
      expect(summary.outcome).toBe('error');
      expect(current.graph.requests).toHaveLength(0);
    });
  });

  it('does nothing, and emits nothing, with the feature off', async () => {
    const summary = await current.run({ source: undefined });
    expect(summary.outcome).toBe('disabled');
    expect(current.db.statements).toHaveLength(0);
    expect(current.graph.requests).toHaveLength(0);
    expect(scanMetrics()).toHaveLength(0);
  });

  it('does not scan when there is no security team to tell', async () => {
    const cfg = config();
    cfg.notification.securityTeamDistribution = [];
    const summary = await current.run({ config: cfg });
    expect(summary.outcome).toBe('error');
    expect(current.graph.requests).toHaveLength(0);
  });

  it('logs no sender, subject or recipient address', async () => {
    await current.run();
    const logged = logLines.join('\n');
    expect(logged).toContain('Fan-out alert sent to the security team');
    expect(logged).not.toContain(SENDER);
    expect(logged).not.toContain('remittance');
    expect(logged).not.toContain('person1@example.com');
  });
});

describe('likelyReporterDomain', () => {
  const flagWith = (addresses: string[]): Parameters<typeof likelyReporterDomain>[0] =>
    ({
      recipients: addresses.map(address => ({ address, status: 'delivered' })),
    }) as never;

  it('is the domain most of the recipients carry', () => {
    const flag = flagWith(['a@example.org', 'b@example.org', 'c@example.com']);
    expect(likelyReporterDomain(flag, ['example.com', 'example.org'])).toBe('example.org');
  });

  it('keeps a subdomain as it is, since that is what a report from it carries', () => {
    const flag = flagWith(['a@eu.example.com', 'b@eu.example.com']);
    expect(likelyReporterDomain(flag, ['example.com'])).toBe('eu.example.com');
  });

  it('breaks ties by configuration order and ignores domains that are not ours', () => {
    const flag = flagWith(['a@example.org', 'b@example.com', 'c@outside.example.net']);
    expect(likelyReporterDomain(flag, ['example.com', 'example.org'])).toBe('example.com');
  });

  it('falls back to the first configured domain when no recipient is listed', () => {
    expect(likelyReporterDomain(flagWith([]), ['Example.com', 'example.org'])).toBe('example.com');
  });
});

describe('runFanoutScan with campaign response', () => {
  const REPORTER = 'reporter@example.com';

  interface ResponseHarness {
    store: InstanceType<typeof FakeResponseStore>;
    service: InstanceType<typeof CampaignResponseService>;
    sendThreadedEmail: jest.Mock;
  }

  /** The real service over an in-memory store, sending through the job's own mock */
  function campaignResponse(
    options: { employeeWarning?: 'approve' | 'auto'; audience?: 'recipients' | 'both' } = {}
  ): ResponseHarness {
    const store = new FakeResponseStore(() => new Date(Date.now()));
    const sendThreadedEmail = jest
      .fn()
      .mockResolvedValue({ success: true, messageId: 'ses-thread-1' });
    const service = new CampaignResponseService({
      store: store.asStore(),
      mailer: { sendEmail: current.sendEmail, sendThreadedEmail },
      config: {
        enabled: true,
        audience: options.audience ?? 'recipients',
        employeeWarning: options.employeeWarning ?? 'approve',
        distributionWarning: 'auto',
        approvalTtlHours: 4,
        maxWarningsPerCampaign: 100,
        maxRemovalMailboxes: 500,
        maxRemovalMessages: 1000,
        updateIntervalMinutes: 30,
        reachThreshold: 5,
        alreadyClickedInstructions: DEFAULT_ALREADY_CLICKED_INSTRUCTIONS,
        timeZone: 'UTC',
      },
      safeDomains: ['example.com'],
      securityTeam: SECURITY_TEAM,
      distributionList: 'everyone@example.com',
      commandsEnabled: true,
      legacyAlert: jest.fn().mockResolvedValue(false),
      markCampaignAlerted: jest.fn().mockResolvedValue(undefined),
      now: () => new Date(Date.now()),
    });
    return { store, service, sendThreadedEmail };
  }

  function sentSubjects(): string[] {
    return current.sendEmail.mock.calls.map(call => call[1] as string);
  }

  function employeeEmails(): unknown[] {
    return current.sendEmail.mock.calls.filter(call => !SECURITY_TEAM.includes(call[0] as string));
  }

  /** What the email pipeline computes for a forwarded report (lambda.handler.ts) */
  function reportSignature(reporter: string, forwardSubject: string): string {
    return computeCampaignSignature(reporter.split('@')[1] ?? 'unknown', forwardSubject);
  }

  const blastReport = (): BlastRadiusReport => ({
    status: 'complete',
    route: 'trace',
    totals: { recipients: 3, read: 1, replied: 0, forwarded: 0 },
    recipients: [1, 2, 3].map(n => ({
      address: `person${n}@example.com`,
      mailbox: 'found' as const,
      folder: 'inbox' as const,
      isRead: n === 1,
      response: 'none' as const,
      mailboxId: `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`,
      messageIds: [`AAMkAG-${n}`],
      receivedAt: new Date(NOW - 2 * MINUTE).toISOString(),
    })),
    lookedUpAt: new Date(NOW).toISOString(),
  });

  it('opens one incident and sends its email instead of a separate alert', async () => {
    const response = campaignResponse();
    const summary = await current.run({ campaignResponse: response.service });

    expect(summary).toMatchObject({ outcome: 'ok', flagged: 1, alertsSent: 1 });
    // One email to the security team, and it is the incident email
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    const [to, subject, , text, cc] = current.sendEmail.mock.calls[0] as [
      string,
      string,
      string,
      string,
      string[],
    ];
    expect([to, ...cc]).toEqual(SECURITY_TEAM);
    expect(subject).not.toMatch(/fan-out alert/);
    expect(text).toContain('Reports so far: 0');
    expect(text).toContain(
      'The fan-out scan saw one external sender reach 20 internal recipient(s)'
    );
    expect(text).toContain('No message was opened and no AI model was involved');

    expect(response.store.incidents).toHaveLength(1);
    expect(response.store.incidents[0]).toMatchObject({ trigger: 'fanout_scan', reportCount: 0 });
    // The wave is claimed and the window advanced, exactly as for an alert
    expect(current.db.waves).toHaveLength(1);
    expect(current.db.state?.last_window_end?.getTime()).toBe(NOW);
    expect(employeeEmails()).toEqual([]);
  });

  it('never sends to employees without approval, even with warnings set to auto', async () => {
    const response = campaignResponse({ employeeWarning: 'auto', audience: 'both' });
    const lookupBlastRadius = jest.fn().mockResolvedValue(blastReport());
    await current.run({
      campaignResponse: response.service,
      graph: { blastRadius: true, lookupBlastRadius },
    });

    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    expect(employeeEmails()).toEqual([]);
    const proposals = response.store.actions.filter(action => action.status === 'proposed');
    expect(proposals.length).toBeGreaterThan(0);
    expect(proposals.every(action => action.authorization === 'approve')).toBe(true);
    expect(response.store.incidents[0].reach.recipients).toHaveLength(3);
  });

  it('files the incident where a later forwarded report of the same email finds it', async () => {
    const response = campaignResponse();
    await current.run({ campaignResponse: response.service });

    const signature = reportSignature(REPORTER, `FW: ${SUBJECT}`);
    expect(response.store.incidents[0].campaignSignature).toBe(signature);
    expect(await response.store.getIncidentBySignature(signature)).toBeDefined();
  });

  it('sends a material growth as an update in the incident thread, not a second alert', async () => {
    const response = campaignResponse();
    await current.run({ campaignResponse: response.service });
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    const incident = response.store.incidents[0];

    const history = establishedHistory();
    jest.setSystemTime(NOW + 5 * MINUTE);
    const bigger = wave(45);
    current.tenant = {
      windowPages: [bigger],
      inbound: { [SENDER]: [...history.inbound, ...bigger] },
      outbound: { [SENDER]: history.outbound },
    };
    const summary = await current.run({ campaignResponse: response.service });

    expect(summary.alertsSent).toBe(1);
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    expect(response.sendThreadedEmail).toHaveBeenCalledTimes(1);
    const [recipients, , , text, inReplyTo] = response.sendThreadedEmail.mock.calls[0] as [
      string[],
      string,
      string,
      string,
      string,
    ];
    expect(recipients).toEqual(SECURITY_TEAM);
    expect(inReplyTo).toBe(incident.threadMessageId);
    expect(text).toContain(
      'The fan-out scan has now seen it reach 45 internal recipient(s); the previous fan-out sighting reported 20.'
    );
    expect(response.store.incidents).toHaveLength(1);
    expect(current.db.waves[0].alerted_recipients).toBe(45);
  });

  it('sends nothing more for a sighting without material growth', async () => {
    const response = campaignResponse();
    await current.run({ campaignResponse: response.service });
    jest.setSystemTime(NOW + 5 * MINUTE);
    await current.run({ campaignResponse: response.service });
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    expect(response.sendThreadedEmail).not.toHaveBeenCalled();
  });

  it('sends the plain alert when the campaign-response tables are missing, and says what to apply', async () => {
    const response = campaignResponse();
    response.store.unavailable = true;
    const summary = await current.run({ campaignResponse: response.service });

    expect(summary).toMatchObject({ outcome: 'ok', alertsSent: 1 });
    expect(current.sendEmail).toHaveBeenCalledTimes(1);
    expect(sentSubjects()[0]).toMatch(/^Phishy fan-out alert FANOUT-/);
    expect(logLines.join('\n')).toContain('migrations/006_campaign_response.sql');
    expect(current.db.state?.last_window_end?.getTime()).toBe(NOW);
  });

  it('sends the plain alert when the incident email fails', async () => {
    const response = campaignResponse();
    current.sendEmail.mockResolvedValueOnce({ success: false, error: 'Throttling' });
    const summary = await current.run({ campaignResponse: response.service });

    expect(summary).toMatchObject({ outcome: 'ok', alertsSent: 1 });
    expect(current.sendEmail).toHaveBeenCalledTimes(2);
    expect(sentSubjects()[1]).toMatch(/^Phishy fan-out alert FANOUT-/);
    expect(current.db.waves).toHaveLength(1);
  });

  it('holds the window and the claim when nothing could be sent, then sends the incident email', async () => {
    const response = campaignResponse();
    current.sendEmail
      .mockResolvedValueOnce({ success: false, error: 'Throttling' })
      .mockResolvedValueOnce({ success: false, error: 'Throttling' });
    const failed = await current.run({ campaignResponse: response.service });

    expect(failed).toMatchObject({ outcome: 'error', alertsSent: 0 });
    expect(current.db.waves).toHaveLength(0);
    expect(current.db.state?.last_window_end).toBeNull();

    jest.setSystemTime(NOW + 5 * MINUTE);
    const retried = await current.run({ campaignResponse: response.service });
    expect(retried).toMatchObject({ outcome: 'ok', alertsSent: 1 });
    expect(current.sendEmail).toHaveBeenCalledTimes(3);
    // The incident's opening email, which never went out the first time
    expect(sentSubjects()[2]).not.toMatch(/fan-out alert/);
    expect(response.store.incidents).toHaveLength(1);
    expect(current.db.waves).toHaveLength(1);
  });

  it('sends the plain alert for a wave whose incident was ruled a false positive', async () => {
    const response = campaignResponse();
    await current.run({ campaignResponse: response.service });
    response.store.incidents[0].status = 'false_positive';

    jest.setSystemTime(NOW + 25 * 60 * MINUTE);
    const history = establishedHistory();
    const later = wave(20, { atMs: NOW + 25 * 60 * MINUTE - 2 * MINUTE });
    current.tenant = {
      windowPages: [later],
      inbound: { [SENDER]: [...history.inbound, ...later] },
      outbound: { [SENDER]: history.outbound },
    };
    await current.run({ campaignResponse: response.service });
    expect(current.sendEmail).toHaveBeenCalledTimes(2);
    expect(sentSubjects()[1]).toMatch(/^Phishy fan-out alert FANOUT-/);
    expect(response.sendThreadedEmail).not.toHaveBeenCalled();
  });

  it('logs no sender, subject or recipient address', async () => {
    const response = campaignResponse();
    await current.run({ campaignResponse: response.service });
    const logged = logLines.join('\n');
    expect(logged).toContain('as a campaign-response incident');
    expect(logged).not.toContain(SENDER);
    expect(logged).not.toContain('remittance');
    expect(logged).not.toContain('person1@example.com');
  });
});

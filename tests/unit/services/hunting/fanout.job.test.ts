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

const savedLevel = process.env.LOG_LEVEL;
process.env.LOG_LEVEL = 'debug';
jest.resetModules();
/* eslint-disable @typescript-eslint/no-require-imports */
const { createFanoutScanSource } = require('../../../../src/services/graph') as Graph;
const { blastRadiusEmailFor, fanoutWindow, runFanoutScan } =
  require('../../../../src/services/hunting/fanout.job') as Job;
const { isMaterialGrowth } = require('../../../../src/services/hunting/fanout.store') as Store;
const { FakeFanoutDb: FakeDb } = require('../../../mocks/fanout.db') as Db;
const { NOW, SENDER, establishedHistory, fanoutResponder, takeoverTenant, traceRow, wave } =
  require('../../../mocks/fanout.tenant') as Tenant;
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
    expect(current.db.waves).toHaveLength(0);

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

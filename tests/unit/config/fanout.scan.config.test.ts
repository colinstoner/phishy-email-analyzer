/**
 * Fan-out scan configuration: off by default, defaults when on, every
 * environment variable mapped, bounds enforced, and the broker reads the
 * same keys. Invented data only.
 */

import { loadConfig, loadGraphBrokerConfig } from '../../../src/config';
import { PhishyConfigSchema } from '../../../src/config/schema';

const VARS: Record<string, string> = {
  PHISHY_GRAPH_FANOUT_SCAN_ENABLED: 'true',
  PHISHY_GRAPH_FANOUT_SCAN_OVERLAP_MINUTES: '7',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_WINDOW_MINUTES: '30',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_PAGES: '2',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_CANDIDATES: '5',
  PHISHY_GRAPH_FANOUT_SCAN_REQUEST_ALLOWANCE: '15',
  PHISHY_GRAPH_FANOUT_SCAN_BUDGET_MS: '45000',
  PHISHY_GRAPH_FANOUT_SCAN_DEDUPE_HOURS: '12',
};

const GRAPH_BROKER_ENV: Record<string, string> = {
  PHISHY_GRAPH_ENABLED: 'true',
  PHISHY_GRAPH_TENANT_ID: 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb',
  PHISHY_GRAPH_READ_CLIENT_ID: 'cccccccc-4444-4555-8666-dddddddddddd',
  PHISHY_GRAPH_READ_CERTIFICATE:
    'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf',
};

describe('graph.fanoutScan configuration', () => {
  const saved: Record<string, string | undefined> = {};
  const names = [
    ...Object.keys(VARS),
    ...Object.keys(GRAPH_BROKER_ENV),
    'ANTHROPIC_API_KEY',
    'PHISHY_CONFIG_S3',
  ];

  beforeEach(() => {
    for (const name of names) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.ANTHROPIC_API_KEY = 'test-key';
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  });

  it('is off by default', async () => {
    const config = await loadConfig();
    expect(config.graph?.fanoutScan?.enabled ?? false).toBe(false);
  });

  it('has the documented defaults when only the flag is set', async () => {
    process.env.PHISHY_GRAPH_FANOUT_SCAN_ENABLED = 'true';
    const config = await loadConfig();
    expect(config.graph?.fanoutScan).toEqual({
      enabled: true,
      overlapMinutes: 10,
      maxWindowMinutes: 60,
      maxPages: 4,
      maxCandidates: 3,
      requestAllowancePer5Min: 20,
      budgetMs: 60000,
      dedupeHours: 24,
    });
  });

  it('maps every variable', async () => {
    Object.assign(process.env, VARS);
    const config = await loadConfig();
    expect(config.graph?.fanoutScan).toEqual({
      enabled: true,
      overlapMinutes: 7,
      maxWindowMinutes: 30,
      maxPages: 2,
      maxCandidates: 5,
      requestAllowancePer5Min: 15,
      budgetMs: 45000,
      dedupeHours: 12,
    });
  });

  it('keeps the scan well under the tenant’s message-trace limit', () => {
    const parse = (fanoutScan: Record<string, unknown>): boolean =>
      PhishyConfigSchema.shape.graph.safeParse({ fanoutScan }).success;
    expect(parse({ enabled: true, requestAllowancePer5Min: 40 })).toBe(true);
    expect(parse({ enabled: true, requestAllowancePer5Min: 41 })).toBe(false);
    expect(parse({ enabled: true, maxPages: 11 })).toBe(false);
    expect(parse({ enabled: true, maxWindowMinutes: 121 })).toBe(false);
    expect(parse({ enabled: true, budgetMs: 200000 })).toBe(false);
  });

  it('is read by the Graph broker from the same variable', async () => {
    Object.assign(process.env, GRAPH_BROKER_ENV, { PHISHY_GRAPH_FANOUT_SCAN_ENABLED: 'true' });
    const config = await loadGraphBrokerConfig();
    expect(config.graph.fanoutScan?.enabled).toBe(true);
  });
});

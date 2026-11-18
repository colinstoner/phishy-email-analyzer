/**
 * graph.blastRadius configuration: schema defaults and environment mappings
 */

import { loadConfig } from '../../../src/config';
import { safeValidateConfig, validateConfig } from '../../../src/config/schema';

const base = {
  ai: { provider: 'anthropic', anthropic: { apiKey: 'test-key' } },
  email: {},
  notification: { senderEmail: 'phishy@example.com' },
  storage: { s3Bucket: 'test-bucket' },
};

const VARS = [
  'PHISHY_GRAPH_ENABLED',
  'PHISHY_GRAPH_TENANT_ID',
  'PHISHY_GRAPH_READ_CLIENT_ID',
  'PHISHY_GRAPH_READ_CERTIFICATE',
  'PHISHY_GRAPH_BLAST_RADIUS_ENABLED',
  'PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS',
  'PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES',
  'ANTHROPIC_API_KEY',
  'PHISHY_CONFIG_S3',
];

describe('graph.blastRadius configuration', () => {
  it('is absent by default and off when present without a flag', () => {
    expect(validateConfig({ ...base, graph: {} }).graph?.blastRadius).toBeUndefined();
    expect(validateConfig({ ...base, graph: { blastRadius: {} } }).graph?.blastRadius).toEqual({
      enabled: false,
      timeBudgetMs: 45000,
      maxMailboxes: 2000,
    });
  });

  it('bounds the time budget and the mailbox cap', () => {
    const valid = (blastRadius: unknown): boolean =>
      safeValidateConfig({ ...base, graph: { blastRadius } }).success;
    expect(valid({ enabled: true, timeBudgetMs: 10000, maxMailboxes: 500 })).toBe(true);
    expect(valid({ timeBudgetMs: 999 })).toBe(false);
    expect(valid({ timeBudgetMs: 150001 })).toBe(false);
    expect(valid({ maxMailboxes: 0 })).toBe(false);
    expect(valid({ maxMailboxes: 20001 })).toBe(false);
    expect(valid({ maxMailboxes: 1.5 })).toBe(false);
  });

  describe('environment variables', () => {
    const saved: Record<string, string | undefined> = {};

    beforeEach(() => {
      for (const name of VARS) {
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

    it('maps the three variables onto graph.blastRadius.*', async () => {
      process.env.PHISHY_GRAPH_BLAST_RADIUS_ENABLED = 'true';
      process.env.PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS = '30000';
      process.env.PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES = '750';

      const config = await loadConfig();

      // Graph itself is off here: the flag is stored but has no effect
      expect(config.graph?.enabled).toBe(false);
      expect(config.graph?.blastRadius).toEqual({
        enabled: true,
        timeBudgetMs: 30000,
        maxMailboxes: 750,
      });
    });
  });
});

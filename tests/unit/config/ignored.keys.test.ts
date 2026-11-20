/**
 * Accepted-but-unused configuration keys: they still validate (removing them
 * would break existing configurations) and each is warned about when set.
 */

import { ignoredConfigKeyWarnings, loadConfig, PartialPhishyConfig } from '../../../src/config';

function config(extra: Partial<PartialPhishyConfig>): PartialPhishyConfig {
  return {
    ai: { provider: 'bedrock' },
    email: {},
    notification: { senderEmail: 'phishy@example.com' },
    storage: { s3Bucket: 'phishy-emails-example' },
    ...extra,
  } as PartialPhishyConfig;
}

describe('ignoredConfigKeyWarnings', () => {
  it('says nothing for a configuration without the unused keys', () => {
    expect(
      ignoredConfigKeyWarnings(config({ intelligence: { enabled: true, type: 'postgres' } }))
    ).toEqual([]);
  });

  it('names each unused key that is set, never its value', () => {
    const warnings = ignoredConfigKeyWarnings(
      config({
        storage: { s3Bucket: 'phishy-emails-example', s3Prefix: 'custom-prefix' },
        intelligence: { enabled: true, type: 'dynamodb', tableName: 'phishy-table-example' },
      })
    );

    expect(warnings).toHaveLength(3);
    expect(warnings[0]).toContain('storage.s3Prefix (S3_PREFIX)');
    expect(warnings[1]).toContain('intelligence.type is dynamodb');
    expect(warnings[2]).toContain('intelligence.tableName');
    expect(warnings.join(' ')).not.toMatch(/custom-prefix|phishy-table-example/);
  });
});

describe('loadConfig with unused keys', () => {
  const saved: Record<string, string | undefined> = {};
  const names = ['PHISHY_CONFIG_S3', 'PHISHY_AI_PROVIDER', 'SENDER_EMAIL', 'S3_PREFIX'];

  beforeEach(() => {
    for (const name of names) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.SENDER_EMAIL = 'phishy@example.com';
  });

  afterEach(() => {
    for (const name of names) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    }
  });

  it('still loads with S3_PREFIX set, and keeps the default when unset', async () => {
    expect((await loadConfig()).storage.s3Prefix).toBe('emails');

    process.env.S3_PREFIX = 'custom-prefix';
    expect((await loadConfig()).storage.s3Prefix).toBe('custom-prefix');
  });
});

/**
 * Accepted-but-unused configuration keys: they still validate (removing them
 * would break existing configurations) and each is warned about when set.
 */

import { ignoredConfigKeyWarnings, loadConfig, PartialPhishyConfig } from '../../../src/config';
import { PhishyConfigSchema } from '../../../src/config/schema';

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

describe('removed live-removal keys', () => {
  it('warns about the size band and window, from the file or the environment', () => {
    const fromFile = ignoredConfigKeyWarnings(
      config({
        campaignResponse: {
          removal: { mode: 'live', sizeTolerancePercent: 1, windowHours: 6 },
        } as never,
      }),
      {}
    );
    expect(fromFile).toHaveLength(2);
    expect(fromFile[0]).toContain('campaignResponse.removal.sizeTolerancePercent');
    expect(fromFile[1]).toContain('campaignResponse.removal.windowHours');
    const fromEnv = ignoredConfigKeyWarnings(config({}), {
      PHISHY_CAMPAIGN_RESPONSE_REMOVAL_SIZE_TOLERANCE_PERCENT: '5',
    });
    expect(fromEnv).toHaveLength(1);
    expect(fromEnv[0]).toContain('PHISHY_CAMPAIGN_RESPONSE_REMOVAL_SIZE_TOLERANCE_PERCENT');
    expect(fromEnv[0]).not.toContain('5');
  });

  it('still validates a configuration that sets them, and drops them', () => {
    const parsed = PhishyConfigSchema.parse(
      config({
        campaignResponse: { removal: { mode: 'live', sizeTolerancePercent: 1, windowHours: 6 } },
      } as never)
    );
    expect(parsed.campaignResponse?.removal).toEqual({ mode: 'live' });
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

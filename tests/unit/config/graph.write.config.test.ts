/**
 * The write credential's place in configuration: only the Graph write
 * broker loads it, from its own environment; the main function's parsed
 * configuration never holds it, whatever is put in its environment or
 * configuration file. Invented values only; no S3 file, no secret resolved.
 */

import {
  ENV_MAPPINGS,
  GRAPH_WRITE_ENV_MAPPINGS,
  loadGraphWriteBrokerConfig,
} from '../../../src/config';
import { GraphBrokerConfigSchema, PhishyConfigSchema } from '../../../src/config/schema';

const WRITE_CLIENT = 'eeeeeeee-5555-4666-8777-ffffffffffff';
const WRITE_SECRET =
  'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-write-AbCdEf';
const TENANT = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';

const BASE = {
  ai: { provider: 'anthropic', anthropic: { apiKey: 'test-key' } },
  email: { safeDomains: ['example.com'] },
  notification: { senderEmail: 'phishy@example.com' },
  storage: { s3Bucket: 'phishy-emails-example' },
};

describe('the write credential is never part of the main function configuration', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it('has no mapping for any write broker variable', () => {
    for (const name of Object.keys(GRAPH_WRITE_ENV_MAPPINGS)) {
      if (name === 'PHISHY_GRAPH_TENANT_ID' || name === 'LOG_LEVEL') {
        continue; // shared names, not write credentials
      }
      expect(ENV_MAPPINGS[name]).toBeUndefined();
    }
    expect(Object.values(ENV_MAPPINGS).some(path => path.startsWith('graph.write'))).toBe(false);
  });

  it('drops a graph.write block from the main and read broker schemas', () => {
    const graph = {
      enabled: true,
      mode: 'broker',
      brokerFunctionName: 'phishy-graph-broker',
      write: { clientId: WRITE_CLIENT, certificate: WRITE_SECRET },
    };
    const main = PhishyConfigSchema.parse({ ...BASE, graph });
    expect(JSON.stringify(main)).not.toContain(WRITE_CLIENT);
    expect(JSON.stringify(main)).not.toContain(WRITE_SECRET);
    const read = GraphBrokerConfigSchema.parse({
      graph: {
        ...graph,
        tenantId: TENANT,
        read: {
          clientId: 'cccccccc-4444-4555-8666-dddddddddddd',
          certificate: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:read',
        },
      },
    });
    expect(JSON.stringify(read)).not.toContain(WRITE_CLIENT);
    expect(JSON.stringify(read)).not.toContain(WRITE_SECRET);
  });

  it('ignores write variables in the main function environment, and says so', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.PHISHY_GRAPH_WRITE_ENABLED = 'true';
    process.env.PHISHY_GRAPH_WRITE_CLIENT_ID = WRITE_CLIENT;
    process.env.PHISHY_GRAPH_WRITE_CERTIFICATE = WRITE_SECRET;
    process.env.PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS = TENANT;
    delete process.env.PHISHY_CONFIG_S3;
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const previous = process.env.LOG_LEVEL;
    process.env.LOG_LEVEL = 'warn';
    let config: unknown;
    try {
      jest.resetModules();
      const fresh = await import('../../../src/config');
      config = await fresh.loadConfig();
    } finally {
      process.env.LOG_LEVEL = previous;
    }
    const text = JSON.stringify(config);
    expect(text).not.toContain(WRITE_CLIENT);
    expect(text).not.toContain(WRITE_SECRET);
    const warned = warn.mock.calls.map(call => String(call[0])).join('\n');
    expect(warned).toContain('PHISHY_GRAPH_WRITE_CLIENT_ID, PHISHY_GRAPH_WRITE_CERTIFICATE');
    expect(warned).not.toContain(WRITE_SECRET);
  });

  it('keeps removal in dry run unless told otherwise', () => {
    const parsed = PhishyConfigSchema.parse({ ...BASE, campaignResponse: { enabled: true } });
    expect(parsed.campaignResponse?.removal).toBeUndefined();
    const live = PhishyConfigSchema.parse({
      ...BASE,
      campaignResponse: {
        removal: { mode: 'live', writeBrokerFunctionName: 'phishy-graph-write-broker' },
      },
    });
    expect(live.campaignResponse?.removal).toEqual({
      mode: 'live',
      writeBrokerFunctionName: 'phishy-graph-write-broker',
    });
    expect(
      PhishyConfigSchema.safeParse({ ...BASE, campaignResponse: { removal: { mode: 'delete' } } })
        .success
    ).toBe(false);
  });
});

describe('loadGraphWriteBrokerConfig', () => {
  const full = {
    PHISHY_GRAPH_WRITE_ENABLED: 'true',
    PHISHY_GRAPH_TENANT_ID: TENANT,
    PHISHY_GRAPH_WRITE_CLIENT_ID: WRITE_CLIENT,
    PHISHY_GRAPH_WRITE_CERTIFICATE: WRITE_SECRET,
  };

  it('is off with an empty environment', () => {
    expect(loadGraphWriteBrokerConfig({})).toEqual({ enabled: false, logLevel: 'info' });
  });

  it('loads the write registration and the allowlist', () => {
    expect(
      loadGraphWriteBrokerConfig({
        ...full,
        PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS: ` ${TENANT.toUpperCase()} ,, `,
      })
    ).toEqual({
      enabled: true,
      tenantId: TENANT,
      clientId: WRITE_CLIENT,
      certificate: WRITE_SECRET,
      allowedMailboxIds: [TENANT],
      logLevel: 'info',
    });
  });

  it('never reads the read registration or the shared configuration file', () => {
    const config = loadGraphWriteBrokerConfig({
      PHISHY_GRAPH_WRITE_ENABLED: 'false',
      PHISHY_GRAPH_ENABLED: 'true',
      PHISHY_GRAPH_READ_CLIENT_ID: 'cccccccc-4444-4555-8666-dddddddddddd',
      PHISHY_GRAPH_READ_CERTIFICATE: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:read',
      PHISHY_CONFIG_S3: 's3://phishy-config-example/phishy.config.json',
    });
    expect(config).toEqual({ enabled: false, logLevel: 'info' });
  });

  it.each([
    ['no client ID', { ...full, PHISHY_GRAPH_WRITE_CLIENT_ID: undefined }],
    ['no certificate', { ...full, PHISHY_GRAPH_WRITE_CERTIFICATE: undefined }],
    ['a bad tenant', { ...full, PHISHY_GRAPH_TENANT_ID: 'not a tenant' }],
    [
      'a bad allowlist entry',
      { ...full, PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS: 'alice@example.com' },
    ],
  ])('refuses to load when enabled with %s', (_label, env) => {
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => loadGraphWriteBrokerConfig(env as NodeJS.ProcessEnv)).toThrow(
      'Invalid Graph write broker configuration'
    );
    expect(error.mock.calls.join('\n')).not.toContain(WRITE_SECRET);
  });
});

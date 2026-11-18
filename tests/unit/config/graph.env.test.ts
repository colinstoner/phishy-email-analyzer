/**
 * Microsoft Graph environment-variable mappings
 */

import { loadConfig } from '../../../src/config';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf';

const GRAPH_VARS = [
  'PHISHY_GRAPH_ENABLED',
  'PHISHY_GRAPH_TENANT_ID',
  'PHISHY_GRAPH_READ_CLIENT_ID',
  'PHISHY_GRAPH_READ_CERTIFICATE',
  'PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED',
];

describe('Graph environment variables', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of [...GRAPH_VARS, 'ANTHROPIC_API_KEY', 'PHISHY_CONFIG_S3']) {
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

  it('leaves Graph unconfigured by default', async () => {
    const config = await loadConfig();
    expect(config.graph?.enabled ?? false).toBe(false);
  });

  it('maps the four variables onto graph.*', async () => {
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_TENANT_ID = TENANT_ID;
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = CLIENT_ID;
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = SECRET_ARN;

    const config = await loadConfig();

    // The ARN is passed through unresolved: the certificate is fetched
    // lazily by the Graph module, not at configuration load
    expect(config.graph).toEqual({
      enabled: true,
      tenantId: TENANT_ID,
      read: { clientId: CLIENT_ID, certificate: SECRET_ARN },
    });
  });

  it('leaves the original-message lookup off unless its own flag is set', async () => {
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_TENANT_ID = TENANT_ID;
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = CLIENT_ID;
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = SECRET_ARN;

    expect((await loadConfig()).graph?.originalFetch?.enabled ?? false).toBe(false);

    process.env.PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED = 'true';
    expect((await loadConfig()).graph?.originalFetch).toEqual({ enabled: true });
  });

  it('accepts the original-message flag while Graph itself is off', async () => {
    // It has no effect then, but must not break configuration
    process.env.PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED = 'true';
    const config = await loadConfig();
    expect(config.graph?.enabled).toBe(false);
    expect(config.graph?.originalFetch).toEqual({ enabled: true });
  });

  it('fails configuration when enabled without its settings', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    await expect(loadConfig()).rejects.toThrow('graph.tenantId is required');
  });

  it('ignores empty leftovers while disabled', async () => {
    process.env.PHISHY_GRAPH_ENABLED = 'false';
    process.env.PHISHY_GRAPH_TENANT_ID = '';
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = '';
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = '';
    const config = await loadConfig();
    expect(config.graph?.enabled).toBe(false);
  });
});

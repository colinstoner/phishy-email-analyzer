/**
 * Graph broker configuration: `graph.mode` on the main function, and the
 * broker's own loader. Invented identifiers only.
 */

import { loadConfig, loadGraphBrokerConfig } from '../../../src/config';
import { GraphBrokerConfigSchema, validateConfig } from '../../../src/config/schema';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf';
const BROKER = 'phishy-graph-broker';
const BROKER_ARN = 'arn:aws:lambda:us-east-1:000000000000:function:phishy-graph-broker';

const BASE = {
  ai: { provider: 'bedrock' },
  email: {},
  notification: { senderEmail: 'phishy@example.com' },
  storage: { s3Bucket: 'test-bucket' },
};

const GRAPH_VARS = [
  'PHISHY_GRAPH_ENABLED',
  'PHISHY_GRAPH_MODE',
  'PHISHY_GRAPH_BROKER_FUNCTION',
  'PHISHY_GRAPH_TENANT_ID',
  'PHISHY_GRAPH_READ_CLIENT_ID',
  'PHISHY_GRAPH_READ_CERTIFICATE',
  'PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED',
  'PHISHY_GRAPH_BLAST_RADIUS_ENABLED',
  'PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS',
  'PHISHY_GRAPH_SENDER_HISTORY_ENABLED',
];
/** Everything else the main function's configuration is built from */
const OTHER_VARS = [
  'ANTHROPIC_API_KEY',
  'PHISHY_AI_PROVIDER',
  'SENDER_EMAIL',
  'SECURITY_TEAM_DISTRIBUTION',
  'SAFE_DOMAINS',
  'SAFE_SENDERS',
  'S3_BUCKET_NAME',
  'PHISHY_AWS_REGION',
  'PHISHY_DB_CONNECTION',
  'PHISHY_INTELLIGENCE_ENABLED',
  'PHISHY_CONFIG_S3',
];

describe('graph.mode in the main function’s configuration', () => {
  it('defaults to direct, which still needs the credential', () => {
    expect(validateConfig(BASE).graph).toBeUndefined();
    expect(() => validateConfig({ ...BASE, graph: { enabled: true } })).toThrow(
      /graph\.tenantId is required/
    );
    expect(() => validateConfig({ ...BASE, graph: { enabled: true, mode: 'direct' } })).toThrow(
      /graph\.read\.certificate is required/
    );
    const direct = validateConfig({
      ...BASE,
      graph: {
        enabled: true,
        tenantId: TENANT_ID,
        read: { clientId: CLIENT_ID, certificate: SECRET_ARN },
      },
    });
    expect(direct.graph?.mode).toBeUndefined();
    expect(direct.graph?.read?.certificate).toBe(SECRET_ARN);
  });

  it('needs only the broker’s name in broker mode', () => {
    for (const brokerFunctionName of [BROKER, BROKER_ARN, `${BROKER}:live`]) {
      const config = validateConfig({
        ...BASE,
        graph: {
          enabled: true,
          mode: 'broker',
          brokerFunctionName,
          originalFetch: { enabled: true },
        },
      });
      expect(config.graph).toEqual({
        enabled: true,
        mode: 'broker',
        brokerFunctionName,
        originalFetch: { enabled: true },
      });
    }
  });

  it('requires a plausible broker function name in broker mode', () => {
    expect(() => validateConfig({ ...BASE, graph: { enabled: true, mode: 'broker' } })).toThrow(
      /graph\.brokerFunctionName is required/
    );
    for (const brokerFunctionName of [
      'https://example.net/invoke',
      'broker function',
      '../other',
      'x'.repeat(171),
    ]) {
      expect(() =>
        validateConfig({ ...BASE, graph: { enabled: true, mode: 'broker', brokerFunctionName } })
      ).toThrow(/must be a Lambda function name or ARN/);
    }
    expect(() => validateConfig({ ...BASE, graph: { enabled: true, mode: 'proxy' } })).toThrow();
  });

  it('drops any credential found in the main function’s configuration in broker mode', () => {
    const config = validateConfig({
      ...BASE,
      graph: {
        enabled: true,
        mode: 'broker',
        brokerFunctionName: BROKER,
        tenantId: TENANT_ID,
        read: { clientId: CLIENT_ID, certificate: '-----BEGIN PRIVATE KEY-----\nMIIE...' },
      },
    });
    expect(config.graph).toEqual({ enabled: true, mode: 'broker', brokerFunctionName: BROKER });
    expect(JSON.stringify(config)).not.toContain('PRIVATE KEY');
    expect(JSON.stringify(config)).not.toContain(TENANT_ID);
    expect(JSON.stringify(config)).not.toContain(CLIENT_ID);
  });

  it('ignores the broker settings while Graph is off', () => {
    expect(validateConfig({ ...BASE, graph: { enabled: false, mode: 'broker' } }).graph).toEqual({
      enabled: false,
      mode: 'broker',
    });
  });
});

describe('environment and loaders', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of [...GRAPH_VARS, ...OTHER_VARS]) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
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

  it('maps PHISHY_GRAPH_MODE and PHISHY_GRAPH_BROKER_FUNCTION for the main function', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_MODE = 'broker';
    process.env.PHISHY_GRAPH_BROKER_FUNCTION = BROKER;
    process.env.PHISHY_GRAPH_SENDER_HISTORY_ENABLED = 'true';

    const config = await loadConfig();

    expect(config.graph?.mode).toBe('broker');
    expect(config.graph?.brokerFunctionName).toBe(BROKER);
    expect(config.graph?.senderHistory?.enabled).toBe(true);
    expect(config.graph?.tenantId).toBeUndefined();
    expect(config.graph?.read).toBeUndefined();
  });

  it('warns when certificate material itself is given to the main function in broker mode', async () => {
    const warnings: string[] = [];
    const savedLevel = process.env.LOG_LEVEL;
    process.env.LOG_LEVEL = 'warn';
    jest.resetModules();
    jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    });
    try {
      const fresh = await import('../../../src/config');
      process.env.ANTHROPIC_API_KEY = 'test-key';
      process.env.PHISHY_GRAPH_ENABLED = 'true';
      process.env.PHISHY_GRAPH_MODE = 'broker';
      process.env.PHISHY_GRAPH_BROKER_FUNCTION = BROKER;

      process.env.PHISHY_GRAPH_READ_CERTIFICATE = SECRET_ARN;
      await fresh.loadConfig();
      expect(warnings.filter(line => line.includes('inline certificate'))).toHaveLength(0);

      process.env.PHISHY_GRAPH_READ_CERTIFICATE = '-----BEGIN PRIVATE KEY-----MARKER';
      const config = await fresh.loadConfig();
      const [warning] = warnings.filter(line => line.includes('inline certificate'));
      expect(warning).toBeDefined();
      expect(warning).not.toContain('MARKER');
      expect(config.graph?.read).toBeUndefined();
    } finally {
      process.env.LOG_LEVEL = savedLevel;
      jest.resetModules();
    }
  });

  it('loads the broker’s configuration from graph.* alone', async () => {
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_TENANT_ID = TENANT_ID;
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = CLIENT_ID;
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = SECRET_ARN;
    process.env.PHISHY_GRAPH_BLAST_RADIUS_ENABLED = 'true';
    process.env.PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS = '60000';

    const config = await loadGraphBrokerConfig();

    expect(config).toEqual({
      graph: {
        enabled: true,
        tenantId: TENANT_ID,
        // Passed through unresolved: fetched lazily, on the first Graph call
        read: { clientId: CLIENT_ID, certificate: SECRET_ARN },
        blastRadius: { enabled: true, timeBudgetMs: 60000, maxMailboxes: 2000 },
      },
      // LOG_LEVEL, set to error by the test setup
      logLevel: 'error',
    });
    // The same environment is not a valid main-function configuration
    await expect(loadConfig()).rejects.toThrow('Invalid configuration');
  });

  it('gives the broker Graph switched off when nothing is configured', async () => {
    expect((await loadGraphBrokerConfig()).graph).toEqual({ enabled: false });
  });

  it('requires the credential in the broker whatever graph.mode says', async () => {
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_MODE = 'broker';
    process.env.PHISHY_GRAPH_BROKER_FUNCTION = BROKER;

    await expect(loadGraphBrokerConfig()).rejects.toThrow('Invalid Graph broker configuration');
    expect(
      GraphBrokerConfigSchema.safeParse({
        graph: { enabled: true, mode: 'broker', brokerFunctionName: BROKER },
      }).success
    ).toBe(false);

    process.env.PHISHY_GRAPH_TENANT_ID = TENANT_ID;
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = CLIENT_ID;
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = SECRET_ARN;
    const config = await loadGraphBrokerConfig();
    expect(config.graph.read?.certificate).toBe(SECRET_ARN);
  });

  it('does not put a configured value in the error or the log when validation fails', async () => {
    const logged: string[] = [];
    jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      logged.push(args.map(String).join(' '));
    });
    process.env.PHISHY_GRAPH_ENABLED = 'true';
    process.env.PHISHY_GRAPH_TENANT_ID = 'not a tenant MARKER';
    process.env.PHISHY_GRAPH_READ_CLIENT_ID = CLIENT_ID;
    process.env.PHISHY_GRAPH_READ_CERTIFICATE = '-----BEGIN PRIVATE KEY-----MARKER';

    const error = await loadGraphBrokerConfig().catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toContain('MARKER');
    expect(logged.join('\n')).not.toContain('MARKER');
    expect(logged.join('\n')).toContain('graph.tenantId');
  });
});

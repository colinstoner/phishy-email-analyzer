/**
 * Every environment variable in ENV_MAPPINGS, parsed against the schema.
 * List versus scalar is decided by the target field, never by the variable's
 * name. No S3 config is loaded and no secret is resolved.
 */

import { ENV_MAPPINGS, envValueKind, loadConfig, parseEnvValue } from '../../../src/config';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';

/** A plausible value for every mapped variable: all set at once must validate */
const PLAUSIBLE: Record<string, string> = {
  ANTHROPIC_API_KEY: 'test-key',
  CLAUDE_MODEL: 'claude-opus-5-5',
  PHISHY_AI_PROVIDER: 'anthropic',
  PHISHY_BEDROCK_REGION: 'us-east-1',
  PHISHY_BEDROCK_MODEL: 'global.anthropic.claude-opus-5-5',
  PHISHY_AI_EFFORT: 'medium',
  PHISHY_AI_REFUSAL_FALLBACK_MODEL: 'claude-opus-4-8',
  SAFE_DOMAINS: 'example.com, example.org',
  SAFE_SENDERS: 'trusted@example.com,alerts@example.org',
  DELETE_EMAILS_AFTER_PROCESSING: 'false',
  SENDER_EMAIL: 'phishy@example.com',
  REPLY_TO_EMAIL: 'phishy-inbox@example.com',
  SECURITY_TEAM_DISTRIBUTION: 'secops@example.com,analyst@example.com',
  SAFE_SENDER_SECURITY: 'secops@example.com',
  SES_CONFIG_SET: 'phishy-config-set',
  S3_BUCKET_NAME: 'phishy-emails-example',
  S3_PREFIX: 'emails',
  PHISHY_AWS_REGION: 'us-east-1',
  AWS_REGION: 'us-east-1',
  PHISHY_INTELLIGENCE_ENABLED: 'true',
  PHISHY_DB_CONNECTION: 'postgresql://phishy:pw@db.example.com:5432/phishy',
  PHISHY_CAMPAIGN_ALERTS_ENABLED: 'true',
  PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION: 'all-staff@example.com',
  PHISHY_CAMPAIGN_RESPONSE_ENABLED: 'true',
  PHISHY_CAMPAIGN_RESPONSE_AUDIENCE: 'both',
  PHISHY_CAMPAIGN_RESPONSE_EMPLOYEE_WARNING: 'approve',
  PHISHY_CAMPAIGN_RESPONSE_LIST_WARNING: 'auto',
  PHISHY_CAMPAIGN_RESPONSE_APPROVAL_TTL_HOURS: '4',
  PHISHY_CAMPAIGN_RESPONSE_MAX_WARNINGS: '100',
  PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MAILBOXES: '500',
  PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MESSAGES: '1000',
  PHISHY_CAMPAIGN_RESPONSE_UPDATE_INTERVAL_MINUTES: '30',
  PHISHY_CAMPAIGN_RESPONSE_REACH_THRESHOLD: '5',
  PHISHY_CAMPAIGN_RESPONSE_CLICKED_INSTRUCTIONS: 'Call the service desk on extension 100.',
  PHISHY_CAMPAIGN_RESPONSE_TIME_ZONE: 'Europe/London',
  PHISHY_CAMPAIGN_CACHE_ENABLED: 'true',
  PHISHY_CAMPAIGN_CACHE_TTL_HOURS: '24',
  PHISHY_EMAIL_COMMANDS_ENABLED: 'true',
  PHISHY_REPORT_BUTTON_ENABLED: 'true',
  PHISHY_AGENTIC_ENABLED: 'true',
  PHISHY_AGENTIC_MAX_TOOL_ROUNDS: '5',
  PHISHY_SCORING_MODE: 'checklist',
  PHISHY_ATTACHMENT_ANALYSIS_ENABLED: 'true',
  PHISHY_ATTACHMENT_ANALYSIS_TIME_BUDGET_MS: '10000',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_BYTES: '26214400',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_UNCOMPRESSED_BYTES: '67108864',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_ARCHIVE_ENTRIES: '200',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_DEPTH: '3',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_PER_ATTACHMENT: '8000',
  PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_TOTAL: '24000',
  PHISHY_GRAPH_ENABLED: 'true',
  PHISHY_GRAPH_MODE: 'direct',
  PHISHY_GRAPH_BROKER_FUNCTION: 'phishy-graph-broker',
  PHISHY_GRAPH_TENANT_ID: TENANT_ID,
  PHISHY_GRAPH_READ_CLIENT_ID: CLIENT_ID,
  PHISHY_GRAPH_READ_CERTIFICATE:
    'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf',
  PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED: 'true',
  PHISHY_GRAPH_BLAST_RADIUS_ENABLED: 'true',
  PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS: '45000',
  PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES: '2000',
  PHISHY_GRAPH_SENDER_HISTORY_ENABLED: 'true',
  PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS: '30',
  PHISHY_GRAPH_SENDER_HISTORY_BURST_WINDOW_HOURS: '24',
  PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS: '8000',
  PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MIN_RECIPIENTS: '15',
  PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER: '2.5',
  PHISHY_GRAPH_FANOUT_SCAN_ENABLED: 'true',
  PHISHY_GRAPH_FANOUT_SCAN_OVERLAP_MINUTES: '10',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_WINDOW_MINUTES: '60',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_PAGES: '4',
  PHISHY_GRAPH_FANOUT_SCAN_MAX_CANDIDATES: '3',
  PHISHY_GRAPH_FANOUT_SCAN_REQUEST_ALLOWANCE: '20',
  PHISHY_GRAPH_FANOUT_SCAN_BUDGET_MS: '60000',
  PHISHY_GRAPH_FANOUT_SCAN_DEDUPE_HOURS: '24',
  PHISHY_PROFILE: 'default',
  LOG_LEVEL: 'error',
};

/** The schema's list-valued fields reachable from the environment */
const LIST_VARS = ['SAFE_DOMAINS', 'SAFE_SENDERS', 'SECURITY_TEAM_DISTRIBUTION', 'SAFE_SENDER_SECURITY'];

describe('ENV_MAPPINGS', () => {
  const saved: Record<string, string | undefined> = {};
  const touched = [...Object.keys(ENV_MAPPINGS), 'PHISHY_CONFIG_S3'];

  beforeEach(() => {
    for (const name of touched) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
  });

  afterEach(() => {
    for (const name of touched) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    }
  });

  it('has a plausible test value for every mapped variable', () => {
    expect(Object.keys(PLAUSIBLE).sort()).toEqual(Object.keys(ENV_MAPPINGS).sort());
  });

  it('maps every variable onto a field the schema has', () => {
    for (const path of Object.values(ENV_MAPPINGS)) {
      expect(() => envValueKind(path)).not.toThrow();
    }
  });

  it('treats exactly the schema list fields as lists', () => {
    const lists = Object.entries(ENV_MAPPINGS)
      .filter(([, path]) => envValueKind(path) === 'list')
      .map(([name]) => name)
      .sort();
    expect(lists).toEqual([...LIST_VARS].sort());
  });

  it('validates with every mapped variable set at once', async () => {
    Object.assign(process.env, PLAUSIBLE);

    const config = await loadConfig();

    expect(config.campaignAlerts?.distributionList).toBe('all-staff@example.com');
    expect(config.email.safeDomains).toEqual(['example.com', 'example.org']);
    expect(config.email.safeSenders).toEqual(['trusted@example.com', 'alerts@example.org']);
    expect(config.notification.securityTeamDistribution).toEqual([
      'secops@example.com',
      'analyst@example.com',
    ]);
    expect(config.notification.safeSenderSecurity).toEqual(['secops@example.com']);
    expect(config.graph?.tenantId).toBe(TENANT_ID);
    expect(config.graph?.read?.clientId).toBe(CLIENT_ID);
    expect(config.campaignResponse?.maxWarningsPerCampaign).toBe(100);
    expect(config.attachments?.analysis?.maxDepth).toBe(3);
  });

  it('accepts a decimal for a decimal setting', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER = '2.5';
    process.env.PHISHY_CAMPAIGN_RESPONSE_APPROVAL_TTL_HOURS = '0.5';

    const config = await loadConfig();

    expect(config.graph?.senderHistory?.fanoutMultiplier).toBe(2.5);
    expect(config.campaignResponse?.approvalTtlHours).toBe(0.5);
  });

  it('still rejects a decimal for an integer setting', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.PHISHY_AGENTIC_MAX_TOOL_ROUNDS = '2.5';

    await expect(loadConfig()).rejects.toThrow('Invalid configuration');
  });

  it('never converts string settings that look numeric or boolean', async () => {
    process.env.ANTHROPIC_API_KEY = '0123456789';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.SES_CONFIG_SET = '007';
    process.env.PHISHY_GRAPH_BROKER_FUNCTION = '123456789012';
    process.env.CLAUDE_MODEL = '2.5';
    process.env.PHISHY_AI_REFUSAL_FALLBACK_MODEL = 'true';
    process.env.PHISHY_PROFILE = '0044';

    const config = await loadConfig();

    expect(config.ai.anthropic?.apiKey).toBe('0123456789');
    expect(config.ai.anthropic?.model).toBe('2.5');
    expect(config.ai.refusalFallbackModel).toBe('true');
    expect(config.notification.sesConfigSet).toBe('007');
    expect(config.graph?.brokerFunctionName).toBe('123456789012');
    expect(config.profile).toBe('0044');
  });

  it('decides each conversion from the target field', () => {
    expect(parseEnvValue('graph.senderHistory.fanoutMultiplier', '2.5')).toBe(2.5);
    expect(parseEnvValue('graph.senderHistory.fanoutMultiplier', ' 3 ')).toBe(3);
    expect(parseEnvValue('agentic.maxToolRounds', '07')).toBe(7);
    expect(parseEnvValue('agentic.maxToolRounds', '1e3')).toBe('1e3');
    expect(parseEnvValue('agentic.maxToolRounds', 'five')).toBe('five');
    expect(parseEnvValue('graph.tenantId', '00000000')).toBe('00000000');
    expect(parseEnvValue('graph.read.clientId', '1234')).toBe('1234');
    expect(parseEnvValue('agentic.enabled', 'TRUE')).toBe(true);
    expect(parseEnvValue('agentic.enabled', 'False')).toBe(false);
    expect(parseEnvValue('agentic.enabled', 'yes')).toBe('yes');
    expect(parseEnvValue('campaignAlerts.distributionList', 'a@example.com,b@example.com')).toBe(
      'a@example.com,b@example.com'
    );
    expect(parseEnvValue('email.safeDomains', ' example.com ,, example.org')).toEqual([
      'example.com',
      'example.org',
    ]);
  });

  it('keeps PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION a single address', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.PHISHY_CAMPAIGN_ALERTS_ENABLED = 'true';
    process.env.PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION = 'all-staff@example.com';

    const config = await loadConfig();

    expect(config.campaignAlerts).toEqual({
      enabled: true,
      distributionList: 'all-staff@example.com',
    });
  });
});

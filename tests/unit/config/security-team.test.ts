/**
 * notification.securityTeamMembers: individual people who may issue commands
 * and approvals in addition to the distribution addresses. Members off the
 * safe domains are ignored (count-only warning). Members are never
 * recipients. Invented example.com data only.
 */

const mockWarn = jest.fn();
jest.mock('../../../src/utils/logger', () => ({
  createLogger: (): Record<string, jest.Mock> => ({
    debug: jest.fn(),
    info: jest.fn(),
    warn: mockWarn,
    error: jest.fn(),
  }),
}));

import {
  loadConfig,
  partitionSecurityTeamMembers,
  securityTeamCommandSenders,
} from '../../../src/config';

describe('partitionSecurityTeamMembers', () => {
  it('keeps members on a safe domain or a subdomain of one, normalized and de-duplicated', () => {
    expect(
      partitionSecurityTeamMembers(
        [' Alice@Example.com', 'alice@example.com', 'bob@mail.example.com'],
        ['example.com']
      )
    ).toEqual({ accepted: ['alice@example.com', 'bob@mail.example.com'], ignored: 0 });
  });

  it('ignores members off the safe domains, including lookalikes', () => {
    expect(
      partitionSecurityTeamMembers(
        ['alice@example.com', 'mallory@outside.test', 'eve@notexample.com', 'eve@example.com.test'],
        ['example.com']
      )
    ).toEqual({ accepted: ['alice@example.com'], ignored: 3 });
  });

  it('accepts nothing without safe domains, and handles an absent list', () => {
    expect(partitionSecurityTeamMembers(['alice@example.com'], [])).toEqual({
      accepted: [],
      ignored: 1,
    });
    expect(partitionSecurityTeamMembers(undefined, ['example.com'])).toEqual({
      accepted: [],
      ignored: 0,
    });
  });
});

describe('securityTeamCommandSenders', () => {
  it('is the distribution addresses plus the safe-domain members', () => {
    expect(
      securityTeamCommandSenders({
        notification: {
          securityTeamDistribution: ['Security@example.com'],
          securityTeamMembers: [
            'alice@example.com',
            'mallory@outside.test',
            'security@example.com',
          ],
        },
        email: { safeDomains: ['example.com'] },
      })
    ).toEqual(['security@example.com', 'alice@example.com']);
  });

  it('is the distribution alone when no members are configured (unchanged behaviour)', () => {
    expect(
      securityTeamCommandSenders({
        notification: { securityTeamDistribution: ['security@example.com'] },
        email: { safeDomains: ['example.com'] },
      })
    ).toEqual(['security@example.com']);
  });
});

describe('loadConfig with SECURITY_TEAM_MEMBERS', () => {
  const names = [
    'PHISHY_CONFIG_S3',
    'PHISHY_AI_PROVIDER',
    'SENDER_EMAIL',
    'SAFE_DOMAINS',
    'SECURITY_TEAM_DISTRIBUTION',
    'SECURITY_TEAM_MEMBERS',
  ];
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    mockWarn.mockReset();
    for (const name of names) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.SAFE_DOMAINS = 'example.com';
    process.env.SECURITY_TEAM_DISTRIBUTION = 'security@example.com';
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

  it('defaults to no members', async () => {
    const config = await loadConfig();
    expect(config.notification.securityTeamMembers).toEqual([]);
    expect(config.notification.securityTeamDistribution).toEqual(['security@example.com']);
  });

  it('parses the variable as a list and leaves the distribution alone', async () => {
    process.env.SECURITY_TEAM_MEMBERS = 'alice@example.com, bob@example.com';
    const config = await loadConfig();
    expect(config.notification.securityTeamMembers).toEqual([
      'alice@example.com',
      'bob@example.com',
    ]);
    expect(config.notification.securityTeamDistribution).toEqual(['security@example.com']);
    expect(mockWarn.mock.calls.flat().join(' ')).not.toContain('securityTeamMembers');
  });

  it('drops a member off the safe domains and warns with the count only', async () => {
    process.env.SECURITY_TEAM_MEMBERS = 'alice@example.com,mallory@outside.test';
    const config = await loadConfig();
    expect(config.notification.securityTeamMembers).toEqual(['alice@example.com']);
    const warnings = mockWarn.mock.calls.map(call => String(call[0]));
    const warning = warnings.find(w => w.includes('securityTeamMembers'));
    expect(warning).toContain('1 address(es)');
    expect(JSON.stringify(mockWarn.mock.calls)).not.toMatch(/mallory|outside\.test|alice/);
  });
});

/**
 * Agentic tool executor tests
 */

import { AgenticToolExecutor, examineUrl } from '../../../../src/services/ai/agentic/tool.executor';
import { computeCampaignSignature } from '../../../../src/services/intelligence/database.service';
import { EnterpriseProfile } from '../../../../src/models/profile.model';

const PROFILE: EnterpriseProfile = {
  name: 'Example Corp',
  organization: { name: 'Example Corp', domains: ['example.com'] },
  vips: [
    {
      name: 'Pat Boss',
      title: 'CEO',
      email: 'pat.boss@example.com',
      impersonationRisk: 'critical',
    },
  ],
  trustedPartners: [{ name: 'Acme Bank', domains: ['acmebank.com'], relationship: 'vendor' }],
  customPatterns: { knownBadDomains: ['evil-payroll.net'] },
};

function makeDb() {
  return {
    lookupIndicators: jest.fn().mockResolvedValue([
      {
        indicatorValue: 'bad-domain.test',
        confidenceScore: 0.9,
        severity: 'high',
        timesSeen: 4,
        firstSeenAt: new Date('2026-06-01T00:00:00Z'),
        lastSeenAt: new Date('2026-06-10T00:00:00Z'),
      },
    ]),
    getCampaignBySignature: jest.fn().mockResolvedValue(null),
  };
}

describe('AgenticToolExecutor', () => {
  describe('tool availability', () => {
    it('offers only examine_url without database or profile', () => {
      const executor = new AgenticToolExecutor({});
      expect(executor.getToolDefinitions().map(t => t.name)).toEqual(['examine_url']);
    });

    it('offers intelligence tools with a database and profile tool with a profile', () => {
      const executor = new AgenticToolExecutor({ db: makeDb() as never, profile: PROFILE });
      expect(executor.getToolDefinitions().map(t => t.name)).toEqual([
        'examine_url',
        'lookup_indicators',
        'check_campaign',
        'check_profile',
      ]);
    });
  });

  describe('lookup_indicators', () => {
    it('returns known indicators with sighting history', async () => {
      const db = makeDb();
      const executor = new AgenticToolExecutor({ db: db as never });

      const result = await executor.execute('lookup_indicators', {
        indicator_type: 'domain',
        values: ['bad-domain.test', 'clean.test'],
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content);
      expect(parsed.checked).toBe(2);
      expect(parsed.known).toHaveLength(1);
      expect(parsed.known[0]).toMatchObject({
        value: 'bad-domain.test',
        confidence: 0.9,
        severity: 'high',
        timesSeen: 4,
      });
      expect(db.lookupIndicators).toHaveBeenCalledWith('domain', ['bad-domain.test', 'clean.test']);
    });

    it('rejects unsupported indicator types as a tool error, not a throw', async () => {
      const executor = new AgenticToolExecutor({ db: makeDb() as never });
      const result = await executor.execute('lookup_indicators', {
        indicator_type: 'hash; DROP TABLE',
        values: ['x'],
      });
      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content).error).toContain('indicator_type');
    });
  });

  describe('check_campaign', () => {
    it('reports campaign details by recomputing the shared signature', async () => {
      const db = makeDb();
      db.getCampaignBySignature.mockResolvedValue({
        detectionCount: 6,
        uniqueRecipients: ['a@example.com', 'b@example.com'],
        riskLevel: 'high',
        firstSeenAt: new Date('2026-06-11T07:00:00Z'),
        lastSeenAt: new Date('2026-06-11T09:00:00Z'),
        isActive: true,
        sampleIndicators: ['lookalike domain'],
      });
      const executor = new AgenticToolExecutor({ db: db as never });

      const result = await executor.execute('check_campaign', {
        sender_domain: 'evil.test',
        subject: 'Invoice #4821 overdue',
      });

      const parsed = JSON.parse(result.content);
      expect(parsed.knownCampaign).toBe(true);
      expect(parsed.detectionCount).toBe(6);
      expect(parsed.uniqueRecipients).toBe(2);
      expect(db.getCampaignBySignature).toHaveBeenCalledWith(
        computeCampaignSignature('evil.test', 'Invoice #4821 overdue')
      );
    });

    it('reports unknown campaigns plainly', async () => {
      const executor = new AgenticToolExecutor({ db: makeDb() as never });
      const result = await executor.execute('check_campaign', {
        sender_domain: 'evil.test',
        subject: 'never seen before',
      });
      expect(JSON.parse(result.content)).toEqual({ knownCampaign: false });
    });
  });

  describe('check_profile', () => {
    const executor = new AgenticToolExecutor({ profile: PROFILE });

    it('recognizes organization domains', async () => {
      const result = await executor.execute('check_profile', { value: 'mail.example.com' });
      expect(JSON.parse(result.content).isOrganizationDomain).toBe(true);
    });

    it('detects lookalikes of legitimate domains', async () => {
      const result = await executor.execute('check_profile', { value: 'examp1e.com' });
      const parsed = JSON.parse(result.content);
      expect(parsed.isOrganizationDomain).toBe(false);
      expect(parsed.lookalikeOf).toBe('example.com');
    });

    it('flags VIP impersonation by name in a foreign address', async () => {
      const result = await executor.execute('check_profile', {
        value: 'pat boss <ceo@gmail.test>',
      });
      const parsed = JSON.parse(result.content);
      expect(parsed.vipNameMatches).toHaveLength(1);
      expect(parsed.vipNameMatches[0].risk).toBe('critical');
    });

    it('recognizes trusted partners and known-bad domains', async () => {
      const partner = JSON.parse(
        (await executor.execute('check_profile', { value: 'billing@acmebank.com' })).content
      );
      expect(partner.trustedPartner).toEqual({ name: 'Acme Bank', relationship: 'vendor' });

      const bad = JSON.parse(
        (await executor.execute('check_profile', { value: 'evil-payroll.net' })).content
      );
      expect(bad.knownBadDomain).toBe(true);
    });
  });

  it('returns an error result for unknown tools', async () => {
    const executor = new AgenticToolExecutor({});
    const result = await executor.execute('fetch_url', { url: 'https://x.test' });
    expect(result.isError).toBe(true);
  });
});

describe('examineUrl', () => {
  it('flags IP hosts, http, credentials, and embedded redirects', () => {
    const flags = (
      examineUrl('http://user:pw@93.184.216.34:8080/login?next=https://real.test') as {
        redFlags: string[];
      }
    ).redFlags;

    expect(flags.join(' ')).toContain('unencrypted http');
    expect(flags.join(' ')).toContain('credentials before the host');
    expect(flags.join(' ')).toContain('raw IP address');
    expect(flags.join(' ')).toContain('Non-standard port');
    expect(flags.join(' ')).toContain('Embedded URL');
  });

  it('flags punycode hosts', () => {
    const result = examineUrl('https://xn--exmple-cua.com/login') as { redFlags: string[] };
    expect(result.redFlags.join(' ')).toContain('Punycode');
  });

  it('reports clean https URLs with no flags', () => {
    const result = examineUrl('https://www.example.com/docs') as {
      redFlags: string[];
      registrableDomain: string;
    };
    expect(result.redFlags).toEqual([]);
    expect(result.registrableDomain).toBe('example.com');
  });

  it('reports unparseable URLs instead of throwing', () => {
    const result = examineUrl('not a url at all') as { parseable: boolean; redFlags: string[] };
    expect(result.parseable).toBe(false);
    expect(result.redFlags[0]).toContain('could not be parsed');
  });
});

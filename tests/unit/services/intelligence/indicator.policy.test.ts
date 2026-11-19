/**
 * Indicator policy: when indicators are stored, and strong vs weak matches.
 * All values are invented.
 */

import {
  classifyIndicator,
  decideIndicatorStorage,
  indicatorProvenance,
  indicatorRole,
  isIndicatorExpired,
  partitionMatches,
  withProvenance,
} from '../../../../src/services/intelligence/indicator.policy';
import { ThreatIndicatorRecord } from '../../../../src/services/intelligence/database.service';
import { ThreatVerdict } from '../../../../src/types';

const NOW = new Date('2026-11-01T00:00:00Z');

function record(
  metadata: Record<string, unknown> | undefined,
  overrides: Partial<ThreatIndicatorRecord> = {}
): ThreatIndicatorRecord {
  return {
    indicatorType: 'domain',
    indicatorValue: 'landing.example.net',
    indicatorHash: 'h',
    confidenceScore: 0.8,
    severity: 'high',
    timesSeen: 2,
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    isActive: true,
    metadata,
    ...overrides,
  };
}

const PROVEN = { provenance: 'model_malicious', sourceVerdict: 'phishing' };

describe('indicatorRole', () => {
  it('prefers the recorded role', () => {
    expect(indicatorRole(record({ role: 'sender', extractionContext: 'final_url_domain' }))).toBe(
      'sender'
    );
  });

  it('derives a role for legacy rows from the extraction context', () => {
    const role = (extractionContext: string, extra: Record<string, unknown> = {}): unknown =>
      indicatorRole(record({ extractionContext, ...extra }));
    expect(role('sender_domain')).toBe('sender');
    expect(role('original_sender_email')).toBe('sender');
    expect(role('final_url_domain')).toBe('payload');
    expect(role('final_url')).toBe('payload');
    expect(role('url_in_content')).toBe('payload');
    expect(role('url_in_content', { redirectChain: ['a', 'b'] })).toBe('infrastructure');
    expect(role('redirect_intermediary')).toBe('infrastructure');
    expect(role('ip_in_content')).toBe('infrastructure');
    expect(role('ai_nominated:payload')).toBe('payload');
    expect(role('ai_nominated:bogus')).toBeUndefined();
    expect(role('something_else')).toBeUndefined();
    expect(indicatorRole(record(undefined))).toBeUndefined();
  });
});

describe('indicatorProvenance', () => {
  it('requires a malicious source verdict for model provenance', () => {
    expect(indicatorProvenance(record(PROVEN))).toBe('model_malicious');
    expect(
      indicatorProvenance(record({ provenance: 'model_malicious', sourceVerdict: 'graymail' }))
    ).toBeUndefined();
    expect(indicatorProvenance(record(undefined))).toBeUndefined();
  });

  it('recognizes security confirmation and lets a clearance remove provenance', () => {
    expect(indicatorProvenance(record({ securityConfirmed: true }))).toBe('security_confirmed');
    expect(indicatorProvenance(record({ provenance: 'security_confirmed' }))).toBe(
      'security_confirmed'
    );
    expect(indicatorProvenance(record({ ...PROVEN, securityCleared: true }))).toBeUndefined();
  });
});

describe('isIndicatorExpired', () => {
  it('treats no expiry as never expiring', () => {
    expect(isIndicatorExpired(record(PROVEN), NOW)).toBe(false);
  });
  it('compares expires_at to now', () => {
    expect(
      isIndicatorExpired(record(PROVEN, { expiresAt: new Date('2026-10-31T00:00:00Z') }), NOW)
    ).toBe(true);
    expect(
      isIndicatorExpired(record(PROVEN, { expiresAt: new Date('2026-12-01T00:00:00Z') }), NOW)
    ).toBe(false);
  });
});

describe('classifyIndicator', () => {
  const classify = (r: ThreatIndicatorRecord): string => {
    const c = classifyIndicator(r, NOW);
    return `${c.strength}:${c.reason}`;
  };

  it('is strong for a proven sender/payload URL, address or domain', () => {
    for (const indicatorType of ['url', 'email', 'domain'] as const) {
      for (const role of ['sender', 'payload']) {
        expect(classify(record({ ...PROVEN, role }, { indicatorType }))).toBe('strong:strong');
      }
    }
    expect(classify(record({ securityConfirmed: true, role: 'payload' }))).toBe('strong:strong');
  });

  it('is weak for everything else, with the reason', () => {
    expect(classify(record({ ...PROVEN, role: 'payload' }, { isActive: false }))).toBe(
      'weak:inactive'
    );
    expect(
      classify(
        record({ ...PROVEN, role: 'payload' }, { expiresAt: new Date('2026-01-01T00:00:00Z') })
      )
    ).toBe('weak:expired');
    expect(classify(record({ ...PROVEN, role: 'payload', securityCleared: true }))).toBe(
      'weak:security_cleared'
    );
    expect(classify(record({ role: 'payload', extractionContext: 'final_url_domain' }))).toBe(
      'weak:no_provenance'
    );
    expect(classify(record(undefined))).toBe('weak:no_provenance');
    expect(classify(record({ ...PROVEN, role: 'infrastructure' }))).toBe(
      'weak:infrastructure_role'
    );
    expect(classify(record({ ...PROVEN }))).toBe('weak:unknown_role');
    expect(classify(record({ ...PROVEN, role: 'payload' }, { indicatorType: 'ip' }))).toBe(
      'weak:inexact_type'
    );
    expect(classify(record({ ...PROVEN, role: 'payload' }, { indicatorType: 'hash' }))).toBe(
      'weak:inexact_type'
    );
  });

  it('partitions matches', () => {
    const strong = record({ ...PROVEN, role: 'payload' });
    const weak = record(undefined);
    expect(partitionMatches([strong, weak], NOW)).toEqual({ strong: [strong], weak: [weak] });
  });
});

describe('decideIndicatorStorage', () => {
  it('stores only for a malicious model verdict from a fresh analysis', () => {
    for (const modelVerdict of ['bec', 'phishing', 'malware_delivery'] as ThreatVerdict[]) {
      expect(decideIndicatorStorage({ modelVerdict })).toEqual({
        store: true,
        provenance: 'model_malicious',
        reason: 'model_malicious',
      });
    }
    for (const modelVerdict of [
      'suspicious',
      'spam',
      'graymail',
      'legitimate',
      'undetermined',
    ] as ThreatVerdict[]) {
      expect(decideIndicatorStorage({ modelVerdict }).store).toBe(false);
    }
  });

  it('never stores for a failed analysis or a plain campaign-cache hit', () => {
    expect(decideIndicatorStorage({ modelVerdict: 'phishing', analysisFailed: true }).store).toBe(
      false
    );
    expect(
      decideIndicatorStorage({ modelVerdict: 'phishing', fromCampaignCache: true })
    ).toMatchObject({ store: false, reason: 'campaign_cache_hit' });
  });

  it('follows a security-team ruling over the model', () => {
    expect(
      decideIndicatorStorage({
        modelVerdict: 'graymail',
        fromCampaignCache: true,
        humanVerdict: 'confirmed_phishing',
      })
    ).toMatchObject({ store: true, provenance: 'security_confirmed' });
    expect(
      decideIndicatorStorage({ modelVerdict: 'phishing', humanVerdict: 'false_positive' }).store
    ).toBe(false);
  });
});

describe('withProvenance', () => {
  it('stamps provenance without dropping existing metadata', () => {
    const stamped = withProvenance(record({ role: 'payload', sourceMessageId: 'm-1' }), {
      provenance: 'model_malicious',
      sourceVerdict: 'bec',
      sourceAnalysisId: 'analysis-1',
    });
    expect(stamped.metadata).toEqual({
      role: 'payload',
      sourceMessageId: 'm-1',
      provenance: 'model_malicious',
      sourceVerdict: 'bec',
      sourceAnalysisId: 'analysis-1',
    });
    expect(classifyIndicator(stamped, NOW).strength).toBe('strong');
  });

  it('marks a security confirmation', () => {
    const stamped = withProvenance(record({ role: 'sender' }), {
      provenance: 'security_confirmed',
      sourceVerdict: 'confirmed_phishing',
    });
    expect(stamped.metadata?.securityConfirmed).toBe(true);
    expect(stamped.metadata?.sourceAnalysisId).toBeUndefined();
  });
});

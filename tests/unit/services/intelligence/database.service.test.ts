/**
 * Intelligence database service tests — campaign verdict cache queries and
 * graceful degradation when migrations 002/003 are not applied.
 */

import {
  IntelligenceDatabaseService,
  stripSslOverrides,
} from '../../../../src/services/intelligence/database.service';

const mockClient = {
  query: jest.fn().mockResolvedValue({}),
  release: jest.fn(),
};

const mockPool = {
  query: jest.fn(),
  connect: jest.fn().mockResolvedValue(mockClient),
  on: jest.fn(),
  end: jest.fn(),
};

jest.mock('pg', () => ({
  Pool: jest.fn(() => mockPool),
}));

function pgError(code: string): Error {
  return Object.assign(new Error(`pg error ${code}`), { code });
}

const ANALYSIS_ROW = {
  id: 'analysis-1',
  analysis_result: { summary: 'phishy', isPhishing: true, confidence: 'High' },
  created_at: new Date('2026-06-11T08:00:00Z'),
  feedback_verdict: null,
  feedback_by: null,
};

describe('stripSslOverrides (TLS CA pin must not be silently bypassed)', () => {
  it('removes sslmode from URL-form connection strings', () => {
    const out = stripSslOverrides(
      'postgresql://u:p@db.abc.us-west-2.example.com:5432/phishy?sslmode=no-verify'
    );
    expect(out).not.toMatch(/sslmode/i);
    expect(out).toContain('db.abc.us-west-2.example.com');
  });

  it('removes sslmode from libpq key=value form (the silent-failopen case)', () => {
    const out = stripSslOverrides(
      'host=db.abc.us-west-2.example.com port=5432 dbname=phishy sslmode=disable user=u'
    );
    expect(out).not.toMatch(/sslmode/i);
    expect(out).toContain('host=db.abc.us-west-2.example.com');
    expect(out).toContain('dbname=phishy');
  });

  it('is case-insensitive and tolerates whitespace (libpq keyword rules)', () => {
    // URL form, uppercased key
    const url = stripSslOverrides(
      'postgresql://u:p@db.abc.us-west-2.example.com:5432/phishy?SSLMODE=disable'
    );
    expect(url).not.toMatch(/sslmode/i);
    // key=value form, mixed case + spaces around '='
    const kv = stripSslOverrides(
      'host=db.abc.us-west-2.example.com SslMode = no-verify dbname=phishy'
    );
    expect(kv).not.toMatch(/sslmode|no-verify/i);
    expect(kv).toContain('dbname=phishy');
  });

  it('leaves a clean connection string intact', () => {
    const clean = 'postgresql://u:p@db.abc.us-west-2.example.com:5432/phishy';
    expect(stripSslOverrides(clean)).toBe(clean);
  });
});

describe('IntelligenceDatabaseService campaign verdict cache', () => {
  let db: IntelligenceDatabaseService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient.query.mockResolvedValue({});
    db = new IntelligenceDatabaseService('postgresql://test');
  });

  describe('findCampaignVerdict', () => {
    it('returns the mapped cache hit, preferring security-team verdicts', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            ...ANALYSIS_ROW,
            feedback_verdict: 'false_positive',
            feedback_by: 'security@example.com',
          },
        ],
      });

      const hit = await db.findCampaignVerdict('abcd1234abcd1234', 24);

      expect(hit).toEqual({
        analysisId: 'analysis-1',
        analysisResult: ANALYSIS_ROW.analysis_result,
        analyzedAt: ANALYSIS_ROW.created_at,
        feedbackVerdict: 'false_positive',
        feedbackBy: 'security@example.com',
      });
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('LEFT JOIN analysis_feedback');
      expect(sql).toContain('(af.verdict IS NOT NULL) DESC');
      expect(params).toEqual(['abcd1234abcd1234', 24]);
    });

    it('returns null when no recent analysis matches the campaign', async () => {
      mockPool.query.mockResolvedValueOnce({ rows: [] });
      expect(await db.findCampaignVerdict('abcd1234abcd1234', 24)).toBeNull();
    });

    it('returns null when migration 003 is not applied (missing column)', async () => {
      mockPool.query.mockRejectedValueOnce(pgError('42703'));
      expect(await db.findCampaignVerdict('abcd1234abcd1234', 24)).toBeNull();
    });

    it('still serves cache hits without the feedback join when migration 002 is missing', async () => {
      mockPool.query
        .mockRejectedValueOnce(pgError('42P01'))
        .mockResolvedValueOnce({ rows: [ANALYSIS_ROW] });

      const hit = await db.findCampaignVerdict('abcd1234abcd1234', 24);

      expect(hit?.analysisId).toBe('analysis-1');
      expect(hit?.feedbackVerdict).toBeUndefined();
      const [fallbackSql] = mockPool.query.mock.calls[1];
      expect(fallbackSql).not.toContain('analysis_feedback');
    });
  });

  describe('storeAnalysis with campaign signature', () => {
    const record = {
      messageId: 'msg-1',
      fromEmail: 'reporter@example.com',
      fromDomain: 'example.com',
      subject: 'FW: Invoice overdue',
      isPhishing: true,
      confidenceScore: 0.9,
      riskLevel: 'high' as const,
      analysisResult: { summary: 'phishy' } as never,
      indicators: [],
      vipImpersonationDetected: false,
      aiProvider: 'bedrock',
      aiModel: 'global.anthropic.claude-opus-4-8',
      processingTimeMs: 1000,
      campaignSignature: 'abcd1234abcd1234',
    };

    it('stores the campaign signature when the column exists', async () => {
      mockPool.query.mockResolvedValueOnce({ rows: [{ id: 'analysis-1' }] });

      const id = await db.storeAnalysis(record);

      expect(id).toBe('analysis-1');
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('campaign_signature');
      expect(params).toContain('abcd1234abcd1234');
    });

    it('falls back to storing without the signature when migration 003 is missing', async () => {
      mockPool.query
        .mockRejectedValueOnce(pgError('42703'))
        .mockResolvedValueOnce({ rows: [{ id: 'analysis-2' }] });

      const id = await db.storeAnalysis(record);

      expect(id).toBe('analysis-2');
      const [fallbackSql] = mockPool.query.mock.calls[1];
      expect(fallbackSql).not.toContain('campaign_signature');
    });
  });

  describe('applyFeedbackToIndicators', () => {
    it('adjusts indicators across the whole campaign', async () => {
      mockPool.query.mockResolvedValueOnce({ rowCount: 7 });

      const adjusted = await db.applyFeedbackToIndicators('analysis-1', 'confirmed_phishing');

      expect(adjusted).toBe(7);
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('campaign_signature');
      expect(params).toEqual(['analysis-1']);
    });

    it('falls back to per-analysis scope when migration 003 is missing', async () => {
      mockPool.query.mockRejectedValueOnce(pgError('42703')).mockResolvedValueOnce({ rowCount: 2 });

      const adjusted = await db.applyFeedbackToIndicators('analysis-1', 'false_positive');

      expect(adjusted).toBe(2);
      const [fallbackSql] = mockPool.query.mock.calls[1];
      expect(fallbackSql).not.toContain('campaign_signature');
      expect(fallbackSql).toContain("metadata->>'sourceAnalysisId' = $1");
    });

    it('marks confirmed indicators so they count as strong matches', async () => {
      mockPool.query.mockResolvedValueOnce({ rowCount: 1 });
      await db.applyFeedbackToIndicators('analysis-1', 'confirmed_phishing');
      const [sql] = mockPool.query.mock.calls[0];
      expect(sql).toContain('"securityConfirmed": true');
      expect(sql).toContain("- 'securityCleared'");
    });

    it('marks cleared indicators so they can never count as strong', async () => {
      mockPool.query.mockResolvedValueOnce({ rowCount: 1 });
      await db.applyFeedbackToIndicators('analysis-1', 'false_positive');
      const [sql] = mockPool.query.mock.calls[0];
      expect(sql).toContain('"securityCleared": true');
    });
  });
});

describe('IntelligenceDatabaseService indicators', () => {
  let db: IntelligenceDatabaseService;

  const INDICATOR = {
    indicatorType: 'domain' as const,
    indicatorValue: 'landing.example.net',
    indicatorHash: 'ignored',
    confidenceScore: 0.8,
    severity: 'high' as const,
    timesSeen: 1,
    firstSeenAt: new Date('2026-11-01T00:00:00Z'),
    lastSeenAt: new Date('2026-11-01T00:00:00Z'),
    isActive: true,
    metadata: { role: 'payload', provenance: 'model_malicious', sourceVerdict: 'phishing' },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockClient.query.mockResolvedValue({});
    db = new IntelligenceDatabaseService('postgresql://test');
  });

  describe('upsertIndicator', () => {
    it('counts distinct report keys only, with parameterized values', async () => {
      mockPool.query.mockResolvedValueOnce({ rows: [{ id: 'ind-1' }] });

      const id = await db.upsertIndicator(INDICATOR, { reportKey: 'campaign-key-1' });

      expect(id).toBe('ind-1');
      const [sql, params] = mockPool.query.mock.calls[0];
      // A key already recorded leaves times_seen unchanged
      expect(sql).toContain(
        "WHEN threat_indicators.metadata->'reportKeys' @> jsonb_build_array($12::text)"
      );
      expect(sql).toContain('THEN threat_indicators.times_seen');
      // A legacy row (no report keys) restarts at 1, keeping its old count
      expect(sql).toContain("WHEN threat_indicators.metadata->'reportKeys' IS NULL THEN 1");
      expect(sql).toContain("'legacyTimesSeen'");
      // A recorded sender/payload role is never downgraded
      expect(sql).toContain("threat_indicators.metadata->>'role' IN ('sender', 'payload')");
      expect(sql).not.toContain('landing.example.net');
      expect(params[1]).toBe('landing.example.net');
      expect(JSON.parse(params[10] as string)).toEqual({
        ...INDICATOR.metadata,
        reportKeys: ['campaign-key-1'],
      });
      expect(params[11]).toBe('campaign-key-1');
      expect(params[12]).toBe(50);
    });

    it('treats every unkeyed call as a distinct report', async () => {
      mockPool.query
        .mockResolvedValueOnce({ rows: [{ id: 'ind-1' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'ind-1' }] });

      await db.upsertIndicator(INDICATOR);
      await db.upsertIndicator(INDICATOR);

      const first = mockPool.query.mock.calls[0][1][11] as string;
      const second = mockPool.query.mock.calls[1][1][11] as string;
      expect(first).toMatch(/^unkeyed:/);
      expect(first).not.toBe(second);
    });
  });

  describe('audit operations', () => {
    it('scans a page in id order without creating tables', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: '00000000-0000-4000-8000-000000000001',
            indicator_type: 'domain',
            indicator_value: 'landing.example.net',
            indicator_hash: 'h',
            confidence_score: '0.8000',
            severity: 'high',
            times_seen: 3,
            is_active: true,
            metadata: null,
          },
        ],
      });

      const rows = await db.scanIndicators(null, 100);

      expect(rows).toHaveLength(1);
      expect(rows[0].confidenceScore).toBe(0.8);
      expect(mockPool.connect).not.toHaveBeenCalled();
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('ORDER BY id');
      expect(params).toEqual([null, 100]);
    });

    it('deactivates by id with a reversible marker, never deleting', async () => {
      mockPool.query.mockResolvedValueOnce({ rowCount: 2 });

      const count = await db.deactivateIndicators(['a', 'b'], 'expired');

      expect(count).toBe(2);
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('SET is_active = FALSE');
      expect(sql).not.toMatch(/DELETE/i);
      expect(params).toEqual([['a', 'b'], 'indicator-audit', 'expired']);
    });

    it('does nothing for an empty id list', async () => {
      expect(await db.deactivateIndicators([], 'expired')).toBe(0);
      expect(mockPool.query).not.toHaveBeenCalled();
    });

    it('restores only rows the audit deactivated', async () => {
      mockPool.query.mockResolvedValueOnce({ rowCount: 4 });

      expect(await db.restoreAuditDeactivations()).toBe(4);
      const [sql, params] = mockPool.query.mock.calls[0];
      expect(sql).toContain('SET is_active = TRUE');
      expect(params).toEqual(['indicator-audit']);
    });
  });
});

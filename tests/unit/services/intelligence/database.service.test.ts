/**
 * Intelligence database service tests — campaign verdict cache queries and
 * graceful degradation when migrations 002/003 are not applied.
 */

import { IntelligenceDatabaseService } from '../../../../src/services/intelligence/database.service';

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
  });
});

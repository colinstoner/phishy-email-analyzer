/**
 * CloudWatch EMF metrics emitter tests
 */

import {
  emitAIUsageMetric,
  emitAnalysisRefusalMetric,
  emitUserReportMetric,
  AIUsageMetric,
} from '../../../src/utils/metrics';

const SAMPLE: AIUsageMetric = {
  provider: 'bedrock',
  model: 'global.anthropic.claude-opus-4-8',
  inputTokens: 12000,
  outputTokens: 800,
  totalTokens: 12800,
  estimatedCostUsd: 0.08,
  processingTimeMs: 4200,
  isPhishing: true,
};

describe('emitAIUsageMetric', () => {
  let stdoutSpy: jest.SpyInstance;
  const originalDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    delete process.env.PHISHY_DISABLE_METRICS;
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = originalDisable;
  });

  it('writes a single valid EMF JSON line to stdout', () => {
    emitAIUsageMetric(SAMPLE);

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const line = stdoutSpy.mock.calls[0][0] as string;
    expect(line.endsWith('\n')).toBe(true);

    const doc = JSON.parse(line);
    expect(doc._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(typeof doc._aws.Timestamp).toBe('number');
  });

  it('includes dimensions and all metric values', () => {
    emitAIUsageMetric(SAMPLE);

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc.Provider).toBe('bedrock');
    expect(doc.Model).toBe('global.anthropic.claude-opus-4-8');
    expect(doc.AnalysisCount).toBe(1);
    expect(doc.InputTokens).toBe(12000);
    expect(doc.OutputTokens).toBe(800);
    expect(doc.TotalTokens).toBe(12800);
    expect(doc.EstimatedCostUSD).toBeCloseTo(0.08, 6);
    expect(doc.ProcessingTimeMs).toBe(4200);
    expect(doc.PhishingDetected).toBe(1);

    const metricNames = doc._aws.CloudWatchMetrics[0].Metrics.map((m: { Name: string }) => m.Name);
    expect(metricNames).toEqual(
      expect.arrayContaining([
        'AnalysisCount',
        'InputTokens',
        'OutputTokens',
        'TotalTokens',
        'EstimatedCostUSD',
        'ProcessingTimeMs',
        'PhishingDetected',
      ])
    );
  });

  it('reports PhishingDetected=0 for clean emails', () => {
    emitAIUsageMetric({ ...SAMPLE, isPhishing: false });

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc.PhishingDetected).toBe(0);
  });

  it('emits nothing when PHISHY_DISABLE_METRICS=true', () => {
    process.env.PHISHY_DISABLE_METRICS = 'true';
    emitAIUsageMetric(SAMPLE);
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it('adds ThinkingTokens as a property, not a metric, when reported', () => {
    emitAIUsageMetric({ ...SAMPLE, thinkingTokens: 450 });

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc.ThinkingTokens).toBe(450);
    // Thinking is already inside OutputTokens
    expect(doc.OutputTokens).toBe(800);
    const metricNames = doc._aws.CloudWatchMetrics[0].Metrics.map((m: { Name: string }) => m.Name);
    expect(metricNames).not.toContain('ThinkingTokens');
  });

  it('omits ThinkingTokens when the API did not report it', () => {
    emitAIUsageMetric(SAMPLE);

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc).not.toHaveProperty('ThinkingTokens');
  });
});

describe('emitAnalysisRefusalMetric', () => {
  let stdoutSpy: jest.SpyInstance;
  const originalDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    delete process.env.PHISHY_DISABLE_METRICS;
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = originalDisable;
  });

  it('writes one raw EMF line with _aws at the JSON root', () => {
    emitAnalysisRefusalMetric('bedrock', 'global.anthropic.claude-opus-5-5', 'cyber');

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const line = stdoutSpy.mock.calls[0][0] as string;
    expect(line.endsWith('\n')).toBe(true);

    const doc = JSON.parse(line);
    expect(doc._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(doc._aws.CloudWatchMetrics[0].Dimensions).toEqual([['Provider', 'Model'], ['Provider']]);
    expect(doc._aws.CloudWatchMetrics[0].Metrics).toEqual([
      { Name: 'AnalysisRefusalCount', Unit: 'Count' },
    ]);
    expect(doc.Provider).toBe('bedrock');
    expect(doc.Model).toBe('global.anthropic.claude-opus-5-5');
    expect(doc.AnalysisRefusalCount).toBe(1);
  });

  it('carries the category as a property, not a dimension', () => {
    emitAnalysisRefusalMetric('anthropic', 'claude-opus-5-5', 'reasoning_extraction');

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc.RefusalCategory).toBe('reasoning_extraction');
    expect(doc._aws.CloudWatchMetrics[0].Dimensions.flat()).not.toContain('RefusalCategory');
  });

  it('labels a null category as unspecified', () => {
    emitAnalysisRefusalMetric('anthropic', 'claude-opus-5-5', null);

    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc.RefusalCategory).toBe('unspecified');
  });

  it('emits nothing when PHISHY_DISABLE_METRICS=true', () => {
    process.env.PHISHY_DISABLE_METRICS = 'true';
    emitAnalysisRefusalMetric('bedrock', 'global.anthropic.claude-opus-5-5', 'bio');
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});

describe('emitUserReportMetric', () => {
  let stdoutSpy: jest.SpyInstance;
  const originalDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    delete process.env.PHISHY_DISABLE_METRICS;
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = originalDisable;
  });

  it('emits a UserReports count dimensioned by what the employee chose', () => {
    emitUserReportMetric('phishing');

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(doc._aws.CloudWatchMetrics[0].Dimensions).toEqual([['ReportedAs'], []]);
    expect(doc.ReportedAs).toBe('phishing');
    expect(doc.UserReports).toBe(1);
  });

  it('is silenced by PHISHY_DISABLE_METRICS', () => {
    process.env.PHISHY_DISABLE_METRICS = 'true';
    emitUserReportMetric('junk');
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});

/**
 * CloudWatch EMF metrics emitter tests
 */

import { emitAIUsageMetric, AIUsageMetric } from '../../../src/utils/metrics';

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
});

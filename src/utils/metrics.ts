/**
 * CloudWatch Metrics
 * Emits AI usage and cost metrics via CloudWatch Embedded Metric Format (EMF).
 *
 * EMF is a structured-log convention: a JSON line written to stdout that the
 * Lambda log pipeline converts into real CloudWatch metrics automatically.
 * No SDK calls, no extra latency, no additional IAM permissions required.
 * Metrics land in the "Phishy" namespace, dimensioned by Provider and Model.
 */

export interface AIUsageMetric {
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  processingTimeMs: number;
  isPhishing: boolean;
}

const NAMESPACE = 'Phishy';

/**
 * Emit one AI analysis as CloudWatch metrics.
 * Set PHISHY_DISABLE_METRICS=true to suppress (used by the test suite).
 */
export function emitAIUsageMetric(metric: AIUsageMetric): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [['Provider', 'Model'], ['Provider']],
          Metrics: [
            { Name: 'AnalysisCount', Unit: 'Count' },
            { Name: 'InputTokens', Unit: 'Count' },
            { Name: 'OutputTokens', Unit: 'Count' },
            { Name: 'TotalTokens', Unit: 'Count' },
            { Name: 'EstimatedCostUSD', Unit: 'None' },
            { Name: 'ProcessingTimeMs', Unit: 'Milliseconds' },
            { Name: 'PhishingDetected', Unit: 'Count' },
          ],
        },
      ],
    },
    Provider: metric.provider,
    Model: metric.model,
    AnalysisCount: 1,
    InputTokens: metric.inputTokens,
    OutputTokens: metric.outputTokens,
    TotalTokens: metric.totalTokens,
    EstimatedCostUSD: metric.estimatedCostUsd,
    ProcessingTimeMs: metric.processingTimeMs,
    PhishingDetected: metric.isPhishing ? 1 : 0,
  };

  // EMF must be a raw JSON line on stdout — bypass the structured logger,
  // whose envelope would hide the _aws key from the metric extractor.
  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

/**
 * Emit a campaign verdict cache hit: a report answered from a recent analysis
 * of the same campaign instead of a fresh AI call. EstimatedCostSavedUSD
 * approximates what the skipped call would have cost (based on the most
 * recent real analysis in this Lambda instance; 0 on a cold start).
 */
export function emitCampaignCacheHitMetric(estimatedCostSavedUsd: number): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [[]],
          Metrics: [
            { Name: 'CampaignCacheHits', Unit: 'Count' },
            { Name: 'EstimatedCostSavedUSD', Unit: 'None' },
          ],
        },
      ],
    },
    CampaignCacheHits: 1,
    EstimatedCostSavedUSD: estimatedCostSavedUsd,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

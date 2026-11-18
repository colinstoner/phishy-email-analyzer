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
 * Emit an analysis failure: the model could not be reached / did not produce a
 * verdict after retries, so the report went out as "analysis unavailable"
 * rather than a real verdict. Distinct from a successful analysis so it can be
 * alarmed on — a spike means the provider is degraded and reporters are getting
 * un-analyzed emails back.
 */
export function emitAnalysisFailureMetric(provider: string, model: string): void {
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
          Metrics: [{ Name: 'AnalysisFailureCount', Unit: 'Count' }],
        },
      ],
    },
    Provider: provider,
    Model: model,
    AnalysisFailureCount: 1,
  };

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

/**
 * Why a sender-relationship lookup did or did not produce facts.
 * `ok` / `cache_hit` produced facts; everything else means the analysis ran
 * exactly as it would with the feature off.
 */
export type SenderHistoryOutcome =
  | 'ok'
  | 'cache_hit'
  | 'skipped' // no single external sender address of an ordinary shape
  | 'timeout'
  | 'forbidden' // message trace answered 403
  | 'cooldown' // a recent 403; the API is being left alone
  | 'rate_limited' // this instance's own trace allowance is used up
  | 'error';

export interface SenderHistoryMetric {
  outcome: SenderHistoryOutcome;
  durationMs: number;
  /** Code-computed classification (an enum, never an address) */
  classification?: string;
  truncated?: boolean;
}

/**
 * Emit one sender-relationship lookup, dimensioned by Outcome. Alarm on
 * `forbidden` / `timeout` / `error` to notice the check silently not running.
 */
export function emitSenderHistoryMetric(metric: SenderHistoryMetric): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [['Outcome']],
          Metrics: [
            { Name: 'SenderHistoryLookups', Unit: 'Count' },
            { Name: 'SenderHistoryDurationMs', Unit: 'Milliseconds' },
            { Name: 'SenderHistoryAnomalousFanout', Unit: 'Count' },
            { Name: 'SenderHistoryTruncated', Unit: 'Count' },
          ],
        },
      ],
    },
    Outcome: metric.outcome,
    Classification: metric.classification ?? 'none',
    SenderHistoryLookups: 1,
    SenderHistoryDurationMs: metric.durationMs,
    SenderHistoryAnomalousFanout:
      metric.classification === 'established_with_anomalous_fanout' ? 1 : 0,
    SenderHistoryTruncated: metric.truncated ? 1 : 0,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

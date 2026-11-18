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

export interface BlastRadiusMetric {
  /** Route that produced the answer; `none` when no route did */
  route: 'trace' | 'mailbox' | 'none';
  outcome: 'complete' | 'partial' | 'unavailable';
  recipientsFound: number;
  mailboxesChecked: number;
  mailboxesEligible: number;
  /** Graph requests that failed during the lookup */
  errors: number;
  durationMs: number;
  /** Answered from this Lambda instance's short-lived result cache */
  cached?: boolean;
}

/**
 * Emit one blast-radius lookup (who else received a malicious email),
 * dimensioned by route. Counts only: never an address or a subject.
 */
export function emitBlastRadiusMetric(metric: BlastRadiusMetric): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [['BlastRadiusRoute']],
          Metrics: [
            { Name: 'BlastRadiusLookups', Unit: 'Count' },
            { Name: 'BlastRadiusRecipientsFound', Unit: 'Count' },
            { Name: 'BlastRadiusMailboxesChecked', Unit: 'Count' },
            { Name: 'BlastRadiusMailboxesEligible', Unit: 'Count' },
            { Name: 'BlastRadiusCoveragePercent', Unit: 'Percent' },
            { Name: 'BlastRadiusPartial', Unit: 'Count' },
            { Name: 'BlastRadiusFailures', Unit: 'Count' },
            { Name: 'BlastRadiusErrors', Unit: 'Count' },
            { Name: 'BlastRadiusCacheHits', Unit: 'Count' },
            { Name: 'BlastRadiusDurationMs', Unit: 'Milliseconds' },
          ],
        },
      ],
    },
    BlastRadiusRoute: metric.route,
    BlastRadiusLookups: 1,
    BlastRadiusRecipientsFound: metric.recipientsFound,
    BlastRadiusMailboxesChecked: metric.mailboxesChecked,
    BlastRadiusMailboxesEligible: metric.mailboxesEligible,
    BlastRadiusCoveragePercent:
      metric.mailboxesEligible > 0
        ? Math.round((100 * metric.mailboxesChecked) / metric.mailboxesEligible)
        : 0,
    BlastRadiusPartial: metric.outcome === 'partial' ? 1 : 0,
    BlastRadiusFailures: metric.outcome === 'unavailable' ? 1 : 0,
    BlastRadiusErrors: metric.errors,
    BlastRadiusCacheHits: metric.cached ? 1 : 0,
    BlastRadiusDurationMs: metric.durationMs,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

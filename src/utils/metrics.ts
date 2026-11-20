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
  /** Share of outputTokens spent on thinking, when the API reported it */
  thinkingTokens?: number;
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
    // A property, not a metric: thinking is already inside OutputTokens, and a
    // separate metric would invite double counting. Query it with Logs Insights.
    ...(metric.thinkingTokens !== undefined ? { ThinkingTokens: metric.thinkingTokens } : {}),
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
 * Emit a verdict accepted after discarding prose around its JSON object (a
 * note the model appended after the closing brace, or a preamble). A count
 * only: the prose itself can quote the suspicious email and is never logged.
 */
export function emitVerdictProseDiscardedMetric(provider: string, model: string): void {
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
          Metrics: [{ Name: 'VerdictProseDiscardedCount', Unit: 'Count' }],
        },
      ],
    },
    Provider: provider,
    Model: model,
    VerdictProseDiscardedCount: 1,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

/**
 * Emit a model refusal:the model's safety classifiers (or the model itself)
 * declined the request with `stop_reason: "refusal"`. Emitted once per refused
 * call, against the model that refused, so a refusal that the fallback model
 * then answers still counts. Category is a property rather than a dimension —
 * it is an open-ended, informational value and can be null.
 */
export function emitAnalysisRefusalMetric(
  provider: string,
  model: string,
  category: string | null
): void {
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
          Metrics: [{ Name: 'AnalysisRefusalCount', Unit: 'Count' }],
        },
      ],
    },
    Provider: provider,
    Model: model,
    AnalysisRefusalCount: 1,
    RefusalCategory: category ?? 'unspecified',
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
 * Emit an Outlook Report-button submission. Dimensioned by what the employee
 * chose (phishing / junk / not_junk). Button reports arrive through an
 * organization-side mail setting Phishy cannot see, so this count is the only
 * signal that intake is still flowing — alarm on it going quiet.
 */
export function emitUserReportMetric(reportedAs: string): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [['ReportedAs'], []],
          Metrics: [{ Name: 'UserReports', Unit: 'Count' }],
        },
      ],
    },
    ReportedAs: reportedAs,
    UserReports: 1,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

/** How one original-message lookup ended */
export type OriginalFetchOutcome = 'found' | 'not_found' | 'ambiguous' | 'error' | 'skipped';

/**
 * Emit the outcome of one original-message lookup (the optional Graph
 * feature that reads a forwarded email's real headers from the reporter's
 * mailbox). `OriginalFetchCount` is dimensioned by Outcome, so a rising
 * `error` share is alarmable; `OriginalFetchDurationMs` is the time the
 * lookup added to the pipeline. `skipped` means no Graph request was made
 * (nothing usable to search with, or the reporter could not be confirmed).
 */
export function emitOriginalFetchMetric(outcome: OriginalFetchOutcome, durationMs: number): void {
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
            { Name: 'OriginalFetchCount', Unit: 'Count' },
            { Name: 'OriginalFetchDurationMs', Unit: 'Milliseconds' },
          ],
        },
      ],
    },
    Outcome: outcome,
    OriginalFetchCount: 1,
    OriginalFetchDurationMs: durationMs,
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

/**
 * Emit a failure to send the security team's copy of a malicious report
 * carrying the blast-radius result: the separate copy sent after the
 * reporter's, or the single email about a silent Report-button report.
 * The security team was not told: alarm on this.
 */
export function emitSecurityCopyFailureMetric(): void {
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
          Metrics: [{ Name: 'SecurityCopySendFailures', Unit: 'Count' }],
        },
      ],
    },
    SecurityCopySendFailures: 1,
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
  | 'forbidden' // every message trace request answered 403, retries included
  | 'cooldown' // a recent 403; the API is being left alone
  | 'rate_limited' // this instance's own trace allowance is used up
  | 'error';

export interface SenderHistoryMetric {
  outcome: SenderHistoryOutcome;
  durationMs: number;
  /** Code-computed classification (an enum, never an address) */
  classification?: string;
  truncated?: boolean;
  /** Retries made because a trace request answered 403 (the service does so intermittently) */
  forbiddenRetries?: number;
  /**
   * Message trace returned rows that did not match the address filter that
   * was sent (it accepted the filter and did not apply it). The lookup was
   * discarded; nothing computed from those rows was used.
   */
  filterMismatch?: boolean;
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
            { Name: 'SenderHistoryForbiddenRetries', Unit: 'Count' },
            { Name: 'SenderHistoryFilterMismatches', Unit: 'Count' },
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
    SenderHistoryForbiddenRetries: metric.forbiddenRetries ?? 0,
    SenderHistoryFilterMismatches: metric.filterMismatch ? 1 : 0,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

/**
 * How one invocation of the Graph broker ended, as the main function saw it.
 * `ok` is a validated answer. Everything else left the feature that asked
 * exactly as it is when Graph itself fails.
 */
export type GraphBrokerCallOutcome =
  | 'ok'
  | 'refused' // the broker answered but would not run the operation (its reason is logged)
  | 'timeout' // no answer within the feature's time budget
  | 'throttled' // Lambda throttled the invocation (the broker's concurrency limit)
  | 'invoke_error' // the Invoke call itself failed (permissions, network, no such function)
  | 'function_error' // the broker crashed or timed out
  | 'oversized' // the response was larger than the operation can legitimately return
  | 'malformed' // the response did not match the operation's schema
  | 'invalid_request'; // the request did not match the schema and was not sent

/**
 * Emit one Graph broker invocation (broker mode only), dimensioned by
 * Operation and Outcome. The feature's own metric is still emitted, with the
 * outcome the equivalent Graph failure has; this one says why. Alarm on
 * anything but `ok`.
 */
export function emitGraphBrokerCallMetric(
  operation: string,
  outcome: GraphBrokerCallOutcome,
  durationMs: number
): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true') {
    return;
  }

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: [['Operation', 'Outcome']],
          Metrics: [
            { Name: 'GraphBrokerCalls', Unit: 'Count' },
            { Name: 'GraphBrokerCallDurationMs', Unit: 'Milliseconds' },
          ],
        },
      ],
    },
    Operation: operation,
    Outcome: outcome,
    GraphBrokerCalls: 1,
    GraphBrokerCallDurationMs: durationMs,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

/**
 * What happened in campaign response. Each name is its own metric:
 * - `CampaignWarningsSent` / `CampaignThanksSent`: employee emails sent
 *   (dimension `Audience`: `recipients` or `distribution`)
 * - `CampaignWarningsSkipped`: recipients not emailed (dimension `Reason`)
 * - `CampaignWarningSendFailures`: SES refused or failed a send
 * - `CampaignIncidentsOpened` (dimension `Trigger`), `CampaignIncidentUpdates`
 * - `ResponseActionsProposed`, `ResponseActionApprovals`,
 *   `ResponseActionApprovalsRejected` (dimension `Reason`),
 *   `ResponseActionsExpired`, `ResponseActionsDryRun`
 *   (all dimensioned by `ActionType`)
 */
export type CampaignResponseMetricName =
  | 'CampaignWarningsSent'
  | 'CampaignThanksSent'
  | 'CampaignWarningsSkipped'
  | 'CampaignWarningSendFailures'
  | 'CampaignIncidentsOpened'
  | 'CampaignIncidentUpdates'
  | 'ResponseActionsProposed'
  | 'ResponseActionApprovals'
  | 'ResponseActionApprovalsRejected'
  | 'ResponseActionsExpired'
  | 'ResponseActionsDryRun';

/**
 * Emit one campaign-response count. Dimension values are fixed words chosen
 * by code (an action type, an audience, a reason), never data.
 */
export function emitCampaignResponseMetric(
  name: CampaignResponseMetricName,
  count: number,
  dimensions: Record<string, string> = {}
): void {
  if (process.env.PHISHY_DISABLE_METRICS === 'true' || count <= 0) {
    return;
  }
  const keys = Object.keys(dimensions);

  const emf = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [
        {
          Namespace: NAMESPACE,
          Dimensions: keys.length > 0 ? [keys, []] : [[]],
          Metrics: [{ Name: name, Unit: 'Count' }],
        },
      ],
    },
    ...dimensions,
    [name]: count,
  };

  process.stdout.write(`${JSON.stringify(emf)}\n`);
}

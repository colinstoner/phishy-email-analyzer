/**
 * Injection-eval runner. Sends prepared cases through the same pieces the
 * Lambda uses — the provider class (which builds the prompt itself), the
 * agentic analyzer and tool executor, risk fusion with no intelligence
 * signals, and the report templates — and records what came back.
 *
 * It makes billed model calls. Nothing here runs unless a caller hands it a
 * provider; the CLI builds real ones, the tests hand in mocked ones.
 */

import { AIProvider, createFailedAnalysisResult } from '../../services/ai/provider.interface';
import { EffortLevel } from '../../services/ai/model.capabilities';
import { ModelRefusalError, TruncatedResponseError } from '../../services/ai/model.response';
import { AgenticAnalyzer } from '../../services/ai/agentic/agentic.analyzer';
import { AgenticToolExecutor, ToolExecutionResult } from '../../services/ai/agentic/tool.executor';
import { fuseRisk, RiskDecision } from '../../services/intelligence/risk.fusion';
import { ScoringMode } from '../../services/ai/scoring.mode';
import { buildEmailHtml, buildPlainTextReport } from '../../templates/report.html';
import { AnalysisResult, ExtractedEmailData } from '../../types';
import { estimateCostUsd } from '../../utils/pricing';
import { EnterpriseProfile } from '../../models/profile.model';
import { EvalCase, EvalMode } from './cases';
import { PreparedCase } from './prepare';
import {
  AbandonReason,
  FailureKind,
  RunOutcome,
  ToolCallRecord,
  compareRuns,
  findMarkerHits,
} from './scorer';

/** Characters per token used for estimates. Deliberately low, so estimates err high. */
const CHARS_PER_TOKEN = 3;
/** Fixed prompt overhead outside the built prompt (system prompt, tool definitions) */
const OVERHEAD_TOKENS = 400;
/** Output tokens assumed per call until real usage is available (thinking included) */
const ASSUMED_OUTPUT_TOKENS: Record<EvalMode, number> = { single: 3000, agentic: 6000 };
/**
 * Extra output tokens assumed per call in checklist scoring mode: the
 * checklist object is 20 short key/value pairs, about 8-10 tokens each.
 */
export const CHECKLIST_EXTRA_OUTPUT_TOKENS = 250;
/** The agentic loop resends the prompt on every round */
const AGENTIC_INPUT_MULTIPLIER = 3;
const MAX_TOOL_INPUT_CHARS = 400;
/** Matches the providers' default `max_tokens` */
const PROVIDER_MAX_TOKENS = 16000;

export interface RunnerOptions {
  models: string[];
  modes: EvalMode[];
  repeats: number;
  concurrency: number;
  effort: EffortLevel;
  /**
   * `checklist`: the providers (built by `createProvider`) ask for the
   * scoring checklist, and fusion starts from the checklist score. Record
   * both scores per run. Default `model`.
   */
  scoringMode?: ScoringMode;
  /** Stop dispatching when the next call would take estimated spend past this */
  maxCostUsd: number;
  /** Keep each run's raw model reply in the results */
  saveRaw: boolean;
  profile?: EnterpriseProfile;
  essentialHeadersExtractor: (headers: Record<string, string>) => Record<string, string>;
  /** Build the provider for a model. Called once per model. */
  createProvider: (model: string) => AIProvider;
  /** Called after every finished run, in completion order */
  onProgress?: (done: number, total: number, outcome: RunOutcome) => void;
  /** Injected for tests */
  now?: () => number;
}

export interface RunnerResult {
  /** Every planned run, in deterministic order */
  outcomes: RunOutcome[];
  /** True when the cost limit stopped the run before every call was made */
  stoppedForBudget: boolean;
  estimatedSpendUsd: number;
}

interface PlannedRun {
  prepared: PreparedCase;
  model: string;
  mode: EvalMode;
  repeat: number;
}

/** The real tool executor, remembering what the model asked it to do */
class RecordingToolExecutor extends AgenticToolExecutor {
  readonly calls: ToolCallRecord[] = [];

  override execute(name: string, input: Record<string, unknown>): Promise<ToolExecutionResult> {
    this.calls.push({
      name,
      input: JSON.stringify(input).slice(0, MAX_TOOL_INPUT_CHARS),
    });
    return super.execute(name, input);
  }
}

export function estimateInputTokens(prompt: string, mode: EvalMode): number {
  const once = Math.ceil(prompt.length / CHARS_PER_TOKEN) + OVERHEAD_TOKENS;
  return mode === 'agentic' ? once * AGENTIC_INPUT_MULTIPLIER : once;
}

/** Estimated cost of one call before it is made */
export function estimateCallCostUsd(
  model: string,
  prompt: string,
  mode: EvalMode,
  outputTokens: number = ASSUMED_OUTPUT_TOKENS[mode],
  scoringMode: ScoringMode = 'model'
): number {
  if (scoringMode === 'checklist') {
    outputTokens += CHECKLIST_EXTRA_OUTPUT_TOKENS;
  }
  return estimateCostUsd(model, estimateInputTokens(prompt, mode), outputTokens);
}

function classifyFailure(reason: string | undefined): FailureKind {
  if (reason?.startsWith('The model declined')) return 'refusal';
  if (reason?.startsWith("The model's response was incomplete")) return 'truncated';
  return 'malformed';
}

/**
 * Why the agentic loop gave up, when the cause was the model's own output.
 * Anything else (credentials, throttling, network) is not the model's doing
 * and is returned as undefined so the run is reported as an error.
 */
function classifyAbandonment(error: unknown): AbandonReason | undefined {
  if (error instanceof ModelRefusalError) return 'refusal';
  if (error instanceof TruncatedResponseError) return 'truncated';
  const message = error instanceof Error ? error.message : '';
  if (message.includes('exceeded the tool budget')) return 'tool_budget';
  if (message.includes('no usable verdict') || message.includes('no text verdict')) {
    return 'no_verdict';
  }
  return undefined;
}

function describeError(error: unknown): string {
  const name = error instanceof Error ? error.name : 'Error';
  const message = error instanceof Error ? error.message : String(error);
  return `${name}: ${message}`.replace(/\s+/g, ' ').slice(0, 200);
}

/** Render the report exactly as the handler does: fused verdict first */
function renderReports(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData,
  decision: RiskDecision
): string {
  const shown: AnalysisResult = {
    ...analysis,
    isPhishing: decision.isPhishing,
    confidence: decision.confidence,
  };
  const options = {
    risk: {
      verdict: decision.verdict,
      riskScore: decision.riskScore,
      riskLevel: decision.riskLevel,
      reasons: decision.reasons,
      ...(decision.checklistReasons ? { checklistReasons: decision.checklistReasons } : {}),
    },
  };
  return `${buildPlainTextReport(shown, emailData, options)}\n${buildEmailHtml(shown, emailData, options)}`;
}

async function executeRun(
  planned: PlannedRun,
  provider: AIProvider,
  options: RunnerOptions
): Promise<RunOutcome> {
  const { prepared, model, mode, repeat } = planned;
  const evalCase: EvalCase = prepared.evalCase;
  const now = options.now ?? Date.now;
  const outcome: RunOutcome = {
    caseId: evalCase.id,
    model,
    mode,
    repeat,
    status: 'ok',
    toolCalls: [],
    markerHits: [],
    usageEstimated: false,
    costUsd: 0,
    latencyMs: 0,
  };

  // Each run gets its own copy: nothing a provider does to the facts may leak
  // into another run of the same case
  const emailData = structuredClone(prepared.emailData);
  const startedAt = now();
  let analysis: AnalysisResult;
  try {
    if (mode === 'agentic') {
      const executor = new RecordingToolExecutor({ profile: options.profile });
      const analyzer = new AgenticAnalyzer(executor, {
        essentialHeadersExtractor: options.essentialHeadersExtractor,
        scoringMode: options.scoringMode,
      });
      try {
        analysis = await analyzer.analyze(provider, emailData, options.profile);
      } catch (agenticError) {
        const reason = classifyAbandonment(agenticError);
        if (!reason) {
          throw agenticError;
        }
        // What production does next: the single-shot path answers instead
        outcome.agenticAbandoned = reason;
        analysis = await provider.analyzeEmail(emailData, { effort: options.effort });
      }
      outcome.toolCalls = executor.calls;
    } else {
      analysis = await provider.analyzeEmail(emailData, { effort: options.effort });
    }
  } catch (error) {
    outcome.status = 'error';
    outcome.errorClass = describeError(error);
    outcome.latencyMs = now() - startedAt;
    return outcome;
  }
  outcome.latencyMs = now() - startedAt;

  if (analysis.analysisFailed) {
    outcome.status = 'analysis_failed';
    outcome.failureKind = classifyFailure(analysis.failureReason);
  } else {
    outcome.modelVerdict = analysis.assessment?.verdict;
    outcome.modelRiskScore = analysis.assessment?.riskScore;
  }

  // No intelligence database: fusion sees the model's result and nothing else
  const scoringMode = options.scoringMode ?? 'model';
  const decision = fuseRisk(analysis, {}, { scoringMode });
  outcome.fused = {
    verdict: decision.verdict,
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    isPhishing: decision.isPhishing,
  };
  if (scoringMode === 'checklist') {
    // Closed values and numbers only: the answers are enums Phishy validated
    outcome.scoring = {
      mode: 'checklist',
      basis: decision.scoreBasis ?? 'model',
      checklistStatus: analysis.analysisFailed
        ? 'absent'
        : (analysis.checklist?.status ?? 'absent'),
      ...(analysis.checklist?.status === 'ok'
        ? { answers: { ...analysis.checklist.answers } }
        : {}),
      ...(decision.checklistScore !== undefined ? { checklistScore: decision.checklistScore } : {}),
      ...(decision.checklistRawScore !== undefined
        ? { checklistRawScore: decision.checklistRawScore }
        : {}),
    };
  }

  const placeholder = createFailedAnalysisResult('baseline');
  outcome.markerHits = findMarkerHits(evalCase.criteria.markers, {
    raw: analysis.rawResponse ?? '',
    summary: analysis.analysisFailed ? '' : analysis.summary,
    recommendations: analysis.analysisFailed ? [] : analysis.recommendations.map(String),
    indicators: analysis.analysisFailed ? [] : analysis.indicators.map(String),
    report: renderReports(analysis, emailData, decision),
    reportBaseline: renderReports(placeholder, emailData, fuseRisk(placeholder)),
  });

  // A completed agentic run reports the whole loop's usage. After an
  // abandoned loop only the single-shot retry is reported, and a failed
  // analysis reports none, so those runs are estimated (and say so).
  const reported = outcome.agenticAbandoned ? undefined : analysis.tokenUsage;
  if (reported) {
    outcome.usage = {
      inputTokens: reported.inputTokens,
      outputTokens: reported.outputTokens,
      ...(reported.thinkingTokens !== undefined ? { thinkingTokens: reported.thinkingTokens } : {}),
    };
  } else {
    outcome.usageEstimated = true;
    outcome.usage = {
      inputTokens:
        estimateInputTokens(prepared.prompt, mode) + (analysis.tokenUsage?.inputTokens ?? 0),
      outputTokens:
        outcome.failureKind === 'truncated'
          ? PROVIDER_MAX_TOKENS
          : (analysis.tokenUsage?.outputTokens ?? 0),
    };
  }
  outcome.costUsd = estimateCostUsd(model, outcome.usage.inputTokens, outcome.usage.outputTokens);

  if (options.saveRaw && analysis.rawResponse) {
    outcome.rawResponse = analysis.rawResponse;
  }
  return outcome;
}

/**
 * Dispatch order: per model and mode, controls first, then benign probes,
 * then attacks. If the cost limit stops the run, whatever did run still has
 * its baseline.
 */
function planRuns(prepared: PreparedCase[], options: RunnerOptions): PlannedRun[] {
  const rank: Record<EvalCase['kind'], number> = { control: 0, benign_probe: 1, attack: 2 };
  const ordered = [...prepared].sort(
    (a, b) =>
      rank[a.evalCase.kind] - rank[b.evalCase.kind] || (a.evalCase.id < b.evalCase.id ? -1 : 1)
  );
  const planned: PlannedRun[] = [];
  for (const model of options.models) {
    for (const mode of options.modes) {
      for (const p of ordered) {
        if (!p.evalCase.modes.includes(mode)) continue;
        for (let repeat = 1; repeat <= options.repeats; repeat++) {
          planned.push({ prepared: p, model, mode, repeat });
        }
      }
    }
  }
  return planned;
}

/** How many model calls a run would make, and a rough cost, without making any */
export function planSummary(
  prepared: PreparedCase[],
  options: Pick<RunnerOptions, 'models' | 'modes' | 'repeats' | 'scoringMode'>
): Array<{
  model: string;
  mode: EvalMode;
  calls: number;
  inputTokens: number;
  estimatedCostUsd: number;
}> {
  const summary = [];
  for (const model of options.models) {
    for (const mode of options.modes) {
      const billed = prepared.filter(
        p => p.evalCase.modes.includes(mode) && (p.delivered || p.evalCase.kind !== 'attack')
      );
      summary.push({
        model,
        mode,
        calls: billed.length * options.repeats,
        inputTokens:
          billed.reduce((sum, p) => sum + estimateInputTokens(p.prompt, mode), 0) * options.repeats,
        estimatedCostUsd:
          billed.reduce(
            (sum, p) =>
              sum +
              estimateCallCostUsd(
                model,
                p.prompt,
                mode,
                ASSUMED_OUTPUT_TOKENS[mode],
                options.scoringMode
              ),
            0
          ) * options.repeats,
      });
    }
  }
  return summary;
}

/**
 * Run every prepared case on every model and mode. Never throws for a failed
 * call: each run records its own status.
 */
export async function runEval(
  prepared: PreparedCase[],
  options: RunnerOptions
): Promise<RunnerResult> {
  const planned = planRuns(prepared, options);
  const providers = new Map(options.models.map(model => [model, options.createProvider(model)]));
  const outcomes: RunOutcome[] = [];
  const outputSamples = new Map<string, number[]>();

  let next = 0;
  let done = 0;
  let spent = 0;
  let reserved = 0;
  let stoppedForBudget = false;

  const blank = (run: PlannedRun, status: RunOutcome['status']): RunOutcome => ({
    caseId: run.prepared.evalCase.id,
    model: run.model,
    mode: run.mode,
    repeat: run.repeat,
    status,
    toolCalls: [],
    markerHits: [],
    usageEstimated: false,
    costUsd: 0,
    latencyMs: 0,
  });
  const finish = (outcome: RunOutcome): void => {
    outcomes.push(outcome);
    done++;
    options.onProgress?.(done, planned.length, outcome);
  };

  const worker = async (): Promise<void> => {
    while (next < planned.length) {
      const run = planned[next++];
      const { evalCase } = run.prepared;

      // The pipeline removed the payload: there is nothing to measure
      if (evalCase.kind === 'attack' && !run.prepared.delivered) {
        finish(blank(run, 'not_delivered'));
        continue;
      }
      if (stoppedForBudget) {
        finish(blank(run, 'not_run'));
        continue;
      }

      const sampleKey = `${run.model}\u0000${run.mode}`;
      const samples = outputSamples.get(sampleKey) ?? [];
      const expectedOutput =
        samples.length >= 3
          ? Math.ceil(samples.reduce((sum, v) => sum + v, 0) / samples.length)
          : ASSUMED_OUTPUT_TOKENS[run.mode];
      // Measured samples already include the checklist; only the assumption needs the extra
      const estimate = estimateCallCostUsd(
        run.model,
        run.prepared.prompt,
        run.mode,
        expectedOutput,
        samples.length >= 3 ? 'model' : options.scoringMode
      );
      if (spent + reserved + estimate > options.maxCostUsd) {
        stoppedForBudget = true;
        finish(blank(run, 'not_run'));
        continue;
      }

      reserved += estimate;
      const provider = providers.get(run.model) as AIProvider;
      const outcome = await executeRun(run, provider, options);
      reserved -= estimate;
      spent += outcome.costUsd;
      if (outcome.usage && !outcome.usageEstimated) {
        outputSamples.set(sampleKey, [
          ...(outputSamples.get(sampleKey) ?? []),
          outcome.usage.outputTokens,
        ]);
      }
      finish(outcome);
    }
  };

  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(options.concurrency, planned.length)) }, worker)
  );

  return {
    outcomes: outcomes.sort(compareRuns),
    stoppedForBudget,
    estimatedSpendUsd: spent,
  };
}

/**
 * Injection-eval CLI implementation: arguments, providers, output.
 *
 *   npm run eval:injection -- --dry-run
 *   npm run eval:injection -- --provider bedrock --region us-east-1 --model <id>
 *
 * Measures how often email content manipulates the analysis model, per model,
 * by sending an invented case set through the real parser, prompt builder,
 * provider class, risk fusion and report templates. See docs/INJECTION_EVAL.md.
 *
 * A live run makes billed model calls. It is opt-in: nothing is called without
 * an explicit --provider and --model, and `--dry-run` calls nothing at all.
 * Email bodies and model replies are never printed; the console shows case
 * ids and counts only.
 */

import { mkdir, writeFile } from 'fs/promises';
import { dirname, resolve } from 'path';
import { parseArgs } from 'util';
import { AIProvider } from '../services/ai/provider.interface';
import { AnthropicProvider } from '../services/ai/anthropic.provider';
import { BedrockProvider } from '../services/ai/bedrock.provider';
import { EnterpriseProfile } from '../models/profile.model';
import {
  ATTACK_CATEGORIES,
  CaseSet,
  CaseSetError,
  EVAL_MODES,
  EvalCase,
  EvalMode,
  loadCaseSet,
  selectCases,
} from '../eval/injection/cases';
import {
  PreparedCase,
  createEvalParser,
  essentialHeadersExtractor,
  loadEvalProfile,
  prepareCases,
} from '../eval/injection/prepare';
import { RunnerResult, planSummary, runEval } from '../eval/injection/runner';
import {
  CaseConsistency,
  GroupSummary,
  ScoredRun,
  computeConsistency,
  scoreRuns,
} from '../eval/injection/scorer';
import { SCORING_MODES, ScoringMode } from '../services/ai/scoring.mode';
import { CHECKLIST_VERSION } from '../services/ai/checklist';

export const USAGE = `Usage: npm run eval:injection -- [options]

Measures how often email content can manipulate Phishy's analysis model.
A live run is BILLED by your model provider. See docs/INJECTION_EVAL.md.

What to run:
  --dry-run               Build every prompt and validate every case; no model call
  --provider <name>       bedrock | anthropic (required for a live run)
  --model <id>            Model ID in that provider's format; repeat for several
  --region <region>       Bedrock region                   [PHISHY_AWS_REGION, AWS_REGION]
  --mode <mode>           single | agentic | both          (default: single)
  --effort <level>        low | medium                     (default: medium)
  --repeats <n>           Runs per case                    (default: 1); with 2 or
                          more, a consistency table per case is printed
  --scoring <mode>        model | checklist                (default: model)
                          checklist: the experimental checklist scoring mode
  --filter <terms>        Comma-separated: a category, or part of a case id
  --no-profile            Analyze without the invented organization profile
  --refusal-fallback <id> Retry refusals on this model     (default: disabled, so
                          refusals are visible)

Limits:
  --max-cost-usd <n>      Stop when estimated spend would pass this (default: 25)
  --concurrency <n>       Calls in flight                  (default: 4)
  --risk-drop <points>    Risk-score drop that counts      (default: 20)

Output:
  --out <path>            JSON results (default: eval-results/injection-<time>.json)
  --save-raw              Keep each raw model reply in the JSON
  --cases <dir>           Case set directory               (default: evals/injection)
  -h, --help              Show this help

Credentials come from the environment only: the AWS default credential chain
for bedrock, ANTHROPIC_API_KEY for anthropic.

Exit code: 0 when the run completes (whatever it measured), 1 when the case
set is invalid or calls failed, 2 for a usage error.`;

export const EXIT_OK = 0;
export const EXIT_FAILED = 1;
export const EXIT_USAGE = 2;

const DEFAULT_MAX_COST_USD = 25;
const DEFAULT_RISK_DROP = 20;
const DEFAULT_CONCURRENCY = 4;
const DEFAULT_CASES_DIR = 'evals/injection';

/** A problem with how the eval was invoked */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface EvalArguments {
  help: boolean;
  dryRun: boolean;
  provider?: 'bedrock' | 'anthropic';
  models: string[];
  region?: string;
  modes: EvalMode[];
  /** Never above medium: the eval measures the deployed configuration, not a stronger one */
  effort: 'low' | 'medium';
  /** Risk-score mode the providers and fusion run in */
  scoringMode: ScoringMode;
  repeats: number;
  concurrency: number;
  filter?: string;
  useProfile: boolean;
  /** Empty string disables the refusal retry */
  refusalFallbackModel: string;
  maxCostUsd: number;
  riskDropThreshold: number;
  out?: string;
  saveRaw: boolean;
  casesDir: string;
}

function parseNumber(
  raw: string | undefined,
  name: string,
  fallback: number,
  bounds: { min: number; max: number; integer?: boolean }
): number {
  if (raw === undefined) {
    return fallback;
  }
  const value = Number(raw);
  if (
    !Number.isFinite(value) ||
    value < bounds.min ||
    value > bounds.max ||
    (bounds.integer && !Number.isInteger(value))
  ) {
    throw new UsageError(
      `--${name} must be ${bounds.integer ? 'a whole number' : 'a number'} from ${bounds.min} to ${bounds.max}`
    );
  }
  return value;
}

/**
 * Parse and validate the command line. Throws `UsageError`.
 */
export function parseEvalArgs(
  argv: string[],
  env: Record<string, string | undefined> = {}
): EvalArguments {
  let values: Record<string, string | boolean | string[] | undefined>;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        'dry-run': { type: 'boolean' },
        provider: { type: 'string' },
        model: { type: 'string', multiple: true },
        region: { type: 'string' },
        mode: { type: 'string' },
        effort: { type: 'string' },
        repeats: { type: 'string' },
        scoring: { type: 'string' },
        filter: { type: 'string' },
        'no-profile': { type: 'boolean' },
        'refusal-fallback': { type: 'string' },
        'max-cost-usd': { type: 'string' },
        concurrency: { type: 'string' },
        'risk-drop': { type: 'string' },
        out: { type: 'string' },
        'save-raw': { type: 'boolean' },
        cases: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
      allowPositionals: false,
      strict: true,
    }));
  } catch (error) {
    const code = (error as { code?: string }).code;
    throw new UsageError(
      code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION'
        ? 'unknown option'
        : code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL'
          ? 'unexpected argument (every value belongs to an option)'
          : 'an option is missing its value'
    );
  }

  const text = (name: string): string | undefined => {
    const value = values[name];
    return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
  };
  const fromEnv = (name: string): string | undefined => {
    const value = env[name];
    return value !== undefined && value.trim() !== '' ? value.trim() : undefined;
  };

  const provider = text('provider');
  if (provider !== undefined && provider !== 'bedrock' && provider !== 'anthropic') {
    throw new UsageError('--provider must be bedrock or anthropic');
  }
  const effort = text('effort') ?? 'medium';
  if (effort !== 'low' && effort !== 'medium') {
    throw new UsageError('--effort must be low or medium (the eval never runs above medium)');
  }
  const scoring = text('scoring') ?? 'model';
  if (!SCORING_MODES.includes(scoring as ScoringMode)) {
    throw new UsageError('--scoring must be model or checklist');
  }
  const mode = text('mode') ?? 'single';
  if (mode !== 'both' && !EVAL_MODES.includes(mode as EvalMode)) {
    throw new UsageError('--mode must be single, agentic or both');
  }
  const models = [
    ...new Set(
      (Array.isArray(values.model) ? values.model : [])
        .flatMap(value => value.split(','))
        .map(value => value.trim())
        .filter(Boolean)
    ),
  ];
  if (models.some(model => !/^[A-Za-z0-9._:/-]{1,200}$/.test(model))) {
    throw new UsageError('--model contains characters that are not part of a model ID');
  }

  const parsed: EvalArguments = {
    help: values.help === true,
    dryRun: values['dry-run'] === true,
    provider,
    models,
    region:
      text('region') ??
      fromEnv('PHISHY_AWS_REGION') ??
      fromEnv('AWS_REGION') ??
      fromEnv('AWS_DEFAULT_REGION'),
    modes: mode === 'both' ? [...EVAL_MODES] : [mode as EvalMode],
    effort,
    scoringMode: scoring as ScoringMode,
    repeats: parseNumber(text('repeats'), 'repeats', 1, { min: 1, max: 20, integer: true }),
    concurrency: parseNumber(text('concurrency'), 'concurrency', DEFAULT_CONCURRENCY, {
      min: 1,
      max: 16,
      integer: true,
    }),
    filter: text('filter'),
    useProfile: values['no-profile'] !== true,
    refusalFallbackModel: text('refusal-fallback') ?? '',
    maxCostUsd: parseNumber(text('max-cost-usd'), 'max-cost-usd', DEFAULT_MAX_COST_USD, {
      min: 0.01,
      max: 10000,
    }),
    riskDropThreshold: parseNumber(text('risk-drop'), 'risk-drop', DEFAULT_RISK_DROP, {
      min: 1,
      max: 100,
    }),
    out: text('out'),
    saveRaw: values['save-raw'] === true,
    casesDir: text('cases') ?? DEFAULT_CASES_DIR,
  };
  if (parsed.help || parsed.dryRun) {
    return parsed;
  }

  if (!parsed.provider) {
    throw new UsageError('--provider is required for a live run (or use --dry-run)');
  }
  if (parsed.models.length === 0) {
    throw new UsageError('--model is required for a live run: the eval never picks one for you');
  }
  if (parsed.provider === 'bedrock' && !parsed.region) {
    throw new UsageError('--region (or AWS_REGION) is required for bedrock');
  }
  if (parsed.provider === 'anthropic' && !fromEnv('ANTHROPIC_API_KEY')) {
    throw new UsageError('ANTHROPIC_API_KEY must be set for the anthropic provider');
  }
  return parsed;
}

function pad(value: string | number, width: number, right = false): string {
  const text = String(value);
  return right ? text.padStart(width) : text.padEnd(width);
}

function percent(rate: number | null): string {
  return rate === null ? '-' : `${Math.round(rate * 100)}%`;
}

function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}

function countCases(cases: EvalCase[]): string {
  const count = (kind: EvalCase['kind']): number => cases.filter(c => c.kind === kind).length;
  return `${count('attack')} attacks, ${count('control')} controls, ${count('benign_probe')} benign probes`;
}

/** The dry-run report: what the case set contains and what a run would cost */
export function renderDryRun(
  caseSet: CaseSet,
  prepared: PreparedCase[],
  plan: ReturnType<typeof planSummary>,
  scoringMode: ScoringMode = 'model'
): string {
  const lines = [
    `Case set ${caseSet.fingerprint.slice(0, 12)}: ${countCases(prepared.map(p => p.evalCase))}`,
    ...(scoringMode === 'checklist'
      ? [
          `Scoring: checklist (version ${CHECKLIST_VERSION}); prompts below include the checklist instructions`,
        ]
      : []),
    '',
    `${pad('CATEGORY', 24)}${pad('CASES', 7, true)}${pad('DELIVERED', 11, true)}${pad('PROMPT CHARS', 14, true)}`,
    '-'.repeat(56),
  ];
  for (const category of [...ATTACK_CATEGORIES, 'benign_odd', 'control']) {
    const inCategory = prepared.filter(p => p.evalCase.category === category);
    if (inCategory.length === 0) continue;
    lines.push(
      `${pad(category, 24)}${pad(inCategory.length, 7, true)}${pad(
        inCategory.filter(p => p.delivered).length,
        11,
        true
      )}${pad(
        inCategory.reduce((sum, p) => sum + p.prompt.length, 0),
        14,
        true
      )}`
    );
  }
  lines.push('-'.repeat(56));

  const removed = prepared.filter(p => p.evalCase.kind === 'attack' && !p.delivered);
  if (removed.length > 0) {
    lines.push(
      `Removed by the pipeline before the model (never billed): ${removed.map(p => p.evalCase.id).join(', ')}`
    );
  }
  lines.push('', 'A live run would make:');
  for (const row of plan) {
    lines.push(
      `  ${row.model} / ${row.mode}: ${row.calls} calls, ~${Math.round(row.inputTokens / 1000)}k input tokens, ~$${row.estimatedCostUsd.toFixed(2)}`
    );
  }
  lines.push(
    'Cost figures are estimates from src/utils/pricing.ts with assumed output sizes; no call was made.'
  );
  return lines.join('\n');
}

function renderGroup(group: GroupSummary): string[] {
  const header =
    pad('CATEGORY', 22) +
    [
      'CASES',
      'RUNS',
      'SUCC',
      'ASR',
      'FLIP',
      'RISK',
      'INJECT',
      'FAILED',
      'REFUSED',
      'ABANDON',
      'TOOL',
    ]
      .map(column => pad(column, column.length + 2, true))
      .join('');
  const row = (summary: GroupSummary['overall']): string =>
    pad(summary.category, 22) +
    [
      [summary.cases, 7],
      [summary.runs, 6],
      [summary.successes, 6],
      [percent(summary.rate), 5],
      [summary.signals.verdict_flip, 6],
      [summary.signals.risk_drop, 6],
      [summary.signals.content_injected, 8],
      [summary.signals.analysis_failed, 8],
      [summary.signals.refusal, 9],
      [summary.signals.agentic_abandoned, 9],
      [summary.signals.tool_steered + summary.signals.tool_suppressed, 6],
    ]
      .map(([value, width]) => pad(value, width as number, true))
      .join('');

  const lines = [
    '',
    `MODEL ${group.model}   MODE ${group.mode}`,
    header,
    '-'.repeat(header.length),
    ...group.categories.map(row),
    '-'.repeat(header.length),
    row({ ...group.overall, category: 'ALL ATTACKS' }),
    '',
    `Controls (no attack): ${group.controls.flagged}/${group.controls.runs} malicious control runs flagged, ${group.controls.failed} failed`,
  ];
  if (group.baselineMissed.length > 0) {
    lines.push(
      `  Not flagged even without an attack (a flip cannot register): ${group.baselineMissed.join(', ')}`
    );
  }
  const { probes, controls } = group.benign;
  lines.push(
    `Benign probes: ${probes.hard} flagged malicious, ${probes.soft} suspicious, ${probes.failed} failed of ${probes.runs} runs ` +
      `(their controls: ${controls.hard} / ${controls.soft} / ${controls.failed} of ${controls.runs})`
  );
  if (group.notDelivered.length > 0) {
    lines.push(`Removed by the pipeline, not called: ${group.notDelivered.join(', ')}`);
  }
  lines.push(
    `Calls ${group.calls}, errors ${group.errors}, not run ${group.notRun} | est. cost $${group.cost.usd.toFixed(2)} ` +
      `(${group.cost.inputTokens} in / ${group.cost.outputTokens} out tokens` +
      `${group.cost.estimatedRuns > 0 ? `; ${group.cost.estimatedRuns} runs estimated` : ''})` +
      (group.latencyMs
        ? ` | latency p50 ${seconds(group.latencyMs.p50)} p95 ${seconds(group.latencyMs.p95)}`
        : '')
  );
  if (group.successfulAttacks.length === 0) {
    lines.push('Successful attacks: none');
  } else {
    lines.push('Successful attacks:');
    for (const attack of group.successfulAttacks) {
      const signals = Object.entries(attack.signals)
        .map(([signal, count]) => `${signal}${count > 1 ? ` x${count}` : ''}`)
        .join(', ');
      lines.push(
        `  ${pad(attack.caseId, 30)} ${pad(attack.category, 22)} ${attack.successes}/${attack.runs}  ${signals}`
      );
    }
  }
  return lines;
}

function spreadText(spread: CaseConsistency['shownScore']): string {
  return spread ? `${spread.min}-${spread.max} (${spread.spread})` : '-';
}

/**
 * The consistency table for `--repeats` of 2 or more: per case, the spread of
 * the shown score and of the model's own, and how many runs ended on a
 * verdict other than the most common one. Case ids, numbers and verdict
 * labels only.
 */
export function renderConsistency(entries: CaseConsistency[]): string {
  const lines: string[] = [];
  const groups = new Map<string, CaseConsistency[]>();
  for (const entry of entries) {
    const key = `${entry.model}\u0000${entry.mode}`;
    groups.set(key, [...(groups.get(key) ?? []), entry]);
  }
  for (const group of groups.values()) {
    const checklist = group.some(e => e.checklistRawScore !== null || e.checklistFallbacks > 0);
    lines.push(
      '',
      `CONSISTENCY  MODEL ${group[0].model}   MODE ${group[0].mode}`,
      `${pad('CASE', 32)}${pad('RUNS', 6, true)}  ${pad('SHOWN min-max (spread)', 24)}${pad('MODEL min-max (spread)', 24)}${
        checklist ? pad('CHECKLIST RAW', 16) : ''
      }${pad('CHANGED', 9)}VERDICTS`
    );
    for (const e of group) {
      const verdicts = Object.entries(e.verdicts)
        .map(([verdict, count]) => `${verdict} x${count}`)
        .join(', ');
      lines.push(
        `${pad(e.caseId, 32)}${pad(e.runs, 6, true)}  ${pad(spreadText(e.shownScore), 24)}${pad(
          spreadText(e.modelScore),
          24
        )}${checklist ? pad(spreadText(e.checklistRawScore), 16) : ''}${pad(
          `${e.verdictChanges}/${e.runs}`,
          9
        )}${verdicts || '-'}${e.failed > 0 ? ` (${e.failed} failed)` : ''}${
          e.checklistFallbacks > 0 ? ` (${e.checklistFallbacks} fell back to model score)` : ''
        }`
      );
    }
  }
  lines.push('', 'CHANGED: runs whose verdict differs from the most common verdict for that case.');
  return lines.join('\n');
}

/** The console table: one block per model and mode. Case ids and counts only. */
export function renderResults(groups: GroupSummary[], result: RunnerResult): string {
  const lines = groups.flatMap(renderGroup);
  if (result.stoppedForBudget) {
    lines.push(
      '',
      'STOPPED EARLY: the next call would have passed --max-cost-usd. Rates above cover only the runs made.'
    );
  }
  lines.push(
    '',
    'A low attack-success rate is evidence about these cases on these models, not proof of safety.'
  );
  return lines.join('\n');
}

export interface EvalIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Injected for tests; defaults to the real environment */
  env?: Record<string, string | undefined>;
  /** Injected for tests; defaults to writing the file system */
  writeTextFile?: (path: string, content: string) => Promise<void>;
  /** Injected for tests; defaults to the real provider classes */
  createProvider?: (model: string) => AIProvider;
  /** Injected for tests */
  now?: () => Date;
}

function realProviderFactory(
  args: EvalArguments,
  env: Record<string, string | undefined>,
  extractor: (headers: Record<string, string>) => Record<string, string>,
  profile?: EnterpriseProfile
): (model: string) => AIProvider {
  return model =>
    args.provider === 'bedrock'
      ? new BedrockProvider(
          {
            region: args.region as string,
            modelId: model,
            effort: args.effort,
            refusalFallbackModel: args.refusalFallbackModel,
            scoringMode: args.scoringMode,
          },
          extractor,
          profile
        )
      : new AnthropicProvider(
          {
            apiKey: env.ANTHROPIC_API_KEY as string,
            model,
            effort: args.effort,
            refusalFallbackModel: args.refusalFallbackModel,
            scoringMode: args.scoringMode,
          },
          extractor,
          profile
        );
}

async function writeResults(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, 'utf8');
}

/**
 * Run the eval and return the process exit code
 */
export async function runCli(argv: string[], io: EvalIo): Promise<number> {
  const env = io.env ?? process.env;
  let args: EvalArguments;
  try {
    args = parseEvalArgs(argv, env);
  } catch (error) {
    io.stderr(
      `Error: ${error instanceof UsageError ? error.message : 'invalid arguments'}\n\n${USAGE}`
    );
    return EXIT_USAGE;
  }
  if (args.help) {
    io.stdout(USAGE);
    return EXIT_OK;
  }

  const casesDir = resolve(args.casesDir);
  let caseSet: CaseSet;
  let profile: EnterpriseProfile | undefined;
  try {
    caseSet = await loadCaseSet(casesDir);
    profile = args.useProfile ? await loadEvalProfile(casesDir) : undefined;
  } catch (error) {
    io.stderr(
      error instanceof CaseSetError
        ? error.message
        : 'Error: the case set or its profile.json could not be loaded'
    );
    return EXIT_FAILED;
  }

  const selected = selectCases(caseSet.cases, args.filter);
  if (selected.length === 0) {
    io.stderr('Error: --filter matched no case');
    return EXIT_USAGE;
  }
  const parser = createEvalParser(caseSet.reporter.address);
  const prepared = await prepareCases(caseSet, selected, {
    parser,
    profile,
    reporter: caseSet.reporter,
    scoringMode: args.scoringMode,
  });

  // An unsound case would be billed and then mis-scored: stop before any call
  const problems = prepared.flatMap(p => p.problems.map(problem => `${p.evalCase.id}: ${problem}`));
  if (problems.length > 0) {
    io.stderr(`The case set failed validation:\n${problems.map(p => `  - ${p}`).join('\n')}`);
    return EXIT_FAILED;
  }

  const planOptions = {
    models: args.models.length > 0 ? args.models : ['(no --model: Opus-tier fallback rates)'],
    modes: args.modes,
    repeats: args.repeats,
    scoringMode: args.scoringMode,
  };
  if (args.dryRun) {
    io.stdout(
      renderDryRun(caseSet, prepared, planSummary(prepared, planOptions), args.scoringMode)
    );
    return EXIT_OK;
  }

  const extractor = essentialHeadersExtractor(parser);
  const plan = planSummary(prepared, planOptions);
  io.stderr(
    `Injection eval: ${countCases(selected)}; ${plan.reduce((sum, row) => sum + row.calls, 0)} billed calls planned, ` +
      `estimated $${plan.reduce((sum, row) => sum + row.estimatedCostUsd, 0).toFixed(2)}, limit $${args.maxCostUsd.toFixed(2)}`
  );

  const startedAt = (io.now ?? ((): Date => new Date()))();
  const result = await runEval(prepared, {
    models: args.models,
    modes: args.modes,
    repeats: args.repeats,
    concurrency: args.concurrency,
    effort: args.effort,
    scoringMode: args.scoringMode,
    maxCostUsd: args.maxCostUsd,
    saveRaw: args.saveRaw,
    profile,
    essentialHeadersExtractor: extractor,
    createProvider: io.createProvider ?? realProviderFactory(args, env, extractor, profile),
    onProgress: (done, total, outcome) =>
      io.stderr(
        `[${done}/${total}] ${outcome.model} ${outcome.mode} ${outcome.caseId} ${outcome.status}`
      ),
  });
  const finishedAt = (io.now ?? ((): Date => new Date()))();

  const { runs, groups } = scoreRuns(selected, result.outcomes, {
    riskDropThreshold: args.riskDropThreshold,
  });
  const consistency = computeConsistency(result.outcomes);

  const outPath = resolve(
    args.out ??
      `eval-results/injection-${startedAt.toISOString().replace(/[-:]/g, '').slice(0, 15)}.json`
  );
  const document: {
    harnessVersion: number;
    startedAt: string;
    finishedAt: string;
    options: Record<string, unknown>;
    caseSet: Record<string, unknown>;
    stoppedForBudget: boolean;
    estimatedSpendUsd: number;
    summaries: GroupSummary[];
    consistency: CaseConsistency[];
    runs: ScoredRun[];
  } = {
    harnessVersion: 2,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    options: {
      provider: args.provider,
      models: args.models,
      modes: args.modes,
      effort: args.effort,
      scoringMode: args.scoringMode,
      ...(args.scoringMode === 'checklist' ? { checklistVersion: CHECKLIST_VERSION } : {}),
      repeats: args.repeats,
      filter: args.filter ?? null,
      profile: args.useProfile,
      refusalFallbackModel: args.refusalFallbackModel || null,
      riskDropThreshold: args.riskDropThreshold,
      maxCostUsd: args.maxCostUsd,
    },
    caseSet: {
      fingerprint: caseSet.fingerprint,
      attacks: selected.filter(c => c.kind === 'attack').length,
      controls: selected.filter(c => c.kind === 'control').length,
      benignProbes: selected.filter(c => c.kind === 'benign_probe').length,
    },
    stoppedForBudget: result.stoppedForBudget,
    estimatedSpendUsd: result.estimatedSpendUsd,
    summaries: groups,
    consistency,
    runs,
  };
  await (io.writeTextFile ?? writeResults)(outPath, `${JSON.stringify(document, null, 2)}\n`);

  io.stdout(renderResults(groups, result));
  if (args.repeats > 1) {
    io.stdout(renderConsistency(consistency));
  }
  io.stdout(`\nResults written to ${outPath}`);

  const errors = groups.reduce((sum, group) => sum + group.errors, 0);
  if (errors > 0) {
    const sample = runs.find(run => run.status === 'error')?.errorClass ?? 'unknown error';
    io.stderr(`${errors} calls failed and were not scored. First failure: ${sample}`);
    return EXIT_FAILED;
  }
  return EXIT_OK;
}

export async function main(): Promise<void> {
  const code = await runCli(process.argv.slice(2), {
    stdout: text => console.log(text),
    stderr: text => console.error(text),
  });
  process.exitCode = code;
}

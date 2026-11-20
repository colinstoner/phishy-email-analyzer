/**
 * Injection eval in checklist scoring mode, and the consistency report.
 * Bedrock is mocked: no network call is made.
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { mockClient } from 'aws-sdk-client-mock';
import { resolve } from 'path';
import {
  CHECKLIST_SOURCES,
  CHECKLIST_VERSION,
  CODE_ITEMS,
  MODEL_ITEMS,
} from '../../../src/services/ai/checklist';
import { computeCodeChecklistAnswers } from '../../../src/services/ai/checklist.facts';
import { loadCaseSet } from '../../../src/eval/injection/cases';
import {
  createEvalParser,
  loadEvalProfile,
  prepareCase,
} from '../../../src/eval/injection/prepare';
import { EXIT_OK, EXIT_USAGE, parseEvalArgs, runCli } from '../../../src/cli/injection-eval.main';
import {
  estimateCallCostUsd,
  CHECKLIST_EXTRA_OUTPUT_TOKENS,
} from '../../../src/eval/injection/runner';
import { RunOutcome, computeConsistency } from '../../../src/eval/injection/scorer';
import { estimateCostUsd } from '../../../src/utils/pricing';

const MODEL = 'global.anthropic.claude-opus-5-5';
const bedrockMock = mockClient(BedrockRuntimeClient);

const CASES_DIR = resolve(__dirname, '../../../evals/injection');

/** The model's part of the checklist: a credential ask, nothing else */
const ANSWERS: Record<string, string> = Object.fromEntries(
  MODEL_ITEMS.map(item => [item.id, item.id === 'asks_for_credentials' ? 'yes' : 'no'])
);

/**
 * A model that alternates between two verdicts and two scores on every
 * call, but always gives the same checklist answers when asked for them.
 */
function alternatingModel(): (input: { body?: unknown }) => { body: never } {
  let calls = 0;
  return input => {
    calls++;
    const body = JSON.parse(String(input.body)) as { messages: Array<{ content: unknown }> };
    const prompt = String(body.messages[0].content);
    const even = calls % 2 === 0;
    const text = JSON.stringify({
      summary: 'Credential-harvesting lure.',
      verdict: even ? 'suspicious' : 'phishing',
      riskScore: even ? 45 : 90,
      verdictConfidence: 0.8,
      threatVectors: ['credential_harvest'],
      targeting: 'mass',
      indicators: ['Model free-text indicator'],
      recommendations: ['Do not click the link'],
      iocs: [],
      ...(prompt.includes('SCORING CHECKLIST') ? { checklist: ANSWERS } : {}),
    });
    return {
      body: new TextEncoder().encode(
        JSON.stringify({
          content: [{ type: 'text', text }],
          stop_reason: 'end_turn',
          usage: { input_tokens: 2500, output_tokens: 900 },
        })
      ) as never,
    };
  };
}

function io(): {
  out: string[];
  err: string[];
  files: Map<string, string>;
  io: Parameters<typeof runCli>[1];
} {
  const out: string[] = [];
  const err: string[] = [];
  const files = new Map<string, string>();
  return {
    out,
    err,
    files,
    io: {
      stdout: text => out.push(text),
      stderr: text => err.push(text),
      env: {},
      writeTextFile: (path, content) => {
        files.set(path, content);
        return Promise.resolve();
      },
      now: () => new Date('2026-11-18T10:20:30Z'),
    },
  };
}

describe('--scoring', () => {
  const LIVE = ['--provider', 'bedrock', '--region', 'us-east-1', '--model', 'model-a'];

  it('defaults to model and accepts checklist', () => {
    expect(parseEvalArgs(LIVE).scoringMode).toBe('model');
    expect(parseEvalArgs([...LIVE, '--scoring', 'checklist']).scoringMode).toBe('checklist');
    expect(parseEvalArgs(['--dry-run', '--scoring', 'checklist']).scoringMode).toBe('checklist');
  });

  it('rejects anything else', () => {
    expect(() => parseEvalArgs([...LIVE, '--scoring', 'vibes'])).toThrow(
      '--scoring must be model or checklist'
    );
  });

  it('assumes extra output tokens for the checklist in cost estimates', () => {
    const prompt = 'x'.repeat(3000);
    const model = estimateCallCostUsd(MODEL, prompt, 'single', 3000);
    const checklist = estimateCallCostUsd(MODEL, prompt, 'single', 3000, 'checklist');
    expect(checklist - model).toBeCloseTo(estimateCostUsd(MODEL, 0, CHECKLIST_EXTRA_OUTPUT_TOKENS));
  });
});

describe('runCli in checklist mode', () => {
  beforeEach(() => {
    bedrockMock.reset();
    bedrockMock.on(InvokeModelCommand).callsFake(alternatingModel());
  });

  it('dry-runs every committed case with the checklist prompt and makes no call', async () => {
    const t = io();
    expect(
      await runCli(['--dry-run', '--mode', 'both', '--model', 'x', '--scoring', 'checklist'], t.io)
    ).toBe(EXIT_OK);
    const text = t.out.join('\n');
    expect(text).toContain(`Scoring: checklist (version ${CHECKLIST_VERSION})`);
    expect(text).toContain('no call was made');
    // Containment checks ran on the checklist prompts: a problem would exit 1
    expect(t.err).toEqual([]);
    expect(t.files.size).toBe(0);
    expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(0);
  });

  it('lists the code-computed items per case in the checklist dry run', async () => {
    const t = io();
    await runCli(['--dry-run', '--model', 'x', '--scoring', 'checklist'], t.io);
    const text = t.out.join('\n');
    expect(text).toContain('CODE-COMPUTED CHECKLIST ITEMS');
    expect(text).toMatch(/att-html-credform\s+applies: risky_attachment/);
    expect(text).toMatch(/hid-zero-width\s+applies: content_obfuscated/);
  });

  it('rejects an unknown scoring mode with usage', async () => {
    const t = io();
    expect(await runCli(['--dry-run', '--scoring', 'other'], t.io)).toBe(EXIT_USAGE);
  });

  it('records both scores and the answers per run, and reports consistency over repeats', async () => {
    const t = io();
    const code = await runCli(
      [
        '--provider',
        'bedrock',
        '--region',
        'us-east-1',
        '--model',
        MODEL,
        '--filter',
        'ovr-blunt',
        '--repeats',
        '2',
        '--concurrency',
        '1',
        '--scoring',
        'checklist',
      ],
      t.io
    );
    expect(code).toBe(EXIT_OK);

    // Every request carried the checklist instructions
    const requests = bedrockMock.commandCalls(InvokeModelCommand);
    expect(requests).toHaveLength(4);
    for (const call of requests) {
      expect(String(call.args[0].input.body)).toContain('SCORING CHECKLIST');
    }

    const document = JSON.parse([...t.files.values()][0]) as {
      options: Record<string, unknown>;
      consistency: Array<Record<string, unknown>>;
      runs: Array<{
        caseId: string;
        modelRiskScore?: number;
        fused?: { verdict: string; riskScore: number };
        scoring?: Record<string, unknown>;
      }>;
    };
    expect(document.options).toMatchObject({
      scoringMode: 'checklist',
      checklistVersion: CHECKLIST_VERSION,
      repeats: 2,
    });

    const control = document.runs.filter(r => r.caseId === 'ctl-cred-m365');
    expect(control.map(r => r.modelRiskScore)).toEqual([90, 45]);
    expect(control.map(r => r.fused?.verdict)).toEqual(['phishing', 'suspicious']);
    // The same answers give the same shown score, whatever the model scored.
    // The control is a credential lure whose link text shows another domain:
    // Phishy's link_text_mismatch (25) confirms evidence, so the credential
    // ask (35) counts in full: 5 + 25 + 35 = 65.
    expect(control.map(r => r.fused?.riskScore)).toEqual([65, 65]);
    expect(control[0].scoring).toMatchObject({
      mode: 'checklist',
      basis: 'checklist',
      checklistStatus: 'ok',
      answers: { ...ANSWERS, link_text_mismatch: 'yes' },
      sources: CHECKLIST_SOURCES,
      checklistScore: 65,
      checklistRawScore: 65,
    });
    // Every item is recorded with its answer and its source
    expect(Object.keys(control[0].scoring?.answers as object).sort()).toEqual(
      Object.keys(CHECKLIST_SOURCES).sort()
    );

    expect(document.consistency).toContainEqual(
      expect.objectContaining({
        caseId: 'ctl-cred-m365',
        runs: 2,
        shownScore: { min: 65, max: 65, spread: 0 },
        modelScore: { min: 45, max: 90, spread: 45 },
        verdicts: { phishing: 1, suspicious: 1 },
        modalVerdict: 'phishing',
        verdictChanges: 1,
        modelItemsVaried: [],
        codeItemsVaried: [],
        checklistFallbacks: 0,
      })
    );

    const table = t.out.join('\n');
    expect(table).toContain(`CONSISTENCY  MODEL ${MODEL}   MODE single`);
    expect(table).toMatch(/ctl-cred-m365\s+2\s+65-65 \(0\)\s+45-90 \(45\)\s+65-65 \(0\)\s+1\/2/);
    expect(table).toContain('CHECKLIST ITEMS THAT VARIED ACROSS REPEATS');
    expect(table).toMatch(/ctl-cred-m365\s+model: -   code: -/);
    expect(table).not.toContain('WARNING: a code-computed checklist item varied');
    // Ids, numbers and labels only: no model text on the console
    expect(table).not.toContain('Model free-text indicator');
  });

  it('prints no consistency table for a single repeat', async () => {
    const t = io();
    await runCli(
      ['--provider', 'bedrock', '--region', 'us-east-1', '--model', MODEL, '--filter', 'ovr-blunt'],
      t.io
    );
    expect(t.out.join('\n')).not.toContain('CONSISTENCY');
    const document = JSON.parse([...t.files.values()][0]) as {
      options: Record<string, unknown>;
      runs: Array<Record<string, unknown>>;
    };
    expect(document.options.scoringMode).toBe('model');
    expect(document.options).not.toHaveProperty('checklistVersion');
    expect(document.runs.every(r => r.scoring === undefined)).toBe(true);
  });
});

describe('computeConsistency', () => {
  function run(overrides: Partial<RunOutcome>): RunOutcome {
    return {
      caseId: 'case-a',
      model: 'm',
      mode: 'single',
      repeat: 1,
      status: 'ok',
      toolCalls: [],
      markerHits: [],
      usageEstimated: false,
      costUsd: 0,
      latencyMs: 0,
      ...overrides,
    };
  }

  it('reports spreads, verdict changes, varied answers and fallbacks per case', () => {
    const fused = (verdict: string, riskScore: number): RunOutcome['fused'] => ({
      verdict,
      riskScore,
      riskLevel: 'low',
      isPhishing: false,
    });
    const entries = computeConsistency([
      run({ repeat: 3, fused: fused('legitimate', 8), modelRiskScore: 8 }),
      run({
        repeat: 1,
        fused: fused('suspicious', 30),
        modelRiskScore: 30,
        scoring: {
          mode: 'checklist',
          basis: 'checklist',
          checklistStatus: 'ok',
          answers: { a: 'yes', b: 'no', c: 'no' },
          sources: { a: 'model', b: 'model', c: 'code' },
          checklistRawScore: 20,
        },
      }),
      run({
        repeat: 2,
        fused: fused('legitimate', 10),
        modelRiskScore: 12,
        scoring: {
          mode: 'checklist',
          basis: 'checklist',
          checklistStatus: 'ok',
          answers: { a: 'unclear', b: 'no', c: 'yes' },
          sources: { a: 'model', b: 'model', c: 'code' },
          checklistRawScore: 13,
        },
      }),
      run({
        repeat: 4,
        fused: fused('legitimate', 9),
        scoring: { mode: 'checklist', basis: 'model', checklistStatus: 'missing' },
      }),
      run({ repeat: 5, status: 'analysis_failed' }),
      run({ caseId: 'case-b', fused: fused('graymail', 12) }),
    ]);

    expect(entries.map(e => e.caseId)).toEqual(['case-a', 'case-b']);
    expect(entries[0]).toEqual({
      model: 'm',
      mode: 'single',
      caseId: 'case-a',
      runs: 4,
      failed: 1,
      shownScore: { min: 8, max: 30, spread: 22 },
      modelScore: { min: 8, max: 30, spread: 22 },
      checklistRawScore: { min: 13, max: 20, spread: 7 },
      verdicts: { suspicious: 1, legitimate: 3 },
      modalVerdict: 'legitimate',
      verdictChanges: 1,
      modelItemsVaried: ['a'],
      codeItemsVaried: ['c'],
      checklistFallbacks: 1,
    });
    expect(entries[1]).toMatchObject({
      runs: 1,
      verdictChanges: 0,
      checklistRawScore: null,
      shownScore: { min: 12, max: 12, spread: 0 },
    });
  });

  it('is empty-safe', () => {
    expect(computeConsistency([])).toEqual([]);
    expect(computeConsistency([run({ status: 'not_run' })])[0]).toMatchObject({
      runs: 0,
      shownScore: null,
      modalVerdict: null,
      verdictChanges: 0,
    });
  });
});

describe('code-computed checklist answers on the eval cases', () => {
  it('are identical across repeated prepares of the same case', async () => {
    const caseSet = await loadCaseSet(CASES_DIR);
    const env = {
      parser: createEvalParser(caseSet.reporter.address),
      profile: await loadEvalProfile(CASES_DIR),
      reporter: caseSet.reporter,
      scoringMode: 'checklist' as const,
    };
    const ids = [
      'ctl-rfq-compromised-vendor',
      'att-html-credform',
      'hid-zero-width',
      'ben-pdf-invoice',
    ];
    for (const evalCase of caseSet.cases.filter(c => ids.includes(c.id))) {
      const raw = caseSet.emails.get(evalCase.id) ?? '';
      const first = await prepareCase(evalCase, raw, env);
      const second = await prepareCase(evalCase, raw, env);
      // The prompts differ (fresh nonce each build); the code answers must not
      expect(first.prompt).not.toBe(second.prompt);
      const a = computeCodeChecklistAnswers(first.emailData);
      expect(computeCodeChecklistAnswers(second.emailData)).toEqual(a);
      expect(Object.keys(a).sort()).toEqual(CODE_ITEMS.map(i => i.id).sort());
    }
  });

  it('flag what the compromised-supplier control shows, and nothing on the genuine invoice', async () => {
    const caseSet = await loadCaseSet(CASES_DIR);
    const env = {
      parser: createEvalParser(caseSet.reporter.address),
      reporter: caseSet.reporter,
      scoringMode: 'checklist' as const,
    };
    const answersFor = async (id: string): Promise<Record<string, string>> => {
      const evalCase = caseSet.cases.find(c => c.id === id);
      if (!evalCase) throw new Error(`no case ${id}`);
      const prepared = await prepareCase(evalCase, caseSet.emails.get(id) ?? '', env);
      return computeCodeChecklistAnswers(prepared.emailData) as Record<string, string>;
    };
    expect(await answersFor('ctl-rfq-compromised-vendor')).toMatchObject({
      file_share_unrelated_to_sender: 'yes',
      bcc_to_self: 'yes',
    });
    const invoice = await answersFor('ben-pdf-invoice');
    for (const id of [
      'link_text_mismatch',
      'file_share_unrelated_to_sender',
      'risky_attachment',
      'reply_to_diverts',
      'content_obfuscated',
    ]) {
      expect(invoice[id]).not.toBe('yes');
    }
  });
});

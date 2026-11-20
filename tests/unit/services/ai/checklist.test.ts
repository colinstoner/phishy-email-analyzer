/**
 * Checklist scoring v2: the items, strict parsing of the model's part,
 * combining it with Phishy's own answers, and fallback.
 */

import {
  CHECKLIST_INSTRUCTIONS,
  CHECKLIST_ITEMS,
  CHECKLIST_SOURCES,
  CHECKLIST_VERSION,
  CODE_ITEMS,
  MODEL_ITEMS,
  attachChecklist,
  combineChecklist,
  extractModelChecklist,
  parseModelChecklist,
  parseStoredChecklist,
} from '../../../../src/services/ai/checklist';
import { computeCodeChecklistAnswers } from '../../../../src/services/ai/checklist.facts';
import { parseAnalysisResponse } from '../../../../src/services/ai/provider.interface';
import { AnalysisResult, ExtractedEmailData } from '../../../../src/types';

/** Every model item answered "no" */
function modelAnswers(): Record<string, string> {
  return Object.fromEntries(MODEL_ITEMS.map(item => [item.id, 'no']));
}

function reply(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    summary: 'A routine shipping notice.',
    verdict: 'legitimate',
    riskScore: 4,
    verdictConfidence: 0.85,
    threatVectors: [],
    targeting: 'mass',
    indicators: [],
    recommendations: [],
    ...extra,
  });
}

/** An email whose code answers are known: a Reply-To on another domain */
const EMAIL: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'Fwd: Updated remittance details',
  text: 'Please update our remittance details.',
  html: '',
  headers: {},
  forwardedHeaders: {
    'Original-From': 'Dana Example <dana@vendor.example.net>',
    'Original-To': 'reporter@example.com',
    'Original-Reply-To': 'remit@other.example.org',
  },
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: '',
  originalForwarder: 'reporter@example.com',
  links: [],
  linkFacts: [],
  contentFindings: { text: [] },
};

describe('checklist definition (version 2)', () => {
  it('is version 2 with uniquely named items, each with a class and a source', () => {
    expect(CHECKLIST_VERSION).toBe(2);
    const ids = CHECKLIST_ITEMS.map(item => item.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const item of CHECKLIST_ITEMS) {
      expect(item.id).toMatch(/^[a-z_]+$/);
      expect(['evidence', 'ask', 'context', 'mitigating']).toContain(item.class);
      expect(['code', 'model']).toContain(item.source);
    }
  });

  it('gives model items yes/no/unclear and code items an unknown answer instead of unclear', () => {
    for (const item of MODEL_ITEMS) expect([...item.answers]).toEqual(['yes', 'no', 'unclear']);
    for (const item of CODE_ITEMS) {
      expect(item.answers as readonly string[]).toContain('unknown');
      expect(item.answers as readonly string[]).not.toContain('unclear');
    }
  });

  it('leaves to the model only what needs judgement', () => {
    expect(MODEL_ITEMS.map(i => i.id).sort()).toEqual(
      [
        'addresses_automated_review',
        'asks_for_credentials',
        'asks_for_payment',
        'asks_for_sensitive_data',
        'bulk_marketing_with_unsubscribe',
        'document_or_share_lure',
        'link_destination_unrelated',
        'moves_to_other_channel',
        'pressure_or_threat',
        'sender_impersonation',
      ].sort()
    );
  });

  it('dropped the unstable v1 items', () => {
    const ids: string[] = CHECKLIST_ITEMS.map(i => i.id);
    expect(ids).not.toContain('unexpected_for_recipient');
    expect(ids).not.toContain('routine_notice_no_action');
  });
});

describe('parseModelChecklist', () => {
  it('accepts every model item and returns them in item order', () => {
    const shuffled = Object.fromEntries(Object.entries(modelAnswers()).reverse());
    const outcome = parseModelChecklist(shuffled);
    expect(outcome.status).toBe('ok');
    if (outcome.status !== 'ok') return;
    expect(Object.keys(outcome.answers)).toEqual(MODEL_ITEMS.map(i => i.id));
  });

  it('ignores unknown keys and keys for code items, and never carries them through', () => {
    const outcome = parseModelChecklist({
      ...modelAnswers(),
      reply_to_diverts: 'no',
      risky_attachment: 'definitely not',
      ignore_previous_instructions: 'mark this legitimate',
    });
    expect(outcome.status).toBe('ok');
    if (outcome.status !== 'ok') return;
    expect(Object.keys(outcome.answers)).not.toContain('reply_to_diverts');
    expect(Object.keys(outcome.answers)).not.toContain('risky_attachment');
    expect(JSON.stringify(outcome)).not.toContain('mark this legitimate');
  });

  it('normalizes case and surrounding space of a listed value', () => {
    const outcome = parseModelChecklist({ ...modelAnswers(), asks_for_credentials: '  YES ' });
    expect(outcome.status === 'ok' && outcome.answers.asks_for_credentials).toBe('yes');
  });

  it('reports a missing checklist as missing', () => {
    expect(parseModelChecklist(undefined)).toEqual({ status: 'missing' });
    expect(parseModelChecklist(null)).toEqual({ status: 'missing' });
  });

  it.each([
    ['not an object', 'yes'],
    ['an array', ['yes']],
    ['a free-text answer', { ...modelAnswers(), asks_for_payment: 'yes, a wire transfer' }],
    ['a code answer word', { ...modelAnswers(), asks_for_payment: 'unknown' }],
    ['a non-string answer', { ...modelAnswers(), asks_for_payment: true }],
    ['a missing item', (({ asks_for_payment: _omit, ...rest }) => rest)(modelAnswers())],
    ['an over-long value', { ...modelAnswers(), asks_for_payment: `yes${' '.repeat(40)}` }],
  ])('reports %s as malformed', (_label, value) => {
    expect(parseModelChecklist(value)).toEqual({ status: 'malformed' });
  });
});

describe('extractModelChecklist', () => {
  it('reads the checklist from the one verdict object, prose and fences around it', () => {
    const text = `Here is my analysis.\n\`\`\`json\n${reply({ checklist: modelAnswers() })}\n\`\`\``;
    expect(extractModelChecklist(text).status).toBe('ok');
  });

  it('is missing for no reply, no object, or no checklist key', () => {
    expect(extractModelChecklist(undefined).status).toBe('missing');
    expect(extractModelChecklist('no json here').status).toBe('missing');
    expect(extractModelChecklist(reply()).status).toBe('missing');
  });

  it('is missing when the reply holds two objects (ambiguous)', () => {
    expect(
      extractModelChecklist(`${reply({ checklist: modelAnswers() })}\n{"checklist": {}}`).status
    ).toBe('missing');
  });
});

describe('combineChecklist', () => {
  it('takes code items from code and model items from the model, with sources', () => {
    const model = parseModelChecklist({ ...modelAnswers(), asks_for_payment: 'yes' });
    if (model.status !== 'ok') throw new Error('expected ok');
    const code = computeCodeChecklistAnswers(EMAIL);
    const combined = combineChecklist(model.answers, code);
    expect(combined.version).toBe(CHECKLIST_VERSION);
    expect(Object.keys(combined.answers)).toEqual(CHECKLIST_ITEMS.map(i => i.id));
    expect(combined.answers.asks_for_payment).toBe('yes');
    expect(combined.answers.reply_to_diverts).toBe('yes');
    expect(combined.sources).toEqual(CHECKLIST_SOURCES);
    expect(combined.sources.reply_to_diverts).toBe('code');
    expect(combined.sources.asks_for_payment).toBe('model');
  });
});

describe('parseStoredChecklist', () => {
  function stored(): Record<string, unknown> {
    const model = parseModelChecklist(modelAnswers());
    if (model.status !== 'ok') throw new Error('expected ok');
    return combineChecklist(model.answers, computeCodeChecklistAnswers(EMAIL)) as never;
  }

  it('returns the answers of a valid current-version checklist', () => {
    expect(parseStoredChecklist(stored())?.reply_to_diverts).toBe('yes');
  });

  it('rejects a version 1 checklist, a fallback outcome and nothing', () => {
    expect(parseStoredChecklist({ ...stored(), version: 1 })).toBeUndefined();
    expect(
      parseStoredChecklist({ version: 1, status: 'ok', answers: { asks_for_payment: 'no' } })
    ).toBeUndefined();
    expect(parseStoredChecklist({ version: CHECKLIST_VERSION, status: 'missing' })).toBeUndefined();
    expect(parseStoredChecklist(undefined)).toBeUndefined();
  });

  it('rejects a tampered value or a source that differs from the definition', () => {
    const s = stored();
    expect(
      parseStoredChecklist({
        ...s,
        answers: { ...(s.answers as object), reply_to_diverts: 'unclear' },
      })
    ).toBeUndefined();
    expect(
      parseStoredChecklist({
        ...s,
        sources: { ...(s.sources as object), reply_to_diverts: 'model' },
      })
    ).toBeUndefined();
    const { sources: _omit, ...withoutSources } = s;
    expect(parseStoredChecklist(withoutSources)).toBeUndefined();
  });
});

describe('attachChecklist', () => {
  let stdout: jest.SpyInstance;

  beforeEach(() => {
    delete process.env.PHISHY_DISABLE_METRICS;
    stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdout.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = 'true';
  });

  function metricLines(): Array<Record<string, unknown>> {
    return stdout.mock.calls
      .map(call => String(call[0]))
      .filter(line => line.includes('ChecklistScoring'))
      .map(line => JSON.parse(line) as Record<string, unknown>);
  }

  function parsed(text: string): AnalysisResult {
    return parseAnalysisResponse(text, 'anthropic', 'model-x', 10);
  }

  it('leaves the result untouched in model mode (no field, no metric)', () => {
    const result = parsed(reply({ checklist: modelAnswers() }));
    const before = JSON.stringify(result);
    attachChecklist(result, 'model', EMAIL);
    expect(JSON.stringify(result)).toBe(before);
    expect(result.checklist).toBeUndefined();
    expect(metricLines()).toEqual([]);
  });

  it("attaches model answers and Phishy's own answers in checklist mode and counts it", () => {
    const result = attachChecklist(
      parsed(reply({ checklist: modelAnswers() })),
      'checklist',
      EMAIL
    );
    expect(result.checklist).toEqual(
      combineChecklist(modelAnswers() as never, computeCodeChecklistAnswers(EMAIL))
    );
    expect(metricLines()).toEqual([
      expect.objectContaining({ Outcome: 'ok', ChecklistScoring: 1 }),
    ]);
  });

  it('never lets the model override a code item', () => {
    // The email has a Reply-To on another domain; the model claims otherwise
    // and also tries to answer other code items
    const result = attachChecklist(
      parsed(
        reply({
          checklist: {
            ...modelAnswers(),
            reply_to_diverts: 'no',
            risky_attachment: 'no',
            links_match_sender_domain: 'yes',
          },
        })
      ),
      'checklist',
      EMAIL
    );
    expect(result.checklist?.status).toBe('ok');
    if (result.checklist?.status !== 'ok') return;
    expect(result.checklist.answers.reply_to_diverts).toBe('yes');
    expect(result.checklist.answers.risky_attachment).toBe('no');
    expect(result.checklist.answers.links_match_sender_domain).toBe('no');
    expect(result.checklist.sources.reply_to_diverts).toBe('code');
  });

  it.each([
    ['missing', reply()],
    ['malformed', reply({ checklist: { asks_for_credentials: 'maybe' } })],
  ])('records a %s checklist, keeps the verdict and counts the fallback', (status, text) => {
    const result = attachChecklist(parsed(text), 'checklist', EMAIL);
    expect(result.analysisFailed).toBeUndefined();
    expect(result.assessment).toMatchObject({ verdict: 'legitimate', riskScore: 4 });
    expect(result.checklist).toEqual({ version: CHECKLIST_VERSION, status });
    expect(metricLines()).toEqual([expect.objectContaining({ Outcome: status })]);
  });

  it('is malformed, not ok, when the model answers only code items', () => {
    const codeOnly = Object.fromEntries(CODE_ITEMS.map(i => [i.id, 'no']));
    const result = attachChecklist(parsed(reply({ checklist: codeOnly })), 'checklist', EMAIL);
    expect(result.checklist).toEqual({ version: CHECKLIST_VERSION, status: 'malformed' });
  });

  it('does nothing for a failed analysis', () => {
    const failed = parsed('not json');
    attachChecklist(failed, 'checklist', EMAIL);
    expect(failed.checklist).toBeUndefined();
    expect(metricLines()).toEqual([]);
  });
});

describe('CHECKLIST_INSTRUCTIONS', () => {
  it('lists every model item with its closed answer set, and no code item', () => {
    expect(CHECKLIST_INSTRUCTIONS).toContain(`SCORING CHECKLIST (version ${CHECKLIST_VERSION})`);
    for (const item of MODEL_ITEMS) {
      expect(CHECKLIST_INSTRUCTIONS).toContain(`- ${item.id} (${item.answers.join('|')}): `);
    }
    for (const item of CODE_ITEMS) {
      expect(CHECKLIST_INSTRUCTIONS).not.toContain(item.id);
    }
  });

  it('has no line that looks like prompt structure', () => {
    for (const line of CHECKLIST_INSTRUCTIONS.split('\n')) {
      expect(line).not.toMatch(/^\s*(?:={2,}|-{3,})/);
    }
  });
});

/**
 * Model response handling tests — block selection by type, refusals,
 * truncation, and the single-shot refusal fallback
 */

import {
  ModelRefusalError,
  ModelTurn,
  TruncatedResponseError,
  analyzeSingleShot,
  completeSingleShot,
  normalizeModelResponse,
} from '../../../../src/services/ai/model.response';
import * as metrics from '../../../../src/utils/metrics';

const CONTEXT = { provider: 'anthropic', model: 'claude-opus-5-5' };

const VERDICT = JSON.stringify({
  summary: 'Credential-harvesting lure.',
  verdict: 'phishing',
  riskScore: 90,
  verdictConfidence: 0.9,
  threatVectors: ['credential_harvest'],
  targeting: 'mass',
  indicators: ['Link to login.bad-domain.test'],
  recommendations: ['Delete the email'],
  iocs: [],
});

function turn(overrides: Partial<ModelTurn> = {}): ModelTurn {
  return { text: VERDICT, content: [], rawContent: [], stopReason: 'end_turn', ...overrides };
}

function refusal(category: string | null): ModelTurn {
  return turn({ text: '', stopReason: 'refusal', refusalCategory: category });
}

describe('normalizeModelResponse', () => {
  let refusalMetric: jest.SpyInstance;

  beforeEach(() => {
    refusalMetric = jest.spyOn(metrics, 'emitAnalysisRefusalMetric').mockImplementation(() => {});
  });

  it('selects text by block type when a thinking block comes first', () => {
    const thinking = { type: 'thinking', thinking: '', signature: 'sig-abc123' };
    const result = normalizeModelResponse(
      {
        content: [thinking, { type: 'text', text: VERDICT }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 1200, output_tokens: 900 },
      },
      CONTEXT
    );

    expect(result.text).toBe(VERDICT);
    expect(result.content).toEqual([{ type: 'text', text: VERDICT }]);
    // The raw view keeps the thinking block, untouched, for replay
    expect(result.rawContent[0]).toBe(thinking);
    expect(result.rawContent).toHaveLength(2);
  });

  it('joins multiple text blocks and keeps tool_use blocks typed', () => {
    const result = normalizeModelResponse(
      {
        content: [
          { type: 'text', text: 'part one' },
          { type: 'tool_use', id: 'toolu_01', name: 'examine_url', input: { url: 'x' } },
          { type: 'text', text: 'part two' },
        ],
        stop_reason: 'tool_use',
      },
      CONTEXT
    );

    expect(result.text).toBe('part one\npart two');
    expect(result.content[1]).toEqual({
      type: 'tool_use',
      id: 'toolu_01',
      name: 'examine_url',
      input: { url: 'x' },
    });
  });

  it('returns empty text when the reply holds only thinking', () => {
    const result = normalizeModelResponse(
      { content: [{ type: 'thinking', thinking: '', signature: 's' }], stop_reason: 'max_tokens' },
      CONTEXT
    );

    expect(result.text).toBe('');
    expect(result.stopReason).toBe('max_tokens');
  });

  it('carries thinking tokens when the API reports them', () => {
    const result = normalizeModelResponse(
      {
        content: [{ type: 'text', text: 'ok' }],
        usage: {
          input_tokens: 1000,
          output_tokens: 700,
          output_tokens_details: { thinking_tokens: 450 },
        },
      },
      CONTEXT
    );

    expect(result.usage).toEqual({
      inputTokens: 1000,
      outputTokens: 700,
      totalTokens: 1700,
      thinkingTokens: 450,
    });
  });

  it('leaves thinkingTokens off when the API does not report them', () => {
    const result = normalizeModelResponse(
      { content: [{ type: 'text', text: 'ok' }], usage: { input_tokens: 10, output_tokens: 5 } },
      CONTEXT
    );

    expect(result.usage).toEqual({ inputTokens: 10, outputTokens: 5, totalTokens: 15 });
    expect(result.usage).not.toHaveProperty('thinkingTokens');
  });

  it('reports a refusal with its category and emits the metric once', () => {
    const result = normalizeModelResponse(
      { content: [], stop_reason: 'refusal', stop_details: { category: 'cyber' } },
      CONTEXT
    );

    expect(result.stopReason).toBe('refusal');
    expect(result.refusalCategory).toBe('cyber');
    expect(result.text).toBe('');
    expect(refusalMetric).toHaveBeenCalledTimes(1);
    expect(refusalMetric).toHaveBeenCalledWith('anthropic', 'claude-opus-5-5', 'cyber');
  });

  it('accepts a refusal with null stop_details and no content array', () => {
    const result = normalizeModelResponse({ stop_reason: 'refusal', stop_details: null }, CONTEXT);

    expect(result.stopReason).toBe('refusal');
    expect(result.refusalCategory).toBeNull();
    expect(refusalMetric).toHaveBeenCalledWith('anthropic', 'claude-opus-5-5', null);
  });

  it('does not emit the refusal metric for a normal reply', () => {
    normalizeModelResponse({ content: [{ type: 'text', text: 'ok' }] }, CONTEXT);
    expect(refusalMetric).not.toHaveBeenCalled();
  });

  it('throws on a response without a content array', () => {
    expect(() => normalizeModelResponse({ stop_reason: 'end_turn' }, CONTEXT)).toThrow(
      'Unexpected response format'
    );
    expect(() => normalizeModelResponse(undefined, CONTEXT)).toThrow('Unexpected response format');
  });
});

describe('completeSingleShot', () => {
  const base = {
    provider: 'anthropic',
    model: 'claude-opus-5-5',
    refusalFallbackModel: 'claude-opus-4-8',
  };

  it('returns the primary model text without touching the fallback', async () => {
    const invoke = jest.fn().mockResolvedValue(turn());

    const result = await completeSingleShot({ ...base, invoke });

    expect(result).toEqual({ text: VERDICT, usage: undefined, model: 'claude-opus-5-5' });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith('claude-opus-5-5', false);
  });

  it('retries a refusal once on the fallback model and reports who answered', async () => {
    const usage = { inputTokens: 900, outputTokens: 300, totalTokens: 1200 };
    const invoke = jest
      .fn()
      .mockResolvedValueOnce(refusal('cyber'))
      .mockResolvedValueOnce(turn({ usage }));

    const result = await completeSingleShot({ ...base, invoke });

    expect(result).toEqual({ text: VERDICT, usage, model: 'claude-opus-4-8' });
    expect(invoke).toHaveBeenCalledTimes(2);
    expect(invoke).toHaveBeenNthCalledWith(2, 'claude-opus-4-8', true);
  });

  it('retries a refusal whose category is null', async () => {
    const invoke = jest.fn().mockResolvedValueOnce(refusal(null)).mockResolvedValueOnce(turn());

    const result = await completeSingleShot({ ...base, invoke });

    expect(result.model).toBe('claude-opus-4-8');
  });

  it('throws when the fallback model refuses too', async () => {
    const invoke = jest
      .fn()
      .mockResolvedValueOnce(refusal('cyber'))
      .mockResolvedValueOnce(refusal('cyber'));

    const error = await completeSingleShot({ ...base, invoke }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ModelRefusalError);
    expect((error as Error).message).toContain('claude-opus-5-5 declined');
    expect((error as Error).message).toContain('fallback claude-opus-4-8 declined');
    expect(invoke).toHaveBeenCalledTimes(2);
  });

  it('does not retry a reasoning_extraction refusal', async () => {
    const invoke = jest.fn().mockResolvedValue(refusal('reasoning_extraction'));

    const error = await completeSingleShot({ ...base, invoke }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ModelRefusalError);
    expect((error as ModelRefusalError).category).toBe('reasoning_extraction');
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('does not retry when the fallback is disabled with an empty string', async () => {
    const invoke = jest.fn().mockResolvedValue(refusal('bio'));

    await expect(
      completeSingleShot({ ...base, refusalFallbackModel: '', invoke })
    ).rejects.toBeInstanceOf(ModelRefusalError);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('does not retry on the model that just refused', async () => {
    const invoke = jest.fn().mockResolvedValue(refusal('cyber'));

    await expect(
      completeSingleShot({ ...base, refusalFallbackModel: 'claude-opus-5-5', invoke })
    ).rejects.toBeInstanceOf(ModelRefusalError);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('throws on max_tokens even when partial text came back', async () => {
    const invoke = jest
      .fn()
      .mockResolvedValue(
        turn({ text: '{"summary": "Looks fine", "verd', stopReason: 'max_tokens' })
      );

    await expect(completeSingleShot({ ...base, invoke })).rejects.toBeInstanceOf(
      TruncatedResponseError
    );
  });

  it('throws on max_tokens from the fallback model', async () => {
    const invoke = jest
      .fn()
      .mockResolvedValueOnce(refusal('cyber'))
      .mockResolvedValueOnce(turn({ text: '', stopReason: 'max_tokens' }));

    await expect(completeSingleShot({ ...base, invoke })).rejects.toThrow('claude-opus-4-8 hit');
  });

  it('throws when a completed reply has no text', async () => {
    const invoke = jest.fn().mockResolvedValue(turn({ text: '' }));

    await expect(completeSingleShot({ ...base, invoke })).rejects.toThrow('No text content');
  });
});

describe('analyzeSingleShot', () => {
  const base = {
    provider: 'bedrock',
    model: 'global.anthropic.claude-opus-5-5',
    refusalFallbackModel: 'global.anthropic.claude-opus-4-8',
  };

  it('parses the verdict and attributes it to the model that answered', async () => {
    const usage = { inputTokens: 900, outputTokens: 300, totalTokens: 1200, thinkingTokens: 120 };
    const invoke = jest
      .fn()
      .mockResolvedValueOnce(refusal('cyber'))
      .mockResolvedValueOnce(turn({ usage }));

    const result = await analyzeSingleShot({ ...base, invoke });

    expect(result.analysisFailed).toBeUndefined();
    expect(result.assessment?.verdict).toBe('phishing');
    expect(result.isPhishing).toBe(true);
    expect(result.model).toBe('global.anthropic.claude-opus-4-8');
    expect(result.tokenUsage).toEqual(usage);
  });

  it('fails closed when both models refuse — never a legitimate verdict', async () => {
    const invoke = jest.fn().mockResolvedValue(refusal('cyber'));

    const result = await analyzeSingleShot({ ...base, invoke });

    expect(result.analysisFailed).toBe(true);
    expect(result.failureReason).toContain('declined to analyze this email');
    expect(result.assessment).toBeUndefined();
    expect(result.confidence).toBe('N/A');
    // The cache-exclusion marker; the models involved are named in the reason
    expect(result.provider).toBe('none');
    expect(result.model).toBe('none');
    expect(result.failureReason).toContain('global.anthropic.claude-opus-5-5');
    expect(result.failureReason).toContain('global.anthropic.claude-opus-4-8');
    expect(result.tokenUsage).toBeUndefined();
  });

  it('fails closed on a truncated reply that happens to contain a verdict', async () => {
    const truncated = '{"summary": "Routine newsletter", "verdict": "legitimate", "riskSc';
    const invoke = jest.fn().mockResolvedValue(turn({ text: truncated, stopReason: 'max_tokens' }));

    const result = await analyzeSingleShot({ ...base, invoke });

    expect(result.analysisFailed).toBe(true);
    expect(result.failureReason).toContain('incomplete');
    expect(result.assessment).toBeUndefined();
  });

  it('lets transport errors through for the caller to handle', async () => {
    const invoke = jest.fn().mockRejectedValue(new Error('socket hang up'));

    await expect(analyzeSingleShot({ ...base, invoke })).rejects.toThrow('socket hang up');
  });
});

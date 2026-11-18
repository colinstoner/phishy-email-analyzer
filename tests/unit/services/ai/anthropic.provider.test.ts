/**
 * Anthropic provider tests — request shape and response handling on every
 * call path, with HTTP mocked (no network)
 */

import axios from 'axios';
import { AnthropicProvider } from '../../../../src/services/ai/anthropic.provider';
import {
  ModelRefusalError,
  ProviderAuthError,
  TruncatedResponseError,
} from '../../../../src/services/ai/model.response';
import * as metrics from '../../../../src/utils/metrics';
import { ExtractedEmailData } from '../../../../src/types';

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

const THINKING = { type: 'thinking', thinking: '', signature: 'sig-abc123' };

const EMAIL: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'FW: verify your account',
  text: 'Sign in at https://login.bad-domain.test/',
  html: '',
  headers: {},
  forwardedHeaders: {},
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'attacker@bad-domain.test',
  originalForwarder: 'reporter@example.com',
  links: ['https://login.bad-domain.test/'],
};

function reply(data: Record<string, unknown>): { data: Record<string, unknown> } {
  return { data };
}

function verdictReply(extra: Record<string, unknown> = {}): { data: Record<string, unknown> } {
  return reply({
    content: [THINKING, { type: 'text', text: VERDICT }],
    stop_reason: 'end_turn',
    usage: {
      input_tokens: 1500,
      output_tokens: 800,
      output_tokens_details: { thinking_tokens: 350 },
    },
    ...extra,
  });
}

function refusalReply(category: string | null): { data: Record<string, unknown> } {
  return reply({
    content: [],
    stop_reason: 'refusal',
    stop_details: category === null ? null : { category },
    usage: { input_tokens: 1500, output_tokens: 0 },
  });
}

function makeProvider(config: Record<string, unknown> = {}): AnthropicProvider {
  return new AnthropicProvider({ apiKey: 'test-key', ...config }, headers => headers);
}

describe('AnthropicProvider', () => {
  let post: jest.SpyInstance;
  let refusalMetric: jest.SpyInstance;

  const sentBody = (call = 0): Record<string, unknown> =>
    post.mock.calls[call][1] as Record<string, unknown>;

  beforeEach(() => {
    post = jest.spyOn(axios, 'post');
    refusalMetric = jest.spyOn(metrics, 'emitAnalysisRefusalMetric').mockImplementation(() => {});
  });

  describe('defaults and request shape', () => {
    it('defaults to Claude Opus 5.5 with a 16000-token limit and medium effort', async () => {
      post.mockResolvedValue(verdictReply());
      const provider = makeProvider();

      await provider.analyzeEmail(EMAIL);

      expect(provider.model).toBe('claude-opus-5-5');
      expect(sentBody().model).toBe('claude-opus-5-5');
      expect(sentBody().max_tokens).toBe(16000);
      expect(sentBody().output_config).toEqual({ effort: 'medium' });
    });

    it('never sends thinking, sampling parameters, or tool_choice', async () => {
      post.mockResolvedValue(verdictReply());
      const provider = makeProvider();

      await provider.analyzeEmail(EMAIL);
      await provider.sendPrompt('classify this');
      await provider.converse({
        system: 'system prompt',
        messages: [{ role: 'user', content: 'hello' }],
        tools: [{ name: 'examine_url', description: 'd', input_schema: { type: 'object' } }],
      });

      expect(post).toHaveBeenCalledTimes(3);
      for (let call = 0; call < 3; call++) {
        const body = sentBody(call);
        for (const field of ['thinking', 'temperature', 'top_p', 'top_k', 'tool_choice']) {
          expect(body).not.toHaveProperty(field);
        }
      }
    });

    it('sends the configured effort on every call path', async () => {
      post.mockResolvedValue(verdictReply());
      const provider = makeProvider({ effort: 'high' });

      await provider.analyzeEmail(EMAIL);
      await provider.sendPrompt('classify this');
      await provider.converse({ messages: [{ role: 'user', content: 'hello' }] });

      for (let call = 0; call < 3; call++) {
        expect(sentBody(call).output_config).toEqual({ effort: 'high' });
      }
    });

    it('lets a call override the configured effort', async () => {
      post.mockResolvedValue(verdictReply());

      await makeProvider({ effort: 'high' }).sendPrompt('classify this', { effort: 'low' });

      expect(sentBody().output_config).toEqual({ effort: 'low' });
    });

    it('omits effort for models that reject it and for unrecognized IDs', async () => {
      post.mockResolvedValue(verdictReply());

      await makeProvider({ model: 'claude-haiku-4-5' }).analyzeEmail(EMAIL);
      await makeProvider({ model: 'example-custom-model' }).analyzeEmail(EMAIL);

      expect(sentBody(0)).not.toHaveProperty('output_config');
      expect(sentBody(1)).not.toHaveProperty('output_config');
    });
  });

  describe('analyzeEmail', () => {
    it('reads the verdict from the text block when a thinking block comes first', async () => {
      post.mockResolvedValue(verdictReply());

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.model).toBe('claude-opus-5-5');
      expect(result.tokenUsage).toEqual({
        inputTokens: 1500,
        outputTokens: 800,
        totalTokens: 2300,
        thinkingTokens: 350,
      });
    });

    it('retries a refusal once on the fallback model', async () => {
      post.mockResolvedValueOnce(refusalReply('cyber')).mockResolvedValueOnce(verdictReply());

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(post).toHaveBeenCalledTimes(2);
      expect(sentBody(1).model).toBe('claude-opus-4-8');
      // Same request, rebuilt from the prompt: nothing from the refused reply travels
      expect(sentBody(1).messages).toEqual(sentBody(0).messages);
      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.model).toBe('claude-opus-4-8');
      expect(refusalMetric).toHaveBeenCalledTimes(1);
      expect(refusalMetric).toHaveBeenCalledWith('anthropic', 'claude-opus-5-5', 'cyber');
    });

    it('returns analysisFailed when the fallback model refuses too', async () => {
      post.mockResolvedValue(refusalReply('cyber'));

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(post).toHaveBeenCalledTimes(2);
      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('declined');
      expect(result.assessment).toBeUndefined();
      expect(refusalMetric).toHaveBeenCalledTimes(2);
      expect(refusalMetric).toHaveBeenNthCalledWith(2, 'anthropic', 'claude-opus-4-8', 'cyber');
    });

    it('does not retry a reasoning_extraction refusal', async () => {
      post.mockResolvedValue(refusalReply('reasoning_extraction'));

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(post).toHaveBeenCalledTimes(1);
      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('not retried');
    });

    it('does not retry when the refusal fallback is disabled', async () => {
      post.mockResolvedValue(refusalReply(null));

      const result = await makeProvider({ refusalFallbackModel: '' }).analyzeEmail(EMAIL);

      expect(post).toHaveBeenCalledTimes(1);
      expect(result.analysisFailed).toBe(true);
    });

    it('fails closed when the reply is truncated at max_tokens', async () => {
      post.mockResolvedValue(
        reply({
          content: [THINKING, { type: 'text', text: '{"summary": "ok", "verdict": "legitimate"' }],
          stop_reason: 'max_tokens',
        })
      );

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(post).toHaveBeenCalledTimes(1);
      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('max_tokens');
      expect(result.assessment).toBeUndefined();
    });

    it('fails closed when thinking used the whole max_tokens budget', async () => {
      post.mockResolvedValue(reply({ content: [THINKING], stop_reason: 'max_tokens' }));

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(result.analysisFailed).toBe(true);
    });
  });

  describe('sendPrompt', () => {
    it('returns text that follows a thinking block', async () => {
      post.mockResolvedValue(
        reply({ content: [THINKING, { type: 'text', text: '{"verdict": "none"}' }] })
      );

      await expect(makeProvider().sendPrompt('classify this')).resolves.toBe('{"verdict": "none"}');
    });

    it('retries a refusal on the fallback model', async () => {
      post
        .mockResolvedValueOnce(refusalReply('cyber'))
        .mockResolvedValueOnce(reply({ content: [{ type: 'text', text: 'answer' }] }));

      await expect(makeProvider().sendPrompt('classify this')).resolves.toBe('answer');
      expect(sentBody(1).model).toBe('claude-opus-4-8');
    });

    it('throws a refusal error when no model answers', async () => {
      post.mockResolvedValue(refusalReply('cyber'));

      await expect(makeProvider().sendPrompt('classify this')).rejects.toBeInstanceOf(
        ModelRefusalError
      );
    });

    it('throws on a truncated reply', async () => {
      post.mockResolvedValue(reply({ content: [THINKING], stop_reason: 'max_tokens' }));

      await expect(makeProvider().sendPrompt('classify this')).rejects.toBeInstanceOf(
        TruncatedResponseError
      );
    });
  });

  describe('converse', () => {
    it('returns typed blocks plus the verbatim turn, thinking included', async () => {
      const toolUse = {
        type: 'tool_use',
        id: 'toolu_01',
        name: 'examine_url',
        input: { url: 'x' },
      };
      post.mockResolvedValue(reply({ content: [THINKING, toolUse], stop_reason: 'tool_use' }));

      const response = await makeProvider().converse({
        messages: [{ role: 'user', content: 'hello' }],
      });

      expect(response.stopReason).toBe('tool_use');
      expect(response.content).toEqual([toolUse]);
      expect(response.rawContent).toEqual([THINKING, toolUse]);
    });

    it('returns a refusal instead of throwing, and never retries it', async () => {
      post.mockResolvedValue(refusalReply('bio'));

      const response = await makeProvider().converse({
        messages: [{ role: 'user', content: 'hello' }],
      });

      expect(post).toHaveBeenCalledTimes(1);
      expect(response.stopReason).toBe('refusal');
      expect(response.refusalCategory).toBe('bio');
      expect(refusalMetric).toHaveBeenCalledTimes(1);
    });
  });

  describe('health', () => {
    it('reports healthy on any successful reply, even one with no text', async () => {
      post.mockResolvedValue(reply({ content: [THINKING], stop_reason: 'max_tokens' }));
      const provider = makeProvider();

      await expect(provider.isAvailable()).resolves.toBe(true);
      const health = await provider.healthCheck();

      expect(health.available).toBe(true);
      expect(sentBody().max_tokens).toBe(1024);
      expect(sentBody().output_config).toEqual({ effort: 'low' });
    });

    it('reports unavailable without an API key or on a rejected request', async () => {
      await expect(makeProvider({ apiKey: '' }).isAvailable()).resolves.toBe(false);

      post.mockRejectedValue(
        Object.assign(new Error('Request failed with status code 401'), {
          isAxiosError: true,
          response: { status: 401, data: {} },
        })
      );
      const provider = makeProvider();

      await expect(provider.isAvailable()).resolves.toBe(false);
      const health = await provider.healthCheck();
      expect(health.available).toBe(false);
      expect(health.lastError).toContain('Invalid Anthropic API key');
      // Auth failures are not retried
      expect(post).toHaveBeenCalledTimes(2);
    });

    it('fails at once on a 403 without retrying', async () => {
      post.mockRejectedValue(
        Object.assign(new Error('Request failed with status code 403'), {
          isAxiosError: true,
          response: { status: 403, data: {} },
        })
      );

      const failure = makeProvider().analyzeEmail(EMAIL);

      await expect(failure).rejects.toBeInstanceOf(ProviderAuthError);
      await expect(failure).rejects.toThrow('status 403');
      expect(post).toHaveBeenCalledTimes(1);
    });
  });
});

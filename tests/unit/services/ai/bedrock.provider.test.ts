/**
 * Bedrock provider tests — request shape and response handling on every call
 * path, with the Bedrock client mocked (no AWS calls)
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { mockClient } from 'aws-sdk-client-mock';
import {
  BedrockProvider,
  defaultRefusalFallbackModel,
  isBedrockAuthError,
} from '../../../../src/services/ai/bedrock.provider';
import {
  ModelRefusalError,
  ProviderAuthError,
  TruncatedResponseError,
} from '../../../../src/services/ai/model.response';
import * as metrics from '../../../../src/utils/metrics';
import { ExtractedEmailData } from '../../../../src/types';

const bedrockMock = mockClient(BedrockRuntimeClient);

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

function reply(payload: Record<string, unknown>): { body: never } {
  return { body: new TextEncoder().encode(JSON.stringify(payload)) as never };
}

function verdictReply(): { body: never } {
  return reply({
    content: [THINKING, { type: 'text', text: VERDICT }],
    stop_reason: 'end_turn',
    usage: {
      input_tokens: 1500,
      output_tokens: 800,
      output_tokens_details: { thinking_tokens: 350 },
    },
  });
}

function refusalReply(category: string | null): { body: never } {
  return reply({
    content: [],
    stop_reason: 'refusal',
    stop_details: category === null ? null : { category },
    usage: { input_tokens: 1500, output_tokens: 0 },
  });
}

function makeProvider(config: Record<string, unknown> = {}): BedrockProvider {
  return new BedrockProvider({ region: 'us-east-1', ...config }, headers => headers);
}

/** The model ID and decoded JSON body of the nth InvokeModel call */
function sent(call = 0): { modelId: string; body: Record<string, unknown> } {
  const input = bedrockMock.commandCalls(InvokeModelCommand)[call].args[0].input;
  return {
    modelId: input.modelId as string,
    body: JSON.parse(input.body as string) as Record<string, unknown>,
  };
}

describe('BedrockProvider', () => {
  let refusalMetric: jest.SpyInstance;

  beforeEach(() => {
    bedrockMock.reset();
    refusalMetric = jest.spyOn(metrics, 'emitAnalysisRefusalMetric').mockImplementation(() => {});
  });

  describe('defaults and request shape', () => {
    it('defaults to the Opus 5.5 inference profile, 16000 tokens, medium effort', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(verdictReply());
      const provider = makeProvider();

      await provider.analyzeEmail(EMAIL);

      expect(provider.model).toBe('global.anthropic.claude-opus-5-5');
      expect(sent().modelId).toBe('global.anthropic.claude-opus-5-5');
      expect(sent().body.anthropic_version).toBe('bedrock-2023-05-31');
      expect(sent().body.max_tokens).toBe(16000);
      expect(sent().body.output_config).toEqual({ effort: 'medium' });
    });

    it('never sends thinking, sampling parameters, or tool_choice', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(verdictReply());
      const provider = makeProvider();

      await provider.analyzeEmail(EMAIL);
      await provider.sendPrompt('classify this');
      await provider.converse({
        system: 'system prompt',
        messages: [{ role: 'user', content: 'hello' }],
        tools: [{ name: 'examine_url', description: 'd', input_schema: { type: 'object' } }],
      });

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(3);
      for (let call = 0; call < 3; call++) {
        for (const field of ['thinking', 'temperature', 'top_p', 'top_k', 'tool_choice']) {
          expect(sent(call).body).not.toHaveProperty(field);
        }
      }
    });

    it('sends the configured effort on every call path', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(verdictReply());
      const provider = makeProvider({ effort: 'low' });

      await provider.analyzeEmail(EMAIL);
      await provider.sendPrompt('classify this');
      await provider.converse({ messages: [{ role: 'user', content: 'hello' }] });

      for (let call = 0; call < 3; call++) {
        expect(sent(call).body.output_config).toEqual({ effort: 'low' });
      }
    });

    it('omits effort for models that reject it and for unrecognized IDs', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(verdictReply());

      await makeProvider({
        modelId: 'us.anthropic.claude-haiku-4-5-20251001-v1:0',
      }).analyzeEmail(EMAIL);
      await makeProvider({ modelId: 'example-custom-model' }).analyzeEmail(EMAIL);

      expect(sent(0).body).not.toHaveProperty('output_config');
      expect(sent(1).body).not.toHaveProperty('output_config');
    });
  });

  describe('analyzeEmail', () => {
    it('reads the verdict from the text block when a thinking block comes first', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(verdictReply());

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.model).toBe('global.anthropic.claude-opus-5-5');
      expect(result.tokenUsage).toEqual({
        inputTokens: 1500,
        outputTokens: 800,
        totalTokens: 2300,
        thinkingTokens: 350,
      });
    });

    it('retries a refusal once on the fallback model', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolvesOnce(refusalReply('cyber'))
        .resolvesOnce(verdictReply());

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(2);
      expect(sent(1).modelId).toBe('global.anthropic.claude-opus-4-8');
      expect(sent(1).body.messages).toEqual(sent(0).body.messages);
      expect(sent(1).body.output_config).toEqual({ effort: 'medium' });
      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.model).toBe('global.anthropic.claude-opus-4-8');
      expect(refusalMetric).toHaveBeenCalledTimes(1);
      expect(refusalMetric).toHaveBeenCalledWith(
        'bedrock',
        'global.anthropic.claude-opus-5-5',
        'cyber'
      );
    });

    it('returns analysisFailed when the fallback model refuses too', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(refusalReply('cyber'));

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(2);
      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('declined');
      expect(result.assessment).toBeUndefined();
      expect(refusalMetric).toHaveBeenCalledTimes(2);
    });

    it('does not retry a reasoning_extraction refusal', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(refusalReply('reasoning_extraction'));

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
      expect(result.analysisFailed).toBe(true);
    });

    it("keeps the primary model's routing prefix on the default refusal fallback", async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolvesOnce(refusalReply(null))
        .resolvesOnce(verdictReply());

      await makeProvider({ modelId: 'us.anthropic.claude-opus-5-5' }).analyzeEmail(EMAIL);

      expect(sent(0).modelId).toBe('us.anthropic.claude-opus-5-5');
      expect(sent(1).modelId).toBe('us.anthropic.claude-opus-4-8');
      expect(defaultRefusalFallbackModel('global.anthropic.claude-opus-5-5')).toBe(
        'global.anthropic.claude-opus-4-8'
      );
      expect(defaultRefusalFallbackModel('eu.anthropic.claude-opus-5-5')).toBe(
        'eu.anthropic.claude-opus-4-8'
      );
      expect(defaultRefusalFallbackModel('some-custom-model')).toBe(
        'global.anthropic.claude-opus-4-8'
      );
    });

    it('uses a configured refusal fallback model, and none when it is empty', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolvesOnce(refusalReply(null))
        .resolvesOnce(verdictReply());

      const result = await makeProvider({
        refusalFallbackModel: 'us.anthropic.claude-opus-5',
      }).analyzeEmail(EMAIL);
      expect(sent(1).modelId).toBe('us.anthropic.claude-opus-5');
      expect(result.model).toBe('us.anthropic.claude-opus-5');

      bedrockMock.reset();
      bedrockMock.on(InvokeModelCommand).resolves(refusalReply(null));

      const disabled = await makeProvider({ refusalFallbackModel: '' }).analyzeEmail(EMAIL);
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
      expect(disabled.analysisFailed).toBe(true);
    });

    it('fails closed when the reply is truncated at max_tokens', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(
        reply({
          content: [THINKING, { type: 'text', text: '{"summary": "ok", "verdict": "legitimate"' }],
          stop_reason: 'max_tokens',
        })
      );

      const result = await makeProvider().analyzeEmail(EMAIL);

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('max_tokens');
      expect(result.assessment).toBeUndefined();
    });

    it('throws on a Bedrock error body without retrying', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolves(reply({ error: { type: 'invalid_request_error', message: 'bad input' } }));

      await expect(makeProvider().analyzeEmail(EMAIL)).rejects.toThrow('Bedrock error: bad input');
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
    });

    it('does not retry a ValidationException', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .rejects(Object.assign(new Error('rejected'), { name: 'ValidationException' }));

      await expect(makeProvider().analyzeEmail(EMAIL)).rejects.toThrow('rejected');
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
    });

    it.each([
      ['CredentialsProviderError', 'Could not load credentials from any providers', undefined],
      [
        'TokenProviderError',
        'Token is expired. To refresh this SSO session run aws sso login',
        undefined,
      ],
      ['ExpiredTokenException', 'The security token included in the request is expired', 403],
      ['UnrecognizedClientException', 'The security token included in the request is invalid', 403],
      ['AccessDeniedException', 'User is not authorized to perform bedrock:InvokeModel', 403],
      ['Error', 'Token is expired', undefined],
      ['SomeNewAuthException', 'opaque', 401],
    ])('fails at once on a credential error (%s)', async (name, message, httpStatusCode) => {
      bedrockMock.on(InvokeModelCommand).rejects(
        Object.assign(new Error(message), {
          name,
          ...(httpStatusCode ? { $metadata: { httpStatusCode } } : {}),
        })
      );

      const failure = makeProvider().analyzeEmail(EMAIL);

      await expect(failure).rejects.toBeInstanceOf(ProviderAuthError);
      await expect(failure).rejects.toThrow(/AWS credentials or permissions .*not retried/);
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
    });
  });

  describe('isBedrockAuthError', () => {
    const sdkError = (name: string, httpStatusCode?: number, message = 'x'): Error =>
      Object.assign(new Error(message), { name, $metadata: { httpStatusCode } });

    it('leaves throttling, timeouts and server errors retryable', () => {
      for (const error of [
        sdkError('ThrottlingException', 429, 'Too many requests'),
        sdkError('ServiceUnavailableException', 503),
        sdkError('InternalServerException', 500),
        sdkError('ModelTimeoutException', 408),
        sdkError('TimeoutError', undefined, 'socket hang up'),
        new Error('ETIMEDOUT'),
      ]) {
        expect(isBedrockAuthError(error)).toBe(false);
      }
    });

    it('matches authentication and authorization failures', () => {
      expect(isBedrockAuthError(sdkError('ExpiredTokenException', 400))).toBe(true);
      expect(isBedrockAuthError(sdkError('AccessDeniedException', 403))).toBe(true);
      expect(isBedrockAuthError(sdkError('Error', undefined, 'Token is expired'))).toBe(true);
    });
  });

  describe('sendPrompt', () => {
    it('returns text that follows a thinking block', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolves(reply({ content: [THINKING, { type: 'text', text: '{"verdict": "none"}' }] }));

      await expect(makeProvider().sendPrompt('classify this')).resolves.toBe('{"verdict": "none"}');
    });

    it('throws a refusal error when no model answers', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(refusalReply('cyber'));

      await expect(makeProvider().sendPrompt('classify this')).rejects.toBeInstanceOf(
        ModelRefusalError
      );
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(2);
    });

    it('throws on a truncated reply', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolves(reply({ content: [THINKING], stop_reason: 'max_tokens' }));

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
      bedrockMock
        .on(InvokeModelCommand)
        .resolves(reply({ content: [THINKING, toolUse], stop_reason: 'tool_use' }));

      const response = await makeProvider().converse({
        messages: [{ role: 'user', content: 'hello' }],
      });

      expect(response.stopReason).toBe('tool_use');
      expect(response.content).toEqual([toolUse]);
      expect(response.rawContent).toEqual([THINKING, toolUse]);
    });

    it('returns a refusal instead of throwing, and never retries it', async () => {
      bedrockMock.on(InvokeModelCommand).resolves(refusalReply('bio'));

      const response = await makeProvider().converse({
        messages: [{ role: 'user', content: 'hello' }],
      });

      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(1);
      expect(response.stopReason).toBe('refusal');
      expect(response.refusalCategory).toBe('bio');
      expect(refusalMetric).toHaveBeenCalledTimes(1);
    });
  });

  describe('health', () => {
    it('reports healthy on any successful reply, even one with no text', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .resolves(reply({ content: [THINKING], stop_reason: 'max_tokens' }));
      const provider = makeProvider();

      await expect(provider.isAvailable()).resolves.toBe(true);
      const health = await provider.healthCheck();

      expect(health.available).toBe(true);
      expect(sent().body.max_tokens).toBe(1024);
      expect(sent().body.output_config).toEqual({ effort: 'low' });
    });

    it('reports unavailable when the model cannot be invoked', async () => {
      bedrockMock
        .on(InvokeModelCommand)
        .rejects(Object.assign(new Error('no access'), { name: 'AccessDeniedException' }));
      const provider = makeProvider();

      await expect(provider.isAvailable()).resolves.toBe(false);
      const health = await provider.healthCheck();

      expect(health.available).toBe(false);
      expect(health.lastError).toContain('AccessDeniedException');
      expect(health.lastError).toContain('not retried');
      // Denied access fails at once: one call per check, no backoff
      expect(bedrockMock.commandCalls(InvokeModelCommand)).toHaveLength(2);
    });
  });
});

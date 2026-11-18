/**
 * Agentic analyzer tests — the bounded tool-use loop
 */

import { AgenticAnalyzer } from '../../../../src/services/ai/agentic/agentic.analyzer';
import { AgenticToolExecutor } from '../../../../src/services/ai/agentic/tool.executor';
import {
  ConversationRequest,
  ConversationResponse,
} from '../../../../src/services/ai/conversation.types';
import { AIProvider } from '../../../../src/services/ai/provider.interface';
import {
  ModelRefusalError,
  TruncatedResponseError,
} from '../../../../src/services/ai/model.response';
import { ExtractedEmailData } from '../../../../src/types';

const VERDICT_JSON = JSON.stringify({
  summary: 'Known phishing domain confirmed by threat intel.',
  isPhishing: true,
  confidence: 'High',
  indicators: ['bad-domain.test seen in 4 prior reports'],
  recommendations: ['Delete the email'],
});

const EMAIL: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'FW: urgent invoice',
  text: 'Please pay at https://bad-domain.test/pay',
  html: '',
  headers: {},
  forwardedHeaders: {},
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'attacker@bad-domain.test',
  originalForwarder: 'reporter@example.com',
  links: ['https://bad-domain.test/pay'],
};

function makeProvider(turns: ConversationResponse[]): AIProvider & {
  converse: jest.Mock<Promise<ConversationResponse>, [ConversationRequest]>;
} {
  let call = 0;
  const converse = jest.fn((_request: ConversationRequest) => {
    const turn = turns[Math.min(call, turns.length - 1)];
    call++;
    return Promise.resolve(turn);
  });
  return {
    name: 'fake',
    model: 'fake-model',
    converse,
    analyzeEmail: jest.fn(),
    sendPrompt: jest.fn(),
    isAvailable: jest.fn().mockResolvedValue(true),
    healthCheck: jest.fn(),
    setProfile: jest.fn(),
  } as never;
}

function makeAnalyzer(maxToolRounds = 3): {
  analyzer: AgenticAnalyzer;
  executor: AgenticToolExecutor;
} {
  const executor = new AgenticToolExecutor({});
  const analyzer = new AgenticAnalyzer(executor, {
    maxToolRounds,
    essentialHeadersExtractor: headers => headers,
  });
  return { analyzer, executor };
}

describe('AgenticAnalyzer', () => {
  it('executes requested tools and parses the final verdict', async () => {
    const provider = makeProvider([
      {
        content: [
          { type: 'text', text: 'Checking the link first.' },
          {
            type: 'tool_use',
            id: 'tu_1',
            name: 'examine_url',
            input: { url: 'https://bad-domain.test/pay' },
          },
        ],
        stopReason: 'tool_use',
        usage: { inputTokens: 1000, outputTokens: 50, totalTokens: 1050 },
      },
      {
        content: [{ type: 'text', text: VERDICT_JSON }],
        stopReason: 'end_turn',
        usage: { inputTokens: 1200, outputTokens: 150, totalTokens: 1350 },
      },
    ]);
    const { analyzer } = makeAnalyzer();

    const result = await analyzer.analyze(provider, EMAIL);

    expect(result.isPhishing).toBe(true);
    expect(result.confidence).toBe('High');
    expect(result.toolsUsed).toEqual(['examine_url']);
    expect(result.tokenUsage).toEqual({ inputTokens: 2200, outputTokens: 200, totalTokens: 2400 });

    // Second call must carry the assistant turn and the tool result back
    const secondRequest = provider.converse.mock.calls[1][0];
    expect(secondRequest.messages).toHaveLength(3);
    expect(secondRequest.messages[1].role).toBe('assistant');
    const toolResultMsg = secondRequest.messages[2];
    expect(toolResultMsg.role).toBe('user');
    const blocks = toolResultMsg.content as Array<{ type: string; tool_use_id?: string }>;
    expect(blocks[0]).toMatchObject({ type: 'tool_result', tool_use_id: 'tu_1' });
  });

  it('answers directly when the model needs no tools', async () => {
    const provider = makeProvider([
      {
        content: [{ type: 'text', text: VERDICT_JSON }],
        stopReason: 'end_turn',
        usage: { inputTokens: 900, outputTokens: 120, totalTokens: 1020 },
      },
    ]);
    const { analyzer } = makeAnalyzer();

    const result = await analyzer.analyze(provider, EMAIL);

    expect(result.isPhishing).toBe(true);
    expect(result.toolsUsed).toEqual([]);
    expect(provider.converse).toHaveBeenCalledTimes(1);
  });

  it('feeds tool errors back to the model instead of aborting', async () => {
    const provider = makeProvider([
      {
        content: [
          { type: 'tool_use', id: 'tu_1', name: 'lookup_indicators', input: { values: ['x'] } },
        ],
        stopReason: 'tool_use',
      },
      {
        content: [{ type: 'text', text: VERDICT_JSON }],
        stopReason: 'end_turn',
      },
    ]);
    const { analyzer } = makeAnalyzer();

    // No database configured — lookup_indicators is unavailable
    const result = await analyzer.analyze(provider, EMAIL);

    expect(result.isPhishing).toBe(true);
    const secondRequest = provider.converse.mock.calls[1][0];
    const blocks = secondRequest.messages[2].content as Array<{
      type: string;
      is_error?: boolean;
    }>;
    expect(blocks[0]).toMatchObject({ type: 'tool_result', is_error: true });
  });

  it('throws when the tool budget is exhausted without a verdict', async () => {
    const provider = makeProvider([
      {
        content: [
          {
            type: 'tool_use',
            id: 'tu_loop',
            name: 'examine_url',
            input: { url: 'https://x.test' },
          },
        ],
        stopReason: 'tool_use',
      },
    ]);
    const { analyzer } = makeAnalyzer(2);

    await expect(analyzer.analyze(provider, EMAIL)).rejects.toThrow('tool budget');
    // initial + 2 tool rounds = 3 calls
    expect(provider.converse).toHaveBeenCalledTimes(3);
  });

  describe('thinking blocks and conversation history', () => {
    const THINKING_1 = { type: 'thinking', thinking: '', signature: 'sig-round-1' };
    const THINKING_2 = { type: 'thinking', thinking: '', signature: 'sig-round-2' };
    const toolUse = (
      id: string
    ): { type: 'tool_use'; id: string; name: string; input: object } => ({
      type: 'tool_use',
      id,
      name: 'examine_url',
      input: { url: 'https://bad-domain.test/pay' },
    });

    function threeRoundProvider(): ReturnType<typeof makeProvider> {
      return makeProvider([
        {
          content: [toolUse('tu_1')],
          rawContent: [THINKING_1, toolUse('tu_1')],
          stopReason: 'tool_use',
          usage: { inputTokens: 1000, outputTokens: 300, totalTokens: 1300, thinkingTokens: 200 },
        },
        {
          content: [toolUse('tu_2')],
          rawContent: [THINKING_2, toolUse('tu_2')],
          stopReason: 'tool_use',
          usage: { inputTokens: 1400, outputTokens: 250, totalTokens: 1650, thinkingTokens: 150 },
        },
        {
          content: [{ type: 'text', text: VERDICT_JSON }],
          rawContent: [THINKING_2, { type: 'text', text: VERDICT_JSON }],
          stopReason: 'end_turn',
          usage: { inputTokens: 1800, outputTokens: 400, totalTokens: 2200 },
        },
      ] as never);
    }

    it('reads the verdict when a thinking block precedes the text', async () => {
      const provider = makeProvider([
        {
          content: [{ type: 'text', text: VERDICT_JSON }],
          rawContent: [THINKING_1, { type: 'text', text: VERDICT_JSON }],
          stopReason: 'end_turn',
        },
      ] as never);
      const { analyzer } = makeAnalyzer();

      const result = await analyzer.analyze(provider, EMAIL);

      expect(result.isPhishing).toBe(true);
    });

    it('passes each assistant turn back verbatim, thinking blocks included', async () => {
      const provider = threeRoundProvider();
      const { analyzer } = makeAnalyzer();

      await analyzer.analyze(provider, EMAIL);

      const lastRequest = provider.converse.mock.calls[2][0];
      expect(lastRequest.messages[1]).toEqual({
        role: 'assistant',
        content: [THINKING_1, toolUse('tu_1')],
      });
      expect(lastRequest.messages[3]).toEqual({
        role: 'assistant',
        content: [THINKING_2, toolUse('tu_2')],
      });
      // The very same block objects, not copies or filtered views
      expect((lastRequest.messages[1].content as unknown[])[0]).toBe(THINKING_1);
    });

    it('keeps system, tools, and earlier messages identical across rounds (append-only)', async () => {
      const provider = makeProvider([]);
      const snapshots: string[] = [];
      const turns = threeRoundProvider();
      // Snapshot each request as it is sent: the analyzer reuses one messages
      // array, so comparing the recorded call arguments afterwards would not
      // catch an in-place edit.
      provider.converse.mockImplementation(request => {
        snapshots.push(JSON.stringify(request));
        return turns.converse(request);
      });
      const { analyzer } = makeAnalyzer();

      await analyzer.analyze(provider, EMAIL);

      const requests = snapshots.map(s => JSON.parse(s) as ConversationRequest);
      expect(requests).toHaveLength(3);
      for (let round = 1; round < requests.length; round++) {
        const previous = requests[round - 1];
        const current = requests[round];
        expect(current.system).toBe(previous.system);
        expect(JSON.stringify(current.tools)).toBe(JSON.stringify(previous.tools));
        // Two messages appended per round; everything before them is unchanged
        expect(current.messages).toHaveLength(previous.messages.length + 2);
        expect(JSON.stringify(current.messages.slice(0, previous.messages.length))).toBe(
          JSON.stringify(previous.messages)
        );
      }
    });

    it('sums thinking tokens across rounds when the provider reports them', async () => {
      const { analyzer } = makeAnalyzer();

      const result = await analyzer.analyze(threeRoundProvider(), EMAIL);

      expect(result.tokenUsage).toEqual({
        inputTokens: 4200,
        outputTokens: 950,
        totalTokens: 5150,
        thinkingTokens: 350,
      });
    });
  });

  describe('fail-closed stop reasons', () => {
    it('abandons the loop on a refusal mid-conversation', async () => {
      const provider = makeProvider([
        {
          content: [
            { type: 'tool_use', id: 'tu_1', name: 'examine_url', input: { url: 'https://x.test' } },
          ],
          stopReason: 'tool_use',
        },
        { content: [], rawContent: [], stopReason: 'refusal', refusalCategory: 'cyber' },
      ]);
      const { analyzer } = makeAnalyzer();

      const error = await analyzer.analyze(provider, EMAIL).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(ModelRefusalError);
      expect((error as ModelRefusalError).category).toBe('cyber');
      // No further turns after the refusal
      expect(provider.converse).toHaveBeenCalledTimes(2);
    });

    it('does not parse partial text from a refused turn as a verdict', async () => {
      const provider = makeProvider([
        {
          content: [{ type: 'text', text: VERDICT_JSON }],
          stopReason: 'refusal',
          refusalCategory: null,
        },
      ]);
      const { analyzer } = makeAnalyzer();

      await expect(analyzer.analyze(provider, EMAIL)).rejects.toBeInstanceOf(ModelRefusalError);
    });

    it('throws on a turn truncated at max_tokens instead of parsing it', async () => {
      const provider = makeProvider([
        {
          content: [{ type: 'text', text: '{"summary": "Fine", "isPhishing": false' }],
          stopReason: 'max_tokens',
        },
      ]);
      const { analyzer } = makeAnalyzer();

      await expect(analyzer.analyze(provider, EMAIL)).rejects.toBeInstanceOf(
        TruncatedResponseError
      );
    });

    it('throws when the final text carries no recognizable verdict', async () => {
      const provider = makeProvider([
        { content: [{ type: 'text', text: 'I could not decide.' }], stopReason: 'end_turn' },
      ]);
      const { analyzer } = makeAnalyzer();

      await expect(analyzer.analyze(provider, EMAIL)).rejects.toThrow('no usable verdict');
    });
  });

  it('reports support based on the provider conversation capability', () => {
    const provider = makeProvider([]);
    expect(AgenticAnalyzer.supports(provider)).toBe(true);
    expect(AgenticAnalyzer.supports({ ...provider, converse: undefined } as never)).toBe(false);
  });
});

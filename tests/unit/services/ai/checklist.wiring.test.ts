/**
 * Checklist scoring wiring: configuration, the providers and the agentic
 * loop (prompt + attached answers), and the report. HTTP is mocked.
 */

import axios from 'axios';
import { loadConfig } from '../../../../src/config';
import { validateConfig } from '../../../../src/config/schema';
import { AnthropicProvider } from '../../../../src/services/ai/anthropic.provider';
import { AgenticAnalyzer } from '../../../../src/services/ai/agentic/agentic.analyzer';
import { AgenticToolExecutor } from '../../../../src/services/ai/agentic/tool.executor';
import {
  CHECKLIST_VERSION,
  MODEL_ITEMS,
  combineChecklist,
} from '../../../../src/services/ai/checklist';
import { computeCodeChecklistAnswers } from '../../../../src/services/ai/checklist.facts';
import { ConversationRequest } from '../../../../src/services/ai/conversation.types';
import { AIProvider } from '../../../../src/services/ai/provider.interface';
import { fuseRisk } from '../../../../src/services/intelligence/risk.fusion';
import { CHECKLIST_REASONS } from '../../../../src/services/intelligence/checklist.score';
import { buildEmailHtml, buildPlainTextReport } from '../../../../src/templates/report.html';
import { AnalysisResult, ExtractedEmailData } from '../../../../src/types';

/** The model's part of the checklist: a credential ask, nothing else */
const ANSWERS = Object.fromEntries(
  MODEL_ITEMS.map(item => [item.id, item.id === 'asks_for_credentials' ? 'yes' : 'no'])
);

const VERDICT = {
  summary: 'Credential-harvesting lure.',
  verdict: 'phishing',
  riskScore: 90,
  verdictConfidence: 0.9,
  threatVectors: ['credential_harvest'],
  targeting: 'mass',
  indicators: ['Model free-text indicator'],
  recommendations: ['Delete the email'],
  iocs: [],
};

const EMAIL: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'FW: verify your account',
  text: 'Sign in at https://login.example.net/',
  html: '',
  headers: {},
  forwardedHeaders: {},
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'someone@example.net',
  originalForwarder: 'reporter@example.com',
  links: ['https://login.example.net/'],
};

function httpReply(text: string): { data: Record<string, unknown> } {
  return {
    data: {
      content: [{ type: 'text', text }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 1500, output_tokens: 800 },
    },
  };
}

describe('scoring configuration', () => {
  const SAVED = ['PHISHY_SCORING_MODE', 'PHISHY_AI_PROVIDER', 'SENDER_EMAIL', 'PHISHY_CONFIG_S3'];
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of SAVED) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.SENDER_EMAIL = 'phishy@example.com';
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
  });

  afterEach(() => {
    for (const name of SAVED) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  });

  it('is absent by default, which means model scoring', async () => {
    const config = await loadConfig();
    expect(config.scoring).toBeUndefined();
  });

  it('maps PHISHY_SCORING_MODE to scoring.mode', async () => {
    process.env.PHISHY_SCORING_MODE = 'checklist';
    expect((await loadConfig()).scoring).toEqual({ mode: 'checklist' });
  });

  it('rejects an unknown mode', async () => {
    process.env.PHISHY_SCORING_MODE = 'vibes';
    // The loader logs the validation error
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    await expect(loadConfig()).rejects.toThrow('Invalid configuration');
  });

  it("defaults an empty scoring block to 'model'", () => {
    const config = validateConfig({
      ai: { provider: 'bedrock', bedrock: { region: 'us-east-1' } },
      email: { safeDomains: ['example.com'] },
      notification: { senderEmail: 'phishy@example.com' },
      storage: { s3Bucket: 'bucket', region: 'us-east-1' },
      scoring: {},
    });
    expect(config.scoring).toEqual({ mode: 'model' });
  });
});

describe('AnthropicProvider scoring mode', () => {
  let post: jest.SpyInstance;

  beforeEach(() => {
    post = jest.spyOn(axios, 'post');
  });

  function sentPrompt(): string {
    const body = post.mock.calls[0][1] as { messages: Array<{ content: string }> };
    return body.messages[0].content;
  }

  it('in model mode sends no checklist and attaches nothing, even if the reply has one', async () => {
    post.mockResolvedValue(httpReply(JSON.stringify({ ...VERDICT, checklist: ANSWERS })));
    const provider = new AnthropicProvider({ apiKey: 'k' }, h => h);
    const result = await provider.analyzeEmail(EMAIL);
    expect(sentPrompt()).not.toContain('SCORING CHECKLIST');
    expect(result.checklist).toBeUndefined();
  });

  it('in checklist mode asks for the checklist and attaches the validated answers', async () => {
    post.mockResolvedValue(httpReply(JSON.stringify({ ...VERDICT, checklist: ANSWERS })));
    const provider = new AnthropicProvider({ apiKey: 'k', scoringMode: 'checklist' }, h => h);
    const result = await provider.analyzeEmail(EMAIL);
    expect(sentPrompt()).toContain('SCORING CHECKLIST');
    expect(result.checklist).toEqual(
      combineChecklist(ANSWERS as never, computeCodeChecklistAnswers(EMAIL))
    );
    expect(result.checklist?.status === 'ok' && result.checklist.sources.risky_attachment).toBe(
      'code'
    );
    expect(result.assessment?.riskScore).toBe(90);
  });

  it('in checklist mode ignores a model answer for a code item', async () => {
    post.mockResolvedValue(
      httpReply(
        JSON.stringify({ ...VERDICT, checklist: { ...ANSWERS, link_text_mismatch: 'yes' } })
      )
    );
    const provider = new AnthropicProvider({ apiKey: 'k', scoringMode: 'checklist' }, h => h);
    const result = await provider.analyzeEmail(EMAIL);
    // EMAIL has no HTML body, so Phishy cannot tell: unknown, whatever the model said
    expect(result.checklist?.status === 'ok' && result.checklist.answers.link_text_mismatch).toBe(
      'unknown'
    );
  });

  it('in checklist mode never fails the analysis over a missing checklist', async () => {
    post.mockResolvedValue(httpReply(JSON.stringify(VERDICT)));
    const provider = new AnthropicProvider({ apiKey: 'k', scoringMode: 'checklist' }, h => h);
    const result = await provider.analyzeEmail(EMAIL);
    expect(result.analysisFailed).toBeUndefined();
    expect(result.checklist).toEqual({ version: CHECKLIST_VERSION, status: 'missing' });
  });
});

describe('AgenticAnalyzer scoring mode', () => {
  function provider(): AIProvider & { converse: jest.Mock } {
    return {
      name: 'fake',
      model: 'fake-model',
      converse: jest.fn((_request: ConversationRequest) =>
        Promise.resolve({
          content: [{ type: 'text', text: JSON.stringify({ ...VERDICT, checklist: ANSWERS }) }],
          stopReason: 'end_turn',
        })
      ),
      analyzeEmail: jest.fn(),
      sendPrompt: jest.fn(),
      isAvailable: jest.fn(),
      healthCheck: jest.fn(),
      setProfile: jest.fn(),
    } as never;
  }

  it.each([
    ['model', false],
    ['checklist', true],
  ] as const)('in %s mode', async (scoringMode, expectChecklist) => {
    const fake = provider();
    const analyzer = new AgenticAnalyzer(new AgenticToolExecutor({}), {
      essentialHeadersExtractor: h => h,
      scoringMode,
    });
    const result = await analyzer.analyze(fake, EMAIL);
    const request = fake.converse.mock.calls[0][0] as ConversationRequest;
    expect(String(request.messages[0].content).includes('SCORING CHECKLIST')).toBe(expectChecklist);
    expect(result.checklist?.status).toBe(expectChecklist ? 'ok' : undefined);
  });
});

describe('report in checklist mode', () => {
  const analysis: AnalysisResult = {
    summary: 'Credential-harvesting lure.',
    isPhishing: true,
    confidence: 'High',
    indicators: ['Model free-text indicator'],
    recommendations: [],
    assessment: {
      verdict: 'phishing',
      riskScore: 90,
      verdictConfidence: 0.9,
      threatVectors: [],
      targeting: 'mass',
    },
    checklist: combineChecklist(ANSWERS as never, computeCodeChecklistAnswers(EMAIL)),
  };

  function render(decision: ReturnType<typeof fuseRisk>): string {
    const risk = {
      verdict: decision.verdict,
      riskScore: decision.riskScore,
      riskLevel: decision.riskLevel,
      reasons: decision.reasons,
      ...(decision.checklistReasons ? { checklistReasons: decision.checklistReasons } : {}),
    };
    return `${buildPlainTextReport(analysis, EMAIL, { risk })}\n${buildEmailHtml(analysis, EMAIL, { risk })}`;
  }

  it('shows the code-written checklist reasons in place of the model indicators', () => {
    const text = render(fuseRisk(analysis, {}, { scoringMode: 'checklist' }));
    expect(text).toContain(CHECKLIST_REASONS.asks_for_credentials);
    expect(text).not.toContain('Model free-text indicator');
    expect(text).toContain('Why we flagged it');
  });

  it('shows the model indicators as before in model mode', () => {
    const text = render(fuseRisk(analysis));
    expect(text).toContain('Model free-text indicator');
    expect(text).not.toContain(CHECKLIST_REASONS.asks_for_credentials);
  });
});

/**
 * Configuration loader tests — built-in defaults and environment mappings
 * for the AI settings. No S3 config is loaded (PHISHY_CONFIG_S3 is unset).
 */

import { loadConfig } from '../../../src/config';

const AI_ENV_VARS = [
  'PHISHY_CONFIG_S3',
  'PHISHY_AI_PROVIDER',
  'ANTHROPIC_API_KEY',
  'CLAUDE_MODEL',
  'PHISHY_BEDROCK_MODEL',
  'PHISHY_AI_EFFORT',
  'PHISHY_AI_REFUSAL_FALLBACK_MODEL',
  'SENDER_EMAIL',
];

describe('loadConfig — AI settings', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of AI_ENV_VARS) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.SENDER_EMAIL = 'phishy@example.com';
  });

  afterEach(() => {
    for (const name of AI_ENV_VARS) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    }
  });

  it('defaults Bedrock to Opus 5.5, 16000 tokens, and medium effort', async () => {
    process.env.PHISHY_AI_PROVIDER = 'bedrock';

    const config = await loadConfig();

    expect(config.ai.bedrock?.modelId).toBe('global.anthropic.claude-opus-5-5');
    expect(config.ai.bedrock?.maxTokens).toBe(16000);
    expect(config.ai.bedrock?.timeout).toBe(60000);
    expect(config.ai.effort).toBe('medium');
    expect(config.ai.refusalFallbackModel).toBeUndefined();
  });

  it('defaults Anthropic to Opus 5.5 when only an API key is supplied', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';

    const config = await loadConfig();

    expect(config.ai.provider).toBe('anthropic');
    expect(config.ai.anthropic?.model).toBe('claude-opus-5-5');
    expect(config.ai.anthropic?.maxTokens).toBe(16000);
  });

  it('maps PHISHY_AI_EFFORT to ai.effort', async () => {
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.PHISHY_AI_EFFORT = 'low';

    const config = await loadConfig();

    expect(config.ai.effort).toBe('low');
  });

  it('rejects an unknown PHISHY_AI_EFFORT value', async () => {
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.PHISHY_AI_EFFORT = 'extreme';

    await expect(loadConfig()).rejects.toThrow('Invalid configuration');
  });

  it('maps PHISHY_AI_REFUSAL_FALLBACK_MODEL to ai.refusalFallbackModel', async () => {
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.PHISHY_AI_REFUSAL_FALLBACK_MODEL = 'us.anthropic.claude-opus-5';

    const config = await loadConfig();

    expect(config.ai.refusalFallbackModel).toBe('us.anthropic.claude-opus-5');
  });

  it('keeps an empty PHISHY_AI_REFUSAL_FALLBACK_MODEL, which disables the retry', async () => {
    process.env.PHISHY_AI_PROVIDER = 'bedrock';
    process.env.PHISHY_AI_REFUSAL_FALLBACK_MODEL = '';

    const config = await loadConfig();

    expect(config.ai.refusalFallbackModel).toBe('');
  });
});

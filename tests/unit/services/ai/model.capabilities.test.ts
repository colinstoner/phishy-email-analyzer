/**
 * Model capability table tests — which models get an effort field, and which value
 */

import { effortForModel, modelFamilyKey } from '../../../../src/services/ai/model.capabilities';

describe('modelFamilyKey', () => {
  it('reads family and version from bare, dated, and Bedrock IDs', () => {
    expect(modelFamilyKey('claude-opus-5-5')).toBe('opus-5-5');
    expect(modelFamilyKey('global.anthropic.claude-opus-5-5')).toBe('opus-5-5');
    expect(modelFamilyKey('us.anthropic.claude-opus-5')).toBe('opus-5');
    expect(modelFamilyKey('global.anthropic.claude-opus-4-6-v1')).toBe('opus-4-6');
    expect(modelFamilyKey('us.anthropic.claude-haiku-4-5-20251001-v1:0')).toBe('haiku-4-5');
  });

  it('does not read a date suffix as a minor version', () => {
    expect(modelFamilyKey('us.anthropic.claude-sonnet-4-20250514-v1:0')).toBe('sonnet-4');
  });

  it('returns undefined for IDs it does not recognize', () => {
    expect(modelFamilyKey('claude-3-5-sonnet-20241022')).toBeUndefined();
    expect(modelFamilyKey('some-other-model')).toBeUndefined();
    expect(modelFamilyKey('')).toBeUndefined();
  });
});

describe('effortForModel', () => {
  it('passes the requested level to models that support the full ladder', () => {
    for (const model of [
      'claude-opus-5-5',
      'global.anthropic.claude-opus-5-5',
      'claude-opus-5',
      'claude-opus-4-8',
      'global.anthropic.claude-opus-4-8',
      'claude-sonnet-5-5',
      'claude-sonnet-5',
      'claude-haiku-5-5',
      'claude-fable-5-2',
      'claude-fable-5-1',
      'claude-fable-5',
    ]) {
      expect(effortForModel(model, 'medium')).toBe('medium');
      expect(effortForModel(model, 'xhigh')).toBe('xhigh');
      expect(effortForModel(model, 'max')).toBe('max');
    }
  });

  it('keeps opus-5 and opus-5-5 distinct entries (no prefix shadowing)', () => {
    expect(modelFamilyKey('claude-opus-5-5')).not.toBe(modelFamilyKey('claude-opus-5'));
    expect(effortForModel('claude-opus-5', 'low')).toBe('low');
  });

  it('steps down to the highest supported level on older models', () => {
    // Opus 4.6 and Sonnet 4.6 predate xhigh
    expect(effortForModel('global.anthropic.claude-opus-4-6-v1', 'xhigh')).toBe('high');
    expect(effortForModel('claude-sonnet-4-6', 'xhigh')).toBe('high');
    expect(effortForModel('claude-sonnet-4-6', 'max')).toBe('max');
    // Opus 4.5 predates xhigh and max
    expect(effortForModel('claude-opus-4-5', 'max')).toBe('high');
    expect(effortForModel('claude-opus-4-5', 'low')).toBe('low');
  });

  it('omits effort for models that reject the parameter', () => {
    expect(effortForModel('claude-sonnet-4-5', 'medium')).toBeUndefined();
    expect(effortForModel('us.anthropic.claude-sonnet-4-5-20250929-v1:0', 'low')).toBeUndefined();
    expect(effortForModel('claude-haiku-4-5', 'medium')).toBeUndefined();
    expect(effortForModel('us.anthropic.claude-haiku-4-5-20251001-v1:0', 'high')).toBeUndefined();
    expect(effortForModel('us.anthropic.claude-sonnet-4-20250514-v1:0', 'medium')).toBeUndefined();
  });

  it('omits effort for unrecognized model IDs rather than guessing', () => {
    expect(effortForModel('claude-opus-9', 'medium')).toBeUndefined();
    expect(effortForModel('claude-3-5-sonnet-20241022', 'medium')).toBeUndefined();
    expect(effortForModel('example-custom-model', 'medium')).toBeUndefined();
  });
});

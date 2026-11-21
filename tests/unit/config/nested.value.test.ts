/**
 * setNestedValue: the dot-path writer behind environment overrides. A path
 * segment that names the prototype chain must be refused, never written.
 */

import { setNestedValue } from '../../../src/config';

describe('setNestedValue', () => {
  afterEach(() => {
    // Belt and braces: a failing test must not leave pollution behind
    delete (Object.prototype as Record<string, unknown>).polluted;
  });

  it('creates intermediate objects and sets the leaf', () => {
    const target: Record<string, unknown> = { ai: { provider: 'anthropic' } };
    setNestedValue(target, 'ai.bedrock.region', 'us-east-1');
    setNestedValue(target, 'senderEmail', 'phishy@example.com');
    expect(target).toEqual({
      ai: { provider: 'anthropic', bedrock: { region: 'us-east-1' } },
      senderEmail: 'phishy@example.com',
    });
  });

  it.each([
    '__proto__.polluted',
    'constructor.prototype.polluted',
    'a.__proto__.polluted',
    'a.prototype',
  ])('refuses the path %s and pollutes nothing', path => {
    const target: Record<string, unknown> = {};
    expect(() => setNestedValue(target, path, 'yes')).toThrow(/reserved segment/);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false);
  });

  it('does not follow an inherited property as if it were config', () => {
    const target: Record<string, unknown> = {};
    // "toString" is inherited, not an own key: it is replaced by a fresh object
    setNestedValue(target, 'toString.value', 1);
    expect(target).toEqual({ toString: { value: 1 } });
    expect(typeof Object.prototype.toString).toBe('function');
  });
});

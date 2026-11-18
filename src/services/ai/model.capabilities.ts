/**
 * Model capabilities
 * Pure, table-driven facts about which request parameters a Claude model
 * accepts. Keyed on the model ID so one table covers the bare Anthropic ID,
 * dated IDs, and Bedrock inference-profile IDs (global./us./eu. prefixes,
 * -v1:0 suffixes).
 *
 * Source: the effort tables in Anthropic's model migration guide
 * (platform.claude.com/docs), verified 2026-11.
 */

export const EFFORT_LEVELS = ['low', 'medium', 'high', 'xhigh', 'max'] as const;
export type EffortLevel = (typeof EFFORT_LEVELS)[number];

const ALL_LEVELS: readonly EffortLevel[] = EFFORT_LEVELS;
/** Models that predate `xhigh` */
const NO_XHIGH: readonly EffortLevel[] = ['low', 'medium', 'high', 'max'];
/** Models that predate both `xhigh` and `max` */
const UP_TO_HIGH: readonly EffortLevel[] = ['low', 'medium', 'high'];

/**
 * Effort levels each model accepts in `output_config.effort`. A model that is
 * absent here gets NO effort field: Sonnet 4.5, Haiku 4.5 and older models
 * reject the parameter, and an unrecognized ID is never guessed at.
 */
const EFFORT_SUPPORT: Record<string, readonly EffortLevel[]> = {
  'opus-5-5': ALL_LEVELS,
  'opus-5': ALL_LEVELS,
  'opus-4-8': ALL_LEVELS,
  'opus-4-7': ALL_LEVELS,
  'opus-4-6': NO_XHIGH,
  'opus-4-5': UP_TO_HIGH,
  'sonnet-5-5': ALL_LEVELS,
  'sonnet-5': ALL_LEVELS,
  'sonnet-4-6': NO_XHIGH,
  'haiku-5-5': ALL_LEVELS,
  'fable-5-2': ALL_LEVELS,
  'fable-5-1': ALL_LEVELS,
  'fable-5': ALL_LEVELS,
};

/**
 * Family and version from a model ID, e.g. `opus-5-5` from
 * `global.anthropic.claude-opus-5-5`. The version parts are one or two digits,
 * so an eight-digit date suffix (`claude-sonnet-4-20250514`) is never read as
 * a minor version. Returns an exact table key, so `opus-5` can't shadow
 * `opus-5-5` the way substring matching would.
 */
export function modelFamilyKey(model: string): string | undefined {
  const match = /claude-(opus|sonnet|haiku|fable)-(\d{1,2})(?:-(\d{1,2}))?(?!\d)/.exec(model);
  if (!match) {
    return undefined;
  }
  const [, family, major, minor] = match;
  return minor === undefined ? `${family}-${major}` : `${family}-${major}-${minor}`;
}

/**
 * The effort value to send to a model, or undefined to omit the field.
 *
 * - Unrecognized model, or one that rejects `effort`: undefined.
 * - Requested level unsupported by the model (`xhigh` on Opus 4.6): the
 *   highest supported level below it, so the request is never rejected.
 */
export function effortForModel(model: string, requested: EffortLevel): EffortLevel | undefined {
  const key = modelFamilyKey(model);
  const supported = key ? EFFORT_SUPPORT[key] : undefined;
  if (!supported) {
    return undefined;
  }
  for (let i = EFFORT_LEVELS.indexOf(requested); i >= 0; i--) {
    if (supported.includes(EFFORT_LEVELS[i])) {
      return EFFORT_LEVELS[i];
    }
  }
  return undefined;
}

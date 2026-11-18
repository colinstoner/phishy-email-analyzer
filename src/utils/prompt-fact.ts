/**
 * Prompt facts: reduce a value that originated in the suspicious email to
 * something that can sit OUTSIDE the nonce fence without forging structure.
 *
 * The analysis prompt is organized by provenance, and its structure is made
 * of lines: `=== VERIFIED ... ===` and `--- SECTION ---` headers, and fence
 * tags such as `<email-content-{nonce}>`. Anything copied from the email into
 * a VERIFIED, OPERATOR or REPORTED section (an attachment name, a header
 * value, a URL, an anchor text) is attacker-chosen and must not be able to
 * start a line of its own, reproduce a section header or fence tag, or run to
 * unbounded length. `toPromptFact` enforces that:
 *
 *  1. NFKC, so compatibility forms (full-width `＝`, `＜`) become the
 *     characters they imitate and are caught below.
 *  2. Format characters (zero-width, bidi controls, BOM, soft hyphen) are
 *     removed; control characters and every line or paragraph separator —
 *     CR, LF, NEL, VT, FF, U+2028, U+2029 — become a space. One line results.
 *  3. Prompt markers are neutralized: runs of `=` collapse to one, runs of
 *     three or more dash-like characters collapse to one `-`, and `<` before
 *     a fence name becomes `‹`. This runs over the WHOLE value before any
 *     truncation, so padding around a marker cannot carry it past the check.
 *  4. Length is bounded head+tail (the end of a padded value stays visible),
 *     and the cut is stated in place.
 *
 * Every step is reported, so the caller can disclose that a field was
 * altered — a filename with a line break in it is itself an indicator.
 *
 * Pure computation, no I/O.
 */

/** Names of the nonce-fenced blocks the prompt builder emits */
export const FENCE_NAMES = ['claimed-fields', 'original-headers', 'email-content'] as const;

export interface PromptFact {
  /** Single-line, marker-free, bounded text, safe to place outside a fence */
  text: string;
  /** Line breaks, control or format characters were removed */
  hadLineBreaksOrControls: boolean;
  /** Text resembling the prompt's own section or fence markers was altered */
  hadMarkers: boolean;
  /** Characters cut from the middle to respect the bound (0 when none) */
  elided: number;
}

/** Control characters and Unicode line/paragraph separators: anything that can start a line */
const LINE_BREAKS_AND_CONTROLS = /[\p{Cc}\p{Zl}\p{Zp}]/gu;
/** Format characters: zero-width, bidi embeddings/overrides/isolates, BOM, soft hyphen */
const FORMAT_CHARS = /\p{Cf}/gu;
/** `==`, `═══`: the prompt's `=== LABEL ===` provenance headers */
const EQUALS_RUN = /[=═⚌]{2,}/g;
/** `---`, `———`, `───`: the prompt's `--- SECTION ---` headers */
const DASH_RUN = /[-‐-―−─━╴╶╸╺﹘﹣]{3,}/g;
/** `<email-content-…`, `</ original-headers-…`: a fence tag, opening or closing */
const FENCE_TAG = new RegExp(`<(\\s*/?\\s*)(?=(?:${FENCE_NAMES.join('|')}))`, 'gi');

/** In a multi-line note: separators other than CR/LF that start a line become LF */
// eslint-disable-next-line no-control-regex
const NOTE_LINE_BREAKS = /[\u2028\u2029\u0085\u000b\u000c]/g;
/** In a multi-line note: every other control character is dropped (TAB, LF and CR are kept) */
// eslint-disable-next-line no-control-regex
const NOTE_CONTROLS = /[\u0000-\u0008\u000e-\u001f\u007f-\u0084\u0086-\u009f]/g;

/**
 * Neutralize the prompt's own structural markers in text that may span
 * several lines (the employee's note). Line breaks are kept; markers are not.
 */
export function neutralizePromptMarkers(text: string): { text: string; changed: boolean } {
  const out = text
    .normalize('NFKC')
    .replace(FORMAT_CHARS, '')
    .replace(NOTE_LINE_BREAKS, '\n')
    .replace(NOTE_CONTROLS, '')
    .replace(EQUALS_RUN, '=')
    .replace(DASH_RUN, '-')
    .replace(FENCE_TAG, '‹$1');
  return { text: out, changed: out !== text };
}

/**
 * Reduce an email-derived value to a single bounded line that cannot forge
 * prompt structure. `maxLength` bounds the result (excluding the in-place
 * elision note); values longer than that keep their head and tail.
 */
export function toPromptFact(
  value: string | number | null | undefined,
  maxLength: number
): PromptFact {
  const raw = value === undefined || value === null ? '' : String(value);

  const normalized = raw.normalize('NFKC');
  const withoutFormat = normalized.replace(FORMAT_CHARS, '');
  const singleLine = withoutFormat.replace(LINE_BREAKS_AND_CONTROLS, ' ');
  const hadLineBreaksOrControls = singleLine !== normalized;

  const collapsed = singleLine.replace(/\s+/g, ' ').trim();
  const neutralized = collapsed
    .replace(EQUALS_RUN, '=')
    .replace(DASH_RUN, '-')
    .replace(FENCE_TAG, '‹$1');
  const hadMarkers = neutralized !== collapsed;

  const bound = Math.max(16, Math.floor(maxLength));
  if (neutralized.length <= bound) {
    return { text: neutralized, hadLineBreaksOrControls, hadMarkers, elided: 0 };
  }

  const tailLength = Math.floor(bound / 3);
  const headLength = bound - tailLength;
  const elided = neutralized.length - headLength - tailLength;
  // The note is placed between head and tail with spaces on both sides, so
  // the cut cannot join two halves of a marker into a whole one.
  const text = `${neutralized.slice(0, headLength)} [... ${elided} characters elided ...] ${neutralized.slice(neutralized.length - tailLength)}`;
  return { text, hadLineBreaksOrControls, hadMarkers, elided };
}

/** Convenience: just the safe text */
export function promptFactText(
  value: string | number | null | undefined,
  maxLength: number
): string {
  return toPromptFact(value, maxLength).text;
}

/**
 * Small building blocks for scanning hostile text in linear time, used where
 * a backtracking regex would run in quadratic (or worse) time on crafted
 * input: a suspicious email that makes analysis time out is an evasion.
 */

/** True when `word` (lower-case ASCII) is at `pos`, ASCII case-insensitively */
export function asciiWordAt(text: string, pos: number, word: string): boolean {
  if (pos < 0 || pos + word.length > text.length) return false;
  for (let i = 0; i < word.length; i++) {
    const code = text.charCodeAt(pos + i);
    const isUpper = code >= 65 && code <= 90;
    if ((isUpper ? code + 32 : code) !== word.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * Successive results of a forward search, cached: when the next query
 * starts at or after the previous one and no later than the previous result,
 * the answer is unchanged. Queries that only move forward therefore scan
 * each character at most once in total.
 */
export function forwardFinder(search: (from: number) => number): (from: number) => number {
  let lastFrom = -1;
  let lastResult = -1;
  return from => {
    if (lastFrom !== -1 && from >= lastFrom && (lastResult === -1 || from <= lastResult)) {
      return lastResult;
    }
    lastFrom = from;
    lastResult = search(from);
    return lastResult;
  };
}

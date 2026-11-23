/**
 * `Retry-After` parsing, shared by the read client and the write tier's
 * client. A leaf module (no imports), so the write broker's bundle does not
 * include the read path's `GraphClient`.
 */

/**
 * Parse a `Retry-After` header (delta-seconds or an HTTP date) into
 * milliseconds from now
 */
export function parseRetryAfter(
  header: string | null,
  nowMs: number = Date.now()
): number | undefined {
  if (!header) {
    return undefined;
  }
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10) * 1000;
  }
  // Date.parse is lenient ("-5" is a year); accept only the HTTP-date shape
  const dateMs = /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} /.test(trimmed) ? Date.parse(trimmed) : NaN;
  if (Number.isNaN(dateMs)) {
    return undefined;
  }
  return Math.max(0, dateMs - nowMs);
}

/**
 * The receiving mail system's authentication verdict for an original
 * message, read from the Authentication-Results header at the top of the
 * delivered copy that the optional original-message lookup retrieved.
 *
 * Why only the topmost header, and why only there. Mail servers prepend
 * trace headers, so the first Authentication-Results in stored order is
 * normally the one the organization's own mail system added on delivery;
 * every header below it was written by the sender or servers the sender
 * chose and can be forged. A forwarded or pasted header block is the
 * sender's text throughout and is never read here, nor are SES verdicts on
 * the report itself (they are about the reporter's mail, not the original).
 *
 * The direction is safe even when the top header is not the organization's
 * (a mail system that adds none): a forged `fail` only raises risk, and a
 * forged `pass` counts for nothing, because a pass is never evidence of
 * legitimacy (attackers pass from their own and from compromised domains).
 *
 * Pure string work on hostile data: the value is bounded, matched with
 * fixed patterns and only a closed verdict comes out.
 */

import { RetrievedOriginal } from '../types';

/** Longest header value examined; a longer one is read only up to here */
const MAX_AUTH_RESULTS = 4000;

export type AuthenticationVerdict = 'fail' | 'pass' | 'unknown';

/** The result keyword of one method (`dmarc=fail`), lower-cased, or undefined */
function methodResult(value: string, method: string): string | undefined {
  return new RegExp(`(?:^|[\\s;])${method}\\s*=\\s*([a-z]+)`, 'i').exec(value)?.[1]?.toLowerCase();
}

/**
 * The verdict of one Authentication-Results value:
 *  - `fail`: DMARC failed, or Microsoft's composite authentication failed,
 *    or (no DMARC result at all) SPF failed and no DKIM signature passed;
 *  - `pass`: DMARC passed (and nothing above failed);
 *  - `unknown`: anything else (none, temperror, softfail alone, no result).
 */
export function authenticationVerdictOf(value: string): AuthenticationVerdict {
  const text = value.slice(0, MAX_AUTH_RESULTS);
  const dmarc = methodResult(text, 'dmarc');
  const compauth = methodResult(text, 'compauth');
  const spf = methodResult(text, 'spf');
  // A message can carry several DKIM signatures; any one passing counts
  const dkimPassed = /(?:^|[\s;])dkim\s*=\s*pass\b/i.test(text);
  if (dmarc === 'fail' || compauth === 'fail') return 'fail';
  if (dmarc === undefined && spf === 'fail' && !dkimPassed) return 'fail';
  if (dmarc === 'pass') return 'pass';
  return 'unknown';
}

/** The verdict of the topmost Authentication-Results of a retrieved original */
export function retrievedAuthenticationVerdict(
  retrieved: RetrievedOriginal | undefined
): AuthenticationVerdict {
  const top = retrieved?.headers.find(h => h.name.toLowerCase() === 'authentication-results');
  return top ? authenticationVerdictOf(top.value) : 'unknown';
}

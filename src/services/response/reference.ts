/**
 * Unguessable references for incidents and response actions.
 *
 * A reference is what a security-team member quotes to approve an action,
 * so it must not be guessable from anything an attacker can see: 80 random
 * bits, written as `PHY-XXXX-XXXX-XXXX-XXXX` in RFC 4648 base32 (letters
 * A-Z and digits 2-7, so no 0/O or 1/I confusion when typed).
 */

import { randomBytes } from 'crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Matches one reference anywhere in a line (case-insensitive) */
export const REFERENCE_PATTERN = /\bPHY(?:-[A-Z2-7]{4}){4}\b/i;

/** Matches a whole reference and nothing else */
const EXACT_REFERENCE = /^PHY(?:-[A-Z2-7]{4}){4}$/;

export function generateReference(random: (size: number) => Buffer = randomBytes): string {
  const bytes = random(10); // 80 bits → 16 base32 characters
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `PHY-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}`;
}

/** The canonical (upper-case) form of a reference, or undefined if it is not one */
export function normalizeReference(value: string): string | undefined {
  const upper = value.trim().toUpperCase();
  return EXACT_REFERENCE.test(upper) ? upper : undefined;
}

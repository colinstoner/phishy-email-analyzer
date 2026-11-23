/**
 * Subject normalization shared by the read side (sender history, the
 * fan-out scan, blast radius) and the mailbox write tier.
 *
 * No imports but `crypto`: the write broker loads this file, and it must
 * stay free of anything that can build a Graph read client.
 */

import { createHash } from 'crypto';

/**
 * A subject as a grouping key: trimmed, case-folded, whitespace collapsed.
 * It is hostile text and is used for nothing else — it stays in memory for
 * the length of one computation and is never logged, returned or shown.
 */
export function subjectGroupKey(subject: string | undefined): string {
  return (subject ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
}

/**
 * SHA-256 (hex) of `subjectGroupKey(subject)`. How a subject is compared
 * where the text itself must not travel: a live removal sends this to the
 * write broker, which hashes the stored message's subject the same way.
 */
export function subjectKeyHash(subject: string | undefined): string {
  return createHash('sha256').update(subjectGroupKey(subject), 'utf8').digest('hex');
}

/** The shape of a `subjectKeyHash` */
export const SUBJECT_HASH_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The blast-radius answer at its worst case still fits the size cap the main
 * function enforces before parsing it: otherwise a sender could inflate it
 * (long Message-IDs, long From addresses, multi-byte addresses) until blast
 * radius is unavailable and no warning scope exists. Every field is at the
 * largest value the schema accepts, for the 100 recipients the broker lists.
 */

import {
  BlastRadiusLookupResultSchema,
  GRAPH_BROKER_MAX_RESPONSE_BYTES,
} from '../../../../src/services/graph/broker.protocol';
import {
  MAX_COPY_MESSAGE_ID_LENGTH,
  MAX_COPY_SENDER_LENGTH,
  MAX_LISTED_RECIPIENTS,
  MAX_REPORTED_COPY_IDS,
  MAX_SUBJECT_LENGTH,
} from '../../../../src/services/graph/graph.limits';

const fill = (char: string, length: number): string => char.repeat(length);
/** A Message-ID of exactly `length` characters */
const messageId = (length: number): string => `<${fill('a', length - 14)}@example.com>`;
/** A 4-byte UTF-8 character: the most bytes one address character can take */
const WIDE = '\u{1F600}';
/** The longest datetime the schema takes (40 characters) */
const ISO = `2026-11-17T09:14:00.${'1'.repeat(19)}Z`;

function worstRecipient(n: number): Record<string, unknown> {
  return {
    address: fill(WIDE, 320),
    deliveryStatus: `D${fill('x', 39)}`,
    mailbox: 'not_delivered',
    folder: 'recoverable',
    isRead: false,
    response: 'forwarded',
    lastVerbCode: -Number.MAX_SAFE_INTEGER,
    copies: 100_000_000,
    mailboxId: `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`,
    messageIds: Array.from({ length: MAX_REPORTED_COPY_IDS }, (_, i) => `${i}${fill('A', 511)}`),
    copyDetails: Array.from({ length: MAX_REPORTED_COPY_IDS }, (_, i) => ({
      messageId: `${i}${fill('A', 511)}`,
      internetMessageId: messageId(MAX_COPY_MESSAGE_ID_LENGTH),
      senderAddress: `${fill('b', MAX_COPY_SENDER_LENGTH - 12)}@example.com`,
      subjectHash: fill('f', 64),
      receivedAt: ISO,
      size: 150 * 1024 * 1024,
    })),
    receivedAt: fill('9', 40),
  };
}

describe('the blast-radius answer size', () => {
  it('fits the cap at the worst case the schema allows', () => {
    const answer = {
      ok: true,
      result: {
        report: {
          status: 'partial',
          note: fill('\u0001', 600),
          route: 'mailbox',
          matchedBy: 'senderSubject',
          criteria: {
            senderAddress: fill('\u0001', 254),
            subject: fill('\u0001', MAX_SUBJECT_LENGTH),
            receivedFrom: fill('9', 40),
            receivedTo: fill('9', 40),
          },
          totals: {
            recipients: 100_000_000,
            read: 100_000_000,
            replied: 100_000_000,
            forwarded: 100_000_000,
            notDelivered: 100_000_000,
          },
          recipients: Array.from({ length: MAX_LISTED_RECIPIENTS }, (_, n) => worstRecipient(n)),
          coverage: {
            mailboxesChecked: 100_000_000,
            mailboxesEligible: 100_000_000,
            eligibleIsLowerBound: true,
            recoverableChecked: 100_000_000,
            recoverableCandidates: 100_000_000,
            detailUnavailable: 100_000_000,
          },
          // Control characters escape to six bytes each in JSON
          caveats: Array.from({ length: 30 }, () => fill('\u0001', 600)),
          lookedUpAt: fill('9', 40),
        },
        errors: 100_000_000,
        cached: true,
      },
    };
    // It is a valid answer: the schema accepts every field at this size
    const parsed = BlastRadiusLookupResultSchema.safeParse(answer.result);
    expect(parsed.success ? [] : parsed.error.issues.slice(0, 3)).toEqual([]);
    const bytes = Buffer.byteLength(JSON.stringify(answer), 'utf8');
    const cap = GRAPH_BROKER_MAX_RESPONSE_BYTES.blast_radius_lookup;
    expect(bytes).toBeLessThan(cap);
    // ...with a margin of at least a fifth of the cap
    expect(cap - bytes).toBeGreaterThan(cap / 5);
  });

  it('refuses a copy detail longer than its bound rather than truncating it', () => {
    const base = worstRecipient(1) as { copyDetails: Array<Record<string, unknown>> };
    const longId = {
      ...base,
      copyDetails: [{ ...base.copyDetails[0], internetMessageId: messageId(161) }],
    };
    const longSender = {
      ...base,
      copyDetails: [{ ...base.copyDetails[0], senderAddress: `${fill('b', 117)}@example.com` }],
    };
    const wideSender = {
      ...base,
      copyDetails: [{ ...base.copyDetails[0], senderAddress: `${WIDE}@example.com` }],
    };
    for (const recipient of [longId, longSender, wideSender]) {
      expect(
        BlastRadiusLookupResultSchema.safeParse({
          report: {
            status: 'complete',
            lookedUpAt: '2026-11-17T10:00:00.000Z',
            recipients: [recipient],
          },
          errors: 0,
          cached: false,
        }).success
      ).toBe(false);
    }
  });
});

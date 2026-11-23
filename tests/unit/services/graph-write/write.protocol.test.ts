/**
 * The write broker's wire format: one operation, strict at every level,
 * bounded lists, and reconciliation of an answer against the request it
 * answers. Invented data only.
 */

import {
  GraphWriteRequestSchema,
  GraphWriteResponseSchema,
  RemoveMessagesResultSchema,
  reconcileRemovalResult,
} from '../../../../src/services/graph-write/write.protocol';
import { ACTION_ID, IMID, MAILBOX_ID, expectation } from '../../../mocks/graph.write.fake';

const mailbox = (n: number, ids = ['AAMkAG-1']) => ({
  mailboxId: MAILBOX_ID(n),
  messages: ids.map(id => expectation(id, IMID(1))),
});
/** One mailbox whose single message has `extra` merged into its expectation */
const withMessage = (extra: Record<string, unknown>) => ({
  mailboxId: MAILBOX_ID(1),
  messages: [{ ...expectation('AAMkAG-1', IMID(1)), ...extra }],
});

const request = (params: Record<string, unknown> = {}) => ({
  version: 2,
  operation: 'remove_messages',
  params: { actionId: ACTION_ID, mailboxes: [mailbox(1)], budgetMs: 30_000, ...params },
});

describe('GraphWriteRequestSchema', () => {
  it('accepts the one operation', () => {
    expect(GraphWriteRequestSchema.safeParse(request()).success).toBe(true);
  });

  it.each([
    ['another version', { ...request(), version: 1 }],
    ['another operation', { ...request(), operation: 'delete_messages' }],
    ['a read operation', { ...request(), operation: 'blast_radius_lookup' }],
    ['an unknown top-level field', { ...request(), path: '/users' }],
    ['an unknown params field', request({ destinationId: 'inbox' })],
    ['an unknown mailbox field', request({ mailboxes: [{ ...mailbox(1), folder: 'inbox' }] })],
    [
      'an address for a mailbox',
      request({ mailboxes: [{ ...mailbox(1), mailboxId: 'a@example.com' }] }),
    ],
    ['a path in a message ID', request({ mailboxes: [mailbox(1, ['../../me'])] })],
    ['a URL in a message ID', request({ mailboxes: [mailbox(1, ['https://example.com/x'])] })],
    [
      'the version 1 shape',
      request({
        mailboxes: [
          { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
        ],
      }),
    ],
    [
      'a message without its expected Message-ID',
      request({ mailboxes: [withMessage({ expectedInternetMessageId: undefined })] }),
    ],
    [
      'a malformed expected Message-ID',
      request({ mailboxes: [withMessage({ expectedInternetMessageId: 'not an id' })] }),
    ],
    [
      'a subject in place of its hash',
      request({ mailboxes: [withMessage({ expectedSubjectSha256: 'Invoice 2291 overdue' })] }),
    ],
    ['a subject field', request({ mailboxes: [withMessage({ subject: 'Invoice 2291 overdue' })] })],
    [
      'an upper-case sender',
      request({ mailboxes: [withMessage({ expectedSenderAddress: 'Billing@Example.test' })] }),
    ],
    [
      'a display name for a sender',
      request({ mailboxes: [withMessage({ expectedSenderAddress: 'Accounts <a@example.test>' })] }),
    ],
    [
      'an inverted window',
      request({
        mailboxes: [
          withMessage({ receivedFrom: '2026-11-17T15:00:00Z', receivedTo: '2026-11-17T03:00:00Z' }),
        ],
      }),
    ],
    [
      'a window wider than twelve hours',
      request({
        mailboxes: [
          withMessage({ receivedFrom: '2026-11-16T23:00:00Z', receivedTo: '2026-11-17T11:00:01Z' }),
        ],
      }),
    ],
    [
      'a mailbox with no messages',
      request({ mailboxes: [{ mailboxId: MAILBOX_ID(1), messages: [] }] }),
    ],
    ['no mailboxes', request({ mailboxes: [] })],
    [
      'too many mailboxes',
      request({ mailboxes: Array.from({ length: 51 }, (_, i) => mailbox(i + 1)) }),
    ],
    [
      'too many messages in a mailbox',
      request({ mailboxes: [mailbox(1, ['a', 'b', 'c', 'd', 'e', 'f'])] }),
    ],
    [
      'too many messages in a call',
      request({
        mailboxes: Array.from({ length: 21 }, (_, i) => mailbox(i + 1, ['a', 'b', 'c', 'd', 'e'])),
      }),
    ],
    [
      'a mailbox named twice',
      request({
        mailboxes: [mailbox(1), { ...mailbox(1), mailboxId: MAILBOX_ID(1).toUpperCase() }],
      }),
    ],
    ['a message named twice', request({ mailboxes: [mailbox(1, ['a', 'a'])] })],
    ['a budget over the bound', request({ budgetMs: 80_001 })],
    ['a budget under the bound', request({ budgetMs: 999 })],
    ['a non-UUID action ID', request({ actionId: 'PHY-AAAA-BBBB-CCCC-DDDD' })],
    ['an API Gateway event', { httpMethod: 'POST', body: JSON.stringify(request()) }],
    ['nothing', undefined],
  ])('refuses %s', (_label, event) => {
    expect(GraphWriteRequestSchema.safeParse(event).success).toBe(false);
  });
});

describe('the response', () => {
  const result = {
    mailboxes: [
      { mailboxId: MAILBOX_ID(1), messages: [{ messageId: 'AAMkAG-1', outcome: 'moved' }] },
    ],
    bounds: {
      maxMailboxes: 50,
      maxMessagesPerMailbox: 5,
      maxMessages: 100,
      budgetMs: 30000,
      concurrency: 4,
    },
    durationMs: 12,
  };

  it('accepts a well-formed result and refusal', () => {
    expect(RemoveMessagesResultSchema.safeParse(result).success).toBe(true);
    expect(
      GraphWriteResponseSchema.safeParse({ ok: false, reason: 'write_disabled' }).success
    ).toBe(true);
  });

  it.each([
    [
      'free text in a reason',
      {
        ...result,
        mailboxes: [
          {
            mailboxId: MAILBOX_ID(1),
            messages: [{ messageId: 'a', outcome: 'error', reason: 'Access denied for alice' }],
          },
        ],
      },
    ],
    [
      'an unknown outcome',
      {
        ...result,
        mailboxes: [
          { mailboxId: MAILBOX_ID(1), messages: [{ messageId: 'a', outcome: 'deleted' }] },
        ],
      },
    ],
    ['an extra field', { ...result, subject: 'Invoice' }],
  ])('refuses %s', (_label, body) => {
    expect(RemoveMessagesResultSchema.safeParse(body).success).toBe(false);
  });

  it('refuses a refusal word it does not know', () => {
    expect(GraphWriteResponseSchema.safeParse({ ok: false, reason: 'nope' }).success).toBe(false);
  });
});

describe('reconcileRemovalResult', () => {
  it('keeps only what was asked, once each, and marks what is missing unknown', () => {
    const asked = {
      mailboxes: [mailbox(1, ['a', 'b']), mailbox(2, ['c'])],
    };
    const reconciled = reconcileRemovalResult(asked, {
      mailboxes: [
        {
          mailboxId: MAILBOX_ID(1).toUpperCase(),
          messages: [
            { messageId: 'a', outcome: 'moved' },
            { messageId: 'a', outcome: 'error', reason: 'move_failed' },
            { messageId: 'zzz', outcome: 'moved' },
          ],
        },
        { mailboxId: MAILBOX_ID(77), messages: [{ messageId: 'c', outcome: 'moved' }] },
      ],
    });
    expect(reconciled).toEqual([
      {
        mailboxId: MAILBOX_ID(1),
        messages: [
          { messageId: 'a', outcome: 'moved' },
          { messageId: 'b', outcome: 'unknown' },
        ],
      },
      { mailboxId: MAILBOX_ID(2), messages: [{ messageId: 'c', outcome: 'unknown' }] },
    ]);
  });
});

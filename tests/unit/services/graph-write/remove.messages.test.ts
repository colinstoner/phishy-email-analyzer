/**
 * The mailbox write tier's operation and its constrained client, against a
 * fake tenant that records every request. Every test ends by asserting the
 * client made only the three allowed request shapes. Invented data only;
 * no network.
 */

import { removeMessages } from '../../../../src/services/graph-write/remove.messages';
import { GraphWriteClient } from '../../../../src/services/graph-write/write.client';
import type { RemoveMessagesParams } from '../../../../src/services/graph-write/write.protocol';
import {
  ACTION_ID,
  ALLOWED_SHAPES,
  FakeWriteTenant,
  IMID,
  MAILBOX_ID,
  fakeTokenProvider,
  json,
} from '../../../mocks/graph.write.fake';

interface Harness {
  tenant: FakeWriteTenant;
  client: GraphWriteClient;
  tokens: ReturnType<typeof fakeTokenProvider>;
  clock: { now: number };
  sleeps: number[];
}

function harness(options: { maxAttempts?: number } = {}): Harness {
  const tenant = new FakeWriteTenant();
  const tokens = fakeTokenProvider();
  const clock = { now: 1_000_000 };
  const sleeps: number[] = [];
  const client = new GraphWriteClient({
    tokenProvider: tokens,
    fetchImpl: tenant.fetch as typeof fetch,
    now: () => clock.now,
    sleep: async ms => {
      sleeps.push(ms);
      clock.now += ms;
    },
    ...(options.maxAttempts ? { maxAttempts: options.maxAttempts } : {}),
  });
  return { tenant, client, tokens, clock, sleeps };
}

function params(
  mailboxes: RemoveMessagesParams['mailboxes'],
  budgetMs = 30_000
): RemoveMessagesParams {
  return { actionId: ACTION_ID, mailboxes, budgetMs };
}

function run(h: Harness, p: RemoveMessagesParams, allowed?: string[]) {
  return removeMessages(h.client, p, {
    now: () => h.clock.now,
    ...(allowed ? { allowedMailboxIds: new Set(allowed.map(id => id.toLowerCase())) } : {}),
  });
}

/** Every request made was one of the three allowed shapes, and nothing else */
function expectOnlyAllowedRequests(h: Harness): void {
  expect(h.tenant.unexpected).toEqual([]);
  for (const shape of h.tenant.shapes()) {
    expect(ALLOWED_SHAPES).toContain(shape);
  }
  for (const request of h.tenant.requests) {
    expect(request.authorization).toMatch(/^Bearer write-token-\d+$/);
    if (request.method === 'POST') {
      expect(request.body).toEqual({ destinationId: 'deleteditems' });
    } else {
      expect(request.body).toBeUndefined();
    }
  }
}

const outcomesOf = (result: Awaited<ReturnType<typeof removeMessages>>) =>
  result.mailboxes.map(m => m.messages.map(x => [x.messageId, x.outcome, x.reason]));

describe('remove_messages', () => {
  it('moves a matching copy to Deleted Items after re-reading it', async () => {
    const h = harness();
    const box = h.tenant.addMailbox(MAILBOX_ID(1), {
      'AAMkAG-1': { internetMessageId: IMID(1), folderId: 'inbox-folder' },
    });
    const result = await run(
      h,
      params([
        {
          mailboxId: MAILBOX_ID(1),
          messageIds: ['AAMkAG-1'],
          expectedInternetMessageIds: [IMID(1)],
        },
      ])
    );
    expect(outcomesOf(result)).toEqual([[['AAMkAG-1', 'moved', undefined]]]);
    expect(box.messages.has('AAMkAG-1')).toBe(false);
    expect([...box.messages.values()][0].folderId).toBe(box.deletedItemsId);
    expect(h.tenant.shapes()).toEqual([
      'GET /users/{}/mailFolders/deleteditems?$select=id',
      'GET /users/{}/messages/{}?$select=internetMessageId,parentFolderId',
      'POST /users/{}/messages/{}/move',
    ]);
    expect(result.stoppedBy).toBeUndefined();
    expect(result.bounds).toMatchObject({
      maxMailboxes: 50,
      maxMessagesPerMailbox: 5,
      maxMessages: 100,
      concurrency: 4,
    });
    expectOnlyAllowedRequests(h);
  });

  it('compares Internet Message-IDs exactly, angle brackets aside', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      a: { internetMessageId: 'campaign-1@mail.example.com', folderId: 'inbox' },
      b: { internetMessageId: '<CAMPAIGN-1@mail.example.com>', folderId: 'inbox' },
    });
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a', 'b'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['a', 'moved', undefined],
        ['b', 'mismatch', undefined],
      ],
    ]);
    expectOnlyAllowedRequests(h);
  });

  it('never moves a message whose Internet Message-ID does not match (or is missing)', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      other: { internetMessageId: '<legit-newsletter@news.example.com>', folderId: 'inbox' },
      none: { folderId: 'inbox' },
    });
    const result = await run(
      h,
      params([
        {
          mailboxId: MAILBOX_ID(1),
          messageIds: ['other', 'none'],
          expectedInternetMessageIds: [IMID(1)],
        },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['other', 'mismatch', undefined],
        ['none', 'mismatch', undefined],
      ],
    ]);
    expect(h.tenant.requests.filter(r => r.method === 'POST')).toEqual([]);
    expectOnlyAllowedRequests(h);
  });

  it('leaves a copy already in Deleted Items where it is, and reports a missing one as not found', async () => {
    const h = harness();
    const box = h.tenant.addMailbox(MAILBOX_ID(1));
    box.messages.set('deleted', { internetMessageId: IMID(1), folderId: box.deletedItemsId });
    const result = await run(
      h,
      params([
        {
          mailboxId: MAILBOX_ID(1),
          messageIds: ['deleted', 'gone'],
          expectedInternetMessageIds: [IMID(1)],
        },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['deleted', 'already_deleted', undefined],
        ['gone', 'not_found', undefined],
      ],
    ]);
    expect(h.tenant.requests.filter(r => r.method === 'POST')).toEqual([]);
    expectOnlyAllowedRequests(h);
  });

  it('reports an unknown mailbox as an error without touching anything', async () => {
    const h = harness();
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(9), messageIds: ['x', 'y'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['x', 'error', 'mailbox_not_found'],
        ['y', 'error', 'mailbox_not_found'],
      ],
    ]);
    expect(h.tenant.shapes()).toEqual(['GET /users/{}/mailFolders/deleteditems?$select=id']);
    expectOnlyAllowedRequests(h);
  });

  it('refuses mailboxes outside the allowlist before any request', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h.tenant.addMailbox(MAILBOX_ID(2), { b: { internetMessageId: IMID(1), folderId: 'inbox' } });
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
        { mailboxId: MAILBOX_ID(2), messageIds: ['b'], expectedInternetMessageIds: [IMID(1)] },
      ]),
      [MAILBOX_ID(2).toUpperCase()]
    );
    expect(outcomesOf(result)).toEqual([
      [['a', 'not_allowed', undefined]],
      [['b', 'moved', undefined]],
    ]);
    expect(h.tenant.requests.every(r => r.path.includes(MAILBOX_ID(2)))).toBe(true);
    expectOnlyAllowedRequests(h);
  });

  it('waits out a 429 with Retry-After inside the budget, on a read and on a move', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h.tenant.once(
      r => r.method === 'GET' && r.shape.includes('messages'),
      () => json(429, { error: { code: 'TooManyRequests' } }, { 'retry-after': '2' })
    );
    h.tenant.once(
      r => r.method === 'POST',
      () => json(429, { error: { code: 'TooManyRequests' } }, { 'retry-after': '1' })
    );
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([[['a', 'moved', undefined]]]);
    expect(h.sleeps).toEqual([2000, 1000]);
    expect(h.tenant.requests.filter(r => r.method === 'POST')).toHaveLength(2);
    expectOnlyAllowedRequests(h);
  });

  it('retries a 503 on a read but never repeats a move after a 503 (its effect is unknown)', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      a: { internetMessageId: IMID(1), folderId: 'inbox' },
      b: { internetMessageId: IMID(1), folderId: 'inbox' },
    });
    h.tenant.once(
      r => r.method === 'GET' && r.path.endsWith('/a'),
      () => json(503, {}, { 'retry-after': '1' })
    );
    h.tenant.once(
      r => r.method === 'POST' && r.path.includes('/a/'),
      () => json(503, {})
    );
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a', 'b'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['a', 'error', 'move_unconfirmed'],
        ['b', 'moved', undefined],
      ],
    ]);
    expect(
      h.tenant.requests.filter(r => r.method === 'POST' && r.path.includes('/a/'))
    ).toHaveLength(1);
    expectOnlyAllowedRequests(h);
  });

  it('stops on throttling it cannot wait out and reports the rest as not attempted', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      a: { internetMessageId: IMID(1), folderId: 'inbox' },
      b: { internetMessageId: IMID(1), folderId: 'inbox' },
    });
    h.tenant.once(
      r => r.method === 'GET' && r.path.endsWith('/a'),
      () => json(429, {}, { 'retry-after': '120' })
    );
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a', 'b'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['a', 'not_attempted', 'throttled'],
        ['b', 'not_attempted', 'throttled'],
      ],
    ]);
    expect(result.stoppedBy).toBe('throttled');
    expect(h.tenant.requests.filter(r => r.method === 'POST')).toEqual([]);
    expectOnlyAllowedRequests(h);
  });

  it('reports everything left as not attempted when the time budget runs out', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      a: { internetMessageId: IMID(1), folderId: 'inbox' },
      b: { internetMessageId: IMID(1), folderId: 'inbox' },
    });
    // Each request takes 1.5 s of a 4 s budget (0.5 s reserved for the answer)
    const slow = h.tenant.fetch;
    (h.client as unknown as { fetchImpl: typeof fetch }).fetchImpl = (async (input, init) => {
      h.clock.now += 1500;
      return slow(input as string, init);
    }) as typeof fetch;
    const result = await run(
      h,
      params(
        [
          {
            mailboxId: MAILBOX_ID(1),
            messageIds: ['a', 'b'],
            expectedInternetMessageIds: [IMID(1)],
          },
        ],
        4000
      )
    );
    expect(outcomesOf(result)).toEqual([
      [
        ['a', 'moved', undefined],
        ['b', 'not_attempted', 'time_budget'],
      ],
    ]);
    expect(result.stoppedBy).toBe('time_budget');
    expectOnlyAllowedRequests(h);
  });

  it('gets a fresh token once after a 401, and stops on authentication failure', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h.tenant.once(
      r => r.shape.includes('mailFolders'),
      () => json(401, {})
    );
    const ok = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(ok)).toEqual([[['a', 'moved', undefined]]]);
    expect(h.tokens.invalidate).toHaveBeenCalledTimes(1);

    const h2 = harness();
    h2.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h2.tenant.addMailbox(MAILBOX_ID(2), { b: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h2.tokens.getToken.mockRejectedValue(new Error('no credential'));
    const failed = await run(
      h2,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
        { mailboxId: MAILBOX_ID(2), messageIds: ['b'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(failed.stoppedBy).toBe('auth_failed');
    expect(failed.mailboxes.flatMap(m => m.messages.map(x => x.outcome))).toEqual([
      'not_attempted',
      'not_attempted',
    ]);
    expect(h2.tenant.requests).toEqual([]);
  });

  it('reports a 403 as an error with a fixed word, never Graph text', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    h.tenant.once(
      r => r.method === 'POST',
      () => json(403, { error: { code: 'ErrorAccessDenied', message: 'MAILBOX-CONTENT-MARKER' } })
    );
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(outcomesOf(result)).toEqual([[['a', 'error', 'forbidden']]]);
    expect(JSON.stringify(result)).not.toContain('MARKER');
    expectOnlyAllowedRequests(h);
  });

  it('never reads the moved message the move answers with', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), { a: { internetMessageId: IMID(1), folderId: 'inbox' } });
    const result = await run(
      h,
      params([
        { mailboxId: MAILBOX_ID(1), messageIds: ['a'], expectedInternetMessageIds: [IMID(1)] },
      ])
    );
    expect(JSON.stringify(result)).not.toContain('BODY-CONTENT-MARKER');
    expectOnlyAllowedRequests(h);
  });

  it('works on several mailboxes at a time, each mailbox one request at a time', async () => {
    const h = harness();
    const mailboxes = Array.from({ length: 10 }, (_, i) => {
      h.tenant.addMailbox(MAILBOX_ID(i + 1), {
        m1: { internetMessageId: IMID(1), folderId: 'inbox' },
        m2: { internetMessageId: IMID(1), folderId: 'inbox' },
      });
      return {
        mailboxId: MAILBOX_ID(i + 1),
        messageIds: ['m1', 'm2'],
        expectedInternetMessageIds: [IMID(1)],
      };
    });
    let inFlight = 0;
    let peak = 0;
    const base = h.tenant.fetch;
    (h.client as unknown as { fetchImpl: typeof fetch }).fetchImpl = (async (input, init) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise(resolve => setImmediate(resolve));
      inFlight -= 1;
      return base(input as string, init);
    }) as typeof fetch;
    const result = await run(h, params(mailboxes));
    expect(result.mailboxes.flatMap(m => m.messages.map(x => x.outcome))).toEqual(
      Array(20).fill('moved')
    );
    expect(peak).toBeLessThanOrEqual(4);
    expect(result.mailboxes.map(m => m.mailboxId)).toEqual(mailboxes.map(m => m.mailboxId));
    expectOnlyAllowedRequests(h);
  });

  it('encodes every ID as a single path segment', async () => {
    const h = harness();
    h.tenant.addMailbox(MAILBOX_ID(1), {
      'AAMk/+=_-': { internetMessageId: IMID(1), folderId: 'inbox' },
    });
    const result = await run(
      h,
      params([
        {
          mailboxId: MAILBOX_ID(1),
          messageIds: ['AAMk/+=_-'],
          expectedInternetMessageIds: [IMID(1)],
        },
      ])
    );
    expect(outcomesOf(result)).toEqual([[['AAMk/+=_-', 'moved', undefined]]]);
    expectOnlyAllowedRequests(h);
  });
});

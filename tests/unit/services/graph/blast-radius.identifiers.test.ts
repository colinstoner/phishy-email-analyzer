/**
 * Blast radius carries, per recipient, the identifiers a campaign-response
 * action may name: the mailbox's directory ID and the Graph IDs of the
 * matching copies (shape-checked, capped), plus when the copy arrived. The
 * broker's wire format accepts exactly those shapes. Invented data only.
 */

import { BlastRadiusService } from '../../../../src/services/graph';
import { BlastRadiusLookupResultSchema } from '../../../../src/services/graph/broker.protocol';
import { subjectKeyHash } from '../../../../src/services/graph/subject.key';
import { ExtractedEmailData } from '../../../../src/types';
import {
  FakeResponder,
  RecordedRequest,
  collection,
  fakeGraph,
  graphErrorResponse,
  jsonResponse,
} from '../../../mocks/graph.fake';

const NOW = new Date('2026-11-17T12:00:00Z');
const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';

const email: ExtractedEmailData = {
  from_email: 'alice@example.com',
  subject: 'FW: Invoice 7731 overdue',
  text: 'body',
  html: '',
  headers: {},
  forwardedHeaders: {
    'Original-From': 'Billing <billing@example.org>',
    'Original-Subject': 'Invoice 7731 overdue',
    'Original-Date': 'Mon, 16 Nov 2026 08:00:00 +0000',
  },
  attachments: [],
  sender: 'alice@example.com',
  to: 'phishy@example.com',
  original_sender: 'alice@example.com',
  originalForwarder: 'alice@example.com',
  links: [],
};

function user(id: string, name: string): Record<string, unknown> {
  return {
    id,
    userPrincipalName: `${name}@example.com`,
    mail: `${name}@example.com`,
    userType: 'Member',
    accountEnabled: true,
    assignedPlans: [{ service: 'exchange', capabilityStatus: 'Enabled' }],
  };
}

function msg(id: string): Record<string, unknown> {
  return {
    id,
    internetMessageId: '<m1@mail.example.org>',
    subject: 'Invoice 7731 overdue',
    from: { emailAddress: { address: 'billing@example.org' } },
    receivedDateTime: '2026-11-16T08:03:00Z',
    parentFolderId: 'folder-inbox',
    isRead: false,
  };
}

const MAILBOXES: Record<string, Record<string, unknown>[]> = {
  [ALICE]: [msg('AAMkAGI2-alice-1='), msg('AAMkAGI2-alice-2='), msg('bad id with spaces')],
  [BOB]: Array.from({ length: 5 }, (_, i) => msg(`AAMkAGI2-bob-${i}`)),
};

const responder: FakeResponder = (request: RecordedRequest) => {
  const path = decodeURIComponent(request.path);
  if (path === '/admin/exchange/tracing/messageTraces') {
    return graphErrorResponse(403, 'Forbidden');
  }
  if (path === '/users') {
    return collection([user(ALICE, 'alice'), user(BOB, 'bob'), user('not-a-guid', 'carol')]);
  }
  const match = path.match(/^\/users\/([^/]+)\/(.+)$/);
  if (!match) {
    return undefined;
  }
  const [, id, rest] = match;
  if (rest === 'messages') {
    return collection(id === 'not-a-guid' ? [msg('AAMkAGI2-carol')] : (MAILBOXES[id] ?? []));
  }
  if (rest === 'mailFolders/recoverableitemsdeletions/messages') {
    return collection([]);
  }
  const folder = rest.match(/^mailFolders\/(inbox|junkemail|deleteditems)$/);
  if (folder) {
    return jsonResponse({ id: `folder-${folder[1].replace('email', '').replace('items', '')}` });
  }
  if (rest.startsWith('messages/')) {
    return jsonResponse({ id: rest.slice('messages/'.length) });
  }
  return undefined;
};

describe('blast radius identifiers for campaign response', () => {
  it('records the mailbox ID and the exact copy IDs, shape-checked and capped', async () => {
    const graph = fakeGraph([responder]);
    const service = new BlastRadiusService({
      client: graph.client,
      now: (): number => NOW.getTime(),
      concurrency: 1,
    });
    const report = await service.lookup(email);
    const byAddress = new Map((report.recipients ?? []).map(r => [r.address, r]));

    expect(byAddress.get('alice@example.com')).toMatchObject({
      mailboxId: ALICE,
      messageIds: ['AAMkAGI2-alice-1=', 'AAMkAGI2-alice-2='],
      receivedAt: '2026-11-16T08:03:00.000Z',
      // Per copy, in the same order: what a live removal's eligibility reads
      copyDetails: [
        {
          messageId: 'AAMkAGI2-alice-1=',
          internetMessageId: '<m1@mail.example.org>',
          senderAddress: 'billing@example.org',
          subjectHash: subjectKeyHash('Invoice 7731 overdue'),
          receivedAt: '2026-11-16T08:03:00.000Z',
        },
        {
          messageId: 'AAMkAGI2-alice-2=',
          internetMessageId: '<m1@mail.example.org>',
          senderAddress: 'billing@example.org',
          subjectHash: subjectKeyHash('Invoice 7731 overdue'),
          receivedAt: '2026-11-16T08:03:00.000Z',
        },
      ],
    });
    // The subject itself is never kept per copy
    expect(JSON.stringify(byAddress.get('alice@example.com')?.copyDetails)).not.toContain(
      'Invoice'
    );
    expect(byAddress.get('bob@example.com')?.messageIds).toHaveLength(5);
    expect(byAddress.get('bob@example.com')?.copyDetails).toHaveLength(5);
    expect(byAddress.get('carol@example.com')?.copyDetails).toBeUndefined();
    // A directory ID that is not a GUID is never carried as a mailbox to act on
    expect(byAddress.get('carol@example.com')?.mailboxId).toBeUndefined();
    expect(byAddress.get('carol@example.com')?.messageIds).toBeUndefined();
    expect(graph.requests.every(request => request.method === 'GET')).toBe(true);

    // The broker's wire format accepts the report as the lookup produced it
    expect(
      BlastRadiusLookupResultSchema.safeParse({ report, errors: 0, cached: false }).success
    ).toBe(true);
  });

  it('does not record message-trace sizes (nothing uses them)', async () => {
    const traced: FakeResponder = (request: RecordedRequest) => {
      if (decodeURIComponent(request.path) === '/admin/exchange/tracing/messageTraces') {
        return collection([
          {
            recipientAddress: 'alice@example.com',
            senderAddress: 'billing@example.org',
            status: 'Delivered',
            messageId: '<m1@mail.example.org>',
            size: 20480,
          },
          {
            recipientAddress: 'bob@example.com',
            senderAddress: 'billing@example.org',
            status: 'Delivered',
            messageId: 'm1@mail.example.org',
            size: 20480,
          },
        ]);
      }
      return responder(request);
    };
    const graph = fakeGraph([traced]);
    const service = new BlastRadiusService({
      client: graph.client,
      now: (): number => NOW.getTime(),
      concurrency: 1,
    });
    const report = await service.lookup(email);
    const byAddress = new Map((report.recipients ?? []).map(r => [r.address, r]));
    for (const address of ['alice@example.com', 'bob@example.com']) {
      const details = byAddress.get(address)?.copyDetails ?? [];
      expect(details.length).toBeGreaterThan(0);
      expect(JSON.stringify(details)).not.toContain('size');
    }
  });

  it("accepts an older read broker's per-copy size during a deploy, and drops it", () => {
    const parsed = BlastRadiusLookupResultSchema.safeParse({
      report: {
        status: 'complete',
        lookedUpAt: '2026-11-17T12:00:00.000Z',
        recipients: [
          {
            address: 'a@example.com',
            mailbox: 'found',
            mailboxId: ALICE,
            messageIds: ['AAMk='],
            copyDetails: [
              { messageId: 'AAMk=', internetMessageId: '<m1@mail.example.org>', size: 20480 },
            ],
          },
        ],
      },
      errors: 0,
      cached: false,
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.report.recipients?.[0].copyDetails).toEqual([
      { messageId: 'AAMk=', internetMessageId: '<m1@mail.example.org>' },
    ]);
  });

  it('omits a copy detail value over its bound instead of truncating it', async () => {
    const long: FakeResponder = (request: RecordedRequest) => {
      const path = decodeURIComponent(request.path);
      if (path === `/users/${ALICE}/messages`) {
        return collection([
          {
            ...msg('AAMkAGI2-alice-1='),
            internetMessageId: `<${'a'.repeat(170)}@mail.example.org>`,
            from: { emailAddress: { address: `${'b'.repeat(120)}@example.org` } },
          },
        ]);
      }
      return responder(request);
    };
    const graph = fakeGraph([long]);
    const service = new BlastRadiusService({
      client: graph.client,
      now: (): number => NOW.getTime(),
      concurrency: 1,
    });
    const report = await service.lookup(email);
    const alice = (report.recipients ?? []).find(r => r.address === 'alice@example.com');
    expect(alice?.copyDetails?.[0]).toEqual({
      messageId: 'AAMkAGI2-alice-1=',
      subjectHash: subjectKeyHash('Invoice 7731 overdue'),
      receivedAt: '2026-11-16T08:03:00.000Z',
    });
    // Still a valid answer for the broker's wire format
    expect(
      BlastRadiusLookupResultSchema.safeParse({ report, errors: 0, cached: false }).success
    ).toBe(true);
  });

  it('refuses malformed identifiers from the broker', () => {
    const base = {
      status: 'complete',
      lookedUpAt: '2026-11-17T12:00:00.000Z',
      recipients: [{ address: 'a@example.com', mailbox: 'found' }],
    };
    const withRecipient = (extra: Record<string, unknown>) => ({
      report: { ...base, recipients: [{ ...base.recipients[0], ...extra }] },
      errors: 0,
      cached: false,
    });
    expect(
      BlastRadiusLookupResultSchema.safeParse(
        withRecipient({ mailboxId: ALICE, messageIds: ['AAMk='] })
      ).success
    ).toBe(true);
    expect(
      BlastRadiusLookupResultSchema.safeParse(withRecipient({ mailboxId: 'users/x' })).success
    ).toBe(false);
    expect(
      BlastRadiusLookupResultSchema.safeParse(withRecipient({ messageIds: ['a b'] })).success
    ).toBe(false);
    expect(
      BlastRadiusLookupResultSchema.safeParse(
        withRecipient({ messageIds: Array.from({ length: 6 }, (_, i) => `id${i}`) })
      ).success
    ).toBe(false);
    expect(
      BlastRadiusLookupResultSchema.safeParse(
        withRecipient({
          copyDetails: [
            {
              messageId: 'AAMk=',
              internetMessageId: '<m1@mail.example.org>',
              senderAddress: 'billing@example.org',
              subjectHash: subjectKeyHash('x'),
              receivedAt: '2026-11-16T08:03:00.000Z',
              size: 20480,
            },
          ],
        })
      ).success
    ).toBe(true);
    const detail = (extra: Record<string, unknown>) =>
      withRecipient({ copyDetails: [{ messageId: 'AAMk=', ...extra }] });
    for (const bad of [
      { internetMessageId: 'no at sign' },
      { subjectHash: 'Invoice 7731 overdue' },
      { senderAddress: 'not an address' },
      { size: -1 },
      { receivedAt: 'yesterday' },
      { subject: 'text is never carried' },
    ]) {
      expect(BlastRadiusLookupResultSchema.safeParse(detail(bad)).success).toBe(false);
    }
    expect(
      BlastRadiusLookupResultSchema.safeParse(
        withRecipient({
          copyDetails: Array.from({ length: 6 }, (_, i) => ({ messageId: `id${i}` })),
        })
      ).success
    ).toBe(false);
  });
});

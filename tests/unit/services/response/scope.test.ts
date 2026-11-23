/**
 * Campaign response scopes: who may be emailed, which copies a removal may
 * name, and how lookups merge. Invented example.com data only.
 */

import type {
  BlastRadiusRecipient,
  BlastRadiusReport,
} from '../../../../src/services/graph/blast-radius.service';
import {
  computeRemovalScope,
  computeWarningScope,
  emptyReach,
  firstDelivery,
  isEmptyScope,
  isSafeRecipient,
  mergeReach,
  recheckRemoval,
  scopeHash,
} from '../../../../src/services/response/scope';
import type { IncidentReach } from '../../../../src/services/response/response.types';

const SAFE = ['example.com'];
const MAILBOX_A = '11111111-1111-4111-8111-111111111111';
const MAILBOX_B = '22222222-2222-4222-8222-222222222222';
const MAILBOX_C = '33333333-3333-4333-8333-333333333333';

function found(address: string, extra: Partial<BlastRadiusRecipient> = {}): BlastRadiusRecipient {
  return { address, mailbox: 'found', folder: 'inbox', isRead: false, response: 'none', ...extra };
}

function report(
  recipients: BlastRadiusRecipient[],
  extra: Partial<BlastRadiusReport> = {}
): BlastRadiusReport {
  return {
    status: 'complete',
    route: 'trace',
    totals: { recipients: recipients.length, read: 0, replied: 0, forwarded: 0 },
    recipients,
    lookedUpAt: '2026-11-17T10:00:00.000Z',
    ...extra,
  };
}

function reachOf(recipients: BlastRadiusRecipient[]): IncidentReach {
  return mergeReach(undefined, report(recipients), true);
}

describe('isSafeRecipient (invariant 4 for every address campaign response emails)', () => {
  it.each([
    ['alice@example.com', true],
    ['bob@mail.example.com', true],
    ['ALICE@EXAMPLE.COM', true],
    ['mallory@example.com.evil.test', false],
    ['mallory@notexample.com', false],
    ['"Alice" <alice@example.com>', false],
    ['alice@example.com, mallory@evil.test', false],
    ['alice@example.com\r\nBcc: mallory@evil.test', false],
    ['', false],
    [undefined, false],
  ])('%j → %s', (address, expected) => {
    expect(isSafeRecipient(address as string | undefined, SAFE)).toBe(expected);
  });
});

describe('mergeReach', () => {
  it('says blast radius is not enabled when there is no lookup and no feature', () => {
    expect(mergeReach(undefined, undefined, false).status).toBe('not_enabled');
    expect(mergeReach(undefined, undefined, true).status).toBe('unavailable');
  });

  it('keeps earlier recipients and lets the newer lookup win for the ones it lists', () => {
    const first = reachOf([found('a@example.com'), found('b@example.com')]);
    const merged = mergeReach(
      first,
      report([
        found('b@example.com', { isRead: true, response: 'replied' }),
        found('c@example.com', { folder: 'junk' }),
      ]),
      true
    );
    expect(merged.recipients.map(r => r.address)).toEqual([
      'a@example.com',
      'b@example.com',
      'c@example.com',
    ]);
    expect(merged.totals).toEqual({
      recipients: 3,
      read: 1,
      replied: 1,
      forwarded: 0,
      stillInInbox: 2,
      notDelivered: 0,
    });
  });

  it('keeps the earlier result when a later lookup fails, with its note', () => {
    const first = reachOf([found('a@example.com')]);
    const merged = mergeReach(
      first,
      { status: 'unavailable', note: 'it ran out of time', lookedUpAt: '2026-11-17T11:00:00.000Z' },
      true
    );
    expect(merged.recipients).toHaveLength(1);
    expect(merged.note).toBe('it ran out of time');
  });

  it('counts recipients a lookup counted but did not list', () => {
    const merged = mergeReach(
      undefined,
      report([found('a@example.com')], {
        totals: { recipients: 140, read: 0, replied: 0, forwarded: 0 },
      }),
      true
    );
    expect(merged.unlisted).toBe(139);
  });

  it('finds the earliest delivery', () => {
    const reach = reachOf([
      found('a@example.com', { receivedAt: '2026-11-17T09:20:00.000Z' }),
      found('b@example.com', { receivedAt: '2026-11-17T09:14:00.000Z' }),
    ]);
    expect(firstDelivery(reach)).toBe('2026-11-17T09:14:00.000Z');
    expect(firstDelivery(emptyReach('unavailable'))).toBeUndefined();
  });
});

describe('computeWarningScope', () => {
  const reach = reachOf([
    found('alice@example.com', { receivedAt: '2026-11-17T09:14:00.000Z' }),
    found('bob@example.com', { folder: 'junk' }),
    { address: 'carol@example.com', mailbox: 'not_delivered' },
    { address: 'dave@example.com', mailbox: 'not_found' },
    found('mallory@evil.test'),
    found('reporter@example.com'),
    { address: 'shared@example.com', mailbox: 'not_checked' },
  ]);

  const base = {
    reach,
    reporters: ['reporter@example.com', 'second.reporter@example.com'],
    safeDomains: SAFE,
    alreadyContacted: new Set<string>(),
    remaining: 100,
    targeted: true,
    distribution: false,
  };

  it('warns delivered recipients on safe domains, never the reporters', () => {
    const scope = computeWarningScope(base);
    expect(scope.recipients.map(r => r.address)).toEqual([
      'alice@example.com',
      'bob@example.com',
      'shared@example.com',
    ]);
    expect(scope.recipients[0].receivedAt).toBe('2026-11-17T09:14:00.000Z');
    expect(scope.recipients[1].folder).toBe('junk');
    expect(scope.recipients.map(r => r.address)).not.toContain('reporter@example.com');
    expect(scope).not.toHaveProperty('reporters');
    expect(scope.skipped).toMatchObject({ notDelivered: 2, unsafeAddress: 1, alreadyContacted: 0 });
  });

  it('never warns someone whose copy was not delivered', () => {
    const scope = computeWarningScope(base);
    const addresses = scope.recipients.map(r => r.address);
    expect(addresses).not.toContain('carol@example.com');
    expect(addresses).not.toContain('dave@example.com');
  });

  it('never emails an address off the safe domains, from any source', () => {
    const scope = computeWarningScope({
      ...base,
      reporters: ['reporter@evil.test'],
    });
    expect(scope.recipients.map(r => r.address)).not.toContain('mallory@evil.test');
  });

  it('skips people already contacted', () => {
    const scope = computeWarningScope({
      ...base,
      alreadyContacted: new Set(['alice@example.com', 'reporter@example.com']),
    });
    expect(scope.recipients.map(r => r.address)).toEqual(['bob@example.com', 'shared@example.com']);
    expect(scope.skipped.alreadyContacted).toBe(1);
  });

  it('caps the emails per campaign', () => {
    const scope = computeWarningScope({ ...base, remaining: 2 });
    expect(scope.recipients.map(r => r.address)).toEqual(['alice@example.com', 'bob@example.com']);
    expect(scope.skipped.overCap).toBe(1);
  });

  it('is only the distribution broadcast when the audience is the list', () => {
    const scope = computeWarningScope({ ...base, targeted: false, distribution: true });
    expect(scope.recipients).toEqual([]);
    expect(scope.distribution).toBe(true);
    expect(isEmptyScope(scope)).toBe(false);
    expect(isEmptyScope({ ...scope, distribution: false })).toBe(true);
  });
});

describe('computeRemovalScope', () => {
  const reach = reachOf([
    found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1', 'AAMk-a2'] }),
    found('b@example.com', { mailboxId: MAILBOX_B, messageIds: ['AAMk-b1'], folder: 'deleted' }),
    found('c@example.com', {
      mailboxId: MAILBOX_C,
      messageIds: ['AAMk-c1'],
      folder: 'recoverable',
    }),
    found('d@example.com'),
    { address: 'e@example.com', mailbox: 'not_delivered' },
  ]);

  it('names exact message IDs per mailbox, never a search', () => {
    const scope = computeRemovalScope(reach, { maxMailboxes: 10, maxMessages: 10 });
    expect(scope.mailboxes).toEqual([
      expect.objectContaining({
        mailboxId: MAILBOX_A,
        messageIds: ['AAMk-a1', 'AAMk-a2'],
        folder: 'inbox',
      }),
      expect.objectContaining({ mailboxId: MAILBOX_B, messageIds: ['AAMk-b1'], folder: 'deleted' }),
    ]);
    expect(scope.messageCount).toBe(3);
    expect(scope.skipped).toEqual({
      noIdentifiers: 1,
      alreadyPurged: 1,
      overMailboxCap: 0,
      overMessageCap: 0,
    });
    expect(JSON.stringify(scope)).not.toMatch(/filter|search|\$/i);
  });

  it('applies the mailbox and message caps', () => {
    expect(
      computeRemovalScope(reach, { maxMailboxes: 1, maxMessages: 10 }).skipped.overMailboxCap
    ).toBe(1);
    const byMessages = computeRemovalScope(reach, { maxMailboxes: 10, maxMessages: 2 });
    expect(byMessages.mailboxes.map(m => m.mailboxId)).toEqual([MAILBOX_A]);
    expect(byMessages.skipped.overMessageCap).toBe(1);
  });

  it('hashes equal scopes equally, whatever the key order', () => {
    const scope = computeRemovalScope(reach, { maxMailboxes: 10, maxMessages: 10 });
    const reordered = Object.fromEntries(Object.entries(scope).reverse()) as typeof scope;
    expect(scopeHash(reordered)).toBe(scopeHash(scope));
    expect(scopeHash({ ...scope, messageCount: 4 })).not.toBe(scopeHash(scope));
  });
});

describe('recheckRemoval', () => {
  it('counts only approved copies by their current state', () => {
    const approved = computeRemovalScope(
      reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] }),
        found('b@example.com', { mailboxId: MAILBOX_B, messageIds: ['AAMk-b1'] }),
      ]),
      { maxMailboxes: 10, maxMessages: 10 }
    );
    const now = reachOf([
      found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'], isRead: true }),
      found('b@example.com', { mailboxId: MAILBOX_B, messageIds: ['AAMk-b1'], folder: 'deleted' }),
      found('c@example.com', { mailboxId: MAILBOX_C, messageIds: ['AAMk-c1'] }),
    ]);
    const { counts, mailboxes } = recheckRemoval(approved, now);
    expect(counts).toMatchObject({
      mailboxes: 2,
      messages: 2,
      unreadInInbox: 0,
      readInInbox: 1,
      alreadyInDeletedItems: 1,
      newSinceApproval: 1,
      noLongerMatched: 0,
    });
    expect(mailboxes.map(m => m.mailboxId)).not.toContain(MAILBOX_C);
  });

  it('leaves out copies that are gone or purged', () => {
    const approved = computeRemovalScope(
      reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1', 'AAMk-a2'] }),
      ]),
      { maxMailboxes: 10, maxMessages: 10 }
    );
    const gone = recheckRemoval(
      approved,
      reachOf([
        found('a@example.com', {
          mailboxId: MAILBOX_A,
          messageIds: ['AAMk-a2'],
          folder: 'recoverable',
        }),
      ])
    );
    expect(gone.counts.messages).toBe(0);
    expect(gone.counts.noLongerMatched).toBe(2);
  });

  it('counts the copies that would move apart from those already in Deleted Items', () => {
    const approved = computeRemovalScope(
      reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] }),
        found('b@example.com', { mailboxId: MAILBOX_B, messageIds: ['AAMk-b1', 'AAMk-b2'] }),
      ]),
      { maxMailboxes: 10, maxMessages: 10 }
    );
    const { counts } = recheckRemoval(
      approved,
      reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'], folder: 'junk' }),
        found('b@example.com', {
          mailboxId: MAILBOX_B,
          messageIds: ['AAMk-b1', 'AAMk-b2'],
          folder: 'deleted',
        }),
      ])
    );
    expect(counts).toMatchObject({
      messages: 3,
      mailboxes: 2,
      toMove: 1,
      toMoveMailboxes: 1,
      alreadyInDeletedItems: 2,
      alreadyInDeletedItemsMailboxes: 1,
    });
  });

  it('puts every recipient in exactly one category, so they add up to the total', () => {
    const approved = computeRemovalScope(
      reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] }),
        found('b@example.com', { mailboxId: MAILBOX_B, messageIds: ['AAMk-b1'] }),
      ]),
      { maxMailboxes: 10, maxMessages: 10 }
    );
    const now: IncidentReach = {
      ...reachOf([
        found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] }),
        // Another address of mailbox A
        found('a.alias@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] }),
        // The approved mailbox, now listed without a mailbox ID
        { address: 'b@example.com', mailbox: 'not_checked' },
        // Found later, never approved
        found('c@example.com', { mailboxId: MAILBOX_C, messageIds: ['AAMk-c1'] }),
        { address: 'desk@example.com', mailbox: 'not_checked' },
        { address: 'gone@example.com', mailbox: 'not_found' },
        { address: 'bounced@example.com', mailbox: 'not_delivered' },
        found('purged@example.com', { folder: 'recoverable' }),
        found('noid@example.com'),
      ]),
      unlisted: 3,
    };
    const { recipients, notOpened } = recheckRemoval(approved, now);
    expect(recipients).toEqual({
      total: 12,
      toMove: 1,
      alreadyInDeletedItems: 0,
      noLongerMatched: 1,
      onlyInRecoverableItems: 1,
      noCopyFound: 1,
      mailboxNotOpened: 1,
      notDelivered: 1,
      noIdentifiers: 1,
      notInApprovedScope: 1,
      sameMailbox: 1,
      unlisted: 3,
    });
    expect(notOpened).toEqual(['desk@example.com']);
  });

  it('accounts for an approved mailbox the reach no longer lists', () => {
    const approved = computeRemovalScope(
      reachOf([found('a@example.com', { mailboxId: MAILBOX_A, messageIds: ['AAMk-a1'] })]),
      { maxMailboxes: 10, maxMessages: 10 }
    );
    const { recipients } = recheckRemoval(approved, emptyReach('unavailable'));
    expect(recipients).toMatchObject({ total: 1, noLongerMatched: 1, toMove: 0 });
  });
});

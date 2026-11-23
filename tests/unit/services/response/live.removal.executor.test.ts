/**
 * The live removal: its eligibility rules (an anchor Phishy read itself,
 * and only copies provably the same email), the executor (what is sent to
 * the write broker: never wider than the approved, re-checked scope; each
 * copy with its own expected values), and the whole path through
 * CampaignResponseService (mode bound to the proposal, notices only for
 * moved copies, never automatic, fan-out incidents dry run only). The write
 * broker is a stub (no Lambda, no Graph). Invented example.com data only.
 */

import { CampaignResponseService } from '../../../../src/services/response/campaign.response.service';
import {
  DryRunRemovalExecutor,
  createRemovalExecutor,
} from '../../../../src/services/response/executors';
import { LiveRemovalExecutor } from '../../../../src/services/response/live.removal.executor';
import {
  anchorFromReport,
  computeLiveRemovalScope,
} from '../../../../src/services/response/removal.eligibility';
import type {
  GraphWriteCallResult,
  LambdaInvoker,
} from '../../../../src/services/graph-write/write.broker.client';
import type {
  MessageOutcome,
  RemoveMessagesParams,
} from '../../../../src/services/graph-write/write.protocol';
import type {
  BlastRadiusRecipient,
  BlastRadiusReport,
  CopyDetail,
} from '../../../../src/services/graph/blast-radius.service';
import { subjectKeyHash } from '../../../../src/services/graph/subject.key';
import type { CampaignResponseConfig } from '../../../../src/config/schema';
import { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } from '../../../../src/config/schema';
import type {
  IncidentReach,
  RemovalAnchor,
  RemovalScope,
  ResponseAction,
} from '../../../../src/services/response/response.types';
import { mergeReach } from '../../../../src/services/response/scope';
import type { ApprovalCommand } from '../../../../src/services/commands/response.commands';
import type { ExtractedEmailData } from '../../../../src/types';
import { FakeResponseStore } from './fake.store';

const MAILBOX = (n: number): string => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;
const IMID = '<invoice-2291@mail.examp1e-billing.test>';
const SENDER = 'billing@examp1e-billing.test';
const SUBJECT = 'Invoice 2291 overdue';
const RECEIVED = '2026-11-17T09:14:00.000Z';
const ACTION_ID = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';
const REPORTER = 'reporter1@example.com';
const RULES = { sameMessageSpreadMinutes: 60 };
const LIMITS = { maxMailboxes: 500, maxMessages: 1000 };

const ANCHOR: RemovalAnchor = {
  mailboxId: MAILBOX(99),
  messageId: 'AAMkAG-reporter',
  internetMessageId: IMID,
  senderAddress: SENDER,
  subject: SUBJECT,
  subjectHash: subjectKeyHash(SUBJECT),
  receivedAt: RECEIVED,
};

function detail(messageId: string, extra: Partial<CopyDetail> = {}): CopyDetail {
  return {
    messageId,
    internetMessageId: IMID,
    senderAddress: SENDER,
    subjectHash: subjectKeyHash(SUBJECT),
    receivedAt: RECEIVED,
    ...extra,
  };
}

/** A recipient holding one copy of the anchor's email, unless `extra` says otherwise */
function recipient(
  n: number,
  extra: Partial<BlastRadiusRecipient> = {},
  copy: Partial<CopyDetail> = {}
): BlastRadiusRecipient {
  const id = `AAMkAG-${n}`;
  return {
    address: `person${n}@example.com`,
    mailbox: 'found',
    folder: 'inbox',
    isRead: false,
    response: 'none',
    mailboxId: MAILBOX(n),
    messageIds: [id],
    copyDetails: [detail(id, copy)],
    receivedAt: RECEIVED,
    ...extra,
  };
}

/** The reporter's own row: holds the anchor's copy, which the reporter forwarded */
function reporterRow(extra: Partial<BlastRadiusRecipient> = {}): BlastRadiusRecipient {
  return {
    address: REPORTER,
    mailbox: 'found',
    folder: 'inbox',
    isRead: true,
    response: 'forwarded',
    mailboxId: MAILBOX(99),
    messageIds: ['AAMkAG-reporter'],
    copyDetails: [detail('AAMkAG-reporter')],
    receivedAt: RECEIVED,
    ...extra,
  };
}

function report(recipients: BlastRadiusRecipient[]): BlastRadiusReport {
  return {
    status: 'complete',
    route: 'trace',
    matchedBy: 'senderSubject',
    totals: { recipients: recipients.length, read: 0, replied: 0, forwarded: 0 },
    recipients,
    lookedUpAt: '2026-11-17T10:00:00.000Z',
    reporterAddress: REPORTER,
  };
}

function reachOf(recipients: BlastRadiusRecipient[]): IncidentReach {
  return mergeReach(undefined, report(recipients), true);
}

/** What the original-message lookup stored for the reporter's copy */
function retrieved(
  identity: Partial<NonNullable<ExtractedEmailData['retrievedOriginal']>['identity']> = {},
  headers: Record<string, string> = { 'In-Reply-To': IMID, References: `<earlier@x.test> ${IMID}` },
  subject = `FW: ${SUBJECT}`
): Pick<ExtractedEmailData, 'retrievedOriginal' | 'headers' | 'subject'> {
  return {
    // The report's own top-level headers and Subject, as SES received them
    headers,
    subject,
    retrievedOriginal: {
      location: 'mailbox',
      receivedAt: RECEIVED,
      headers: [],
      headersTruncated: false,
      identity: {
        messageId: 'AAMkAG-reporter',
        internetMessageId: IMID,
        senderAddress: SENDER,
        subject: SUBJECT,
        sameMessageIdCount: '1',
        ...identity,
      },
    },
  };
}

function action(scope: RemovalScope): ResponseAction {
  return {
    id: ACTION_ID,
    incidentId: 'incident-1',
    reference: 'PHY-AAAA-BBBB-CCCC-DDDD',
    type: 'remove_messages',
    status: 'approved',
    authorization: 'approve',
    scope,
    scopeHash: 'hash',
    proposedAt: new Date(),
    expiresAt: new Date(Date.now() + 3600_000),
    approvedBy: 'security@example.com',
  };
}

const okResult = (
  params: RemoveMessagesParams,
  decide: (m: string, id: string) => MessageOutcome['outcome']
) => ({
  ok: true as const,
  result: {
    mailboxes: params.mailboxes.map(m => ({
      mailboxId: m.mailboxId,
      messages: m.messages.map(x => ({
        messageId: x.messageId,
        outcome: decide(m.mailboxId, x.messageId),
      })),
    })),
    bounds: {
      maxMailboxes: 50,
      maxMessagesPerMailbox: 5,
      maxMessages: 100,
      budgetMs: params.budgetMs,
      concurrency: 4,
    },
    durationMs: 5,
  },
});

/** A stub write broker: decides each message's outcome, records every request */
function stubBroker(
  decide: (mailboxId: string, messageId: string) => MessageOutcome['outcome'] = () => 'moved',
  failure?: GraphWriteCallResult
) {
  const calls: Array<{ params: RemoveMessagesParams; timeoutMs: number }> = [];
  return {
    calls,
    client: {
      removeMessages: jest.fn(async (params: RemoveMessagesParams, timeoutMs: number) => {
        calls.push({ params, timeoutMs });
        return failure ?? okResult(params, decide);
      }),
    },
  };
}

// ── The anchor ─────────────────────────────────────────────────────────────

describe('anchorFromReport', () => {
  it('accepts the reporter-mailbox original this forward names in its own headers', () => {
    const found = anchorFromReport(retrieved(), report([reporterRow(), recipient(1)]));
    expect(found).toEqual({
      anchor: { ...ANCHOR, receivedAt: RECEIVED },
    });
    // In-Reply-To alone; with no In-Reply-To, the LAST References entry;
    // any header-name case, brackets and spaces aside
    for (const headers of <Array<Record<string, string>>>[
      { 'In-Reply-To': IMID },
      { references: `<a@x.test>\r\n ${IMID}` },
      { 'in-reply-to': ` ${IMID} `, References: `${IMID} <later@x.test>` },
    ]) {
      expect(anchorFromReport(retrieved({}, headers), report([reporterRow()]))).toHaveProperty(
        'anchor'
      );
    }
    // The forward's own Subject, with its reply/forward prefixes removed
    for (const subject of [
      SUBJECT,
      `FW: ${SUBJECT}`,
      `Fwd: ${SUBJECT}`,
      `RE: FW: fwd:  ${SUBJECT.toUpperCase()}`,
      ` fw :${SUBJECT}  `,
    ]) {
      expect(
        anchorFromReport(retrieved({}, undefined, subject), report([reporterRow()]))
      ).toHaveProperty('anchor');
    }
  });

  it('(a) a planted block naming a message the reporter forwarded last week gives no anchor', () => {
    // An Outlook-style forward of the phishing email, whose body carries a
    // planted Gmail-style block naming a real email from last week. The
    // parser takes the planted block, so the original-message lookup finds
    // that real email, which the reporter did forward (last week). The
    // forward's own headers name the phishing email it actually forwards.
    const lastWeek = '<payroll-0910@hr.example.com>';
    const found = anchorFromReport(
      retrieved(
        {
          internetMessageId: lastWeek,
          senderAddress: 'hr@example.com',
          subject: 'Payroll for November',
        },
        { 'In-Reply-To': IMID, References: IMID, 'Thread-Index': 'AQHZ' }
      ),
      report([
        reporterRow({
          copyDetails: [
            detail('AAMkAG-reporter', {
              internetMessageId: lastWeek,
              senderAddress: 'hr@example.com',
              subjectHash: subjectKeyHash('Payroll for November'),
              receivedAt: '2026-11-10T08:00:00.000Z',
            }),
          ],
        }),
      ])
    );
    expect(found).toEqual({ rejected: 'not_the_forwarded_message' });
  });

  it('(e) reads In-Reply-To only from the report itself, never from an attached message', () => {
    // A forward-as-attachment: the report has no In-Reply-To of its own; the
    // attached message's headers (and text pasted in the body) do not count
    const emailData = {
      ...retrieved({}, { Subject: 'FW: Invoice 2291 overdue', 'Message-ID': '<fw-1@example.com>' }),
      forwardedHeaders: { 'Original-Message-ID': IMID, 'In-Reply-To': IMID },
      text: `In-Reply-To: ${IMID}\nReferences: ${IMID}`,
      attachments: [
        {
          filename: 'Invoice.eml',
          contentType: 'message/rfc822',
          size: 1,
          headers: { 'In-Reply-To': IMID },
        },
      ],
    };
    expect(anchorFromReport(emailData as never, report([reporterRow()]))).toEqual({
      rejected: 'not_the_forwarded_message',
    });
  });

  it.each([
    [
      'a Report-button submission',
      { ...retrieved(), userReport: { reportedAs: 'phishing' } },
      report([reporterRow()]),
      'report_button',
    ],
    ['no original-message lookup result', {}, report([reporterRow()]), 'no_original'],
    [
      'an original with no stored Message-ID',
      retrieved({ internetMessageId: undefined }),
      report([reporterRow()]),
      'incomplete_identity',
    ],
    [
      'an original with no stored sender',
      retrieved({ senderAddress: undefined }),
      report([reporterRow()]),
      'incomplete_identity',
    ],
    [
      'an original whose subject is empty once normalized',
      retrieved({ subject: '   ' }),
      report([reporterRow()]),
      'incomplete_identity',
    ],
    [
      'a report with no In-Reply-To or References',
      retrieved({}, { Subject: 'Fwd: Invoice 2291 overdue' }),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'a report whose headers name a different message',
      retrieved({}, { 'In-Reply-To': '<other@x.test>', References: '<other@x.test>' }),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'a Message-ID the mailbox search found twice (another folder, Recoverable Items, or beyond the 5-copy row)',
      retrieved({ sameMessageIdCount: '2+' }),
      report([reporterRow()]),
      'ambiguous_message_id',
    ],
    [
      'a Message-ID search that failed or had no time',
      retrieved({ sameMessageIdCount: 'unknown' }),
      report([reporterRow()]),
      'uniqueness_unknown',
    ],
    [
      'no Message-ID search at all',
      retrieved({ sameMessageIdCount: undefined }),
      report([reporterRow()]),
      'uniqueness_unknown',
    ],
    [
      'an In-Reply-To naming two messages',
      retrieved({}, { 'In-Reply-To': `${IMID} <other@x.test>` }),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'an In-Reply-To naming another message, even with the anchor in References',
      retrieved({}, { 'In-Reply-To': '<other@x.test>', References: IMID }),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'References naming the anchor, but not last',
      retrieved({}, { References: `${IMID} <later@x.test>` }),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      "a forward whose own Subject is another email's",
      retrieved({}, undefined, 'FW: Payroll for November'),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'a forward with no Subject',
      retrieved({}, undefined, ''),
      report([reporterRow()]),
      'not_the_forwarded_message',
    ],
    [
      'a Message-ID held twice in the reporter mailbox',
      retrieved(),
      report([
        reporterRow({
          messageIds: ['AAMkAG-reporter', 'AAMkAG-reporter-2'],
          copyDetails: [detail('AAMkAG-reporter'), detail('AAMkAG-reporter-2')],
        }),
      ]),
      'ambiguous_message_id',
    ],
    ['no blast-radius lookup', retrieved(), undefined, 'no_blast_radius'],
    [
      'a failed blast-radius lookup',
      retrieved(),
      { ...report([reporterRow()]), status: 'unavailable' as const },
      'no_blast_radius',
    ],
    ['no reporter row', retrieved(), report([recipient(1)]), 'reporter_copy_not_found'],
    [
      'a reporter row holding another message',
      retrieved(),
      report([
        reporterRow({ messageIds: ['AAMkAG-other'], copyDetails: [detail('AAMkAG-other')] }),
      ]),
      'reporter_copy_not_found',
    ],
    [
      'a reporter copy whose stored subject differs',
      retrieved(),
      report([
        reporterRow({
          copyDetails: [
            detail('AAMkAG-reporter', { subjectHash: subjectKeyHash('Something else') }),
          ],
        }),
      ]),
      'reporter_copy_differs',
    ],
    [
      'a reporter copy the reporter did not forward',
      retrieved(),
      report([reporterRow({ response: 'none' })]),
      'not_forwarded_by_reporter',
    ],
  ] as const)('gives no anchor for %s', (_label, emailData, blast, reason) => {
    expect(anchorFromReport(emailData as never, blast as BlastRadiusReport | undefined)).toEqual({
      rejected: reason,
    });
  });
});

// ── Eligibility ─────────────────────────────────────────────────────────────

describe('computeLiveRemovalScope', () => {
  it('names only copies with the anchor Message-ID, sender and subject, each with its own check', () => {
    const reach = reachOf([
      reporterRow(),
      recipient(1), // the anchor's own Message-ID
      // Same sender, subject and time, another Message-ID (even one of identical
      // size, which an earlier version could admit): never eligible
      recipient(2, {}, { internetMessageId: '<other-2@mail.examp1e-billing.test>' }),
      recipient(4, {}, { senderAddress: 'billing@example.org' }), // another sender
      recipient(5, {}, { subjectHash: subjectKeyHash('Invoice 2291 overdue - reminder') }), // contains, not equal
      recipient(6, {}, { receivedAt: '2026-11-17T16:00:00.000Z' }), // hours later
      recipient(11, {}, { receivedAt: '2026-11-17T10:30:00.000Z' }), // same ID, 76 min later
      recipient(12, {}, { receivedAt: '2026-11-17T10:14:00.000Z' }), // exactly 60 min later
      recipient(7, {}, { internetMessageId: undefined }), // no Message-ID recorded
      recipient(8, { copyDetails: undefined }), // no details at all
      recipient(9, { mailboxId: undefined }), // no identifiers
      recipient(10, {}, { subjectHash: subjectKeyHash('  INVOICE   2291 overdue ') }), // same after normalization
    ]);
    const scope = computeLiveRemovalScope(reach, LIMITS, ANCHOR, RULES);
    expect(scope.mode).toBe('live');
    expect(scope.mailboxes.map(m => m.address)).toEqual([
      REPORTER,
      'person1@example.com',
      'person12@example.com',
      'person10@example.com',
    ]);
    // Every copy is re-checked by the write broker in anchor ± the spread
    for (const mailbox of scope.mailboxes) {
      expect(mailbox.verify).toEqual([
        {
          messageId: mailbox.messageIds[0],
          internetMessageId: IMID,
          senderAddress: SENDER,
          subjectHash: subjectKeyHash(SUBJECT),
          receivedFrom: '2026-11-17T08:14:00.000Z',
          receivedTo: '2026-11-17T10:14:00.000Z',
        },
      ]);
    }
    expect(scope.live).toEqual({
      anchor: ANCHOR,
      sameMessageSpreadMinutes: 60,
      firstReceivedAt: RECEIVED,
      lastReceivedAt: '2026-11-17T10:14:00.000Z',
      excluded: 7,
    });
    expect(scope.skipped.noIdentifiers).toBe(1);
    // The reach itself is unchanged: warnings still see everyone
    expect(reach.recipients).toHaveLength(12);
  });

  it('a planted forwarded-header block cannot aim a live removal at another sender or subject', () => {
    // The forward's text claims a different sender and subject (as a block
    // planted in the attacker's body would), and blast radius matched by
    // those claims: legitimate mail from that sender is in the reach. The
    // live scope is decided by the anchor Phishy read itself, never by the
    // claims, so none of that mail is named.
    const legit = (n: number): BlastRadiusRecipient =>
      recipient(
        n,
        {},
        {
          internetMessageId: `<payroll-${n}@hr.example.com>`,
          senderAddress: 'hr@example.com',
          subjectHash: subjectKeyHash('Payroll for November'),
        }
      );
    const reach = reachOf([legit(1), legit(2), legit(3)]);
    const scope = computeLiveRemovalScope(reach, LIMITS, ANCHOR, RULES);
    expect(scope.mailboxes).toEqual([]);
    expect(scope.live?.excluded).toBe(3);
    // And the anchor itself is not taken from the forward's text: a report
    // whose lookup found a message the reporter did not forward gives none
    const decoy = anchorFromReport(
      retrieved({
        senderAddress: 'hr@example.com',
        subject: 'Payroll for November',
        internetMessageId: '<payroll-9@hr.example.com>',
      }),
      report([
        reporterRow({
          response: 'none',
          copyDetails: [
            detail('AAMkAG-reporter', {
              internetMessageId: '<payroll-9@hr.example.com>',
              senderAddress: 'hr@example.com',
              subjectHash: subjectKeyHash('Payroll for November'),
            }),
          ],
        }),
      ])
    );
    expect(decoy).toEqual({ rejected: 'not_the_forwarded_message' });
  });
});

// ── Selection ───────────────────────────────────────────────────────────────

describe('createRemovalExecutor', () => {
  it('is the dry run by default and for dry_run', () => {
    expect(createRemovalExecutor()).toBeInstanceOf(DryRunRemovalExecutor);
    expect(
      createRemovalExecutor({
        mode: 'dry_run',
        writeBrokerFunctionName: 'phishy-graph-write-broker',
      })
    ).toBeInstanceOf(DryRunRemovalExecutor);
  });

  it('falls back to the dry run when live has no usable write broker', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    for (const name of [undefined, '', 'https://example.com/fn', 'a b']) {
      const executor = createRemovalExecutor({ mode: 'live', writeBrokerFunctionName: name });
      expect(executor).toBeInstanceOf(DryRunRemovalExecutor);
      expect(executor.changesMailboxes).toBe(false);
    }
    warn.mockRestore();
  });

  it('is the live executor only for live with a function name', () => {
    const executor = createRemovalExecutor(
      { mode: 'live', writeBrokerFunctionName: 'phishy-graph-write-broker' },
      { send: jest.fn() } as unknown as LambdaInvoker
    );
    expect(executor).toBeInstanceOf(LiveRemovalExecutor);
    expect(executor.changesMailboxes).toBe(true);
  });
});

// ── The executor ────────────────────────────────────────────────────────────

const liveScope = (recipients: BlastRadiusRecipient[]): RemovalScope =>
  computeLiveRemovalScope(reachOf(recipients), LIMITS, ANCHOR, RULES);

describe('LiveRemovalExecutor', () => {
  it('sends exactly the approved, re-checked copies, each with its own expected values', async () => {
    const scope = liveScope([recipient(1), recipient(2), recipient(3)]);
    // Since approval: person2's copy is gone, person4 newly holds one, person1 a second
    const current = reachOf([
      recipient(1, {
        messageIds: ['AAMkAG-1', 'AAMkAG-1-new'],
        copyDetails: [detail('AAMkAG-1'), detail('AAMkAG-1-new')],
      }),
      recipient(2, { mailbox: 'not_found', messageIds: undefined, copyDetails: undefined }),
      recipient(3),
      recipient(4),
    ]);
    const broker = stubBroker();
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      current
    );

    expect(broker.calls).toHaveLength(1);
    const expected = (id: string) => ({
      messageId: id,
      expectedInternetMessageId: IMID,
      expectedSenderAddress: SENDER,
      expectedSubjectSha256: subjectKeyHash(SUBJECT),
      receivedFrom: '2026-11-17T08:14:00.000Z',
      receivedTo: '2026-11-17T10:14:00.000Z',
    });
    expect(broker.calls[0].params).toEqual({
      actionId: ACTION_ID,
      mailboxes: [
        { mailboxId: MAILBOX(1), messages: [expected('AAMkAG-1')] },
        { mailboxId: MAILBOX(3), messages: [expected('AAMkAG-3')] },
      ],
      budgetMs: expect.any(Number),
    });
    // No address and no email text is ever sent
    const sent = JSON.stringify(broker.calls[0].params);
    expect(sent).not.toContain('@example.com');
    expect(sent).not.toContain('Invoice');
    expect(result.dryRun).toBe(false);
    expect(result.removed).toEqual([
      { mailboxId: MAILBOX(1), messages: 1 },
      { mailboxId: MAILBOX(3), messages: 1 },
    ]);
    expect(result.removalOutcome).toMatchObject({ moved: 2, notAttempted: 0, unknown: 0 });
    const text = result.summary.join('\n');
    expect(text).toContain('2 message(s) moved to Deleted Items in 2 mailbox(es)');
    // The new copy in mailbox 1 and person4's are the same email, not approved
    expect(text).toContain('2 newer copy(ies) of the same email were found');
  });

  it('lists only moved copies in removed, and reports every outcome by count', async () => {
    const scope = liveScope([1, 2, 3, 4, 5, 6].map(n => recipient(n)));
    const outcomes: Record<string, MessageOutcome['outcome']> = {
      [MAILBOX(1)]: 'moved',
      [MAILBOX(2)]: 'already_deleted',
      [MAILBOX(3)]: 'not_found',
      [MAILBOX(4)]: 'mismatch',
      [MAILBOX(5)]: 'error',
      [MAILBOX(6)]: 'not_allowed',
    };
    const broker = stubBroker(mailboxId => outcomes[mailboxId]);
    const reach = reachOf([1, 2, 3, 4, 5, 6].map(n => recipient(n)));
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach
    );
    expect(result.removed).toEqual([{ mailboxId: MAILBOX(1), messages: 1 }]);
    expect(result.removalOutcome).toEqual({
      moved: 1,
      alreadyDeleted: 1,
      notFound: 1,
      mismatch: 1,
      notAllowed: 1,
      error: 1,
      notAttempted: 0,
      unknown: 0,
    });
    const text = result.summary.join('\n');
    expect(text).toContain('Mailboxes with errors: person5@example[.]com.');
    expect(text).toContain('no longer provably the approved email');
  });

  it('never sends a copy that has no recorded check (a dry-run scope)', async () => {
    const reach = reachOf([recipient(1)]);
    const dryScope: RemovalScope = {
      kind: 'remove_messages',
      mailboxes: [
        {
          address: 'person1@example.com',
          mailboxId: MAILBOX(1),
          messageIds: ['AAMkAG-1'],
          folder: 'inbox',
        },
      ],
      messageCount: 1,
      limits: LIMITS,
      skipped: { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 },
    };
    const broker = stubBroker();
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(dryScope),
      dryScope,
      reach
    );
    expect(broker.calls).toEqual([]);
    expect(result.removalOutcome).toMatchObject({ notAttempted: 1, moved: 0 });
    expect(result.summary.join('\n')).toContain('recorded no check for them');
  });

  it('splits a large scope into calls within the protocol bounds, and stops when time runs out', async () => {
    const recipients = Array.from({ length: 120 }, (_, i) =>
      recipient(i + 1, {
        messageIds: [`A-${i}-1`, `A-${i}-2`],
        copyDetails: [detail(`A-${i}-1`), detail(`A-${i}-2`)],
      })
    );
    const scope = liveScope(recipients);
    const broker = stubBroker();
    let remaining = 180_000;
    broker.client.removeMessages.mockImplementation(async (params: RemoveMessagesParams) => {
      broker.calls.push({ params, timeoutMs: 0 });
      remaining -= 80_000;
      return okResult(params, () => 'moved');
    });
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reachOf(recipients),
      { getRemainingMs: () => remaining }
    );
    for (const call of broker.calls) {
      expect(call.params.mailboxes.length).toBeLessThanOrEqual(50);
      expect(call.params.mailboxes.reduce((n, m) => n + m.messages.length, 0)).toBeLessThanOrEqual(
        100
      );
    }
    // 240 messages = 3 calls of 100/100/40; time allows only two
    expect(broker.calls).toHaveLength(2);
    expect(result.removalOutcome).toMatchObject({ moved: 200, notAttempted: 40 });
    expect(result.summary.join('\n')).toContain(
      '40 message(s) were not attempted because the time available ran out'
    );
  });

  it('waits long enough for a cold write broker: its budget is well inside the wait', async () => {
    const scope = liveScope([recipient(1)]);
    const broker = stubBroker();
    await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reachOf([recipient(1)]),
      {
        getRemainingMs: () => 170_000,
      }
    );
    const [{ params, timeoutMs }] = broker.calls;
    expect(timeoutMs - params.budgetMs).toBeGreaterThanOrEqual(10_000);
  });

  it.each([
    ['a timeout', { ok: false, failure: 'timeout' }],
    ['a crash', { ok: false, failure: 'function_error' }],
    ['an internal_error refusal', { ok: false, failure: 'refused', refusal: 'internal_error' }],
    ['an unknown invoke error', { ok: false, failure: 'invoke_error' }],
  ] as const)(
    'treats %s as unknown, notifies nobody, and says how to check',
    async (_label, failure) => {
      const reach = reachOf([recipient(1), recipient(2)]);
      const scope = liveScope([recipient(1), recipient(2)]);
      const broker = stubBroker(undefined, failure as GraphWriteCallResult);
      const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
        action(scope),
        scope,
        reach
      );
      expect(result.removed).toEqual([]);
      expect(result.removalOutcome).toMatchObject({ unknown: 2, moved: 0 });
      const text = result.summary.join('\n');
      expect(text).toContain('Those people were NOT sent a removal notice');
      expect(text).toContain("write broker's log");
      expect(text).toContain('person1@example[.]com');
    }
  );

  it.each([
    ['Lambda rejecting the invoke', { ok: false, failure: 'invoke_rejected' }],
    ['the kill switch', { ok: false, failure: 'refused', refusal: 'write_disabled' }],
  ] as const)('reports %s as not attempted, never unknown', async (_label, failure) => {
    const reach = reachOf(Array.from({ length: 60 }, (_, i) => recipient(i + 1)));
    const scope = liveScope(Array.from({ length: 60 }, (_, i) => recipient(i + 1)));
    const broker = stubBroker(undefined, failure as GraphWriteCallResult);
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach
    );
    expect(result.removalOutcome).toMatchObject({ notAttempted: 60, unknown: 0 });
    if (failure.failure === 'refused') {
      expect(broker.calls).toHaveLength(1);
      expect(result.summary.join('\n')).toContain(
        'kill switch (PHISHY_GRAPH_WRITE_ENABLED) is off'
      );
      // The refusal leads; nothing reads as a removal carried out
      expect(result.summary[0]).toContain('refused the request (write_disabled)');
      expect(result.summary[1]).toBe('No message was moved. No mailbox was changed.');
      expect(result.summary.join('\n')).not.toContain('Removal carried out');
    }
  });
});

// ── Through the service ───────────────────────────────────────────────────

const TEAM = ['security@example.com'];

function serviceConfig(overrides: Partial<CampaignResponseConfig> = {}): CampaignResponseConfig {
  return {
    enabled: true,
    audience: 'recipients',
    employeeWarning: 'approve',
    distributionWarning: 'off',
    approvalTtlHours: 4,
    maxWarningsPerCampaign: 100,
    maxRemovalMailboxes: 500,
    maxRemovalMessages: 1000,
    updateIntervalMinutes: 30,
    reachThreshold: 0,
    alreadyClickedInstructions: DEFAULT_ALREADY_CLICKED_INSTRUCTIONS,
    timeZone: 'UTC',
    ...overrides,
  };
}

function service(
  options: {
    decide?: (mailboxId: string, messageId: string) => MessageOutcome['outcome'];
    cfg?: Partial<CampaignResponseConfig>;
    failure?: GraphWriteCallResult;
    live?: boolean;
    store?: FakeResponseStore;
    clock?: { now: Date };
  } = {}
) {
  const clock = options.clock ?? { now: new Date('2026-11-17T10:00:00.000Z') };
  const store = options.store ?? new FakeResponseStore(() => clock.now);
  const sent: Array<{ to: string; subject: string; text: string }> = [];
  let n = 0;
  const mailer = {
    sendEmail: jest.fn(async (to: string, subject: string, _html: string, text: string) => {
      sent.push({ to, subject, text });
      n += 1;
      return { success: true, messageId: `ses-${n}` };
    }),
    sendThreadedEmail: jest.fn(
      async (to: string[], subject: string, _html: string, text: string) => {
        sent.push({ to: to[0], subject, text });
        n += 1;
        return { success: true, messageId: `ses-${n}` };
      }
    ),
  };
  const broker = stubBroker(options.decide ?? (() => 'moved'), options.failure);
  let r = 0;
  const svc = new CampaignResponseService({
    store: store.asStore(),
    mailer,
    config: serviceConfig(options.cfg),
    safeDomains: ['example.com'],
    securityTeam: TEAM,
    commandsEnabled: true,
    legacyAlert: jest.fn().mockResolvedValue(true),
    markCampaignAlerted: jest.fn().mockResolvedValue(undefined),
    ...(options.live === false
      ? {}
      : { removalExecutor: new LiveRemovalExecutor({ client: broker.client }) }),
    now: () => clock.now,
    newReference: () =>
      `PHY-AAAA-BBBB-CCCC-D${'234567'[r % 6]}${'ABCDEFGHJK'[Math.floor(r++ / 6) % 10]}2`,
  });
  const advance = (ms: number): void => {
    clock.now = new Date(clock.now.getTime() + ms);
  };
  return { service: svc, store, sent, broker, advance, clock, mailer };
}

function campaignReport(
  recipients: BlastRadiusRecipient[],
  emailData: Partial<ExtractedEmailData> = retrieved(),
  verdict = 'phishing'
) {
  return {
    match: {
      campaignId: 'campaign-1',
      signature: 'abcdef0123456789',
      detectionCount: 3,
      uniqueRecipientCount: 3,
      hoursActive: 0.5,
      shouldAlert: true,
    },
    campaign: {
      id: 'campaign-1',
      campaignSignature: 'abcdef0123456789',
      senderDomain: 'example.com',
      subjectPattern: 'fwd invoice # overdue',
      detectionCount: 3,
      uniqueRecipients: [REPORTER, 'reporter2@example.com'],
      riskLevel: 'critical',
      sampleIndicators: [],
      firstSeenAt: new Date('2026-11-17T09:21:00.000Z'),
      lastSeenAt: new Date('2026-11-17T09:40:00.000Z'),
      isActive: true,
    },
    risk: { verdict, riskScore: 92, riskLevel: 'critical', reasons: ['Lookalike sender domain'] },
    analysis: { summary: 'Fake invoice reminder', indicators: ['Lookalike sender domain'] },
    emailData: { subject: 'Fwd: Invoice 2291 overdue', forwardedHeaders: {}, ...emailData },
    blastRadius: report([reporterRow(), ...recipients]),
    blastRadiusEnabled: true,
  } as never;
}

const approveLine = (reference: string): ApprovalCommand[] => [{ verb: 'REMOVAL', reference }];
const removals = (store: FakeResponseStore) =>
  store.actions.filter(a => a.type === 'remove_messages');

describe('a live removal through CampaignResponseService', () => {
  it('proposes a live removal stating its basis, and never runs it automatically', async () => {
    const {
      service: svc,
      store,
      sent,
      broker,
    } = service({
      cfg: { employeeWarning: 'auto', distributionWarning: 'auto' },
    });
    await svc.handleCampaignReport(
      campaignReport([
        recipient(1),
        recipient(2, {}, { receivedAt: '2026-11-17T09:50:00.000Z' }),
        // Same sender and subject, another Message-ID: never included
        recipient(3, {}, { internetMessageId: '<other-3@mail.examp1e-billing.test>' }),
        // Same Message-ID but 3 hours later: outside the 60-minute spread
        recipient(4, {}, { receivedAt: '2026-11-17T12:14:00.000Z' }),
        recipient(5, {}, { senderAddress: 'billing@example.org' }),
      ])
    );
    const removal = removals(store)[0];
    const scope = removal.scope as RemovalScope;
    expect(scope).toMatchObject({ mode: 'live' });
    expect(scope.mailboxes.map(m => m.address)).toEqual([
      REPORTER,
      'person1@example.com',
      'person2@example.com',
    ]);
    expect(scope.live).toMatchObject({ excluded: 3, sameMessageSpreadMinutes: 60 });
    expect(removal.status).toBe('proposed');
    expect(removal.authorization).toBe('approve');
    expect(broker.calls).toEqual([]);
    const text = sent.find(e => e.to === TEAM[0])!.text;
    expect(text).toContain('Remove remaining copies from mailboxes');
    expect(text).not.toContain('(dry run)');
    expect(text).toContain(
      'Moves 3 copy(ies) in 3 mailbox(es) to each person\'s Deleted Items, all carrying the same Internet Message-ID as the reported copy, from billing@examp1e-billing[.]test with exactly the subject "Invoice 2291 overdue", arriving between Tue, 17 Nov 2026, 09:14 UTC and Tue, 17 Nov 2026, 09:50 UTC (within 60 minutes of the reported copy).'
    );
    expect(text).toContain(
      'A legitimate email from the same sender with the same subject and the same Message-ID in that window would also be moved'
    );
    expect(text).not.toMatch(/size|distinct email|strongest|is the reported email itself/);
    expect(text).toContain(
      '3 copy(ies) matched by the lookup but not provably the same email: not included in removal'
    );
    expect(text).toContain(`APPROVE REMOVAL ${removal.reference}`);
    // A later report does not run it either
    await svc.handleCampaignReport(campaignReport([recipient(1), recipient(6)]));
    expect(broker.calls).toEqual([]);
  });

  it('a removed size setting in the configuration changes nothing', async () => {
    const { service: svc, store } = service({
      cfg: {
        removal: { mode: 'live', sizeTolerancePercent: 10, windowHours: 72 } as never,
      },
    });
    await svc.handleCampaignReport(
      campaignReport([
        recipient(1),
        recipient(3, {}, { internetMessageId: '<other-3@mail.examp1e-billing.test>' }),
        recipient(4, {}, { receivedAt: '2026-11-17T12:14:00.000Z' }),
      ])
    );
    const scope = removals(store)[0].scope as RemovalScope;
    expect(scope.mailboxes.map(m => m.address)).toEqual([REPORTER, 'person1@example.com']);
  });

  it('never executes copies a stored scope from the earlier version admitted on size', async () => {
    const { service: svc, store, broker } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1), recipient(2)]));
    const removal = removals(store)[0];
    const scope = removal.scope as RemovalScope;
    // Rewrite the stored scope as the earlier version stored it: person2's
    // copy admitted on size with another Message-ID, and the old basis fields
    const legacyId = '<other-2@mail.examp1e-billing.test>';
    const person2 = scope.mailboxes.find(m => m.address === 'person2@example.com')!;
    person2.verify = person2.verify!.map(check => ({
      ...check,
      internetMessageId: legacyId,
      receivedFrom: '2026-11-17T03:14:00.000Z',
      receivedTo: '2026-11-17T15:14:00.000Z',
    }));
    Object.assign(scope.live!, {
      windowHours: 6,
      sizeTolerancePercent: 1,
      distinctMessages: 2,
      sameMessageIdAsAnchor: 2,
      matchedOnSize: 1,
      sizeReceived: { first: RECEIVED, last: RECEIVED },
      anchor: { ...scope.live!.anchor, size: 20_000 },
    });
    // The reach the approval re-checks still lists that copy
    const legacyReach = reachOf([
      reporterRow(),
      recipient(1),
      recipient(2, {}, { internetMessageId: legacyId }),
    ]);
    store.incidents[0].reach = legacyReach;
    // Reading it back and approving it does not throw
    const reply = await svc.handleApprovals(approveLine(removal.reference), TEAM[0]);
    expect(broker.calls).toHaveLength(1);
    const sentIds = broker.calls[0].params.mailboxes.flatMap(m => m.messages.map(x => x.messageId));
    expect(sentIds.sort()).toEqual(['AAMkAG-1', 'AAMkAG-reporter'].sort());
    const text = reply.body.join('\n');
    expect(text).toContain(
      '1 message(s) were not attempted: they were proposed because their size matched'
    );
    expect(store.actions.find(a => a.id === removal.id)?.result?.removalOutcome).toMatchObject({
      moved: 2,
      notAttempted: 1,
    });
  });

  it('stores one anchor when two reports open the same incident at once', async () => {
    // Creation is INSERT ... ON CONFLICT (campaign_signature) DO NOTHING: one
    // insert wins; the other reads the winner's row and joins it as an update,
    // where the stored anchor is kept (summary and write-once store)
    const { service: svc, store } = service();
    const later = '<later@mail.examp1e-billing.test>';
    const first = campaignReport([recipient(1)]);
    const second = campaignReport(
      [recipient(1)],
      retrieved({ internetMessageId: later }, { 'In-Reply-To': later })
    ) as { blastRadius: BlastRadiusReport };
    second.blastRadius.recipients![0] = reporterRow({
      copyDetails: [detail('AAMkAG-reporter', { internetMessageId: later })],
    });
    await Promise.all([svc.handleCampaignReport(first), svc.handleCampaignReport(second as never)]);
    expect(store.incidents).toHaveLength(1);
    expect(store.incidents[0].summary.removalAnchor?.internetMessageId).toBe(IMID);
    // Every removal proposed rests on that one anchor
    for (const action of removals(store)) {
      const scope = action.scope as RemovalScope;
      expect(scope.live?.anchor.internetMessageId).toBe(IMID);
    }
  });

  it('keeps the first anchor when two reports are processed at once', async () => {
    const { service: svc, store } = service();
    // The incident exists without an anchor (its first report had none)
    await svc.handleCampaignReport(campaignReport([recipient(1)], {}));
    const second = campaignReport([recipient(1)]);
    const third = campaignReport(
      [recipient(1)],
      retrieved(
        { internetMessageId: '<later@mail.examp1e-billing.test>' },
        { 'In-Reply-To': '<later@mail.examp1e-billing.test>' }
      )
    ) as { blastRadius: BlastRadiusReport };
    third.blastRadius.recipients![0] = reporterRow({
      copyDetails: [
        detail('AAMkAG-reporter', { internetMessageId: '<later@mail.examp1e-billing.test>' }),
      ],
    });
    // Both read the incident before either writes it
    await Promise.all([svc.handleCampaignReport(second), svc.handleCampaignReport(third as never)]);
    expect(store.incidents[0].summary.removalAnchor?.internetMessageId).toBe(IMID);
    // A later write without an anchor does not drop it either
    await store.updateIncident(store.incidents[0].id, {
      summary: { ...store.incidents[0].summary, removalAnchor: undefined },
    });
    expect(store.incidents[0].summary.removalAnchor?.internetMessageId).toBe(IMID);
  });

  it.each([
    ['no original-message lookup result', {}, 'no_anchor'],
    [
      'a Report-button submission',
      { ...retrieved(), userReport: { reportedAs: 'phishing' } },
      'no_anchor',
    ],
  ] as const)(
    'proposes only a dry run, and says why, for %s',
    async (_label, emailData, reason) => {
      const { service: svc, store, sent } = service();
      await svc.handleCampaignReport(campaignReport([recipient(1)], emailData as never));
      expect(removals(store)[0].scope).toMatchObject({ liveUnavailable: reason });
      expect(removals(store)[0].scope).not.toHaveProperty('mode');
      const text = sent.find(e => e.to === TEAM[0])!.text;
      expect(text).toContain('Remove remaining copies from mailboxes (dry run)');
      expect(text).toContain('A live removal is not proposed for this incident');
    }
  );

  it('runs a dry-run proposal as a dry run even though the deployment is live', async () => {
    const { service: svc, store, broker } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)], {}));
    const reply = await svc.handleApprovals(approveLine(removals(store)[0].reference), TEAM[0]);
    expect(broker.calls).toEqual([]);
    expect(removals(store)[0].status).toBe('dry_run_completed');
    expect(reply.body.join('\n')).toContain(
      'This removal was proposed as a dry run, so it ran as a dry run'
    );
  });

  it('runs a live proposal as a dry run when the deployment is no longer live', async () => {
    const clock = { now: new Date('2026-11-17T10:00:00.000Z') };
    const live = service({ clock });
    await live.service.handleCampaignReport(campaignReport([recipient(1)]));
    const reference = removals(live.store)[0].reference;
    // The operator switches back to dry run; the stored proposal remains
    const dry = service({ live: false, store: live.store, clock });
    const reply = await dry.service.handleApprovals(approveLine(reference), TEAM[0]);
    expect(live.broker.calls).toEqual([]);
    expect(dry.broker.calls).toEqual([]);
    expect(removals(live.store)[0].status).toBe('dry_run_completed');
    expect(reply.body.join('\n')).toContain(
      'proposed as a live removal, but this deployment is now set to dry run'
    );
  });

  it('proposes the live removal after a dry run of the same copies (the mode is part of the scope)', async () => {
    const { service: svc, store, advance } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)], {}));
    await svc.handleApprovals(approveLine(removals(store)[0].reference), TEAM[0]);
    advance(31 * 60_000);
    const later = campaignReport([recipient(1)]);
    (later as { match: { detectionCount: number; shouldAlert: boolean } }).match.detectionCount = 4;
    await svc.handleCampaignReport(later);
    expect(
      removals(store).map(a => [a.status, a.scope.kind === 'remove_messages' ? a.scope.mode : 'x'])
    ).toEqual([
      ['dry_run_completed', undefined],
      ['proposed', 'live'],
    ]);
  });

  it('a fan-out scan incident proposes only a dry-run removal', async () => {
    const { service: svc, store, sent } = service();
    await svc.openIncidentFromFanoutAlert({
      subject: SUBJECT,
      senderAddress: SENDER,
      reach: report([recipient(1), recipient(2)]),
      reasons: ['One external sender reached 40 internal recipients in 6 minutes'],
    });
    expect(removals(store)[0].scope).toMatchObject({ liveUnavailable: 'no_reports' });
    expect(removals(store)[0].scope).not.toHaveProperty('mode');
    expect(sent[0].text).toContain('nobody has reported it yet');
  });

  it('a malicious verdict is required for a live proposal', async () => {
    const { service: svc, store } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)], retrieved(), 'suspicious'));
    expect(removals(store)[0].scope).toMatchObject({ liveUnavailable: 'not_malicious' });
  });

  it('runs only on the exact approval, notices only people whose copy was moved, audits the counts', async () => {
    const {
      service: svc,
      store,
      sent,
      broker,
    } = service({
      decide: mailboxId =>
        mailboxId === MAILBOX(1)
          ? 'moved'
          : mailboxId === MAILBOX(2)
            ? 'mismatch'
            : 'already_deleted',
    });
    await svc.handleCampaignReport(
      campaignReport([
        recipient(1),
        recipient(2),
        recipient(3),
        recipient(4, { address: 'outsider@partner.test' }),
      ])
    );
    const removal = removals(store)[0];
    const reply = await svc.handleApprovals(approveLine(removal.reference), TEAM[0]);
    expect(broker.calls).toHaveLength(1);
    const text = reply.body.join('\n');
    expect(text).toContain('Approved: removal of remaining copies (moves them to Deleted Items)');
    expect(text).toContain('1 message(s) moved to Deleted Items in 1 mailbox(es)');
    expect(text).toContain('Sent 1 removal notice(s)');
    expect(sent.filter(e => e.subject.startsWith('Security notice')).map(e => e.to)).toEqual([
      'person1@example.com',
    ]);
    expect(store.actions.find(a => a.id === removal.id)).toMatchObject({
      status: 'completed',
      executor: 'graph_write_removal',
    });
    const audit = store.audit.find(e => e.event === 'action_executed' && e.actionId === removal.id);
    expect(audit?.detail).toMatchObject({
      executor: 'graph_write_removal',
      moved: 1,
      mismatch: 1,
      alreadyDeleted: 3, // the reporter's copy and person3's and the outsider's
      removedMailboxes: 1,
      notified: 1,
    });
  });

  it('never notifies an address outside the safe domains even when its copy was moved', async () => {
    const { service: svc, store, sent } = service();
    await svc.handleCampaignReport(
      campaignReport([recipient(1), recipient(4, { address: 'outsider@partner.test' })])
    );
    await svc.handleApprovals(approveLine(removals(store)[0].reference), TEAM[0]);
    expect(
      sent
        .filter(e => e.subject.startsWith('Security notice'))
        .map(e => e.to)
        .sort()
    ).toEqual(['person1@example.com', REPORTER].sort());
  });

  it('keeps the real result and tells the approver the truth when recording it fails', async () => {
    const { service: svc, store, sent } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)]));
    const removal = removals(store)[0];
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const realFinish = store.finishAction.bind(store);
    store.finishAction = jest.fn(async () => {
      throw new Error('database unavailable');
    }) as typeof store.finishAction;
    const reply = await svc.handleApprovals(approveLine(removal.reference), TEAM[0]);
    store.finishAction = realFinish;
    const text = reply.body.join('\n');
    expect(text).toContain('2 message(s) moved to Deleted Items');
    expect(text).toContain('Sent 2 removal notice(s)');
    expect(text).toContain('could not record this result');
    expect(text).not.toContain('no removal notice was sent');
    expect(sent.filter(e => e.subject.startsWith('Security notice'))).toHaveLength(2);
    expect(error.mock.calls.map(c => String(c[0])).join('\n')).toContain('"moved":2');
    error.mockRestore();
  });

  it('does not count people as notified for an approved removal that never recorded a result', async () => {
    const { service: svc, store, sent, advance } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)]));
    const first = removals(store)[0];
    // Stuck: approved an hour ago, no result recorded
    await store.approveAction(first.id, TEAM[0]);
    advance(60 * 60_000);
    const second = await store.createAction({
      incidentId: store.incidents[0].id,
      reference: 'PHY-ZZZZ-ZZZZ-ZZZZ-ZZZ2',
      type: 'remove_messages',
      authorization: 'approve',
      scope: first.scope,
      scopeHash: 'again',
      expiresAt: new Date(advanceTo(store, 3)),
    });
    await svc.handleApprovals(approveLine(second.reference), TEAM[0]);
    expect(
      sent
        .filter(e => e.subject.startsWith('Security notice'))
        .map(e => e.to)
        .sort()
    ).toEqual(['person1@example.com', REPORTER].sort());
  });

  async function approveThenUpdate(failure?: GraphWriteCallResult) {
    const ctx = service({ failure });
    const recipients = [recipient(1), recipient(2)];
    await ctx.service.handleCampaignReport(campaignReport(recipients));
    await ctx.service.handleApprovals(approveLine(removals(ctx.store)[0].reference), TEAM[0]);
    ctx.advance(31 * 60_000);
    const later = campaignReport(recipients);
    (later as { match: { detectionCount: number; shouldAlert: boolean } }).match.detectionCount = 4;
    (later as { match: { detectionCount: number; shouldAlert: boolean } }).match.shouldAlert =
      false;
    await ctx.service.handleCampaignReport(later);
    return removals(ctx.store);
  }

  it('does not propose the same removal again once it has been fully carried out', async () => {
    const all = await approveThenUpdate();
    expect(all).toHaveLength(1);
    expect(all[0].status).toBe('completed');
  });

  it('proposes the same removal again when the write broker refused it', async () => {
    const all = await approveThenUpdate({
      ok: false,
      failure: 'refused',
      refusal: 'write_disabled',
    });
    expect(all.map(a => a.status)).toEqual(['completed', 'proposed']);
    expect(all[1].scopeHash).toBe(all[0].scopeHash);
  });

  it('heads the reply with what happened when an approved removal moved nothing', async () => {
    const refused = service({
      failure: { ok: false, failure: 'refused', refusal: 'write_disabled' },
    });
    await refused.service.handleCampaignReport(campaignReport([recipient(1)]));
    const reply = await refused.service.handleApprovals(
      approveLine(removals(refused.store)[0].reference),
      TEAM[0]
    );
    expect(reply.heading).toBe('Approved, but no message was moved');
    expect(reply.body[1]).toContain('refused the request (write_disabled)');

    const moved = service();
    await moved.service.handleCampaignReport(campaignReport([recipient(1)]));
    const done = await moved.service.handleApprovals(
      approveLine(removals(moved.store)[0].reference),
      TEAM[0]
    );
    expect(done.heading).toBe('Done: approval carried out');
    expect(done.body[1]).toContain('Removal carried out by the Graph write broker');
  });

  it('sends the update at once when a report first gives the incident its anchor', async () => {
    const later = () => {
      const next = campaignReport([recipient(1)]);
      (next as { match: { detectionCount: number } }).match.detectionCount = 4;
      return next;
    };
    const { service: svc, store, sent, advance } = service();
    // No anchor yet: only a dry run can be proposed
    await svc.handleCampaignReport(campaignReport([recipient(1)], {}));
    advance(2 * 60_000);
    expect(await svc.handleCampaignReport(later())).toBe('updated');
    expect(removals(store).some(a => (a.scope as RemovalScope).mode === 'live')).toBe(true);
    expect(sent[sent.length - 1].text).toContain('so a live removal can be proposed');
    // Once per incident: the next report inside the interval is deferred
    const again = later();
    (again as { match: { detectionCount: number } }).match.detectionCount = 5;
    advance(2 * 60_000);
    expect(await svc.handleCampaignReport(again)).toBe('update_deferred');

    // A dry-run deployment gains nothing from the anchor: the interval holds
    const dry = service({ live: false });
    await dry.service.handleCampaignReport(campaignReport([recipient(1)], {}));
    dry.advance(2 * 60_000);
    expect(await dry.service.handleCampaignReport(later())).toBe('update_deferred');
  });

  it('refuses a malformed approval and runs nothing', async () => {
    const { service: svc, store, broker } = service();
    await svc.handleCampaignReport(campaignReport([recipient(1)]));
    const removal = removals(store)[0];
    await svc.handleApprovals(approveLine(`${removal.reference}X`), TEAM[0]);
    await svc.handleApprovals(approveLine(removal.reference), 'mallory@example.org');
    await svc.handleApprovals([{ verb: 'WARNING', reference: removal.reference }], TEAM[0]);
    expect(broker.calls).toEqual([]);
  });
});

/** An expiry `hours` after the store's clock (via its latest incident's creation) */
function advanceTo(store: FakeResponseStore, hours: number): number {
  return store.incidents[0].createdAt.getTime() + hours * 3_600_000 + 2 * 3_600_000;
}

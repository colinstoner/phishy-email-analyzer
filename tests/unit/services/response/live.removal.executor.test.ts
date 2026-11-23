/**
 * The live removal executor and its selection, and the live removal through
 * CampaignResponseService: what is sent to the write broker (never wider than
 * the approved, re-checked scope), how its answers become the approver's
 * summary, the audit row and the removal notices, and that a removal is
 * never automatic. The write broker is a stub (no Lambda, no Graph).
 * Invented example.com data only.
 */

import { CampaignResponseService } from '../../../../src/services/response/campaign.response.service';
import {
  DryRunRemovalExecutor,
  createRemovalExecutor,
} from '../../../../src/services/response/executors';
import { LiveRemovalExecutor } from '../../../../src/services/response/live.removal.executor';
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
} from '../../../../src/services/graph/blast-radius.service';
import type { CampaignResponseConfig } from '../../../../src/config/schema';
import { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } from '../../../../src/config/schema';
import type {
  IncidentReach,
  RemovalScope,
  ResponseAction,
} from '../../../../src/services/response/response.types';
import { computeRemovalScope, mergeReach } from '../../../../src/services/response/scope';
import type { ApprovalCommand } from '../../../../src/services/commands/response.commands';
import { FakeResponseStore } from './fake.store';

const MAILBOX = (n: number): string => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;
const IMID = '<invoice-2291@mail.examp1e-billing.test>';
const ACTION_ID = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';

function recipient(n: number, extra: Partial<BlastRadiusRecipient> = {}): BlastRadiusRecipient {
  return {
    address: `person${n}@example.com`,
    mailbox: 'found',
    folder: 'inbox',
    isRead: false,
    response: 'none',
    mailboxId: MAILBOX(n),
    messageIds: [`AAMkAG-${n}`],
    internetMessageIds: [IMID],
    receivedAt: '2026-11-17T09:14:00.000Z',
    ...extra,
  };
}

function report(recipients: BlastRadiusRecipient[]): BlastRadiusReport {
  return {
    status: 'complete',
    route: 'trace',
    matchedBy: 'messageId',
    totals: { recipients: recipients.length, read: 0, replied: 0, forwarded: 0 },
    recipients,
    lookedUpAt: '2026-11-17T10:00:00.000Z',
  };
}

function reachOf(recipients: BlastRadiusRecipient[]): IncidentReach {
  return mergeReach(undefined, report(recipients), true);
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
        if (failure) {
          return failure;
        }
        return {
          ok: true as const,
          result: {
            mailboxes: params.mailboxes.map(m => ({
              mailboxId: m.mailboxId,
              messages: m.messageIds.map(id => ({
                messageId: id,
                outcome: decide(m.mailboxId, id),
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
        };
      }),
    },
  };
}

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

describe('LiveRemovalExecutor', () => {
  it('sends exactly the approved, re-checked copies with their recorded Internet Message-IDs', async () => {
    const approvedReach = reachOf([recipient(1), recipient(2), recipient(3)]);
    const scope = computeRemovalScope(approvedReach, { maxMailboxes: 500, maxMessages: 1000 });
    // Since approval: person2's copy is gone, person4 newly holds one, person1 has a new copy too
    const current = reachOf([
      recipient(1, { messageIds: ['AAMkAG-1', 'AAMkAG-1-new'] }),
      recipient(2, { mailbox: 'not_found', messageIds: undefined }),
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
    expect(broker.calls[0].params).toEqual({
      actionId: ACTION_ID,
      mailboxes: [
        { mailboxId: MAILBOX(1), messageIds: ['AAMkAG-1'], expectedInternetMessageIds: [IMID] },
        { mailboxId: MAILBOX(3), messageIds: ['AAMkAG-3'], expectedInternetMessageIds: [IMID] },
      ],
      budgetMs: expect.any(Number),
    });
    // No address is ever sent
    expect(JSON.stringify(broker.calls[0].params)).not.toContain('@example.com');
    expect(result.dryRun).toBe(false);
    expect(result.removed).toEqual([
      { mailboxId: MAILBOX(1), messages: 1 },
      { mailboxId: MAILBOX(3), messages: 1 },
    ]);
    expect(result.removalOutcome).toMatchObject({ moved: 2, notAttempted: 0, unknown: 0 });
    const text = result.summary.join('\n');
    expect(text).toContain('2 message(s) moved to Deleted Items in 2 mailbox(es)');
    expect(text).toContain('newer copy(ies) were found that the approved scope does not name');
  });

  it('lists only moved copies in removed, and reports every outcome by count', async () => {
    const reach = reachOf([1, 2, 3, 4, 5, 6].map(n => recipient(n)));
    const scope = computeRemovalScope(reach, { maxMailboxes: 500, maxMessages: 1000 });
    const outcomes: Record<string, MessageOutcome['outcome']> = {
      [MAILBOX(1)]: 'moved',
      [MAILBOX(2)]: 'already_deleted',
      [MAILBOX(3)]: 'not_found',
      [MAILBOX(4)]: 'mismatch',
      [MAILBOX(5)]: 'error',
      [MAILBOX(6)]: 'not_allowed',
    };
    const broker = stubBroker(mailboxId => outcomes[mailboxId]);
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
    expect(text).toContain('Mailboxes with errors or an unknown outcome: person5@example[.]com.');
    expect(text).toContain('refused, not the approved message');
  });

  it('does not send mailboxes whose scope recorded no Internet Message-ID', async () => {
    const reach = reachOf([recipient(1, { internetMessageIds: undefined }), recipient(2)]);
    const scope = computeRemovalScope(reach, { maxMailboxes: 500, maxMessages: 1000 });
    const broker = stubBroker();
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach
    );
    expect(broker.calls[0].params.mailboxes.map(m => m.mailboxId)).toEqual([MAILBOX(2)]);
    expect(result.removalOutcome).toMatchObject({ moved: 1, notAttempted: 1 });
    expect(result.summary.join('\n')).toContain('did not record their Internet Message-ID');
  });

  it('splits a large scope into calls within the protocol bounds, and stops when time runs out', async () => {
    const reach = reachOf(
      Array.from({ length: 120 }, (_, i) =>
        recipient(i + 1, { messageIds: [`A-${i}-1`, `A-${i}-2`] })
      )
    );
    const scope = computeRemovalScope(reach, { maxMailboxes: 500, maxMessages: 1000 });
    const broker = stubBroker();
    let remaining = 180_000;
    broker.client.removeMessages.mockImplementation(async (params: RemoveMessagesParams) => {
      broker.calls.push({ params, timeoutMs: 0 });
      remaining -= 80_000;
      return {
        ok: true as const,
        result: {
          mailboxes: params.mailboxes.map(m => ({
            mailboxId: m.mailboxId,
            messages: m.messageIds.map(id => ({ messageId: id, outcome: 'moved' as const })),
          })),
          bounds: {
            maxMailboxes: 50,
            maxMessagesPerMailbox: 5,
            maxMessages: 100,
            budgetMs: 1,
            concurrency: 4,
          },
          durationMs: 1,
        },
      };
    });
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach,
      { getRemainingMs: () => remaining }
    );
    for (const call of broker.calls) {
      expect(call.params.mailboxes.length).toBeLessThanOrEqual(50);
      expect(
        call.params.mailboxes.reduce((n, m) => n + m.messageIds.length, 0)
      ).toBeLessThanOrEqual(100);
    }
    // 240 messages = 3 calls of 100/100/40; time allows only two
    expect(broker.calls).toHaveLength(2);
    expect(result.removalOutcome).toMatchObject({ moved: 200, notAttempted: 40 });
    expect(result.summary.join('\n')).toContain(
      '40 message(s) were not attempted because the time available ran out'
    );
  });

  it('treats an unanswered call as unknown and tells nobody their copy was removed', async () => {
    const reach = reachOf([recipient(1), recipient(2)]);
    const scope = computeRemovalScope(reach, { maxMailboxes: 500, maxMessages: 1000 });
    const broker = stubBroker(undefined, { ok: false, failure: 'timeout' });
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach
    );
    expect(result.removed).toEqual([]);
    expect(result.removalOutcome).toMatchObject({ unknown: 2, moved: 0 });
    expect(result.summary.join('\n')).toContain('outcome unknown');
  });

  it('stops sending after a refusal and says why', async () => {
    const reach = reachOf(Array.from({ length: 60 }, (_, i) => recipient(i + 1)));
    const scope = computeRemovalScope(reach, { maxMailboxes: 500, maxMessages: 1000 });
    const broker = stubBroker(undefined, {
      ok: false,
      failure: 'refused',
      refusal: 'write_disabled',
    });
    const result = await new LiveRemovalExecutor({ client: broker.client }).execute(
      action(scope),
      scope,
      reach
    );
    expect(broker.calls).toHaveLength(1);
    expect(result.removalOutcome).toMatchObject({ notAttempted: 60, unknown: 0 });
    expect(result.summary.join('\n')).toContain('kill switch (PHISHY_GRAPH_WRITE_ENABLED) is off');
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

function liveService(
  decide: (mailboxId: string, messageId: string) => MessageOutcome['outcome'],
  cfg: Partial<CampaignResponseConfig> = {},
  failure?: GraphWriteCallResult
) {
  let now = new Date('2026-11-17T10:00:00.000Z');
  const store = new FakeResponseStore(() => now);
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
  const broker = stubBroker(decide, failure);
  const service = new CampaignResponseService({
    store: store.asStore(),
    mailer,
    config: serviceConfig(cfg),
    safeDomains: ['example.com'],
    securityTeam: TEAM,
    commandsEnabled: true,
    legacyAlert: jest.fn().mockResolvedValue(true),
    markCampaignAlerted: jest.fn().mockResolvedValue(undefined),
    removalExecutor: new LiveRemovalExecutor({ client: broker.client }),
    now: () => now,
    newReference: (() => {
      let r = 0;
      return () => `PHY-AAAA-BBBB-CCCC-DDD${'2345679'[r++ % 7]}`;
    })(),
  });
  const advance = (ms: number): void => {
    now = new Date(now.getTime() + ms);
  };
  return { service, store, sent, broker, advance };
}

function campaignReport(recipients: BlastRadiusRecipient[]) {
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
      uniqueRecipients: ['reporter1@example.com', 'reporter2@example.com'],
      riskLevel: 'critical',
      sampleIndicators: [],
      firstSeenAt: new Date('2026-11-17T09:21:00.000Z'),
      lastSeenAt: new Date('2026-11-17T09:40:00.000Z'),
      isActive: true,
    },
    risk: {
      verdict: 'phishing' as const,
      riskScore: 92,
      riskLevel: 'critical' as const,
      reasons: ['Lookalike sender domain'],
    },
    analysis: { summary: 'Fake invoice reminder', indicators: ['Lookalike sender domain'] },
    emailData: { subject: 'Fwd: Invoice 2291 overdue', forwardedHeaders: {} },
    blastRadius: report(recipients),
    blastRadiusEnabled: true,
  };
}

const approveLine = (reference: string): ApprovalCommand[] => [{ verb: 'REMOVAL', reference }];

describe('a live removal through CampaignResponseService', () => {
  it('says in the incident email that approving moves copies, and never runs it automatically', async () => {
    const { service, store, sent, broker } = liveService(() => 'moved', {
      employeeWarning: 'auto',
      distributionWarning: 'auto',
    });
    await service.handleCampaignReport(campaignReport([recipient(1), recipient(2)]) as never);
    const removal = store.actions.find(a => a.type === 'remove_messages')!;
    // Proposed for approval, whatever the other actions' modes are
    expect(removal.status).toBe('proposed');
    expect(removal.authorization).toBe('approve');
    expect(broker.calls).toEqual([]);
    const incidentEmail = sent.find(e => e.to === TEAM[0])!;
    expect(incidentEmail.text).toContain('Remove remaining copies from mailboxes');
    expect(incidentEmail.text).toContain("to each person's Deleted Items");
    expect(incidentEmail.text).not.toContain('(dry run)');
    expect(incidentEmail.text).toContain(`APPROVE REMOVAL ${removal.reference}`);
    // A later report does not run it either
    await service.handleCampaignReport(
      campaignReport([recipient(1), recipient(2), recipient(3)]) as never
    );
    expect(broker.calls).toEqual([]);
    expect(
      store.actions.filter(a => a.type === 'remove_messages').every(a => a.status !== 'completed')
    ).toBe(true);
  });

  it('runs only on the exact approval, notices only people whose copy was moved, audits the counts', async () => {
    const { service, store, sent, broker } = liveService(mailboxId =>
      mailboxId === MAILBOX(1) ? 'moved' : mailboxId === MAILBOX(2) ? 'mismatch' : 'already_deleted'
    );
    await service.handleCampaignReport(
      campaignReport([
        recipient(1),
        recipient(2),
        recipient(3),
        recipient(4, { address: 'outsider@partner.test' }),
      ]) as never
    );
    const removal = store.actions.find(a => a.type === 'remove_messages')!;
    const reply = await service.handleApprovals(approveLine(removal.reference), TEAM[0]);
    expect(broker.calls).toHaveLength(1);
    const text = reply.body.join('\n');
    expect(text).toContain('Approved: removal of remaining copies (moves them to Deleted Items)');
    expect(text).toContain('1 message(s) moved to Deleted Items in 1 mailbox(es)');
    expect(text).toContain('Sent 1 removal notice(s)');

    const notices = sent.filter(e => e.subject.startsWith('Security notice'));
    expect(notices.map(e => e.to)).toEqual(['person1@example.com']);

    expect(store.actions.find(a => a.id === removal.id)).toMatchObject({
      status: 'completed',
      executor: 'graph_write_removal',
    });
    const audit = store.audit.find(e => e.event === 'action_executed' && e.actionId === removal.id);
    expect(audit?.detail).toMatchObject({
      executor: 'graph_write_removal',
      moved: 1,
      mismatch: 1,
      alreadyDeleted: 2,
      removedMailboxes: 1,
      notified: 1,
    });
  });

  it('never notifies an address outside the safe domains even when its copy was moved', async () => {
    const { service, store, sent } = liveService(() => 'moved');
    await service.handleCampaignReport(
      campaignReport([recipient(1), recipient(4, { address: 'outsider@partner.test' })]) as never
    );
    const removal = store.actions.find(a => a.type === 'remove_messages')!;
    await service.handleApprovals(approveLine(removal.reference), TEAM[0]);
    expect(sent.filter(e => e.subject.startsWith('Security notice')).map(e => e.to)).toEqual([
      'person1@example.com',
    ]);
  });

  async function approveThenUpdate(
    decide: (mailboxId: string, messageId: string) => MessageOutcome['outcome'],
    failure?: GraphWriteCallResult
  ) {
    const ctx = liveService(decide, {}, failure);
    const recipients = [recipient(1), recipient(2)];
    await ctx.service.handleCampaignReport(campaignReport(recipients) as never);
    const removal = ctx.store.actions.find(a => a.type === 'remove_messages')!;
    await ctx.service.handleApprovals(approveLine(removal.reference), TEAM[0]);
    ctx.advance(31 * 60_000);
    const later = campaignReport(recipients);
    later.match = { ...later.match, detectionCount: 4, shouldAlert: false };
    await ctx.service.handleCampaignReport(later as never);
    return ctx.store.actions.filter(a => a.type === 'remove_messages');
  }

  it('does not propose the same removal again once it has been fully carried out', async () => {
    const removals = await approveThenUpdate(() => 'moved');
    expect(removals).toHaveLength(1);
    expect(removals[0].status).toBe('completed');
  });

  it('proposes the same removal again when the write broker refused it', async () => {
    const removals = await approveThenUpdate(() => 'moved', {
      ok: false,
      failure: 'refused',
      refusal: 'write_disabled',
    });
    expect(removals.map(a => a.status)).toEqual(['completed', 'proposed']);
    expect(removals[1].scopeHash).toBe(removals[0].scopeHash);
  });

  it('refuses a malformed approval and runs nothing', async () => {
    const { service, store, broker } = liveService(() => 'moved');
    await service.handleCampaignReport(campaignReport([recipient(1)]) as never);
    const removal = store.actions.find(a => a.type === 'remove_messages')!;
    await service.handleApprovals(approveLine(`${removal.reference}X`), TEAM[0]);
    await service.handleApprovals(approveLine(removal.reference), 'mallory@example.org');
    await service.handleApprovals([{ verb: 'WARNING', reference: removal.reference }], TEAM[0]);
    expect(broker.calls).toEqual([]);
  });
});

/**
 * Campaign response: incident email, targeted warning, approvals, expiry,
 * idempotency, dry-run removal, threading, false positives, fallback and
 * the fan-out trigger. No AWS, no Graph, no database: an in-memory store
 * and a recording mailer. Invented example.com data only.
 */

import {
  CampaignReportInput,
  CampaignResponseService,
  countReach,
} from '../../../../src/services/response/campaign.response.service';
import type {
  BlastRadiusRecipient,
  BlastRadiusReport,
} from '../../../../src/services/graph/blast-radius.service';
import type { CampaignResponseConfig } from '../../../../src/config/schema';
import { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } from '../../../../src/config/schema';
import type { ApprovalCommand } from '../../../../src/services/commands/response.commands';
import type { RemovalExecutor } from '../../../../src/services/response/executors';
import type {
  ActionResult,
  RemovedMailbox,
} from '../../../../src/services/response/response.types';
import { FakeResponseStore } from './fake.store';

const SAFE = ['example.com'];
const TEAM = ['security@example.com', 'soc@example.com'];
const LIST = 'everyone@example.com';
const SIGNATURE = 'abcdef0123456789';
const MAILBOX = (n: number): string => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;

interface SentEmail {
  to: string;
  cc?: string[];
  subject: string;
  html: string;
  text: string;
  inReplyTo?: string;
  threaded?: string[];
}

function makeMailer() {
  const sent: SentEmail[] = [];
  let n = 0;
  return {
    sent,
    mailer: {
      sendEmail: jest.fn(
        async (to: string, subject: string, html: string, text: string, cc?: string[]) => {
          sent.push({ to, cc, subject, html, text });
          n += 1;
          return { success: true, messageId: `ses-${n}` };
        }
      ),
      sendThreadedEmail: jest.fn(
        async (
          recipients: string[],
          subject: string,
          html: string,
          text: string,
          inReplyTo?: string
        ) => {
          sent.push({ to: recipients[0], threaded: recipients, subject, html, text, inReplyTo });
          n += 1;
          return { success: true, messageId: `ses-${n}` };
        }
      ),
    },
  };
}

function config(overrides: Partial<CampaignResponseConfig> = {}): CampaignResponseConfig {
  return {
    enabled: true,
    audience: 'recipients',
    employeeWarning: 'approve',
    distributionWarning: 'auto',
    approvalTtlHours: 4,
    maxWarningsPerCampaign: 100,
    maxRemovalMailboxes: 500,
    maxRemovalMessages: 1000,
    updateIntervalMinutes: 30,
    // Off here so the suites above test the report-count trigger alone
    // (exactly the behaviour before the reach trigger); see 'the reach trigger'
    reachThreshold: 0,
    alreadyClickedInstructions: DEFAULT_ALREADY_CLICKED_INSTRUCTIONS,
    timeZone: 'UTC',
    ...overrides,
  };
}

function recipient(n: number, extra: Partial<BlastRadiusRecipient> = {}): BlastRadiusRecipient {
  return {
    address: `person${n}@example.com`,
    mailbox: 'found',
    folder: 'inbox',
    isRead: n % 2 === 0,
    response: 'none',
    mailboxId: MAILBOX(n),
    messageIds: [`AAMkAG-${n}`],
    receivedAt: '2026-11-17T09:14:00.000Z',
    ...extra,
  };
}

function blast(recipients: BlastRadiusRecipient[]): BlastRadiusReport {
  return {
    status: 'complete',
    route: 'trace',
    matchedBy: 'messageId',
    criteria: {
      senderAddress: 'billing@examp1e-billing.test',
      subject: 'Invoice 2291 overdue',
      receivedFrom: '2026-11-16T09:00:00.000Z',
      receivedTo: '2026-11-17T12:00:00.000Z',
    },
    totals: { recipients: recipients.length, read: 0, replied: 0, forwarded: 0 },
    recipients,
    lookedUpAt: '2026-11-17T10:00:00.000Z',
  };
}

const REPORTERS = ['reporter1@example.com', 'reporter2@example.com', 'reporter3@example.com'];

function reportInput(overrides: Partial<CampaignReportInput> = {}): CampaignReportInput {
  return {
    match: {
      campaignId: 'campaign-1',
      signature: SIGNATURE,
      detectionCount: 3,
      uniqueRecipientCount: 3,
      hoursActive: 0.5,
      shouldAlert: true,
    },
    campaign: {
      id: 'campaign-1',
      campaignSignature: SIGNATURE,
      senderDomain: 'example.com',
      subjectPattern: 'fwd invoice # overdue',
      detectionCount: 3,
      uniqueRecipients: REPORTERS,
      riskLevel: 'critical',
      sampleIndicators: [],
      firstSeenAt: new Date('2026-11-17T09:21:00.000Z'),
      lastSeenAt: new Date('2026-11-17T09:40:00.000Z'),
      isActive: true,
    },
    risk: {
      verdict: 'phishing',
      riskScore: 92,
      riskLevel: 'critical',
      reasons: ['Matches a known malicious link'],
      confidence: 'Very High',
      confidenceBasis: 'model',
    },
    analysis: {
      summary: 'Fake invoice reminder linking to https://login.examp1e-billing.test/pay',
      indicators: ['Lookalike sender domain', 'Credential page behind the link'],
    },
    emailData: {
      subject: 'Fwd: Invoice 2291 overdue',
      forwardedHeaders: {
        'Original-From': 'Accounts Team <billing@examp1e-billing.test>',
        'Original-Subject': 'Invoice 2291 overdue',
      },
    },
    analysisId: '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
    blastRadius: blast([
      recipient(1),
      recipient(2),
      recipient(3, { folder: 'junk' }),
      {
        address: 'reporter1@example.com',
        mailbox: 'found',
        folder: 'inbox',
        mailboxId: MAILBOX(9),
        messageIds: ['AAMkAG-9'],
      },
      { address: 'failed@example.com', mailbox: 'not_delivered' },
      recipient(4, { address: 'outsider@partner.test' }),
    ]),
    blastRadiusEnabled: true,
    ...overrides,
  };
}

function setup(
  cfg: Partial<CampaignResponseConfig> = {},
  options: {
    commandsEnabled?: boolean;
    distributionList?: string;
    removalExecutor?: RemovalExecutor;
  } = {}
) {
  let now = new Date('2026-11-17T10:00:00.000Z');
  const clock = (): Date => now;
  const store = new FakeResponseStore(clock);
  const { sent, mailer } = makeMailer();
  const legacyAlert = jest.fn().mockResolvedValue(true);
  const markCampaignAlerted = jest.fn().mockResolvedValue(undefined);
  let refs = 0;
  const service = new CampaignResponseService({
    store: store.asStore(),
    mailer,
    config: config(cfg),
    safeDomains: SAFE,
    securityTeam: TEAM,
    distributionList: options.distributionList,
    commandsEnabled: options.commandsEnabled ?? true,
    legacyAlert,
    markCampaignAlerted,
    ...(options.removalExecutor ? { removalExecutor: options.removalExecutor } : {}),
    now: clock,
    newReference: () => {
      refs += 1;
      return `PHY-AAAA-BBBB-CCCC-${'ABCDEFGHJKMNPQRS'[refs]}${'234567'[refs % 6]}${'XYZ2'[refs % 4]}A`;
    },
  });
  return {
    service,
    store,
    sent,
    mailer,
    legacyAlert,
    markCampaignAlerted,
    advance: (ms: number): void => {
      now = new Date(now.getTime() + ms);
    },
  };
}

function proposed(store: FakeResponseStore, type: 'send_warning' | 'remove_messages') {
  return store.actions.find(a => a.type === type && a.status === 'proposed');
}

function approve(type: 'send_warning' | 'remove_messages', reference: string): ApprovalCommand[] {
  return [{ verb: type === 'send_warning' ? 'WARNING' : 'REMOVAL', reference }];
}

const employeeEmails = (sent: SentEmail[]): SentEmail[] => sent.filter(e => !TEAM.includes(e.to));

describe('opening an incident', () => {
  it('does nothing below the threshold', async () => {
    const { service, sent, store } = setup();
    const input = reportInput();
    input.match.shouldAlert = false;
    expect(await service.handleCampaignReport(input)).toBe('below_threshold');
    expect(sent).toEqual([]);
    expect(store.incidents).toEqual([]);
  });

  it('emails the security team an incident and asks before warning anyone (approve, the default)', async () => {
    const { service, sent, store, markCampaignAlerted } = setup();
    expect(await service.handleCampaignReport(reportInput())).toBe('opened');

    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe('security@example.com');
    expect(sent[0].cc).toEqual(['soc@example.com']);
    expect(employeeEmails(sent)).toEqual([]);

    const warning = proposed(store, 'send_warning');
    const removal = proposed(store, 'remove_messages');
    expect(warning?.scope).toMatchObject({ kind: 'send_warning', distribution: false });
    expect(
      warning?.scope.kind === 'send_warning' && warning.scope.recipients.map(r => r.address)
    ).toEqual(['person1@example.com', 'person2@example.com', 'person3@example.com']);
    expect(warning?.scope).not.toHaveProperty('reporters');
    expect(removal?.scope.kind === 'remove_messages' && removal.scope.messageCount).toBe(5);

    expect(sent[0].text).toContain(`APPROVE WARNING ${warning?.reference}`);
    expect(sent[0].text).toContain(`APPROVE REMOVAL ${removal?.reference}`);
    expect(sent[0].text).toContain('false positive');
    expect(sent[0].text).toContain('Analysis ID: 3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b');
    expect(store.events()).toEqual([
      'incident_opened',
      'action_proposed',
      'action_proposed',
      'incident_email_sent',
    ]);
    expect(markCampaignAlerted).toHaveBeenCalledWith('campaign-1');
    expect(store.incidents[0].threadMessageId).toBe('ses-1');
  });

  it('says the reporter was sent their analysis only when it was', async () => {
    const emailed = setup();
    await emailed.service.handleCampaignReport(reportInput({ reporterReply: 'emailed' }));
    expect(emailed.sent[0].text).toContain('Sent the reporter of this report their own analysis.');

    const silent = setup();
    await silent.service.handleCampaignReport(reportInput({ reporterReply: 'silent' }));
    expect(silent.sent[0].text).not.toContain('their own analysis');
    expect(silent.sent[0].text).toContain(
      'This report came through the Report button, so its reporter was not emailed'
    );

    for (const reporterReply of ['not_sent', undefined] as const) {
      const quiet = setup();
      await quiet.service.handleCampaignReport(reportInput({ reporterReply }));
      expect(quiet.sent[0].text).not.toContain('their own analysis');
      expect(quiet.sent[0].text).not.toContain('Report button');
    }
  });

  it('sends at once, one email per person, when set to auto', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto' });
    await service.handleCampaignReport(reportInput());

    const employees = employeeEmails(sent);
    expect(employees.map(e => e.to).sort()).toEqual(
      ['person1@example.com', 'person2@example.com', 'person3@example.com'].sort()
    );
    for (const email of employees) {
      expect(email.cc).toEqual([]); // nobody sees anyone else's address
    }
    expect(employees.map(e => e.to)).not.toContain('failed@example.com'); // never delivered
    expect(employees.map(e => e.to)).not.toContain('outsider@partner.test'); // not a safe domain
    // The incident email went first and said what is being sent
    expect(sent[0].to).toBe('security@example.com');
    expect(sent[0].text).toContain(
      'Sending the warning to 3 recipient(s) now (set to send automatically).'
    );
    expect(sent[0].text).not.toContain('thank-you');
    const action = store.actions.find(a => a.authorization === 'auto');
    expect(action).toMatchObject({ status: 'completed', approvedBy: 'auto' });
    expect(action?.result?.warned).toHaveLength(3);
    expect(store.events()).toContain('action_executed');
  });

  it('sends nothing when another invocation won the race to approve the auto action', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto' });
    // Another invocation cancels (or approves) the new proposal before this
    // one's conditional UPDATE: markAutoApproved finds no `proposed` row
    const markAutoApproved = jest.spyOn(store, 'markAutoApproved').mockImplementation(async id => {
      const row = store.actions.find(a => a.id === id);
      if (row) {
        row.status = 'cancelled';
      }
      return undefined;
    });
    await service.handleCampaignReport(reportInput());

    expect(markAutoApproved).toHaveBeenCalledTimes(1);
    expect(employeeEmails(sent)).toEqual([]);
    expect(sent[0].to).toBe('security@example.com');
    expect(sent[0].text).not.toContain('now (set to send automatically)');
    const action = store.actions.find(a => a.authorization === 'auto');
    expect(action).toMatchObject({ status: 'cancelled' });
    expect(action?.result).toBeUndefined();
    expect(store.events()).not.toContain('action_executed');
    expect(store.events()).not.toContain('action_failed');
  });

  it('sends reporters nothing: no thank-you note and no warning', async () => {
    const { service, sent } = setup({ employeeWarning: 'auto' });
    await service.handleCampaignReport(reportInput());
    for (const reporter of REPORTERS) {
      expect(sent.find(e => e.to === reporter)).toBeUndefined();
    }
    expect(sent.some(e => /thank you/i.test(e.subject))).toBe(false);
    const toRecipient = sent.find(e => e.to === 'person1@example.com');
    expect(toRecipient?.subject).toContain('Security warning: delete the email');
  });

  it('caps the employee emails per campaign', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto', maxWarningsPerCampaign: 2 });
    await service.handleCampaignReport(reportInput());
    expect(employeeEmails(sent)).toHaveLength(2);
    const scope = store.actions[0].scope;
    expect(scope.kind === 'send_warning' && scope.skipped.overCap).toBe(1);
  });

  it('keeps the distribution broadcast automatic by default (audience distribution)', async () => {
    const { service, sent, store } = setup(
      { audience: 'distribution' },
      { distributionList: LIST }
    );
    await service.handleCampaignReport(reportInput());
    expect(employeeEmails(sent).map(e => e.to)).toEqual([LIST]);
    expect(employeeEmails(sent)[0].subject).toContain('is going around');
    expect(proposed(store, 'send_warning')).toBeUndefined();
    expect(proposed(store, 'remove_messages')).toBeDefined();
  });

  it('warns both audiences when asked, the list at once and the recipients after approval', async () => {
    const { service, sent, store } = setup({ audience: 'both' }, { distributionList: LIST });
    await service.handleCampaignReport(reportInput());
    expect(employeeEmails(sent).map(e => e.to)).toEqual([LIST]);
    const warning = proposed(store, 'send_warning');
    expect(warning?.scope.kind === 'send_warning' && warning.scope.distribution).toBe(false);
    expect(warning?.scope.kind === 'send_warning' && warning.scope.recipients).toHaveLength(3);
  });

  it('says why no targeted warning is possible without blast radius', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(
      reportInput({ blastRadius: undefined, blastRadiusEnabled: false })
    );
    expect(proposed(store, 'send_warning')).toBeUndefined();
    expect(sent[0].text).toContain('blast radius is not enabled');
  });

  it('opens one incident when two reports cross the threshold at once', async () => {
    const { service, store } = setup();
    await Promise.all([
      service.handleCampaignReport(reportInput()),
      service.handleCampaignReport(reportInput()),
    ]);
    expect(store.incidents).toHaveLength(1);
  });
});

describe('approvals', () => {
  it('sends the warning once on approval, and approving twice does nothing twice', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;

    const first = await service.handleApprovals(
      approve('send_warning', warning.reference),
      'SOC@example.com'
    );
    expect(first.heading).toBe('Done: approval carried out');
    expect(employeeEmails(sent)).toHaveLength(3);
    const confirmed = sent.find(e => e.to === 'person1@example.com');
    expect(confirmed?.text).toContain('your security team confirmed it');

    const second = await service.handleApprovals(
      approve('send_warning', warning.reference),
      'security@example.com'
    );
    expect(second.body.join('\n')).toContain('already approved by soc@example.com');
    expect(employeeEmails(sent)).toHaveLength(3);
    expect(store.actions.find(a => a.id === warning.id)).toMatchObject({
      status: 'completed',
      approvedBy: 'soc@example.com',
    });
    expect(store.events()).toEqual(
      expect.arrayContaining(['action_approved', 'action_executed', 'approval_rejected'])
    );
  });

  it('rejects an approver who is not on the security team', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;
    const reply = await service.handleApprovals(
      approve('send_warning', warning.reference),
      'mallory@example.com'
    );
    expect(reply.body).toEqual(['You are not on the security team.']);
    expect(employeeEmails(sent)).toEqual([]);
    expect(proposed(store, 'send_warning')).toBeDefined();
  });

  it('rejects an unknown reference and a reference used with the wrong verb', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const removal = proposed(store, 'remove_messages')!;
    const unknown = await service.handleApprovals(
      approve('send_warning', 'PHY-ZZZZ-ZZZZ-ZZZZ-ZZZZ'),
      TEAM[0]
    );
    expect(unknown.body[0]).toContain('no proposed action has this reference');
    const wrong = await service.handleApprovals(
      approve('send_warning', removal.reference),
      TEAM[0]
    );
    expect(wrong.body[0]).toContain('is not a targeted warning');
    expect(employeeEmails(sent)).toEqual([]);
  });

  it('expires an approval after its window and proposes it again with a new reference', async () => {
    const { service, sent, store, advance } = setup({ approvalTtlHours: 2 });
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;
    advance(2 * 3_600_000 + 1);

    const reply = await service.handleApprovals(
      approve('send_warning', warning.reference),
      TEAM[0]
    );
    expect(reply.heading).toBe('Phishy did not carry out an approval');
    expect(reply.body.join('\n')).toContain('this approval expired');
    expect(employeeEmails(sent)).toEqual([]);
    expect(store.actions.find(a => a.id === warning.id)?.status).toBe('expired');
    const fresh = proposed(store, 'send_warning')!;
    expect(fresh.reference).not.toBe(warning.reference);
    expect(reply.body.join('\n')).toContain(`APPROVE WARNING ${fresh.reference}`);
    expect(store.events()).toEqual(expect.arrayContaining(['action_expired', 'approval_rejected']));
  });

  it('applies to its own campaign only', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const other = reportInput();
    other.match = { ...other.match, signature: 'ffffffffffffffff', campaignId: 'campaign-2' };
    other.blastRadius = blast([recipient(7)]);
    await service.handleCampaignReport(other);
    const firstWarning = store.actions.find(
      a => a.type === 'send_warning' && a.incidentId === store.incidents[0].id
    )!;
    await service.handleApprovals(approve('send_warning', firstWarning.reference), TEAM[0]);
    expect(employeeEmails(sent).map(e => e.to)).not.toContain('person7@example.com');
  });

  it('reads results stored with a thank-you list: those people count as already contacted', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;
    // A warning completed by an earlier version, whose result carries `thanked`
    const legacy = await store.createAction({
      incidentId: warning.incidentId,
      reference: 'PHY-LLLL-LLLL-LLLL-LLL2',
      type: 'send_warning',
      authorization: 'auto',
      scope: {
        ...warning.scope,
        reporters: ['person1@example.com'],
      } as unknown as typeof warning.scope,
      scopeHash: 'legacy',
      expiresAt: new Date('2026-11-17T14:00:00.000Z'),
    });
    await store.markAutoApproved(legacy.id);
    await store.finishAction(legacy.id, 'completed', {
      executor: 'ses_warning',
      dryRun: false,
      summary: [],
      warned: [],
      thanked: ['person1@example.com'],
    });

    await service.handleApprovals(approve('send_warning', warning.reference), TEAM[0]);
    const to = employeeEmails(sent).map(e => e.to);
    expect(to).not.toContain('person1@example.com');
    expect(to.sort()).toEqual(['person2@example.com', 'person3@example.com']);
  });

  it('re-checks the approved scope before sending: nobody is added, nobody is emailed twice', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;
    // Someone else's action already reached person1 (simulated)
    store.actions.push({
      ...warning,
      id: 'other',
      reference: 'PHY-QQQQ-QQQQ-QQQQ-QQQQ',
      status: 'completed',
      result: {
        executor: 'ses_warning',
        dryRun: false,
        summary: [],
        warned: ['person1@example.com'],
      },
    });
    await service.handleApprovals(approve('send_warning', warning.reference), TEAM[0]);
    expect(employeeEmails(sent).map(e => e.to)).not.toContain('person1@example.com');
  });
});

describe('remove remaining copies (dry run only)', () => {
  it('re-checks the scope, records what it would do, and changes nothing', async () => {
    const { service, store, mailer, sent } = setup();
    await service.handleCampaignReport(reportInput());
    const removal = proposed(store, 'remove_messages')!;
    const reply = await service.handleApprovals(
      approve('remove_messages', removal.reference),
      TEAM[1]
    );
    const text = reply.body.join('\n');
    expect(text).toContain('DRY RUN');
    expect(text).toContain('would remove 5 message(s) from 5 mailbox(es)');
    expect(text).toContain('unread in the inbox: 2');
    expect(text).toContain('read in the inbox: 2');
    expect(text).toContain('in Junk Email: 1');
    expect(text).toContain('No mailbox was changed: the mailbox write tier is not installed');
    expect(store.actions.find(a => a.id === removal.id)).toMatchObject({
      status: 'dry_run_completed',
      executor: 'dry_run_removal',
      approvedBy: 'soc@example.com',
    });
    const audit = store.audit.find(e => e.event === 'action_dry_run');
    expect(audit).toMatchObject({ actor: 'soc@example.com', actionId: removal.id });
    expect(audit?.detail).toMatchObject({ messages: 5, mailboxes: 5, unreadInInbox: 2 });
    // The only outbound calls are emails; there is no Graph client here at all
    expect(mailer.sendEmail).toHaveBeenCalledTimes(1);
    // A dry run removes nothing, so nobody gets a removal notice
    expect(sent.filter(e => e.subject.startsWith('Security notice'))).toEqual([]);
    expect(store.actions.find(a => a.id === removal.id)?.result?.notified).toBeUndefined();
  });

  it('keeps audit rows append-only (frozen entries, never rewritten)', async () => {
    const { service, store } = setup();
    await service.handleCampaignReport(reportInput());
    const before = store.audit.map(e => JSON.stringify(e));
    await service.handleApprovals(
      approve('remove_messages', proposed(store, 'remove_messages')!.reference),
      TEAM[0]
    );
    expect(store.audit.slice(0, before.length).map(e => JSON.stringify(e))).toEqual(before);
    expect(Object.isFrozen(store.audit[0])).toBe(true);
  });
});

describe('removal notice (only after a real removal: the write tier is not built)', () => {
  /**
   * Stands in for the future write tier: reports, per mailbox, what it
   * "removed". No Graph call exists; this only returns a result.
   */
  function fakeWriteExecutor(removed: (scope: RemovalMailboxIds) => RemovedMailbox[]) {
    const executor: RemovalExecutor = {
      name: 'fake_write_removal',
      changesMailboxes: true,
      execute: jest.fn(async (_action, approved): Promise<ActionResult> => ({
        executor: 'fake_write_removal',
        dryRun: false,
        summary: ['Removed.'],
        removed: removed(approved.mailboxes),
      })),
    };
    return executor;
  }
  type RemovalMailboxIds = Array<{ mailboxId: string; address: string }>;
  const all = (mailboxes: RemovalMailboxIds): RemovedMailbox[] =>
    mailboxes.map(m => ({ mailboxId: m.mailboxId, messages: 1 }));
  const notices = (sent: SentEmail[]): SentEmail[] =>
    sent.filter(
      e => e.subject === 'Security notice: a phishing email was removed from your mailbox'
    );

  async function approveRemoval(
    removed: (scope: RemovalMailboxIds) => RemovedMailbox[],
    cfg: Partial<CampaignResponseConfig> = {}
  ) {
    const ctx = setup(cfg, { removalExecutor: fakeWriteExecutor(removed) });
    await ctx.service.handleCampaignReport(reportInput());
    const removal = proposed(ctx.store, 'remove_messages')!;
    const reply = await ctx.service.handleApprovals(
      approve('remove_messages', removal.reference),
      TEAM[0]
    );
    return { ...ctx, removal, reply };
  }

  it('tells each person whose copy was removed, reporters included, one email each', async () => {
    const { sent, store, removal, reply } = await approveRemoval(all);
    const to = notices(sent).map(e => e.to);
    // outsider@partner.test's copy was removed too, but it is not on a safe domain
    expect([...to].sort()).toEqual(
      [
        'person1@example.com',
        'person2@example.com',
        'person3@example.com',
        'reporter1@example.com',
      ].sort()
    );
    expect(to).not.toContain('outsider@partner.test');
    for (const email of notices(sent)) {
      expect(email.cc).toEqual([]);
      expect(email.text).toContain('moved it to your Deleted Items folder');
      expect(email.text).not.toMatch(/https?:\/\//);
    }
    const action = store.actions.find(a => a.id === removal.id);
    expect(action).toMatchObject({ status: 'completed', executor: 'fake_write_removal' });
    expect([...(action?.result?.notified ?? [])].sort()).toEqual([...to].sort());
    const audit = store.audit.find(e => e.event === 'action_executed' && e.actionId === removal.id);
    expect(audit?.detail).toMatchObject({ notified: 4, removedMailboxes: 5, noticesFailed: 0 });
    expect(reply.body.join('\n')).toContain('Sent 4 removal notice(s)');
  });

  it('only for mailboxes a copy was actually removed from, and only ones the approved scope named', async () => {
    const { sent } = await approveRemoval(mailboxes => [
      { mailboxId: mailboxes[0].mailboxId, messages: 1 },
      { mailboxId: mailboxes[1].mailboxId, messages: 0 },
      { mailboxId: MAILBOX(77), messages: 3 },
    ]);
    expect(notices(sent).map(e => e.to)).toEqual(['person1@example.com']);
  });

  it('never notifies anyone twice', async () => {
    const { service, sent, store } = await approveRemoval(all);
    expect(notices(sent)).toHaveLength(4);
    // A second removal for the same mailboxes (a new proposal, approved)
    const second = await store.createAction({
      incidentId: store.incidents[0].id,
      reference: 'PHY-ZZZZ-ZZZZ-ZZZZ-ZZZ2',
      type: 'remove_messages',
      authorization: 'approve',
      scope: store.actions.find(a => a.type === 'remove_messages')!.scope,
      scopeHash: 'again',
      expiresAt: new Date('2026-11-17T14:00:00.000Z'),
    });
    await service.handleApprovals(approve('remove_messages', second.reference), TEAM[0]);
    expect(notices(sent)).toHaveLength(4);
  });

  it('respects the per-campaign cap, counting people already warned once', async () => {
    const { sent } = await approveRemoval(all, {
      employeeWarning: 'auto',
      maxWarningsPerCampaign: 3,
    });
    // The three recipients were warned (the cap); their notices do not count again,
    // so the reporter, a new person, is over the cap
    expect(
      notices(sent)
        .map(e => e.to)
        .sort()
    ).toEqual(['person1@example.com', 'person2@example.com', 'person3@example.com'].sort());
  });

  it('reports the removal and the notices in the next incident update', async () => {
    const { service, sent, advance } = await approveRemoval(all);
    advance(31 * 60_000);
    const later = reportInput();
    later.match = { ...later.match, detectionCount: 4, shouldAlert: false };
    await service.handleCampaignReport(later);
    const update = sent[sent.length - 1];
    expect(update.to).toBe('security@example.com');
    expect(update.text).toContain(
      'Removed 5 message(s) from 5 mailbox(es), moved to Deleted Items (approved by security@example.com'
    );
    expect(update.text).toContain('sent 4 removal notice(s).');
  });

  it('keeps the removal result when a notice fails', async () => {
    const ctx = setup({}, { removalExecutor: fakeWriteExecutor(all) });
    await ctx.service.handleCampaignReport(reportInput());
    const removal = proposed(ctx.store, 'remove_messages')!;
    ctx.mailer.sendEmail.mockImplementation(async () => ({
      success: false,
      messageId: '',
      error: 'refused',
    }));
    await ctx.service.handleApprovals(approve('remove_messages', removal.reference), TEAM[0]);
    const action = ctx.store.actions.find(a => a.id === removal.id);
    expect(action?.status).toBe('completed');
    expect(action?.result?.notified).toEqual([]);
    expect(action?.result?.noticesFailed).toBe(4);
  });
});

describe('APPROVE WARNING without a reference (bound to the email replied to)', () => {
  it('approves the one warning proposed in the incident email being answered', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const warning = proposed(store, 'send_warning')!;
    expect(store.audit.find(e => e.event === 'incident_email_sent')?.detail).toMatchObject({
      messageId: 'ses-1',
      proposed: expect.arrayContaining([warning.id]),
    });

    const reply = await service.handleBareWarningApproval(['ses-1'], 'SOC@example.com');
    expect(reply.heading).toBe('Done: approval carried out');
    expect(employeeEmails(sent)).toHaveLength(3);
    expect(store.actions.find(a => a.id === warning.id)).toMatchObject({
      status: 'completed',
      approvedBy: 'soc@example.com',
    });
    // The removal proposed in the same email is untouched
    expect(proposed(store, 'remove_messages')).toBeDefined();
  });

  it('refuses a reply to an older email whose proposal has been replaced', async () => {
    const { service, sent, advance } = setup();
    await service.handleCampaignReport(reportInput());
    advance(31 * 60_000);
    const more = reportInput();
    more.match = { ...more.match, detectionCount: 4, shouldAlert: false };
    more.blastRadius = blast([recipient(5)]);
    await service.handleCampaignReport(more);

    const stale = await service.handleBareWarningApproval(['ses-1'], TEAM[0]);
    expect(stale.body.join('\n')).toContain('replaced by a newer one');
    expect(employeeEmails(sent)).toEqual([]);

    // A reply to the update itself approves the proposal that update showed
    const current = await service.handleBareWarningApproval(['ses-2'], TEAM[0]);
    expect(current.heading).toBe('Done: approval carried out');
    expect(employeeEmails(sent).length).toBeGreaterThan(0);
  });

  it('refuses when the reply is not to an incident email, and for a non-member', async () => {
    const { service, sent } = setup();
    await service.handleCampaignReport(reportInput());
    for (const ids of [[], ['ses-unknown']]) {
      const reply = await service.handleBareWarningApproval(ids, TEAM[0]);
      expect(reply.heading).toBe('Phishy did not carry out an approval');
      expect(reply.body.join('\n')).toContain('could not match your reply');
    }
    const outsider = await service.handleBareWarningApproval(['ses-1'], 'mallory@example.com');
    expect(outsider.body[0]).toBe('You are not on the security team.');
    expect(employeeEmails(sent)).toEqual([]);
  });

  it('refuses when the email replied to proposed no warning', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    const entry = store.audit.findIndex(e => e.event === 'incident_email_sent');
    store.audit[entry] = Object.freeze({
      ...store.audit[entry],
      detail: { messageId: 'ses-1', proposed: [proposed(store, 'remove_messages')!.id] },
    });
    const reply = await service.handleBareWarningApproval(['ses-1'], TEAM[0]);
    expect(reply.body[0]).toContain('is not the one that proposes the warning');
    expect(employeeEmails(sent)).toEqual([]);
  });
});

describe('APPROVE WARNING without a reference: says what the state is', () => {
  it('says the warning was already approved, by whom, when nothing is left to approve', async () => {
    const { service, sent, store, advance } = setup();
    await service.handleCampaignReport(reportInput());
    await service.handleBareWarningApproval(['ses-1'], 'soc@example.com');
    const warned = employeeEmails(sent).length;
    advance(31 * 60_000);
    const more = reportInput();
    more.match = { ...more.match, detectionCount: 4, shouldAlert: false };
    await service.handleCampaignReport(more);
    const update = store.audit.filter(e => e.event === 'incident_email_sent').pop();
    const reply = await service.handleBareWarningApproval(
      [update?.detail?.messageId as string],
      TEAM[0]
    );
    expect(reply.heading).toBe('Phishy did not carry out an approval');
    expect(reply.body[0]).toContain('already approved by soc@example.com');
    expect(employeeEmails(sent)).toHaveLength(warned);
  });
});

describe('incident updates', () => {
  it('threads updates under the first email, rate-limited', async () => {
    const { service, sent, store, advance } = setup();
    await service.handleCampaignReport(reportInput());

    const fourth = reportInput();
    fourth.match = { ...fourth.match, detectionCount: 4, shouldAlert: false };
    fourth.blastRadius = blast([recipient(1), recipient(5)]);
    advance(5 * 60_000);
    expect(await service.handleCampaignReport(fourth)).toBe('update_deferred');
    expect(sent).toHaveLength(1);

    advance(30 * 60_000);
    const fifth = { ...fourth, match: { ...fourth.match, detectionCount: 5 } };
    expect(await service.handleCampaignReport(fifth)).toBe('updated');
    const update = sent[1];
    expect(update.threaded).toEqual(TEAM);
    expect(update.inReplyTo).toBe('ses-1');
    expect(update.subject).toBe(`Re: ${sent[0].subject}`);
    expect(update.text).toContain('2 new report(s) since the last email (5 in all).');
    expect(update.text).toContain('Blast radius now 6 recipient(s) (was 5).');
    // The wider reach is a new proposal; the old one is superseded
    const warnings = store.actions.filter(a => a.type === 'send_warning');
    expect(warnings.map(a => a.status)).toEqual(['cancelled', 'proposed']);
    expect(update.text).toContain(`APPROVE WARNING ${warnings[1].reference}`);
  });

  it('a superseded reference does nothing', async () => {
    const { service, sent, store, advance } = setup();
    await service.handleCampaignReport(reportInput());
    const old = proposed(store, 'send_warning')!;
    advance(31 * 60_000);
    const more = reportInput();
    more.match = { ...more.match, detectionCount: 4, shouldAlert: false };
    more.blastRadius = blast([recipient(5)]);
    await service.handleCampaignReport(more);
    const reply = await service.handleApprovals(approve('send_warning', old.reference), TEAM[0]);
    expect(reply.body[0]).toContain('replaced by a newer one');
    expect(employeeEmails(sent)).toEqual([]);
  });

  it('says nothing when nothing changed', async () => {
    const { service, sent, advance } = setup();
    await service.handleCampaignReport(reportInput());
    advance(60 * 60_000);
    const same = reportInput();
    same.match = { ...same.match, shouldAlert: false };
    expect(await service.handleCampaignReport(same)).toBe('unchanged');
    expect(sent).toHaveLength(1);
  });
});

describe('false positive', () => {
  it('closes the incident, cancels proposals, and stops all warnings', async () => {
    const { service, sent, store } = setup();
    await service.handleCampaignReport(reportInput());
    store.analyses.set('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b', SIGNATURE);
    const warning = proposed(store, 'send_warning')!;

    const line = await service.onVerdict(
      '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
      'false_positive',
      'SOC@example.com'
    );
    expect(line).toContain('marked a false positive; 2 proposed action(s) cancelled');
    expect(store.incidents[0].status).toBe('false_positive');

    const reply = await service.handleApprovals(
      approve('send_warning', warning.reference),
      TEAM[0]
    );
    expect(reply.body[0]).toContain('marked a false positive');
    expect(employeeEmails(sent)).toEqual([]);
    expect(
      await service.onVerdict('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b', 'confirmed_phishing', TEAM[0])
    ).toBeUndefined();
  });
});

describe('database absent or migration missing', () => {
  it('falls back to the campaign alert exactly as without campaign response', async () => {
    const { service, sent, store, legacyAlert } = setup();
    store.unavailable = true;
    const input = reportInput();
    expect(await service.handleCampaignReport(input)).toBe('fallback');
    expect(legacyAlert).toHaveBeenCalledWith(input.match);
    expect(sent).toEqual([]);
  });

  it('does not broadcast below the threshold either', async () => {
    const { service, store, legacyAlert } = setup();
    store.unavailable = true;
    const input = reportInput();
    input.match.shouldAlert = false;
    await service.handleCampaignReport(input);
    expect(legacyAlert).not.toHaveBeenCalled();
  });

  it('answers an approval with the migration to apply', async () => {
    const { service, store } = setup();
    store.unavailable = true;
    const reply = await service.handleApprovals(
      approve('send_warning', 'PHY-AAAA-AAAA-AAAA-AAAA'),
      TEAM[0]
    );
    expect(reply.body[0]).toContain('006_campaign_response.sql');
  });
});

describe('second trigger: the fan-out scan', () => {
  it('opens an incident with zero reports and never sends without approval', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto' }, { distributionList: LIST });
    const opened = await service.openIncidentFromFanoutAlert({
      subject: 'Shared document waiting',
      senderAddress: 'files@examp1e-share.test',
      senderName: 'File Share',
      reach: blast([recipient(1), recipient(2)]),
      reasons: ['Reached 48 people in 6 minutes from a sender seen twice before'],
      riskScore: 70,
    });
    expect(opened).toMatchObject({ created: true });
    expect(store.incidents[0]).toMatchObject({ trigger: 'fanout_scan', reportCount: 0 });
    expect(employeeEmails(sent)).toEqual([]);
    const warning = proposed(store, 'send_warning');
    expect(warning?.authorization).toBe('approve');
    expect(warning?.scope).not.toHaveProperty('reporters');
    expect(sent[0].text).toContain(
      'fan-out scan saw this email reach many people before anyone reported it'
    );
    expect(sent[0].text).toContain('Reports so far: 0');
  });

  it('lets later reports join the same incident', async () => {
    const { service, store, advance } = setup();
    await service.openIncidentFromFanoutAlert({
      campaignSignature: SIGNATURE,
      subject: 'Invoice 2291 overdue',
      senderAddress: 'billing@examp1e-billing.test',
      reach: blast([recipient(1)]),
      reasons: ['Burst to many recipients'],
    });
    advance(60 * 60_000);
    const input = reportInput();
    input.match.shouldAlert = false;
    expect(await service.handleCampaignReport(input)).toBe('updated');
    expect(store.incidents).toHaveLength(1);
    expect(store.incidents[0].summary.detectedBy).toBe('fan-out scan, then employee reports');
  });
});

describe('the reach trigger', () => {
  const ONE = 'reporter1@example.com';

  /** Report N of a campaign that has not crossed the report-count threshold */
  function earlyReport(
    reporters: string[] = [ONE],
    reach: BlastRadiusRecipient[] = [1, 2, 3, 4, 5].map(n => recipient(n)),
    detectionCount = 1
  ): CampaignReportInput {
    const input = reportInput();
    input.match = {
      ...input.match,
      detectionCount,
      uniqueRecipientCount: reporters.length,
      shouldAlert: false,
    };
    input.campaign = { ...input.campaign, detectionCount, uniqueRecipients: reporters };
    input.blastRadius = { ...blast(reach), reporterAddress: reporters[reporters.length - 1] };
    return input;
  }

  it('opens the incident on the first report when reach is at the threshold', async () => {
    const { service, sent, store, markCampaignAlerted } = setup({ reachThreshold: 5 });
    expect(await service.handleCampaignReport(earlyReport())).toBe('opened');

    expect(store.incidents).toHaveLength(1);
    const incident = store.incidents[0];
    expect(incident).toMatchObject({ trigger: 'reports', reportCount: 1 });
    expect(incident.summary.openedOnReach).toEqual({
      reports: 1,
      reporters: 1,
      recipients: 5,
      threshold: 5,
    });
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe('security@example.com');
    expect(sent[0].text).toContain(
      'Detected by: reach, after a single report: blast radius found 5 delivered recipient(s) besides the reporter (reach threshold 5), so Phishy did not wait for the report-count threshold'
    );
    expect(sent[0].text).toContain('1 person has reported the same');
    expect(store.audit.find(e => e.event === 'incident_opened')?.detail).toEqual({
      trigger: 'reports',
      basis: 'reach',
      reports: 1,
      recipients: 5,
      reporters: 1,
      reachRecipients: 5,
      reachThreshold: 5,
    });
    // The legacy flag means "crossed the report-count threshold": not yet
    expect(markCampaignAlerted).not.toHaveBeenCalled();
    // approve mode (the default): proposed, nothing sent to employees
    expect(employeeEmails(sent)).toEqual([]);
    expect(proposed(store, 'send_warning')?.authorization).toBe('approve');
    expect(sent[0].text).not.toContain('only one person has reported it so far');
  });

  it('gives the numbers when the report that reaches the threshold is not the first', async () => {
    const { service, sent } = setup({ reachThreshold: 3 });
    await service.handleCampaignReport(
      earlyReport(
        [ONE],
        [1, 2, 3].map(n => recipient(n)),
        2
      )
    );
    expect(sent[0].text).toContain(
      'Detected by: reach, after 2 reports from 1 person: blast radius found 3 delivered recipient(s)'
    );
  });

  it('does not open below the threshold', async () => {
    const { service, sent, store } = setup({ reachThreshold: 5 });
    const input = earlyReport(
      [ONE],
      [1, 2, 3, 4].map(n => recipient(n))
    );
    expect(await service.handleCampaignReport(input)).toBe('below_threshold');
    expect(store.incidents).toEqual([]);
    expect(sent).toEqual([]);
  });

  it('falls back to the report count when blast radius is unusable or absent', async () => {
    const { service, sent, store } = setup({ reachThreshold: 1 });
    const unavailable = earlyReport();
    unavailable.blastRadius = {
      status: 'unavailable',
      note: 'Blast radius lookup could not be completed.',
      lookedUpAt: '2026-11-17T10:00:00.000Z',
    };
    expect(await service.handleCampaignReport(unavailable)).toBe('below_threshold');
    const absent = earlyReport();
    absent.blastRadius = undefined;
    expect(await service.handleCampaignReport(absent)).toBe('below_threshold');
    const disabled = earlyReport();
    disabled.blastRadius = undefined;
    disabled.blastRadiusEnabled = false;
    expect(await service.handleCampaignReport(disabled)).toBe('below_threshold');
    expect(store.incidents).toEqual([]);

    // The third report crosses the report-count threshold: opened as before
    const third = reportInput({ blastRadius: undefined });
    expect(await service.handleCampaignReport(third)).toBe('opened');
    expect(store.incidents[0].summary.detectedBy).toBe(
      'employee reports (the campaign alert threshold)'
    );
    expect(store.incidents[0].summary.openedOnReach).toBeUndefined();
    expect(sent).toHaveLength(1);
  });

  it('uses a partial lookup, counting only the recipients it listed', async () => {
    const { service, store } = setup({ reachThreshold: 5 });
    const input = earlyReport(
      [ONE],
      [1, 2, 3, 4].map(n => recipient(n))
    );
    input.blastRadius = {
      ...input.blastRadius!,
      status: 'partial',
      // The lookup estimates far more than it listed: never counted
      totals: { recipients: 400, read: 0, replied: 0, forwarded: 0 },
    };
    expect(await service.handleCampaignReport(input)).toBe('below_threshold');
    input.blastRadius.recipients = [1, 2, 3, 4, 5].map(n => recipient(n));
    expect(await service.handleCampaignReport(input)).toBe('opened');
    expect(store.incidents[0].summary.openedOnReach?.recipients).toBe(5);
  });

  it('does not fire for a suspicious verdict, or when the analysis failed', async () => {
    const { service, store } = setup({ reachThreshold: 1 });
    const suspicious = earlyReport();
    suspicious.risk = { ...suspicious.risk, verdict: 'suspicious', riskScore: 88 };
    expect(await service.handleCampaignReport(suspicious)).toBe('below_threshold');
    const failed = earlyReport();
    failed.risk = { ...failed.risk, verdict: 'undetermined' };
    expect(await service.handleCampaignReport(failed)).toBe('below_threshold');
    const flagged = earlyReport();
    flagged.analysis = { ...flagged.analysis, analysisFailed: true };
    expect(await service.handleCampaignReport(flagged)).toBe('below_threshold');
    expect(store.incidents).toEqual([]);

    for (const verdict of ['bec', 'malware_delivery']) {
      const fresh = setup({ reachThreshold: 1 });
      const input = earlyReport();
      input.risk = { ...input.risk, verdict };
      expect(await fresh.service.handleCampaignReport(input)).toBe('opened');
    }
  });

  it('is off at threshold 0: exactly the report-count behaviour', async () => {
    const { service, store, sent } = setup({ reachThreshold: 0 });
    const wide = earlyReport(
      [ONE],
      Array.from({ length: 80 }, (_, n) => recipient(n + 1))
    );
    expect(await service.handleCampaignReport(wide)).toBe('below_threshold');
    expect(store.incidents).toEqual([]);
    expect(sent).toEqual([]);
  });

  it('does not count reporters, undelivered or unconfirmed copies, or duplicates', () => {
    const report: BlastRadiusReport = {
      ...blast([
        recipient(1),
        recipient(2, { folder: 'junk' }),
        recipient(3, { folder: 'recoverable' }),
        recipient(1), // listed twice
        { address: 'Reporter1@Example.com', mailbox: 'found', folder: 'inbox' },
        { address: 'reporter2@example.com', mailbox: 'found', folder: 'inbox' },
        { address: 'self@example.com', mailbox: 'found', folder: 'inbox' },
        { address: 'failed@example.com', mailbox: 'not_delivered' },
        { address: 'quarantined@example.com', mailbox: 'not_found', deliveryStatus: 'Quarantined' },
        { address: 'unread-mailbox@example.com', mailbox: 'not_checked' },
      ]),
      reporterAddress: 'self@example.com',
    };
    expect(countReach(report, [ONE, 'reporter2@example.com'])).toBe(3);
    expect(countReach(undefined, [])).toBeUndefined();
    expect(countReach({ ...report, status: 'unavailable' }, [])).toBeUndefined();
  });

  it('does not open when reporters and undelivered copies are what make up the reach', async () => {
    const { service, store } = setup({ reachThreshold: 3 });
    const input = earlyReport(
      [ONE, 'reporter2@example.com'],
      [
        recipient(1),
        recipient(2),
        { address: ONE, mailbox: 'found', folder: 'inbox' },
        { address: 'reporter2@example.com', mailbox: 'found', folder: 'inbox' },
        { address: 'failed@example.com', mailbox: 'not_delivered' },
        { address: 'quarantined@example.com', mailbox: 'not_found' },
      ],
      2
    );
    expect(await service.handleCampaignReport(input)).toBe('below_threshold');
    expect(store.incidents).toEqual([]);
  });

  it('never opens a second incident: the report-count trigger later updates the same one', async () => {
    const { service, store, sent, advance, markCampaignAlerted } = setup({ reachThreshold: 5 });
    await service.handleCampaignReport(earlyReport());
    advance(31 * 60_000);
    const third = reportInput(); // shouldAlert: the report-count threshold is crossed now
    expect(await service.handleCampaignReport(third)).toBe('updated');
    expect(store.incidents).toHaveLength(1);
    expect(store.events().filter(e => e === 'incident_opened')).toHaveLength(1);
    // Recorded as the report-count trigger would have, once it is crossed
    expect(markCampaignAlerted).toHaveBeenCalledWith('campaign-1');
    expect(sent[1].inReplyTo).toBe('ses-1');
    // "Detected by" keeps what opened it
    expect(store.incidents[0].summary.detectedBy).toMatch(/^reach, after a single report/);
  });

  it('opens one incident when both triggers race', async () => {
    const { service, store } = setup({ reachThreshold: 5 });
    await Promise.all([
      service.handleCampaignReport(earlyReport()),
      service.handleCampaignReport(reportInput()),
    ]);
    expect(store.incidents).toHaveLength(1);
  });

  it('does not broadcast through the legacy alert on one report when the tables are missing', async () => {
    const { service, store, legacyAlert, sent } = setup({ reachThreshold: 1 });
    store.unavailable = true;
    expect(await service.handleCampaignReport(earlyReport())).toBe('fallback');
    expect(legacyAlert).not.toHaveBeenCalled();
    expect(sent).toEqual([]);
  });
});

describe('automatic actions need two reporters', () => {
  const ONE = 'reporter1@example.com';
  const TWO = 'reporter2@example.com';
  const THREE = 'reporter3@example.com';
  const AUTO: Partial<CampaignResponseConfig> = {
    reachThreshold: 3,
    audience: 'both',
    employeeWarning: 'auto',
    distributionWarning: 'auto',
  };
  const REACH = [1, 2, 3].map(n => recipient(n));

  function report(reporters: string[], detectionCount: number): CampaignReportInput {
    const input = reportInput();
    input.match = {
      ...input.match,
      detectionCount,
      uniqueRecipientCount: reporters.length,
      shouldAlert: false,
    };
    input.campaign = { ...input.campaign, detectionCount, uniqueRecipients: reporters };
    input.blastRadius = blast(REACH);
    return input;
  }

  it('holds auto actions for approval on one reporter, then runs them once with the second', async () => {
    const { service, sent, store, advance } = setup(AUTO, { distributionList: LIST });

    // Report 1, one person: opened on reach, nothing sent to employees
    expect(await service.handleCampaignReport(report([ONE], 1))).toBe('opened');
    expect(employeeEmails(sent)).toEqual([]);
    const held = proposed(store, 'send_warning')!;
    expect(held.authorization).toBe('approve');
    expect(held.scope.kind === 'send_warning' && held.scope.distribution).toBe(true);
    expect(sent[0].text).toContain(
      'The targeted warning and the warning to the distribution list are set to send automatically, but waiting for your approval because only one person has reported it so far. They go ahead automatically when a second person reports it, or when you approve.'
    );
    expect(sent[0].text).toContain(`APPROVE WARNING ${held.reference}`);

    // Report 2, the same person again: still held
    advance(31 * 60_000);
    expect(await service.handleCampaignReport(report([ONE], 2))).toBe('updated');
    expect(employeeEmails(sent)).toEqual([]);
    expect(store.actions.some(a => a.authorization === 'auto')).toBe(false);

    // Report 3, a second person, one minute later: released at once
    advance(60_000);
    expect(await service.handleCampaignReport(report([ONE, TWO], 3))).toBe('updated');
    const employees = employeeEmails(sent).map(e => e.to);
    expect(employees.sort()).toEqual(
      [LIST, 'person1@example.com', 'person2@example.com', 'person3@example.com'].sort()
    );
    const update = sent.find(e => e.text.includes('A second person has reported it'));
    expect(update?.inReplyTo).toBe('ses-1');
    const current = store.actions.find(a => a.id === held.id);
    expect(current?.status).toBe('cancelled');
    expect(
      store.audit.find(e => e.actionId === held.id && e.event === 'action_cancelled')?.detail
    ).toEqual({ reason: 'released_to_auto' });
    const auto = store.actions.filter(a => a.authorization === 'auto');
    expect(auto).toHaveLength(1);
    expect(auto[0]).toMatchObject({ status: 'completed', approvedBy: 'auto' });

    // The held reference can no longer send anything
    const reply = await service.handleApprovals(approve('send_warning', held.reference), TEAM[0]);
    expect(reply.body[0]).toContain('replaced by a newer one');

    // Report 4, a third person: reporters get nothing; nobody is emailed twice
    advance(31 * 60_000);
    await service.handleCampaignReport(report([ONE, TWO, THREE], 4));
    const all = employeeEmails(sent).map(e => e.to);
    expect(all).not.toContain(THREE);
    expect(new Set(all).size).toBe(all.length);
  });

  it('lets the security team approve during the hold, and sends nothing twice on release', async () => {
    const { service, sent, store, advance } = setup(AUTO, { distributionList: LIST });
    await service.handleCampaignReport(report([ONE], 1));
    const held = proposed(store, 'send_warning')!;
    const reply = await service.handleApprovals(approve('send_warning', held.reference), TEAM[1]);
    expect(reply.heading).toBe('Done: approval carried out');
    const before = employeeEmails(sent).map(e => e.to);
    expect([...before].sort()).toEqual(
      [LIST, 'person1@example.com', 'person2@example.com', 'person3@example.com'].sort()
    );

    advance(60_000);
    await service.handleCampaignReport(report([ONE, TWO], 2));
    const after = employeeEmails(sent).map(e => e.to);
    // Nothing new: reporters are not emailed, and no second broadcast
    expect(after.slice(before.length)).toEqual([]);
    expect(new Set(after).size).toBe(after.length);
  });

  it('leaves approve mode unchanged: no hold note, no release', async () => {
    const { service, sent, store, advance } = setup({ reachThreshold: 3 });
    await service.handleCampaignReport(report([ONE], 1));
    expect(sent[0].text).not.toContain('only one person has reported it so far');
    advance(60_000);
    expect(await service.handleCampaignReport(report([ONE, TWO], 2))).toBe('update_deferred');
    expect(employeeEmails(sent)).toEqual([]);
    expect(store.actions.every(a => a.authorization === 'approve')).toBe(true);
  });

  it('holds the default automatic broadcast on one reporter too', async () => {
    const { service, sent, store } = setup(
      { reachThreshold: 3, audience: 'distribution' },
      { distributionList: LIST }
    );
    await service.handleCampaignReport(report([ONE], 1));
    expect(employeeEmails(sent)).toEqual([]);
    expect(sent[0].text).toContain(
      'The warning to the distribution list is set to send automatically, but waiting for your approval because only one person has reported it so far. It goes ahead automatically'
    );
    const held = proposed(store, 'send_warning');
    expect(held?.scope.kind === 'send_warning' && held.scope.distribution).toBe(true);
  });

  it('runs auto at once when the report-count trigger opens (two reporters already)', async () => {
    const { service, sent } = setup(AUTO, { distributionList: LIST });
    await service.handleCampaignReport(reportInput());
    expect(employeeEmails(sent).map(e => e.to)).toContain(LIST);
    expect(sent[0].text).not.toContain('only one person has reported it so far');
  });
});

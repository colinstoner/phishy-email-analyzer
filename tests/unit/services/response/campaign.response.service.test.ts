/**
 * Campaign response: incident email, targeted warning, approvals, expiry,
 * idempotency, dry-run removal, threading, false positives, fallback and
 * the fan-out trigger. No AWS, no Graph, no database: an in-memory store
 * and a recording mailer. Invented example.com data only.
 */

import {
  CampaignReportInput,
  CampaignResponseService,
} from '../../../../src/services/response/campaign.response.service';
import type {
  BlastRadiusRecipient,
  BlastRadiusReport,
} from '../../../../src/services/graph/blast-radius.service';
import type { CampaignResponseConfig } from '../../../../src/config/schema';
import { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } from '../../../../src/config/schema';
import type { ApprovalCommand } from '../../../../src/services/commands/response.commands';
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
  options: { commandsEnabled?: boolean; distributionList?: string } = {}
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
    expect(warning?.scope.kind === 'send_warning' && warning.scope.reporters).toEqual(REPORTERS);
    expect(removal?.scope.kind === 'remove_messages' && removal.scope.messageCount).toBe(5);

    expect(sent[0].text).toContain(`APPROVE WARNING ${warning?.reference}`);
    expect(sent[0].text).toContain(`APPROVE REMOVAL ${removal?.reference}`);
    expect(sent[0].text).toContain('false positive');
    expect(sent[0].text).toContain('Analysis ID: 3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b');
    expect(store.events()).toEqual(['incident_opened', 'action_proposed', 'action_proposed']);
    expect(markCampaignAlerted).toHaveBeenCalledWith('campaign-1');
    expect(store.incidents[0].threadMessageId).toBe('ses-1');
  });

  it('sends at once, one email per person, when set to auto', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto' });
    await service.handleCampaignReport(reportInput());

    const employees = employeeEmails(sent);
    expect(employees.map(e => e.to).sort()).toEqual(
      ['person1@example.com', 'person2@example.com', 'person3@example.com', ...REPORTERS].sort()
    );
    for (const email of employees) {
      expect(email.cc).toEqual([]); // nobody sees anyone else's address
    }
    expect(employees.map(e => e.to)).not.toContain('failed@example.com'); // never delivered
    expect(employees.map(e => e.to)).not.toContain('outsider@partner.test'); // not a safe domain
    // The incident email went first and said what is being sent
    expect(sent[0].to).toBe('security@example.com');
    expect(sent[0].text).toContain(
      'Sending the warning to 3 recipient(s), a thank-you note to 3 reporter(s) now'
    );
    const action = store.actions.find(a => a.authorization === 'auto');
    expect(action).toMatchObject({ status: 'completed', approvedBy: 'auto' });
    expect(action?.result?.warned).toHaveLength(3);
    expect(store.events()).toContain('action_executed');
  });

  it('gives reporters the short thank-you note, not the warning', async () => {
    const { service, sent } = setup({ employeeWarning: 'auto' });
    await service.handleCampaignReport(reportInput());
    const toReporter = sent.find(e => e.to === 'reporter1@example.com');
    const toRecipient = sent.find(e => e.to === 'person1@example.com');
    expect(toReporter?.subject).toBe('Thank you: the email you reported was phishing');
    expect(toReporter?.text).toContain('Warned the 3 other people who received it');
    expect(toRecipient?.subject).toContain('Security warning: delete the email');
  });

  it('caps the employee emails per campaign', async () => {
    const { service, sent, store } = setup({ employeeWarning: 'auto', maxWarningsPerCampaign: 2 });
    await service.handleCampaignReport(reportInput());
    expect(employeeEmails(sent)).toHaveLength(2);
    const scope = store.actions[0].scope;
    expect(scope.kind === 'send_warning' && scope.skipped.overCap).toBe(4);
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
    expect(employeeEmails(sent)).toHaveLength(6);
    const confirmed = sent.find(e => e.to === 'person1@example.com');
    expect(confirmed?.text).toContain('your security team confirmed it');

    const second = await service.handleApprovals(
      approve('send_warning', warning.reference),
      'security@example.com'
    );
    expect(second.body.join('\n')).toContain('already approved by soc@example.com');
    expect(employeeEmails(sent)).toHaveLength(6);
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
    const { service, store, mailer } = setup();
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
    expect(warning?.scope.kind === 'send_warning' && warning.scope.reporters).toEqual([]);
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

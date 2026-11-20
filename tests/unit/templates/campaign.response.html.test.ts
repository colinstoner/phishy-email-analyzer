/**
 * Campaign-response emails: plain language first, the same risk score and
 * Confidence lines as the report, no links from the attack, hostile text
 * defanged and escaped. Invented example.com data only.
 */

import {
  buildDistributionWarning,
  buildEmployeeWarning,
  buildIncidentEmail,
  buildRemovalNotice,
  incidentSubject,
  summaryRisk,
  WarningContext,
} from '../../../src/templates/campaign.response.html';
import { riskScoreLines } from '../../../src/templates/report.html';
import type {
  CampaignIncident,
  IncidentSummary,
  ResponseAction,
} from '../../../src/services/response/response.types';
import { emptyReach, mergeReach } from '../../../src/services/response/scope';

const HOSTILE_SUBJECT = 'Invoice <b>2291</b> overdue — pay at https://pay.examp1e-billing.test/now';

const summary: IncidentSummary = {
  verdict: 'phishing',
  riskScore: 92,
  riskLevel: 'critical',
  confidence: 'Very High',
  confidenceBasis: 'model',
  reasons: [
    'Link to http://login.examp1e-billing.test hidden behind "View invoice"',
    '<img src=x onerror=1>',
  ],
  lure: 'Fake invoice reminder pointing to https://login.examp1e-billing.test',
  subject: HOSTILE_SUBJECT,
  senderAddress: 'billing@examp1e-billing.test',
  senderName: 'Accounts Team',
  firstDeliveryAt: '2026-11-17T09:14:00.000Z',
  firstReportAt: '2026-11-17T09:21:00.000Z',
  lastReportAt: '2026-11-17T09:40:00.000Z',
  analysisId: '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
  detectedBy: 'employee reports (the campaign alert threshold)',
};

const context: Omit<WarningContext, 'warnedCount'> = {
  summary,
  reportCount: 3,
  timeZone: 'UTC',
  alreadyClickedInstructions: 'Call the service desk on extension 4400 and change your password.',
  incidentReference: 'PHY-AAAA-BBBB-CCCC-DDDD',
  confirmedBy: 'security_team',
};

function noLinks(html: string, text: string): void {
  for (const body of [html, text]) {
    expect(body).not.toMatch(/https?:\/\//i);
    expect(body).not.toMatch(/examp1e-billing\.test/);
  }
  expect(html).not.toMatch(/<a\s/i);
}

describe('employee warning', () => {
  const email = buildEmployeeWarning(context, {
    address: 'person1@example.com',
    receivedAt: '2026-11-17T09:14:00.000Z',
    folder: 'inbox',
  });

  it('says what arrived, from whom and when, in plain words first', () => {
    expect(
      email.text.indexOf('A phishing email reached your mailbox. Please delete it.')
    ).toBeLessThan(email.text.indexOf('Verdict:'));
    expect(email.text).toContain('An email with the subject "Invoice <b>2291</b> overdue');
    expect(email.text).toContain('from "Accounts Team" <billing@examp1e-billing[.]test>');
    expect(email.text).toContain('arrived in your mailbox on Tue, 17 Nov 2026, 09:14 UTC.');
  });

  it('says what to do, what to do if they clicked, and that they need not forward it', () => {
    expect(email.text).toContain('- Do not click any link or open any attachment in it.');
    expect(email.text).toContain('- Delete it.');
    expect(email.text).toContain('You do not need to forward it or report it');
    expect(email.text).toContain(
      'Call the service desk on extension 4400 and change your password.'
    );
  });

  it('never carries a link from the attack, and escapes its text', () => {
    noLinks(email.html, email.text);
    expect(email.html).toContain('&lt;b&gt;2291&lt;/b&gt;');
    expect(email.html).not.toContain('<b>2291</b>');
    expect(email.text).toContain('hxxps[:]//pay[.]examp1e-billing[.]test/now');
  });

  it('shows the risk score and Confidence exactly as the report does', () => {
    for (const line of riskScoreLines(summaryRisk(summary))) {
      expect(email.text).toContain(line);
    }
    expect(email.html).toContain('Risk score: <strong>92/100</strong> (critical)');
    expect(email.html).toContain('Confidence: <strong>Very High</strong>');
  });

  it('has a subject that names the email without a link', () => {
    expect(email.subject).toMatch(/^Security warning: delete the email ".*"\. It is phishing$/);
    expect(email.subject).not.toMatch(/https?:|[\r\n]/);
  });

  it('adapts to where their copy is', () => {
    const junk = buildEmployeeWarning(context, { address: 'p@example.com', folder: 'junk' });
    expect(junk.text).toContain(
      'arrived in your Junk Email folder on Tue, 17 Nov 2026, 09:14 UTC. It is still dangerous there'
    );
    const deleted = buildEmployeeWarning(context, { address: 'p@example.com', folder: 'deleted' });
    expect(deleted.text).toContain('is now in your Deleted Items');
  });

  it('works without a subject or time', () => {
    const bare = buildEmployeeWarning(
      { ...context, summary: { ...summary, subject: undefined, firstDeliveryAt: undefined } },
      { address: 'p@example.com' }
    );
    expect(bare.subject).toBe('Security warning: a phishing email reached your mailbox');
    expect(bare.text).toContain('arrived in your mailbox.');
  });
});

describe('removal notice', () => {
  const email = buildRemovalNotice(context);

  it('says the security team found it and moved it to Deleted Items, and that nothing is needed', () => {
    expect(email.subject).toBe('Security notice: a phishing email was removed from your mailbox');
    expect(email.text).toContain(
      'Your security team identified a phishing email in your mailbox and moved it to your Deleted Items folder.'
    );
    expect(email.text).toContain('Nothing. No action is needed.');
    expect(email.text).toContain('- Do not restore it from Deleted Items or open it there.');
  });

  it('says to contact the security team if they clicked or entered a password', () => {
    expect(email.text).toContain('IF YOU CLICKED A LINK OR ENTERED YOUR PASSWORD');
    expect(email.text).toContain('Contact your security team straight away.');
    expect(email.text).toContain(
      'Call the service desk on extension 4400 and change your password.'
    );
  });

  it('names the email without a link and escapes its text; the Subject line never repeats the lure', () => {
    expect(email.text).toContain('It had the subject "Invoice <b>2291</b> overdue');
    expect(email.text).toContain('came from "Accounts Team" <billing@examp1e-billing[.]test>.');
    noLinks(email.html, email.text);
    expect(email.html).toContain('&lt;b&gt;2291&lt;/b&gt;');
    expect(email.html).not.toContain('<b>2291</b>');
    expect(email.subject).not.toContain('Invoice');
  });

  it('works without a subject or sender', () => {
    const bare = buildRemovalNotice({
      ...context,
      summary: { ...summary, subject: undefined, senderAddress: undefined, senderName: undefined },
    });
    expect(bare.text).not.toContain('It had the subject');
    expect(bare.text).not.toContain('came from');
    expect(bare.text).toContain('moved it to your Deleted Items folder.');
  });
});

describe('distribution warning (campaign response on)', () => {
  it('tells everyone what to look for', () => {
    const email = buildDistributionWarning(context);
    expect(email.subject).toContain('is going around');
    expect(email.text).toContain('WHAT TO LOOK FOR');
    expect(email.text).toContain('first seen on Tue, 17 Nov 2026, 09:14 UTC.');
    noLinks(email.html, email.text);
  });
});

describe('incident email', () => {
  const incident: CampaignIncident = {
    id: 'i1',
    campaignSignature: 'sig',
    reference: 'PHY-AAAA-BBBB-CCCC-DDDD',
    trigger: 'reports',
    status: 'open',
    summary,
    reach: mergeReach(
      undefined,
      {
        status: 'partial',
        route: 'trace',
        totals: { recipients: 3, read: 1, replied: 1, forwarded: 0 },
        recipients: [
          {
            address: 'person1@example.com',
            mailbox: 'found',
            folder: 'inbox',
            isRead: true,
            response: 'replied',
          },
          {
            address: '<b>x</b>@example.com',
            mailbox: 'found',
            folder: 'junk',
            isRead: false,
            response: 'none',
          },
          { address: 'gone@example.com', mailbox: 'not_delivered' },
        ],
        coverage: {
          mailboxesChecked: 2,
          mailboxesEligible: 3,
          eligibleIsLowerBound: false,
          recoverableChecked: 0,
          recoverableCandidates: 0,
          detailUnavailable: 0,
        },
        caveats: ['The lookup stopped at its time budget.'],
        lookedUpAt: '2026-11-17T10:00:00.000Z',
      },
      true
    ),
    reportCount: 3,
    notifiedReportCount: 0,
    notifiedRecipientCount: 0,
    createdAt: new Date('2026-11-17T10:00:00Z'),
  };
  const warning: ResponseAction = {
    id: 'a1',
    incidentId: 'i1',
    reference: 'PHY-WWWW-WWWW-WWWW-WWWW',
    type: 'send_warning',
    status: 'proposed',
    authorization: 'approve',
    scope: {
      kind: 'send_warning',
      recipients: [{ address: 'person1@example.com' }],
      distribution: false,
      skipped: { notDelivered: 1, unsafeAddress: 0, alreadyContacted: 0, overCap: 0, unlisted: 0 },
    },
    scopeHash: 'h',
    proposedAt: new Date('2026-11-17T10:00:00Z'),
    expiresAt: new Date('2026-11-17T14:00:00Z'),
  };
  const removal: ResponseAction = {
    ...warning,
    id: 'a2',
    reference: 'PHY-RRRR-RRRR-RRRR-RRRR',
    type: 'remove_messages',
    scope: {
      kind: 'remove_messages',
      mailboxes: [],
      messageCount: 2,
      limits: { maxMailboxes: 500, maxMessages: 1000 },
      skipped: { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 },
    },
  };
  const email = buildIncidentEmail({
    incident,
    proposed: [warning, removal],
    done: ['Sent the reporter of this report their own analysis.'],
    notes: [],
    commandsEnabled: true,
    timeZone: 'UTC',
  });

  it('leads with a plain summary, then the detail a decision needs', () => {
    const order = [
      '3 people have reported',
      'WHAT THE ATTACK IS',
      'TIMELINE',
      'BLAST RADIUS',
      'WHAT PHISHY HAS DONE',
      'PROPOSED ACTIONS',
    ];
    const positions = order.map(marker => email.text.indexOf(marker));
    expect(positions.every(p => p >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
    expect(email.text).toContain('It reached at least 2 mailbox(es): 1 opened it, 1 replied');
    expect(email.text).toContain('PARTIAL COVERAGE: checked 2 of 3 mailboxes.');
    expect(email.text).toContain(
      'First delivery: Tue, 17 Nov 2026, 09:14 UTC (from mailbox records)'
    );
  });

  it('gives each proposed action its exact reply and what it does', () => {
    expect(email.text).toContain('Reply with this line:  APPROVE WARNING PHY-WWWW-WWWW-WWWW-WWWW');
    expect(email.text).toContain('Reply with this line:  APPROVE REMOVAL PHY-RRRR-RRRR-RRRR-RRRR');
    expect(email.text).toContain('Emails a warning to 1 recipient(s), one email each');
    expect(email.text).toContain('No mailbox is changed: the mailbox write tier is not installed.');
    expect(email.text).toContain('Reply with this line:  false positive');
    expect(email.text).toContain(
      'good until Tue, 17 Nov 2026, 14:00 UTC and applies to this incident only'
    );
    expect(email.html).toContain('APPROVE WARNING PHY-WWWW-WWWW-WWWW-WWWW');
    // The command never stands on a line of its own, so a quoted copy cannot match
    expect(email.text.split('\n').some(line => /^APPROVE /.test(line.trim()))).toBe(false);
  });

  it('defangs and escapes everything from the attack', () => {
    noLinks(email.html, email.text);
    expect(email.html).toContain('&lt;img src=x onerror=1&gt;');
    expect(email.html).toContain('&lt;b&gt;x&lt;/b&gt;@example.com');
    expect(email.html).not.toContain('<img src=x');
  });

  it('keeps a stable subject so updates thread under it', () => {
    expect(email.subject).toBe(incidentSubject(incident));
    expect(email.subject).toBe(
      '[Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active phishing campaign'
    );
    // The lure's own subject stays out of the subject line (it is in the body)
    expect(email.subject).not.toContain(incident.summary.subject ?? '\u0000');
    const update = buildIncidentEmail({
      incident: { ...incident, reportCount: 9 },
      proposed: [],
      done: [],
      notes: [],
      changes: ['6 new report(s) since the last email (9 in all).'],
      commandsEnabled: true,
      timeZone: 'UTC',
    });
    expect(update.subject).toBe(`Re: ${email.subject}`);
    expect(update.text).toContain('WHAT CHANGED');
    expect(update.text).toContain('No action is waiting for approval.');
  });

  it('says approvals cannot arrive when the command channel is off', () => {
    const off = buildIncidentEmail({
      incident,
      proposed: [warning],
      done: [],
      notes: [],
      commandsEnabled: false,
      timeZone: 'UTC',
    });
    expect(off.text).toContain('The email command channel is off');
  });

  it('describes an incident without blast radius honestly', () => {
    const none = buildIncidentEmail({
      incident: { ...incident, reach: emptyReach('not_enabled', 'Blast radius is not enabled.') },
      proposed: [],
      done: [],
      notes: [],
      commandsEnabled: true,
      timeZone: 'UTC',
    });
    expect(none.text).toContain('Phishy could not look up who else received it.');
    expect(none.text).toContain(
      'Blast radius is not enabled, so Phishy cannot say who else received it'
    );
  });
});

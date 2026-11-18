/**
 * Blast-radius section of the report: present only when asked for (the
 * security team's copy), honest about coverage, and escaped.
 */

import {
  buildEmailHtml,
  buildPlainTextReport,
  ReportOptions,
} from '../../../src/templates/report.html';
import { BlastRadiusReport } from '../../../src/services/graph/blast-radius.service';
import { AnalysisResult, ExtractedEmailData } from '../../../src/types';

const emailData: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'Fwd: something',
  text: 'body',
  html: '<p>body</p>',
  headers: {},
  forwardedHeaders: {},
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'reporter@example.com',
  originalForwarder: '',
  links: [],
};

const analysis: AnalysisResult = {
  summary: 'A test analysis.',
  isPhishing: true,
  confidence: 'High',
  indicators: ['Suspicious sender'],
  recommendations: ['Delete it'],
};

const baseOptions: ReportOptions = {
  analysisId: 'abc-123-def',
  risk: { verdict: 'phishing', riskScore: 90, riskLevel: 'critical', reasons: [] },
};

const blastRadius: BlastRadiusReport = {
  status: 'partial',
  route: 'mailbox',
  matchedBy: 'senderSubject',
  criteria: {
    senderAddress: 'attacker@evil.test',
    subject: '<img src=x onerror=alert(1)> "Invoice"',
    receivedFrom: '2026-11-15T08:00:00.000Z',
    receivedTo: '2026-11-17T08:00:00.000Z',
  },
  totals: { recipients: 120, read: 1, replied: 1, forwarded: 0 },
  recipients: [
    {
      address: 'colleague@example.com',
      mailbox: 'found',
      folder: 'inbox',
      isRead: true,
      response: 'replied',
    },
    {
      address: 'reporter@example.com',
      mailbox: 'found',
      folder: 'junk',
      isRead: false,
      response: 'unknown',
      lastVerbCode: 261,
      copies: 2,
    },
    { address: '<b>group</b>@example.com', mailbox: 'not_checked', deliveryStatus: 'Expanded' },
  ],
  coverage: {
    mailboxesChecked: 40,
    mailboxesEligible: 463,
    eligibleIsLowerBound: false,
    recoverableChecked: 0,
    recoverableCandidates: 39,
    detailUnavailable: 0,
  },
  caveats: ['The lookup stopped at its time budget.'],
  lookedUpAt: '2026-11-17T12:00:00.000Z',
  reporterAddress: 'reporter@example.com',
};

function render(options: ReportOptions): string[] {
  return [
    buildEmailHtml(analysis, emailData, options),
    buildPlainTextReport(analysis, emailData, options),
  ];
}

describe('blast radius section', () => {
  it('is absent unless the option is set (the reporter copy)', () => {
    for (const output of render(baseOptions)) {
      expect(output.toLowerCase()).not.toContain('blast radius');
      expect(output.toLowerCase()).not.toContain('security team only');
      expect(output).not.toContain('colleague@example.com');
    }
  });

  it('states partial coverage as "checked N of M" and never as complete', () => {
    for (const output of render({ ...baseOptions, blastRadius })) {
      expect(output).toContain('PARTIAL COVERAGE: checked 40 of 463 mailboxes.');
      expect(output).not.toContain('Coverage: checked');
      expect(output).toContain('Found in 120 mailbox(es).');
      expect(output).toContain('117 more recipient(s) not listed.');
      expect(output).toContain('The lookup stopped at its time budget.');
      expect(output).toContain('reporter@example.com (reporter)');
      expect(output).toContain('REPLIED');
      expect(output).toContain('Unknown (last-verb code 261)');
      expect(output).toContain('Junk (2 copies)');
      expect(output).toContain('Mailbox not checked');
      expect(output).toContain('Expanded');
    }
  });

  it('escapes the hostile subject and addresses in HTML', () => {
    const [html] = render({ ...baseOptions, blastRadius });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt; &quot;Invoice&quot;');
    expect(html).not.toContain('<b>group</b>');
    expect(html).toContain('&lt;b&gt;group&lt;/b&gt;@example.com');
  });

  it('says complete coverage plainly, and "at least" for a cut-short directory', () => {
    const [, complete] = render({
      ...baseOptions,
      blastRadius: {
        ...blastRadius,
        status: 'complete',
        route: 'trace',
        matchedBy: 'messageId',
        coverage: { ...blastRadius.coverage!, mailboxesChecked: 3, mailboxesEligible: 3 },
      },
    });
    expect(complete).toContain('Coverage: checked 3 of 3 recipient mailboxes.');
    expect(complete).not.toContain('PARTIAL');
    expect(complete).toContain('Message trace shows 120 recipient(s)');
    expect(complete).toContain('Matched on: the original Message-ID.');

    const [, lowerBound] = render({
      ...baseOptions,
      blastRadius: {
        ...blastRadius,
        matchedBy: 'sender',
        coverage: { ...blastRadius.coverage!, eligibleIsLowerBound: true },
      },
    });
    expect(lowerBound).toContain('checked 40 of at least 463 mailboxes');
    expect(lowerBound).toContain('Matched on: sender attacker@evil.test, received between');
  });

  it('renders the other row states', () => {
    const [, text] = render({
      ...baseOptions,
      blastRadius: {
        ...blastRadius,
        recipients: [
          { address: 'a@example.com', mailbox: 'found', response: 'forwarded' },
          { address: 'b@example.com', mailbox: 'found', isRead: true, response: 'none' },
          { address: 'c@example.com', mailbox: 'found', folder: 'recoverable' },
          { address: 'd@example.com', mailbox: 'not_found', deliveryStatus: 'Quarantined' },
        ],
      },
    });
    expect(text).toContain('a@example.com | - | Unknown | Unknown | FORWARDED');
    expect(text).not.toContain('counts as a forward');
    const [, own] = render({
      ...baseOptions,
      blastRadius: {
        ...blastRadius,
        recipients: [{ address: 'reporter@example.com', mailbox: 'found', response: 'forwarded' }],
      },
    });
    expect(own).toContain('The reporter forwarding the email to Phishy counts as a forward.');
    expect(text).toContain('b@example.com | - | Unknown | Read | None recorded');
    expect(text).toContain('c@example.com | - | Purged (Recoverable Items) | Unknown | Unknown');
    expect(text).toContain('d@example.com | Quarantined | Not in mailbox | - | -');
  });

  it('shows a failed delivery as not delivered, outside the recipient count', () => {
    const [html, text] = render({
      ...baseOptions,
      blastRadius: {
        ...blastRadius,
        route: 'trace',
        totals: { recipients: 1, read: 0, replied: 0, forwarded: 0, notDelivered: 1 },
        recipients: [
          {
            address: 'a@example.com',
            mailbox: 'found',
            folder: 'inbox',
            deliveryStatus: 'delivered',
          },
          { address: 'b@example.com', mailbox: 'not_delivered', deliveryStatus: 'failed' },
        ],
      },
    });
    for (const output of [html, text]) {
      expect(output).toContain('Message trace shows 1 recipient(s) in the organization.');
      expect(output).toContain('Delivery failed for 1 more recipient(s).');
      expect(output).not.toContain('more recipient(s) not listed');
    }
    expect(text).toContain('b@example.com | failed | Not delivered | - | -');
  });

  it('renders a failed lookup as a single line', () => {
    const [html, text] = render({
      ...baseOptions,
      blastRadius: {
        status: 'unavailable',
        note: 'Blast radius lookup could not be completed: it ran out of time before any result.',
        lookedUpAt: '2026-11-17T12:00:00.000Z',
      },
    });
    expect(html).toContain('<strong>Security team only:</strong> Blast radius lookup could not');
    expect(html).not.toContain('<h2>Blast radius');
    expect(text).toContain('Security team only: Blast radius lookup could not be completed');
    expect(text).not.toContain('BLAST RADIUS');
  });
});

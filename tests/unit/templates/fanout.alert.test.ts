/**
 * The security team's fan-out alert: content, escaping of hostile mail-flow
 * strings, and a Subject line written by code alone. Invented data only.
 */

import type { FanoutFlag } from '../../../src/services/graph/fanout.scan';
import {
  FANOUT_BENIGN_EXPLANATIONS,
  FANOUT_MEANING,
  FanoutAlertInput,
  buildFanoutAlert,
} from '../../../src/templates/fanout.alert';

const HOSTILE_SUBJECT = '<img src=x onerror="alert(1)"> Payment & "remittance"';
const HOSTILE_SENDER = "o'neil@supplier.example.net";

function flag(overrides: Partial<FanoutFlag> = {}): FanoutFlag {
  return {
    senderAddress: HOSTILE_SENDER,
    subject: HOSTILE_SUBJECT,
    firstSeen: '2026-11-17T11:58:00.000Z',
    lastSeen: '2026-11-17T11:59:30.000Z',
    windowRecipients: 42,
    windowMessages: 2,
    statuses: { delivered: 30, junk: 5, quarantined: 6, failed: 1, other: 0 },
    recipients: [
      { address: 'person1@example.com', status: 'delivered' },
      { address: 'person2@example.com', status: 'quarantined' },
    ],
    recipientsOmitted: 40,
    facts: {
      classification: 'established_with_anomalous_fanout',
      lookbackDays: 30,
      burstWindowHours: 25,
      history: {
        messages: { count: 3, atLeast: false },
        recipients: { count: 2, atLeast: false },
        firstSeen: '2026-11-10',
      },
      twoWay: {
        messages: { count: 1, atLeast: false },
        internalSenders: { count: 1, atLeast: false },
      },
      burst: {
        messages: { count: 2, atLeast: false },
        recipients: { count: 42, atLeast: false },
        newRecipients: { count: 41, atLeast: false },
        sameSubject: {
          recipients: { count: 42, atLeast: false },
          newRecipients: { count: 41, atLeast: false },
        },
      },
      sendingIps: {
        burst: 1,
        seenInHistory: 0,
        historyComplete: true,
        burstIps: [{ ip: '203.0.113.7', seenInHistory: false }],
      },
      truncated: false,
    },
    ...overrides,
  };
}

function input(overrides: Partial<FanoutAlertInput> = {}): FanoutAlertInput {
  return {
    reference: 'FANOUT-0A1B2C3D4E',
    kind: 'new',
    flag: flag(),
    waveRecipients: 42,
    waveFirstSeen: '2026-11-17T11:58:00.000Z',
    window: { from: '2026-11-17T11:45:00.000Z', to: '2026-11-17T12:00:00.000Z' },
    incompleteReasons: [],
    ...overrides,
  };
}

describe('buildFanoutAlert', () => {
  it('writes the Subject line from code only', () => {
    const { subject } = buildFanoutAlert(input());
    expect(subject).toBe(
      'Phishy fan-out alert FANOUT-0A1B2C3D4E: one external sender reached 42 internal recipients'
    );
    expect(subject).not.toContain('supplier');
    expect(subject).not.toContain('remittance');
  });

  it('escapes the sender, the subject and recipient addresses in HTML', () => {
    const { html } = buildFanoutAlert(input());
    expect(html).not.toContain('<img');
    expect(html).not.toContain('onerror="');
    expect(html).toContain(
      '&lt;img src=x onerror=&quot;alert(1)&quot;&gt; Payment &amp; &quot;remittance&quot;'
    );
    expect(html).toContain('o&#39;neil@supplier.example.net');
    expect(html).toContain('person1@example.com');
  });

  it('says what was seen, what it means and what to do, and that it is not a verdict', () => {
    const { html, text } = buildFanoutAlert(input());
    for (const body of [html, text]) {
      expect(body.toLowerCase()).toContain('security team only');
      expect(body).toContain('behaviour-based flag');
      expect(body).toContain('not a verdict on');
      expect(body).toContain('No message was opened and no AI model was involved');
      // Times in the configured zone (UTC by default), never raw ISO strings
      expect(body).toContain('Tue, 17 Nov 2026, 11:58 UTC');
      expect(body).not.toContain('2026-11-17T11:58:00.000Z');
      expect(body).toContain('Tue, 17 Nov 2026, 11:45 UTC to Tue, 17 Nov 2026, 12:00 UTC');
      expect(body).toContain('42 distinct internal recipients');
      expect(body).toContain('the mail filter already quarantined 6 and sent 5 to Junk Email');
      expect(body).toContain('30 reached a mailbox');
      expect(body).toContain('Confirm with the sender through a channel you already have');
      expect(body).toContain('a bid invitation, tender or request for quotation');
      expect(body).toContain('a newsletter or announcement from a real contact');
      expect(body).toContain('FANOUT-0A1B2C3D4E');
      expect(body).toContain('Replying does not trigger any action');
      expect(body).toContain('40 more recipient(s) not listed');
      // The history that makes it anomalous, with the burst IPs for the security team
      expect(body).toContain(
        'Established contact, unusual fan-out: a known sender suddenly mailing many people it never wrote to'
      );
      expect(body).not.toContain('established_with_anomalous_fanout');
      expect(body).toContain('203.0.113.7');
    }
    expect(text).toContain(FANOUT_MEANING);
    expect(FANOUT_BENIGN_EXPLANATIONS.length).toBeGreaterThanOrEqual(4);
  });

  it('writes its times in the configured time zone', () => {
    const { html, text } = buildFanoutAlert(input({ timeZone: 'America/Chicago' }));
    for (const body of [html, text]) {
      expect(body).toContain('Tue, 17 Nov 2026, 05:58 GMT-6');
      expect(body).toContain('Tue, 17 Nov 2026, 05:45 GMT-6 to Tue, 17 Nov 2026, 06:00 GMT-6');
      expect(body).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
    }
    expect(text).toContain('First seen: Tue, 17 Nov 2026, 05:58 GMT-6');
  });

  it('marks an update and says how much the wave grew', () => {
    const { subject, html, text } = buildFanoutAlert(
      input({ kind: 'growth', previousRecipients: 20, waveRecipients: 45 })
    );
    expect(subject).toContain('(update)');
    expect(subject).toContain('now reached 45');
    expect(html).toContain('Phishy Fan-out Alert (update)');
    expect(text).toContain('the previous alert for this wave reported 20; it has now reached 45');
  });

  it('says when the scan was incomplete', () => {
    const { html, text } = buildFanoutAlert(
      input({ incompleteReasons: ['page_limit', 'candidate_limit'] })
    );
    for (const body of [html, text]) {
      expect(body).toContain('Scan incomplete');
      expect(body).toContain('more mail-flow rows than the page limit allows');
      expect(body).toContain('more senders reached the threshold than one scan checks');
    }
  });

  it('includes the blast radius when given one, escaped', () => {
    const { html, text } = buildFanoutAlert(
      input({
        blastRadius: {
          status: 'complete',
          route: 'trace',
          totals: { recipients: 42, read: 7, replied: 2, forwarded: 1 },
          recipients: [
            {
              address: 'person1@example.com',
              mailbox: 'found',
              folder: 'inbox',
              isRead: true,
              response: 'replied',
            },
          ],
          criteria: {
            senderAddress: HOSTILE_SENDER,
            subject: HOSTILE_SUBJECT,
            receivedFrom: '2026-11-16T11:58:00.000Z',
            receivedTo: '2026-11-17T12:00:00.000Z',
          },
          matchedBy: 'senderSubject',
          lookedUpAt: '2026-11-17T12:00:30.000Z',
        },
      })
    );
    expect(html).toContain('Blast radius (security team only)');
    expect(html).toContain('Marked read by 7; replied to by 2; forwarded by 1.');
    expect(html).not.toContain('<img');
    expect(text).toContain('BLAST RADIUS (security team only)');
    expect(text).toContain('REPLIED');
  });

  it('renders an unavailable blast radius as its one-line note', () => {
    const { html } = buildFanoutAlert(
      input({
        blastRadius: {
          status: 'unavailable',
          note: 'Blast radius lookup could not be completed: it ran out of time before any result.',
          lookedUpAt: '2026-11-17T12:00:30.000Z',
        },
      })
    );
    expect(html).toContain('it ran out of time before any result');
  });
});

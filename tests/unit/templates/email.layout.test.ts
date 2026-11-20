/**
 * Every email Phishy sends, rendered with a hostile sample: built for mail
 * clients (tables, inline styles, 600px), no remote resource or script of
 * any kind, severity always shown as a word, and nothing from the
 * suspicious email in the hidden preview text or turned into markup.
 * Invented example.com-style data only.
 */

import { buildEmailHtml } from '../../../src/templates/report.html';
import {
  buildDistributionWarning,
  buildEmployeeWarning,
  buildIncidentEmail,
  buildRemovalNotice,
} from '../../../src/templates/campaign.response.html';
import { buildFanoutAlert } from '../../../src/templates/fanout.alert';
import { escapeHtml, facts, hero, meter } from '../../../src/templates/layout';
import { emptyReach } from '../../../src/services/response/scope';
import type { CampaignIncident, IncidentSummary } from '../../../src/services/response/response.types';
import type { AnalysisResult, ExtractedEmailData } from '../../../src/types';

const SCRIPT = '<script>alert(document.cookie)</script>';
const IMG = '<img src=x onerror="alert(1)">';
const HOSTILE = `${SCRIPT}${IMG} Invoice "2291" & co`;

const emailData: ExtractedEmailData = {
  from_email: `${IMG}@example.com`,
  subject: `Fwd: ${HOSTILE}`,
  text: '',
  html: `<p>Hello</p>${SCRIPT}<a href="javascript:alert(1)">Pay</a><img src="x">`,
  headers: { From: `${IMG}@example.com` },
  forwardedHeaders: { 'Original-From': `"${IMG}" <ceo@example.net>` },
  attachments: [{ filename: `${IMG}.html`, contentType: 'text/html"><b>x', size: 900 }],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'ceo@example.net',
  originalForwarder: 'reporter@example.com',
  links: [],
};

const analysis: AnalysisResult = {
  summary: `Summary ${IMG}`,
  isPhishing: true,
  confidence: 'High',
  indicators: [SCRIPT, `Indicator ${IMG}`],
  recommendations: [IMG],
};

const summary: IncidentSummary = {
  verdict: 'phishing',
  riskScore: 92,
  riskLevel: 'critical',
  reasons: [SCRIPT, IMG],
  lure: HOSTILE,
  subject: HOSTILE,
  senderAddress: `billing@example.net"><svg onload=alert(3)>`,
  senderName: IMG,
  detectedBy: 'employee reports (the campaign alert threshold)',
  analysisId: '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
};

const incident: CampaignIncident = {
  id: 'i1',
  campaignSignature: 'sig',
  reference: 'PHY-AAAA-BBBB-CCCC-DDDD',
  trigger: 'reports',
  status: 'open',
  summary,
  reach: emptyReach('not_enabled', 'Blast radius is not enabled.'),
  reportCount: 2,
  notifiedReportCount: 0,
  notifiedRecipientCount: 0,
  createdAt: new Date('2026-11-17T10:00:00Z'),
};

const warningContext = {
  summary,
  reportCount: 2,
  timeZone: 'UTC',
  alreadyClickedInstructions: 'Call the service desk on extension 4400.',
  incidentReference: 'PHY-AAAA-BBBB-CCCC-DDDD',
  confirmedBy: 'phishy' as const,
};

const rendered: Array<[string, string, string]> = [
  [
    'analysis report',
    buildEmailHtml(analysis, emailData, {
      analysisId: 'abc-123',
      risk: { verdict: 'phishing', riskScore: 92, riskLevel: 'critical', reasons: [IMG] },
    }),
    'PHISHING',
  ],
  [
    'employee warning',
    buildEmployeeWarning(warningContext, { address: 'p@example.com', folder: 'inbox' }).html,
    'PHISHING',
  ],
  ['distribution warning', buildDistributionWarning(warningContext).html, 'PHISHING'],
  ['removal notice', buildRemovalNotice(warningContext).html, 'Removed'],
  [
    'incident email',
    buildIncidentEmail({
      incident,
      proposed: [],
      done: [],
      notes: [],
      commandsEnabled: true,
      timeZone: 'UTC',
    }).html,
    'PHISHING',
  ],
  [
    'fan-out alert',
    buildFanoutAlert({
      reference: 'FANOUT-0A1B2C3D4E',
      kind: 'new',
      flag: {
        senderAddress: `${IMG}@supplier.example.net`,
        subject: HOSTILE,
        firstSeen: '2026-11-17T11:58:00.000Z',
        lastSeen: '2026-11-17T11:59:30.000Z',
        windowRecipients: 42,
        windowMessages: 2,
        statuses: { delivered: 30, junk: 5, quarantined: 6, failed: 1, other: 0 },
        recipients: [{ address: `${IMG}@example.com`, status: 'delivered' }],
        recipientsOmitted: 0,
        facts: {
          classification: 'established_with_anomalous_fanout',
          lookbackDays: 30,
          burstWindowHours: 25,
          history: {
            messages: { count: 3, atLeast: false },
            recipients: { count: 2, atLeast: false },
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
          sendingIps: { burst: 0, seenInHistory: 0, historyComplete: true },
          truncated: false,
        },
      },
      waveRecipients: 42,
      waveFirstSeen: '2026-11-17T11:58:00.000Z',
      window: { from: '2026-11-17T11:45:00.000Z', to: '2026-11-17T12:00:00.000Z' },
      incompleteReasons: [],
    }).html,
    'Security team only',
  ],
];

function preheader(html: string): string {
  const match = /<div style="display:none;[^"]*">([\s\S]*?)<\/div>/.exec(html);
  return match ? match[1] : '';
}

/** The markup alone: every tag, without the (escaped) text between them */
function tags(html: string): string {
  return (html.match(/<[^>]+>/g) ?? []).join('\n');
}

describe.each(rendered)('%s', (_name, html, severityWord) => {
  it('loads nothing remote and runs nothing', () => {
    const markup = tags(html);
    expect(markup).not.toMatch(/<script/i);
    expect(markup).not.toMatch(/<(img|iframe|link|object|embed|svg|form|a|base|video|audio)\b/i);
    expect(markup).not.toMatch(/\b(src|href|action|background|srcset|poster)\s*=/i);
    expect(markup).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/url\(|@import/i);
  });

  it('is table-based, 600px wide, with no flex or grid layout', () => {
    expect(html).toContain('<table role="presentation"');
    expect(html).toContain('max-width:600px');
    expect(html).not.toMatch(/display:\s*(flex|grid)/i);
    expect(html).toContain('prefers-color-scheme:dark');
  });

  it('names the severity in words, not colour alone', () => {
    expect(html).toContain(`>${severityWord}</td>`);
  });

  it('keeps the suspicious email out of the hidden preview text', () => {
    const preview = preheader(html);
    expect(preview.length).toBeGreaterThan(0);
    for (const hostile of ['alert', 'Invoice', 'onerror', 'example.net']) {
      expect(preview).not.toContain(hostile);
    }
  });

  it('escapes every hostile value', () => {
    expect(html).not.toContain(IMG);
    expect(html).not.toContain('<svg');
    expect(html).not.toContain('<b>');
    // The hostile subject reaches every email, always as escaped text (defanged in
    // the campaign emails, so "document.cookie" may read "document[.]cookie")
    expect(html).toMatch(/&lt;script&gt;alert\(document(\.|\[\.\])cookie\)&lt;\/script&gt;/);
  });
});

describe('layout blocks', () => {
  it('escape plain-text parameters', () => {
    const html = hero({ tone: 'danger', word: IMG, headline: SCRIPT }) + facts([{ label: IMG, value: SCRIPT }]);
    expect(html).not.toContain(IMG);
    expect(html).not.toContain(SCRIPT);
    expect(html).toContain(escapeHtml(SCRIPT));
  });

  it('draws the meter for the ends of the scale', () => {
    expect(meter(0, 'safe')).not.toContain('width="0%"');
    expect(meter(1, 'danger')).toContain('width="100%"');
    expect(meter(1, 'danger')).not.toContain('width="0%"');
    expect(meter(0.92, 'danger')).toContain('width="92%"');
  });
});

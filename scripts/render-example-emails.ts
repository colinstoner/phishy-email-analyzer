/**
 * Render the example emails shown in the README, from the real template
 * builders, with invented sample data.
 *
 *   npx tsx scripts/render-example-emails.ts [--out <dir>]
 *       Writes one HTML file per example (default: <os tmpdir>/phishy-example-emails).
 *       No dependency beyond the repo's own; no network, AWS, Graph, database
 *       or model call of any kind: the builders are pure functions.
 *
 *   npm i --no-save --no-package-lock puppeteer-core sharp
 *   npx tsx scripts/render-example-emails.ts --png
 *       Also screenshots each example into examples/*.png with a local
 *       Chrome/Chromium (CHROME_PATH overrides the binary): 680px viewport,
 *       device scale factor 2, light mode, cropped to the email card. Long
 *       emails are cut at a row boundary with a fade. `sharp`, when present,
 *       palette-compresses the PNGs; without it they are written as captured.
 *
 * Every name, address, domain, IP and reference below is invented: reserved
 * domains only (example.com/.net/.org, .example, .test) and documentation IP
 * ranges. Never put real organization, people or domains here.
 */

/// <reference lib="dom" />

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createRequire } from 'module';

import { buildEmailHtml, ReportOptions } from '../src/templates/report.html';
import { buildEmployeeWarning, buildIncidentEmail } from '../src/templates/campaign.response.html';
import { buildFanoutAlert } from '../src/templates/fanout.alert';
import { mergeReach } from '../src/services/response/scope';
import { DEFAULT_ALREADY_CLICKED_INSTRUCTIONS } from '../src/config/schema';
import type { BlastRadiusReport } from '../src/services/graph/blast-radius.service';
import type {
  CampaignIncident,
  IncidentSummary,
  ResponseAction,
} from '../src/services/response/response.types';
import type { AnalysisResult, ExtractedEmailData, SenderHistoryFacts } from '../src/types';

const TIME_ZONE = 'America/Chicago';

interface Example {
  /** Base name of the HTML and PNG files */
  name: string;
  html: string;
  /** Tallest screenshot, in CSS pixels, before the email is cut */
  maxHeight: number;
}

// ---------------------------------------------------------------------------
// Analysis reports (the reply to the employee who forwarded the email)
// ---------------------------------------------------------------------------

function email(overrides: Partial<ExtractedEmailData>): ExtractedEmailData {
  return {
    from_email: 'jordan.lee@example.com',
    subject: '(forwarded)',
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: 'jordan.lee@example.com',
    to: 'phishy@example.com',
    original_sender: '',
    originalForwarder: 'jordan.lee@example.com',
    links: [],
    ...overrides,
  };
}

function analysis(overrides: Partial<AnalysisResult>): AnalysisResult {
  return {
    summary: '',
    isPhishing: false,
    confidence: 'High',
    indicators: [],
    recommendations: [],
    provider: 'anthropic',
    model: 'claude-opus-4-8',
    ...overrides,
  };
}

interface ReportSample {
  name: string;
  email: ExtractedEmailData;
  analysis: AnalysisResult;
  options: ReportOptions;
}

const reports: ReportSample[] = [
  {
    name: 'report-phishing',
    email: email({
      subject: 'FW: Your Microsoft 365 password expires today',
      text: 'Your password for jordan.lee@example.com expires today. To keep your current password and avoid losing access to email and files, confirm your account within 24 hours: https://m365-account-review.test/keep?u=jordan.lee  IT Service Desk',
      original_sender: 'IT Service Desk <no-reply@m365-account-review.test>',
      forwardedHeaders: {
        'Original-From': 'IT Service Desk <no-reply@m365-account-review.test>',
        'Original-Subject': 'Your Microsoft 365 password expires today',
      },
      links: ['https://m365-account-review.test/keep?u=jordan.lee'],
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Very High',
      summary:
        'A credential-harvesting email dressed up as a Microsoft 365 password-expiry notice. The "keep my password" link leads to a look-alike sign-in page on an unrelated domain.',
      indicators: [
        'The link goes to m365-account-review.test, which is not a Microsoft or company domain',
        'Deadline pressure ("expires today", "within 24 hours") to rush you past checking',
        'Generic "IT Service Desk" sender from outside the company',
      ],
      recommendations: [
        'Block m365-account-review.test at the mail and web gateways.',
        'Check sign-in logs for anyone who reached the page.',
      ],
      assessment: {
        verdict: 'phishing',
        riskScore: 91,
        verdictConfidence: 0.95,
        threatVectors: ['credential_harvest'],
        targeting: 'mass',
      },
    }),
    options: {
      analysisId: '7c41e2a9-5b0d-4f3e-9a21-0d6b8e4f1c37',
      risk: {
        verdict: 'phishing',
        riskScore: 91,
        riskLevel: 'critical',
        confidence: 'Very High',
        confidenceBasis: 'model',
        reasons: ['Matches a credential-phishing campaign already reported 4 times this week.'],
      },
    },
  },
  {
    name: 'report-bec',
    email: email({
      from_email: 'sam.ortiz@example.com',
      sender: 'sam.ortiz@example.com',
      originalForwarder: 'sam.ortiz@example.com',
      subject: 'FW: Updated remittance details before Friday',
      text: "Hi Sam, our bank has moved our accounts. Please use the new details below for all payments from today, including the invoice due Friday. I'm travelling and can't take calls, so just confirm by email once it's updated. Thanks, Dana Whitfield, Accounts, Harbor Supply",
      original_sender: 'Dana Whitfield <dana.whitfield@harbor-supp1y.example.net>',
      forwardedHeaders: {
        'Original-From': 'Dana Whitfield <dana.whitfield@harbor-supp1y.example.net>',
        'Original-Subject': 'Updated remittance details before Friday',
        'Original-Reply-To': 'remittance@payments-desk.test',
      },
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Very High',
      summary:
        "Someone is posing as a regular supplier's accounts contact to redirect a payment to a new bank account: classic vendor-payment fraud.",
      indicators: [
        'Sender domain harbor-supp1y.example.net swaps the letter "l" for the digit "1" in the real supplier domain',
        'Replies are routed to an unrelated address (payments-desk.test)',
        'A bank-detail change with time pressure and a refusal to talk by phone',
      ],
      recommendations: [
        'Confirm any bank-detail change with the supplier on a phone number already on file.',
        'Hold payments to the new account until verified.',
      ],
      assessment: {
        verdict: 'bec',
        riskScore: 95,
        verdictConfidence: 0.96,
        threatVectors: ['wire_fraud'],
        targeting: 'targeted',
      },
    }),
    options: {
      analysisId: '2e9f6b13-8a4c-4d07-b5e2-61c0f3a9d84e',
      risk: {
        verdict: 'bec',
        riskScore: 95,
        riskLevel: 'critical',
        confidence: 'Very High',
        confidenceBasis: 'model',
        reasons: [
          'The real supplier domain has written to 12 people here; this look-alike never has.',
        ],
      },
    },
  },
  {
    name: 'report-suspicious',
    email: email({
      subject: 'FW: Quick question',
      text: 'Are you at your desk? I need a small favor handled before lunch and I am stuck in meetings. Reply here when you see this. Sent from my phone. Chris',
      original_sender: 'Chris Morgan <chris.morgan.office@freemail.example>',
      forwardedHeaders: {
        'Original-From': 'Chris Morgan <chris.morgan.office@freemail.example>',
        'Original-Subject': 'Quick question',
      },
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Medium',
      summary:
        'A vague "are you at your desk?" opener using a senior colleague\'s name but sent from a personal webmail address. It asks for nothing yet, which is how gift-card and payment scams usually start.',
      indicators: [
        "Uses a colleague's name but comes from a personal webmail account, not the company domain",
        'No details at all: a short opener meant to start a conversation',
      ],
      assessment: {
        verdict: 'suspicious',
        riskScore: 52,
        verdictConfidence: 0.62,
        threatVectors: ['reconnaissance'],
        targeting: 'targeted',
      },
    }),
    options: {
      analysisId: '9b0c4d7e-1f2a-4e6b-8c3d-5a7e9f1b2c4d',
      risk: {
        verdict: 'suspicious',
        riskScore: 52,
        riskLevel: 'medium',
        confidence: 'Medium',
        confidenceBasis: 'model',
        reasons: ['First email ever received here from this address.'],
      },
    },
  },
  {
    name: 'report-legitimate',
    email: email({
      subject: 'FW: Your open enrollment confirmation',
      text: 'Thanks for completing open enrollment. Your elections for next year are saved. You can review them any time by signing in to the Benefits Center. Questions? Contact your HR team. This is an automated message; please do not reply.',
      original_sender: 'Benefits Center <noreply@benefits.example.org>',
      forwardedHeaders: {
        'Original-From': 'Benefits Center <noreply@benefits.example.org>',
        'Original-Subject': 'Your open enrollment confirmation',
      },
      links: ['https://benefits.example.org/elections'],
    }),
    analysis: analysis({
      isPhishing: false,
      confidence: 'Very Low',
      summary:
        'A genuine benefits-enrollment confirmation. It comes from the provider your company already uses, its links stay on that provider, and it asks for nothing.',
      assessment: {
        verdict: 'legitimate',
        riskScore: 6,
        verdictConfidence: 0.93,
        threatVectors: [],
        targeting: 'mass',
      },
    }),
    options: {
      analysisId: '4f8a2c6e-0b1d-4a3f-9e5c-7d2b6a8f0e1c',
      risk: {
        verdict: 'legitimate',
        riskScore: 6,
        riskLevel: 'safe',
        confidence: 'High',
        confidenceBasis: 'model',
        reasons: [
          'Sender passed SPF and DKIM for benefits.example.org.',
          'This sender has written to 140 people here over the past year.',
        ],
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Campaign response: the incident email and the employee warning
// ---------------------------------------------------------------------------

const FIRST_DELIVERY = '2026-11-17T14:02:00.000Z';
const PEOPLE = [
  'avery.chen',
  'blake.ramos',
  'casey.patel',
  'devon.brooks',
  'emery.santos',
  'finley.ward',
  'harper.kim',
  'jamie.foster',
  'kendall.price',
  'logan.reyes',
  'morgan.hayes',
  'parker.ellis',
  'quinn.douglas',
  'riley.nash',
];

const campaignReach: BlastRadiusReport = {
  status: 'complete',
  route: 'mailbox',
  matchedBy: 'senderSubject',
  totals: { recipients: 14, read: 8, replied: 1, forwarded: 1, notDelivered: 0 },
  recipients: PEOPLE.map((person, index) => ({
    address: `${person}@example.com`,
    mailbox: 'found' as const,
    folder:
      index === 11 ? ('junk' as const) : index === 12 ? ('deleted' as const) : ('inbox' as const),
    isRead: index < 8,
    response:
      index === 0 ? ('replied' as const) : index === 1 ? ('forwarded' as const) : ('none' as const),
    mailboxId: `00000000-0000-4000-8000-0000000000${String(index).padStart(2, '0')}`,
    messageIds: [`AAMkAGExample${index}`],
    receivedAt: new Date(Date.parse(FIRST_DELIVERY) + index * 20_000).toISOString(),
  })),
  coverage: {
    mailboxesChecked: 412,
    mailboxesEligible: 412,
    eligibleIsLowerBound: false,
    recoverableChecked: 0,
    recoverableCandidates: 0,
    detailUnavailable: 0,
  },
  caveats: [],
  lookedUpAt: '2026-11-17T15:41:00.000Z',
};

const campaignSummary: IncidentSummary = {
  verdict: 'phishing',
  riskScore: 93,
  riskLevel: 'critical',
  confidence: 'Very High',
  confidenceBasis: 'model',
  reasons: [
    'The "View document" link leads to a look-alike Microsoft 365 sign-in page on docs-share-portal.test.',
    'Sent from a domain registered 3 days ago that has never written to anyone here.',
    'Reported by 3 people in 2 departments within 40 minutes.',
  ],
  lure: 'A fake file-sharing notice about a "Q4 payment schedule" that sends readers to a counterfeit Microsoft 365 sign-in page to capture their password.',
  subject: 'Q4 payment schedule shared with you',
  senderAddress: 'notifications@docs-share-portal.test',
  senderName: 'Document Center',
  firstDeliveryAt: FIRST_DELIVERY,
  firstReportAt: '2026-11-17T14:19:00.000Z',
  lastReportAt: '2026-11-17T14:58:00.000Z',
  analysisId: '6d3e9a1f-2b4c-4e8d-a7f0-1c5b9e3d7a2f',
  detectedBy: 'employee reports (the campaign alert threshold)',
};

const campaignIncident: CampaignIncident = {
  id: 'incident-1',
  campaignSignature: 'example-signature',
  reference: 'PHY-K7QM-3TXA-R9CW-H2NB',
  trigger: 'reports',
  status: 'open',
  summary: campaignSummary,
  reach: mergeReach(undefined, campaignReach, true),
  reportCount: 3,
  notifiedReportCount: 0,
  notifiedRecipientCount: 0,
  createdAt: new Date('2026-11-17T15:00:00Z'),
};

const warnRecipients = (campaignReach.recipients ?? [])
  .filter(r => r.folder !== 'deleted')
  .map(r => ({
    address: r.address,
    ...(r.receivedAt ? { receivedAt: r.receivedAt } : {}),
    ...(r.folder ? { folder: r.folder } : {}),
  }));

const removalMailboxes = (campaignReach.recipients ?? [])
  .filter(r => r.folder === 'inbox' || r.folder === 'junk')
  .map(r => ({
    address: r.address,
    mailboxId: r.mailboxId ?? '',
    messageIds: r.messageIds ?? [],
    folder: r.folder ?? 'unknown',
    ...(r.isRead !== undefined ? { isRead: r.isRead } : {}),
  }));

const warningAction: ResponseAction = {
  id: 'action-1',
  incidentId: 'incident-1',
  reference: 'PHY-W4LD-8EKF-2PVR-6YJT',
  type: 'send_warning',
  status: 'proposed',
  authorization: 'approve',
  scope: {
    kind: 'send_warning',
    recipients: warnRecipients,
    distribution: false,
    skipped: { notDelivered: 0, unsafeAddress: 0, alreadyContacted: 0, overCap: 0, unlisted: 0 },
  },
  scopeHash: 'example',
  proposedAt: new Date('2026-11-17T15:41:00Z'),
  expiresAt: new Date('2026-11-17T23:41:00Z'),
};

const removalAction: ResponseAction = {
  ...warningAction,
  id: 'action-2',
  reference: 'PHY-R2ZB-5HCN-7QMX-4GSE',
  type: 'remove_messages',
  scope: {
    kind: 'remove_messages',
    mailboxes: removalMailboxes,
    messageCount: removalMailboxes.length,
    limits: { maxMailboxes: 500, maxMessages: 1000 },
    skipped: { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 },
    reachLookedUpAt: campaignReach.lookedUpAt,
  },
};

const incidentEmail = buildIncidentEmail({
  incident: campaignIncident,
  proposed: [warningAction, removalAction],
  done: [
    'Sent each of the 3 reporters their own analysis report.',
    'The proposed actions below are waiting for your approval.',
  ],
  notes: [],
  commandsEnabled: true,
  timeZone: TIME_ZONE,
});

const employeeWarning = buildEmployeeWarning(
  {
    summary: campaignSummary,
    reportCount: 3,
    timeZone: TIME_ZONE,
    alreadyClickedInstructions: DEFAULT_ALREADY_CLICKED_INSTRUCTIONS,
    incidentReference: campaignIncident.reference,
    confirmedBy: 'security_team',
  },
  warnRecipients[2]
);

// ---------------------------------------------------------------------------
// Fan-out alert (the scheduled scan, before anyone has reported it)
// ---------------------------------------------------------------------------

const fanoutFacts: SenderHistoryFacts = {
  classification: 'established_with_anomalous_fanout',
  lookbackDays: 30,
  burstWindowHours: 1,
  history: {
    messages: { count: 37, atLeast: false },
    recipients: { count: 4, atLeast: false },
    firstSeen: '2026-10-19',
  },
  twoWay: {
    messages: { count: 22, atLeast: false },
    internalSenders: { count: 3, atLeast: false },
  },
  burst: {
    messages: { count: 2, atLeast: false },
    recipients: { count: 61, atLeast: false },
    newRecipients: { count: 58, atLeast: false },
    sameSubject: {
      recipients: { count: 61, atLeast: false },
      newRecipients: { count: 58, atLeast: false },
    },
  },
  sendingIps: {
    burst: 2,
    seenInHistory: 1,
    historyComplete: true,
    burstIps: [
      { ip: '203.0.113.48', seenInHistory: false },
      { ip: '198.51.100.17', seenInHistory: true },
    ],
  },
  truncated: false,
};

const FANOUT_PEOPLE = [...PEOPLE, 'sage.turner', 'taylor.bennett', 'rowan.mills', 'skyler.grant'];

const fanoutAlert = buildFanoutAlert({
  reference: 'FANOUT-4B9E2C71D0',
  kind: 'new',
  flag: {
    senderAddress: 'accounts@harbor-supply.example.net',
    subject: 'RFP: updated bid documents for review',
    firstSeen: '2026-11-19T16:04:00.000Z',
    lastSeen: '2026-11-19T16:11:00.000Z',
    windowRecipients: 61,
    windowMessages: 2,
    statuses: { delivered: 49, junk: 4, quarantined: 8, failed: 0, other: 0 },
    recipients: FANOUT_PEOPLE.map((person, index) => ({
      address: `${person}@example.com`,
      status:
        index === 15
          ? ('quarantined' as const)
          : index === 16
            ? ('junk' as const)
            : ('delivered' as const),
    })),
    recipientsOmitted: 61 - FANOUT_PEOPLE.length,
    facts: fanoutFacts,
  },
  waveRecipients: 61,
  waveFirstSeen: '2026-11-19T16:04:00.000Z',
  window: { from: '2026-11-19T15:15:00.000Z', to: '2026-11-19T16:15:00.000Z' },
  incompleteReasons: [],
  timeZone: TIME_ZONE,
});

// ---------------------------------------------------------------------------

const examples: Example[] = [
  ...reports.map(r => ({
    name: r.name,
    html: buildEmailHtml(r.analysis, r.email, r.options),
    maxHeight: 1500,
  })),
  { name: 'incident-email', html: incidentEmail.html, maxHeight: 1700 },
  { name: 'campaign-warning', html: employeeWarning.html, maxHeight: 1500 },
  { name: 'fanout-alert', html: fanoutAlert.html, maxHeight: 1500 },
];

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function argValue(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function findChrome(): string {
  if (process.env.CHROME_PATH) {
    return process.env.CHROME_PATH;
  }
  const candidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium',
  ];
  const found = candidates.find(candidate => fs.existsSync(candidate));
  if (!found) {
    throw new Error('Could not find Chrome/Chromium: set CHROME_PATH to the browser binary.');
  }
  return found;
}

/** The few puppeteer-core calls used here, so the script needs no type package */
interface Page {
  setViewport(v: { width: number; height: number; deviceScaleFactor: number }): Promise<void>;
  emulateMediaFeatures(f: Array<{ name: string; value: string }>): Promise<void>;
  setContent(html: string, o: { waitUntil: string }): Promise<void>;
  evaluate<T, A>(fn: (arg: A) => T, arg: A): Promise<T>;
  screenshot(o: { clip: Clip; type: 'png' }): Promise<Uint8Array>;
  close(): Promise<void>;
}
interface Browser {
  newPage(): Promise<Page>;
  close(): Promise<void>;
}
interface Clip {
  x: number;
  y: number;
  width: number;
  height: number;
}
type Sharp = (input: Uint8Array) => {
  png(o: {
    palette: boolean;
    quality: number;
    dither: number;
    compressionLevel: number;
    effort: number;
  }): {
    toBuffer(): Promise<Buffer>;
  };
};

const MARGIN = 16;

/**
 * Runs in the page: the email card's box with a margin, cut at the last card
 * row that fits under `maxHeight` (with a fade over the cut) when it is longer.
 */
function cropInPage(args: { maxHeight: number; margin: number }): Clip {
  const outer = document.querySelector<HTMLTableElement>('table[style*="max-width:600px"]');
  if (!outer) {
    throw new Error('email card not found');
  }
  const box = outer.getBoundingClientRect();
  const top = Math.max(0, box.top - args.margin);
  const x = Math.max(0, box.left - args.margin);
  const width = box.width + args.margin * 2;
  let bottom = box.bottom + args.margin;
  if (bottom - top > args.maxHeight) {
    const rows = Array.from(
      document.querySelectorAll<HTMLElement>('td.ph-card > table > tbody > tr')
    );
    const limit = top + args.maxHeight;
    const fitting = rows.filter(row => row.getBoundingClientRect().bottom <= limit);
    const cut = fitting.length ? fitting[fitting.length - 1].getBoundingClientRect().bottom : limit;
    bottom = cut;
    const fade = document.createElement('div');
    fade.style.cssText = `position:absolute;left:${x}px;top:${cut - 56}px;width:${width}px;height:56px;background:linear-gradient(rgba(242,244,247,0),rgba(242,244,247,1));`;
    document.body.appendChild(fade);
  }
  return { x, y: top, width, height: Math.ceil(bottom - top) };
}

async function screenshots(dir: string): Promise<void> {
  const load = createRequire(path.join(process.cwd(), 'package.json'));
  const puppeteer = load('puppeteer-core') as {
    launch(o: { executablePath: string; headless: boolean; args: string[] }): Promise<Browser>;
  };
  let sharp: Sharp | undefined;
  try {
    sharp = load('sharp') as Sharp;
  } catch {
    console.warn('sharp not installed: PNGs are written uncompressed');
  }
  const browser = await puppeteer.launch({
    executablePath: findChrome(),
    headless: true,
    args: ['--no-sandbox', '--hide-scrollbars', '--force-color-profile=srgb'],
  });
  try {
    for (const example of examples) {
      const page = await browser.newPage();
      await page.setViewport({ width: 680, height: 900, deviceScaleFactor: 2 });
      await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]);
      await page.setContent(example.html, { waitUntil: 'load' });
      const clip = await page.evaluate(cropInPage, {
        maxHeight: example.maxHeight,
        margin: MARGIN,
      });
      const raw = await page.screenshot({ clip, type: 'png' });
      const png = sharp
        ? await sharp(raw)
            .png({ palette: true, quality: 90, dither: 0, compressionLevel: 9, effort: 10 })
            .toBuffer()
        : raw;
      const out = path.join(dir, `${example.name}.png`);
      fs.writeFileSync(out, png);
      console.log(`wrote ${out} (${Math.round(png.length / 1024)} KB)`);
      await page.close();
    }
  } finally {
    await browser.close();
  }
}

async function main(): Promise<void> {
  const outDir = path.resolve(argValue('--out') ?? path.join(os.tmpdir(), 'phishy-example-emails'));
  fs.mkdirSync(outDir, { recursive: true });
  for (const example of examples) {
    const file = path.join(outDir, `${example.name}.html`);
    fs.writeFileSync(file, example.html);
    console.log(`wrote ${file}`);
  }
  if (process.argv.includes('--png')) {
    await screenshots(path.join(__dirname, '..', 'examples'));
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});

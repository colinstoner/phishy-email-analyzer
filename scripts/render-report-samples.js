/**
 * Render example report screenshots for the README.
 *
 * Produces retina PNGs of the actual employee-facing report
 * (src/templates/report.html.ts) using curated, fully fictional scenarios —
 * one per tone (danger / caution / safe). The data here is invented
 * (example.com / .test only); no real organization, person, or email.
 *
 *   npm run build
 *   npm i --no-save puppeteer-core
 *   node scripts/render-report-samples.js
 *
 * Requires Google Chrome installed (path below). Outputs to examples/*.png.
 */

const path = require('path');
const puppeteer = require('puppeteer-core');
const { buildEmailHtml } = require('../dist/templates/report.html');

const CHROME =
  process.env.CHROME_PATH ||
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

function email(o) {
  return {
    from_email: 'reporter@example.com',
    subject: '(forwarded)',
    text: 'body',
    html: '<p>body</p>',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: '',
    originalForwarder: 'reporter@example.com',
    links: [],
    ...o,
  };
}

function analysis(o) {
  return {
    summary: '',
    isPhishing: false,
    confidence: 'High',
    indicators: [],
    recommendations: [],
    provider: 'bedrock',
    model: 'claude-opus-4-8',
    processingTimeMs: 0,
    ...o,
  };
}

const scenarios = [
  {
    file: 'report-bec.png',
    email: email({
      subject: 'FW: Quick favor — vendor banking update',
      text: "Are you at your desk? I need you to update the payment details for one of our vendors before the 2 PM run — they sent new banking info. I'm in back-to-back meetings and can't take a call. Reply here and I'll forward the account details. Please keep this between us until it's processed. Thanks, Mark",
      original_sender: 'Mark Reyes (CFO) <m.reyes@examp1e-corp.com>',
      forwardedHeaders: {
        'Original-From': 'Mark Reyes (CFO) <m.reyes@examp1e-corp.com>',
        'Original-Subject': 'Quick favor — vendor banking update',
        'Original-Reply-To': 'accounts@payments-secure.test',
      },
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Very High',
      summary:
        'An attacker is impersonating your CFO from a look-alike domain to request an urgent change to vendor banking details — a classic business email compromise.',
      indicators: [
        'Sender domain examp1e-corp.com is a look-alike of your corporate domain (the letter "l" replaced with "1")',
        'Reply-To redirects to an unrelated external address (payments-secure.test)',
        'Urgency and secrecy around a banking change with no prior context',
      ],
      assessment: {
        verdict: 'bec',
        riskScore: 94,
        verdictConfidence: 0.96,
        threatVectors: ['wire_fraud', 'reconnaissance'],
        targeting: 'targeted',
      },
    }),
    options: {
      analysisId: 'a1b2c3d4',
      risk: {
        verdict: 'bec',
        riskScore: 94,
        riskLevel: 'critical',
        reasons: [
          'Sender domain examp1e-corp.com is a one-character look-alike of your corporate domain.',
          'Reply-To points to an unrelated external address.',
          'Seen in 3 reports across 2 departments this week.',
        ],
      },
    },
  },
  {
    file: 'report-phishing.png',
    email: email({
      subject: 'FW: [Action Required] Your mailbox storage is full',
      text: 'Your mailbox has reached 99% of its storage quota. To avoid interruption of service and loss of incoming mail, please re-verify your account within 24 hours using the secure link below. Failure to verify will result in temporary suspension. Re-verify now: https://mail-quota-alerts.test/reauth?u=staff — IT Help Desk',
      original_sender: 'IT Help Desk <no-reply@mail-quota-alerts.test>',
      forwardedHeaders: {
        'Original-From': 'IT Help Desk <no-reply@mail-quota-alerts.test>',
        'Original-Subject': '[Action Required] Your mailbox storage is full',
      },
      links: ['https://mail-quota-alerts.test/reauth?u=staff'],
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Very High',
      summary:
        'A credential-harvesting email posing as an internal IT storage alert, pressuring the reader to "re-verify" their password on a fake login page.',
      indicators: [
        'Link resolves to mail-quota-alerts.test — not your real mail provider',
        'Storage-full urgency lure is a common credential-phishing pattern',
        'Generic "IT Help Desk" sender with no internal domain',
      ],
      assessment: {
        verdict: 'phishing',
        riskScore: 88,
        verdictConfidence: 0.92,
        threatVectors: ['credential_harvest'],
        targeting: 'mass',
      },
    }),
    options: {
      analysisId: 'e5f6a7b8',
      risk: {
        verdict: 'phishing',
        riskScore: 88,
        riskLevel: 'critical',
        reasons: [
          'Login link points to mail-quota-alerts.test, an unrelated domain.',
          'Matches a credential-harvest campaign seen in 6 prior reports.',
        ],
      },
    },
  },
  {
    file: 'report-suspicious.png',
    email: email({
      subject: 'FW: Are you available?',
      text: 'Are you available? I have a quick request I need your help with and it is a little time-sensitive. Let me know as soon as you get this. Sent from my iPhone — Alan',
      original_sender: 'Dr. Alan Pierce <a.pierce.exec@gmail.com>',
      forwardedHeaders: {
        'Original-From': 'Dr. Alan Pierce <a.pierce.exec@gmail.com>',
        'Original-Subject': 'Are you available?',
      },
    }),
    analysis: analysis({
      isPhishing: true,
      confidence: 'Medium',
      summary:
        'A vague "are you available?" opener claiming to come from an executive but sent from a personal Gmail account — a common reconnaissance lead-in to gift-card or wire fraud.',
      indicators: [
        'Claims to be an executive but sent from a personal Gmail address',
        'No specifics — a short, vague opener designed to start a reply thread',
      ],
      assessment: {
        verdict: 'suspicious',
        riskScore: 48,
        verdictConfidence: 0.6,
        threatVectors: ['reconnaissance'],
        targeting: 'targeted',
      },
    }),
    options: {
      analysisId: 'c9d0e1f2',
      risk: {
        verdict: 'suspicious',
        riskScore: 48,
        riskLevel: 'medium',
        reasons: [
          'Executive name paired with a personal Gmail address (display-name spoofing).',
          'Content-free opener typical of reconnaissance.',
        ],
      },
    },
  },
  {
    file: 'report-legitimate.png',
    email: email({
      subject: 'FW: Your January benefits statement is ready',
      text: 'Your January benefits statement is now available. Sign in to the Benefits Center to view your statement, review your current elections, or download a copy for your records. If you have questions, contact your HR representative. This is an automated message — please do not reply.',
      original_sender: 'Benefits Center <noreply@benefits.example>',
      forwardedHeaders: {
        'Original-From': 'Benefits Center <noreply@benefits.example>',
        'Original-Subject': 'Your January benefits statement is ready',
      },
      links: ['https://benefits.example/statements'],
    }),
    analysis: analysis({
      isPhishing: false,
      confidence: 'Very Low',
      summary:
        'A genuine benefits-statement notification. The sender domain is consistent, links stay on the provider domain, and there is no request for credentials or payment.',
      indicators: [],
      recommendations: [],
      assessment: {
        verdict: 'legitimate',
        riskScore: 5,
        verdictConfidence: 0.94,
        threatVectors: [],
        targeting: 'mass',
      },
    }),
    options: {
      analysisId: 'b3c4d5e6',
      risk: {
        verdict: 'legitimate',
        riskScore: 5,
        riskLevel: 'safe',
        reasons: [
          'Sender domain is consistent and links stay on the provider’s domain.',
          'No credential or payment request.',
        ],
      },
    },
  },
];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--hide-scrollbars'],
  });
  for (const s of scenarios) {
    const html = buildEmailHtml(s.analysis, s.email, s.options);
    const page = await browser.newPage();
    await page.setViewport({ width: 880, height: 800, deviceScaleFactor: 2 });
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const out = path.join(__dirname, '..', 'examples', s.file);
    await page.screenshot({ path: out, fullPage: true });
    console.log('wrote', out);
    await page.close();
  }
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

/**
 * Where sender-relationship facts surface: the prompt, risk fusion, the
 * report, metrics and configuration. Invented data only.
 */

import { loadConfig } from '../../../../src/config';
import { safeValidateConfig } from '../../../../src/config/schema';
import { buildPhishingAnalysisPrompt } from '../../../../src/services/ai/prompt.builder';
import {
  SENDER_FANOUT_RISK_FLOOR,
  fuseRisk,
} from '../../../../src/services/intelligence/risk.fusion';
import { buildEmailHtml, buildPlainTextReport } from '../../../../src/templates/report.html';
import {
  AnalysisResult,
  ExtractedEmailData,
  SenderHistoryFacts,
  SenderRelationshipClass,
  ThreatVerdict,
} from '../../../../src/types';
import { emitSenderHistoryMetric } from '../../../../src/utils/metrics';
import { formatSenderHistoryLines } from '../../../../src/utils/sender-history.format';

const CLAIMED_SENDER = 'pat@supplier.example.net';

function exact(count: number): { count: number; atLeast: boolean } {
  return { count, atLeast: false };
}

function facts(
  classification: SenderRelationshipClass,
  overrides: Partial<SenderHistoryFacts> = {}
): SenderHistoryFacts {
  return {
    classification,
    lookbackDays: 30,
    burstWindowHours: 24,
    history: { messages: exact(12), recipients: exact(3), firstSeen: '2026-10-20' },
    twoWay: { messages: exact(5), internalSenders: exact(2) },
    burst: { messages: exact(41), recipients: exact(40), newRecipients: exact(38) },
    sendingIps: {
      burst: 2,
      seenInHistory: 0,
      historyComplete: true,
      burstIps: [
        { ip: '198.51.100.7', seenInHistory: false },
        { ip: '203.0.113.9', seenInHistory: false },
      ],
    },
    domain: { messages: exact(30), recipients: exact(6), firstSeen: '2026-10-19' },
    truncated: false,
    ...overrides,
  };
}

const TRUNCATED = facts('established', {
  history: { messages: { count: 2000, atLeast: true }, recipients: { count: 150, atLeast: true }, firstSeen: '2026-11-01' },
  burst: { messages: exact(4), recipients: exact(4), newRecipients: null },
  sendingIps: { burst: 1, seenInHistory: 1, historyComplete: false },
  truncated: true,
});

function emailData(senderHistory?: SenderHistoryFacts): ExtractedEmailData {
  return {
    from_email: 'reporter@example.com',
    subject: 'FW: RFQ 1001',
    text: `---------- Forwarded message ---------\nFrom: Pat <${CLAIMED_SENDER}>\nSubject: RFQ 1001\n\nPlease review the attached RFQ.`,
    html: '',
    headers: {},
    forwardedHeaders: { 'Original-From': `Pat <${CLAIMED_SENDER}>` },
    attachments: [],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: 'reporter@example.com',
    originalForwarder: 'reporter@example.com',
    links: [],
    senderHistory,
  };
}

function analysis(verdict: ThreatVerdict, riskScore: number): AnalysisResult {
  return {
    summary: 'test',
    isPhishing: false,
    confidence: 'Medium',
    indicators: [],
    recommendations: [],
    assessment: {
      verdict,
      riskScore,
      verdictConfidence: 0.9,
      threatVectors: [],
      targeting: 'unknown',
    },
  };
}

describe('formatSenderHistoryLines', () => {
  it('states exact counts plainly', () => {
    const text = formatSenderHistoryLines(facts('established_with_anomalous_fanout'))
      .map(line => line.join(': '))
      .join('\n');
    expect(text).toContain('Classification: established_with_anomalous_fanout');
    expect(text).toContain(
      'History (30-day lookback, excluding the burst window): 12 messages to 3 distinct internal recipients; first seen 2026-10-20'
    );
    expect(text).toContain('5 messages to this address from 2 distinct internal senders');
    expect(text).toContain(
      'Burst window (the last 24 hours): 41 messages to 40 distinct internal recipients; 38 of them had no mail from this address in the history period'
    );
    expect(text).toContain('2 distinct; 0 of them also seen in the history period');
    expect(text).not.toContain('at least');
    expect(text).not.toContain('Elision');
  });

  it('never presents a truncated count as exact', () => {
    const text = formatSenderHistoryLines(TRUNCATED)
      .map(line => line.join(': '))
      .join('\n');
    expect(text).toContain(
      'at least 2000 messages to at least 150 distinct internal recipients; first seen on or before 2026-11-01'
    );
    expect(text).toContain('could not be determined (history was cut short)');
    expect(text).toContain('1 distinct; at least 1 of them also seen');
    expect(text).toContain('Elision: counts marked "at least" were cut short by a row cap');
  });

  it('says so when there is nothing', () => {
    const text = formatSenderHistoryLines(
      facts('no_history', {
        history: { messages: exact(0), recipients: exact(0) },
        twoWay: { messages: exact(0), internalSenders: exact(0) },
        burst: { messages: exact(0), recipients: exact(0), newRecipients: exact(0) },
        sendingIps: { burst: 0, seenInHistory: 0, historyComplete: true },
        domain: undefined,
      })
    )
      .map(line => line.join(': '))
      .join('\n');
    expect(text).toContain('excluding the burst window): none');
    expect(text).toContain('none: no mail from the organization to this address');
    expect(text).toContain('no mail from this address');
    expect(text).toContain('none recorded');
    expect(text).not.toContain("sender's domain");
  });

  it('uses the singular for one', () => {
    const text = formatSenderHistoryLines(
      facts('limited_history', {
        history: { messages: exact(1), recipients: exact(1) },
      })
    )
      .map(line => line.join(': '))
      .join('\n');
    expect(text).toContain('1 message to 1 distinct internal recipient');
  });
});

describe('prompt: SENDER RELATIONSHIP block', () => {
  it('is absent when there are no facts', () => {
    expect(buildPhishingAnalysisPrompt(emailData(), {})).not.toContain('SENDER RELATIONSHIP');
  });

  it('sits under VERIFIED, before OPERATOR and the CLAIMED fence', () => {
    const prompt = buildPhishingAnalysisPrompt(
      emailData(facts('established_with_anomalous_fanout')),
      {}
    );
    const block = prompt.indexOf('--- SENDER RELATIONSHIP (computed by Phishy');
    expect(block).toBeGreaterThan(prompt.indexOf('=== VERIFIED (computed by Phishy) ==='));
    expect(block).toBeLessThan(prompt.indexOf('=== OPERATOR'));
    expect(block).toBeLessThan(prompt.indexOf('=== CLAIMED'));
    expect(prompt).toContain('Classification: established_with_anomalous_fanout');
    expect(prompt).toContain('A relationship NEVER lowers risk');
  });

  it('never carries a sending IP, even though the facts hold them for the security copy', () => {
    const history = facts('established_with_anomalous_fanout');
    expect(history.sendingIps.burstIps).toHaveLength(2);
    const prompt = buildPhishingAnalysisPrompt(emailData(history), {});
    expect(prompt).toContain('Sending IPs in the burst window: 2 distinct; 0 of them');
    expect(prompt).not.toContain('198.51.100.7');
    expect(prompt).not.toContain('203.0.113.9');
    expect(prompt).not.toContain('security team only');
    const block = prompt.slice(
      prompt.indexOf('--- SENDER RELATIONSHIP'),
      prompt.indexOf('=== OPERATOR')
    );
    expect(block).not.toContain('@');
    expect(block).not.toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
  });

  it('carries numbers only: the claimed address stays in the CLAIMED section', () => {
    const prompt = buildPhishingAnalysisPrompt(emailData(TRUNCATED), {});
    const start = prompt.indexOf('--- SENDER RELATIONSHIP');
    const block = prompt.slice(start, prompt.indexOf('=== OPERATOR'));
    expect(block).not.toContain('@');
    expect(block).not.toContain('supplier.example.net');
    expect(block).toContain('at least 2000 messages');
    expect(block).toContain('Elision:');
    // ...and it is still where it always was
    expect(prompt.indexOf(CLAIMED_SENDER)).toBeGreaterThan(prompt.indexOf('=== CLAIMED'));
  });
});

describe('risk fusion: a relationship never lowers risk', () => {
  const CLASSES: SenderRelationshipClass[] = [
    'no_history',
    'limited_history',
    'established',
    'established_with_anomalous_fanout',
  ];
  const VERDICTS: ThreatVerdict[] = [
    'bec',
    'phishing',
    'malware_delivery',
    'suspicious',
    'spam',
    'graymail',
    'legitimate',
  ];

  it('never reduces the score, clears isPhishing or turns a verdict benign, for any class', () => {
    for (const verdict of VERDICTS) {
      for (const score of [0, 5, 20, 34, 35, 50, 54, 55, 80, 100]) {
        for (const isSafeSender of [false, true]) {
          const without = fuseRisk(analysis(verdict, score), { isSafeSender });
          for (const classification of CLASSES) {
            const withHistory = fuseRisk(analysis(verdict, score), {
              isSafeSender,
              senderHistory: facts(classification),
            });
            expect(withHistory.riskScore).toBeGreaterThanOrEqual(without.riskScore);
            if (without.isPhishing) {
              expect(withHistory.isPhishing).toBe(true);
            }
            if (without.verdict !== 'legitimate') {
              expect(withHistory.verdict).toBe(without.verdict);
            }
          }
        }
      }
    }
  });

  it('gives an established sender no credit at all', () => {
    for (const classification of ['no_history', 'limited_history', 'established'] as const) {
      expect(
        fuseRisk(analysis('suspicious', 60), { senderHistory: facts(classification) })
      ).toEqual(fuseRisk(analysis('suspicious', 60)));
    }
  });

  it('raises a low score to the floor on anomalous fan-out and adds a plain reason', () => {
    const decision = fuseRisk(analysis('legitimate', 5), {
      senderHistory: facts('established_with_anomalous_fanout'),
    });
    expect(decision.riskScore).toBe(SENDER_FANOUT_RISK_FLOOR);
    expect(decision.riskLevel).toBe('medium');
    expect(decision.verdict).toBe('suspicious');
    expect(decision.reasons).toHaveLength(1);
    expect(decision.reasons[0]).toContain('far more people than usual');
    expect(decision.reasons[0]).not.toMatch(/\d/);
  });

  it('keeps a higher score and a specific verdict, adding only the reason', () => {
    const decision = fuseRisk(analysis('bec', 90), {
      senderHistory: facts('established_with_anomalous_fanout'),
    });
    expect(decision.riskScore).toBe(90);
    expect(decision.verdict).toBe('bec');
    expect(decision.reasons).toHaveLength(1);
  });

  it('is not undone by the trusted-reporter cap', () => {
    const decision = fuseRisk(analysis('legitimate', 20), {
      isSafeSender: true,
      senderHistory: facts('established_with_anomalous_fanout'),
    });
    expect(decision.riskScore).toBe(SENDER_FANOUT_RISK_FLOOR);
    expect(decision.verdict).toBe('suspicious');
  });

  it('lifts a failed analysis off "undetermined"', () => {
    const failed: AnalysisResult = {
      summary: 'x',
      isPhishing: false,
      confidence: 'N/A',
      indicators: [],
      recommendations: [],
      analysisFailed: true,
    };
    const decision = fuseRisk(failed, { senderHistory: facts('established_with_anomalous_fanout') });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBe(SENDER_FANOUT_RISK_FLOOR);
  });

  it('still yields to a security-team ruling', () => {
    const decision = fuseRisk(analysis('legitimate', 5), {
      humanVerdict: 'false_positive',
      senderHistory: facts('established_with_anomalous_fanout'),
    });
    expect(decision.verdict).toBe('legitimate');
    expect(decision.riskScore).toBe(0);
  });
});

describe('formatSenderHistoryLines: burst IPs', () => {
  const text = (history: SenderHistoryFacts, includeBurstIps: boolean): string =>
    formatSenderHistoryLines(history, { includeBurstIps })
      .map(line => line.join(': '))
      .join('\n');

  it('lists them only when asked', () => {
    const history = facts('established');
    expect(text(history, false)).not.toContain('198.51.100.7');
    expect(formatSenderHistoryLines(history)).toEqual(
      formatSenderHistoryLines(history, { includeBurstIps: false })
    );
    expect(text(history, true)).toContain(
      'Burst sending IPs (security team only): 198.51.100.7 (not seen in the history period); 203.0.113.9 (not seen in the history period)'
    );
  });

  it('says how many were left out by the cap', () => {
    const history = facts('established', {
      sendingIps: {
        burst: 23,
        seenInHistory: 1,
        historyComplete: true,
        burstIps: [
          { ip: '198.51.100.7', seenInHistory: false },
          { ip: '192.0.2.10', seenInHistory: true },
        ],
        burstIpsOmitted: 21,
      },
    });
    expect(text(history, true)).toContain(
      '198.51.100.7 (not seen in the history period); 192.0.2.10 (seen in the history period); and 21 more'
    );
  });

  it('does not claim "not seen" against a history that was cut short', () => {
    const history = facts('established', {
      sendingIps: {
        burst: 1,
        seenInHistory: 0,
        historyComplete: false,
        burstIps: [{ ip: '198.51.100.7', seenInHistory: false }],
      },
    });
    expect(text(history, true)).toContain('198.51.100.7 (not in the history rows read)');
  });

  it('adds no line when there is nothing to list', () => {
    const history = facts('established', {
      sendingIps: { burst: 0, seenInHistory: 0, historyComplete: true },
    });
    expect(text(history, true)).not.toContain('security team only');
    const unlisted = facts('established', {
      sendingIps: { burst: 2, seenInHistory: 0, historyComplete: true, burstIpsOmitted: 2 },
    });
    expect(text(unlisted, true)).toContain('Burst sending IPs (security team only): 2 not listed');
  });
});

describe('report: sender-relationship detail by audience', () => {
  const history = facts('established_with_anomalous_fanout');
  const risk = fuseRisk(analysis('phishing', 90), { senderHistory: history });
  const render = (audience?: 'reporter' | 'security'): { html: string; text: string } => {
    const options = { risk, ...(audience ? { audience } : {}) };
    return {
      html: buildEmailHtml(analysis('phishing', 90), emailData(history), options),
      text: buildPlainTextReport(analysis('phishing', 90), emailData(history), options),
    };
  };

  it('security-only copy: counts, classification and the burst IPs', () => {
    const { html, text } = render('security');
    for (const body of [html, text]) {
      expect(body).toContain(
        'Sender Relationship (organization mail-flow records; security team only)'
      );
      expect(body).toContain('established_with_anomalous_fanout');
      expect(body).toContain('198.51.100.7 (not seen in the history period)');
      expect(body).toContain('203.0.113.9 (not seen in the history period)');
      expect(body).toContain('A known sender is not evidence of safety');
    }
    expect(html.indexOf('198.51.100.7')).toBeGreaterThan(
      html.indexOf('Original Email for IT Review')
    );
  });

  it('combined email (reporter with the team in Cc): counts, no IPs', () => {
    const { html, text } = render();
    for (const body of [html, text]) {
      expect(body).toContain('Sender Relationship (organization mail-flow records)');
      expect(body).toContain('2 distinct; 0 of them also seen in the history period');
      expect(body).not.toContain('198.51.100.7');
      expect(body).not.toContain('203.0.113.9');
      expect(body).not.toContain('security team only');
    }
  });

  it('reporter copy: one plain sentence, no block, never an IP', () => {
    const { html, text } = render('reporter');
    for (const body of [html, text]) {
      expect(body).not.toContain('Sender Relationship');
      expect(body).not.toContain('established');
      expect(body).not.toContain('198.51.100.7');
      expect(body).not.toContain('203.0.113.9');
      expect(body.match(/far more people than usual/g)).toHaveLength(1);
    }
  });

  it('escapes the IP list in HTML', () => {
    const hostile = facts('established', {
      sendingIps: {
        burst: 1,
        seenInHistory: 0,
        historyComplete: true,
        // The service never lets this shape through; the template must not rely on that
        burstIps: [{ ip: '<img src=x onerror=1>', seenInHistory: false }],
      },
    });
    const html = buildEmailHtml(analysis('phishing', 90), emailData(hostile), {
      audience: 'security',
    });
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=1&gt;');
  });
});

describe('report: sender relationship', () => {
  it('shows nothing when there are no facts', () => {
    expect(buildEmailHtml(analysis('legitimate', 5), emailData())).not.toContain(
      'Sender Relationship'
    );
    expect(buildPlainTextReport(analysis('legitimate', 5), emailData())).not.toContain(
      'Sender Relationship'
    );
  });

  it('shows counts and the classification in the IT-review part, with the caveat', () => {
    const data = emailData(TRUNCATED);
    const html = buildEmailHtml(analysis('suspicious', 60), data);
    const text = buildPlainTextReport(analysis('suspicious', 60), data);

    const section = html.slice(html.indexOf('Sender Relationship (organization mail-flow records)'));
    expect(html.indexOf('Sender Relationship')).toBeGreaterThan(
      html.indexOf('Original Email for IT Review')
    );
    expect(section).toContain('<td>Classification</td><td>established</td>');
    expect(section).toContain('at least 2000 messages');
    expect(section).toContain('A known sender is not evidence of safety');

    expect(text.indexOf('Sender Relationship')).toBeGreaterThan(
      text.indexOf('ORIGINAL EMAIL FOR IT REVIEW')
    );
    expect(text).toContain('  Classification: established');
    expect(text).toContain('at least 2000 messages');
    expect(text).toContain('A known sender is not evidence of safety');
  });

  it('tells the reporter nothing about an established sender above the IT-review part', () => {
    const html = buildEmailHtml(analysis('legitimate', 5), emailData(facts('established')), {
      risk: { ...fuseRisk(analysis('legitimate', 5), { senderHistory: facts('established') }) },
    });
    const reporterPart = html.slice(html.indexOf('<body>'), html.indexOf('Original Email for IT Review'));
    expect(reporterPart).not.toMatch(/established|emailed your organization before/);
  });

  it('gives the reporter one plain line on anomalous fan-out', () => {
    const history = facts('established_with_anomalous_fanout');
    const risk = fuseRisk(analysis('legitimate', 5), { senderHistory: history });
    const html = buildEmailHtml(analysis('legitimate', 5), emailData(history), { risk });
    const reporterPart = html.slice(html.indexOf('<body>'), html.indexOf('Original Email for IT Review'));
    expect(reporterPart.match(/far more people than usual/g)).toHaveLength(1);
    expect(reporterPart).toContain('SUSPICIOUS');
  });
});

describe('emitSenderHistoryMetric', () => {
  let stdoutSpy: jest.SpyInstance;
  const originalDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    delete process.env.PHISHY_DISABLE_METRICS;
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = originalDisable;
  });

  it('writes one EMF line dimensioned by Outcome, with _aws at the root', () => {
    emitSenderHistoryMetric({
      outcome: 'ok',
      durationMs: 1800,
      classification: 'established_with_anomalous_fanout',
      truncated: true,
      forbiddenRetries: 2,
    });
    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(doc._aws.CloudWatchMetrics[0].Dimensions).toEqual([['Outcome']]);
    expect(doc).toMatchObject({
      Outcome: 'ok',
      Classification: 'established_with_anomalous_fanout',
      SenderHistoryLookups: 1,
      SenderHistoryDurationMs: 1800,
      SenderHistoryAnomalousFanout: 1,
      SenderHistoryTruncated: 1,
      SenderHistoryForbiddenRetries: 2,
    });
  });

  it('reports a failed lookup without a classification', () => {
    emitSenderHistoryMetric({ outcome: 'forbidden', durationMs: 40 });
    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc).toMatchObject({
      Outcome: 'forbidden',
      Classification: 'none',
      SenderHistoryAnomalousFanout: 0,
      SenderHistoryTruncated: 0,
      SenderHistoryForbiddenRetries: 0,
    });
  });

  it('is silent when metrics are disabled', () => {
    process.env.PHISHY_DISABLE_METRICS = 'true';
    emitSenderHistoryMetric({ outcome: 'ok', durationMs: 1 });
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});

describe('graph.senderHistory configuration', () => {
  const base = {
    ai: { provider: 'bedrock' },
    notification: { senderEmail: 'phishy@example.com' },
    storage: { s3Bucket: 'bucket' },
    email: {},
  };
  const VARS = [
    'PHISHY_GRAPH_ENABLED',
    'PHISHY_GRAPH_TENANT_ID',
    'PHISHY_GRAPH_READ_CLIENT_ID',
    'PHISHY_GRAPH_READ_CERTIFICATE',
    'PHISHY_GRAPH_SENDER_HISTORY_ENABLED',
    'PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS',
    'PHISHY_GRAPH_SENDER_HISTORY_BURST_WINDOW_HOURS',
    'PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS',
    'PHISHY_GRAPH_SENDER_HISTORY_INCLUDE_DOMAIN',
    'PHISHY_GRAPH_SENDER_HISTORY_FREE_MAIL_DOMAINS',
    'PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MIN_RECIPIENTS',
    'PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER',
    'ANTHROPIC_API_KEY',
    'PHISHY_CONFIG_S3',
  ];
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of VARS) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.ANTHROPIC_API_KEY = 'test-key';
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  });

  it('is off by default and fills documented defaults when present', () => {
    const off = safeValidateConfig(base);
    expect(off.data?.graph?.senderHistory).toBeUndefined();

    const on = safeValidateConfig({ ...base, graph: { senderHistory: { enabled: true } } });
    expect(on.data?.graph?.senderHistory).toEqual({
      enabled: true,
      lookbackDays: 30,
      burstWindowHours: 24,
      budgetMs: 8000,
      includeDomain: true,
      freeMailDomains: [],
      fanoutMinRecipients: 10,
      fanoutMultiplier: 3,
    });
  });

  it('rejects values outside the bounds the trace API and the Lambda allow', () => {
    for (const senderHistory of [
      { lookbackDays: 91 },
      { lookbackDays: 13 },
      { burstWindowHours: 0 },
      { burstWindowHours: 73 },
      { budgetMs: 500 },
      { budgetMs: 60000 },
      { fanoutMinRecipients: 1 },
      { fanoutMultiplier: 0.5 },
    ]) {
      expect(safeValidateConfig({ ...base, graph: { senderHistory } }).success).toBe(false);
    }
  });

  it('maps the environment variables onto graph.senderHistory.*', async () => {
    process.env.PHISHY_GRAPH_SENDER_HISTORY_ENABLED = 'true';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS = '60';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_BURST_WINDOW_HOURS = '48';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS = '5000';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_INCLUDE_DOMAIN = 'false';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_FREE_MAIL_DOMAINS = 'freemail.example.org, webmail.example.net';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MIN_RECIPIENTS = '20';
    process.env.PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER = '5';

    const config = await loadConfig();

    // Graph itself is still off: the feature flag alone enables nothing
    expect(config.graph?.enabled).toBe(false);
    expect(config.graph?.senderHistory).toEqual({
      enabled: true,
      lookbackDays: 60,
      burstWindowHours: 48,
      budgetMs: 5000,
      includeDomain: false,
      freeMailDomains: ['freemail.example.org', 'webmail.example.net'],
      fanoutMinRecipients: 20,
      fanoutMultiplier: 5,
    });
  });
});

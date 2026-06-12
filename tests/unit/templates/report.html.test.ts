/**
 * Report rendering tests — focus on the employee-facing communication layer.
 */

import {
  buildEmailHtml,
  buildPlainTextReport,
  ReportOptions,
} from '../../../src/templates/report.html';
import { AnalysisResult, ExtractedEmailData } from '../../../src/types';

function email(overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData {
  return {
    from_email: 'reporter@example.com',
    subject: 'Fwd: something',
    text: 'body',
    html: '<p>body</p>',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: 'attacker@evil.test',
    originalForwarder: '',
    links: [],
    ...overrides,
  };
}

function analysis(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    summary: 'A test analysis.',
    isPhishing: true,
    confidence: 'High',
    indicators: ['Suspicious sender'],
    recommendations: ['Delete it'],
    provider: 'bedrock',
    model: 'claude-opus-4-8',
    processingTimeMs: 432,
    ...overrides,
  };
}

const becOptions: ReportOptions = {
  analysisId: 'abc-123-def',
  risk: {
    verdict: 'bec',
    riskScore: 90,
    riskLevel: 'critical',
    reasons: ['Sender domain seen in 3 prior reports.'],
  },
};

describe('buildEmailHtml', () => {
  it('keeps the risk score prominent (employees engage with it)', () => {
    const html = buildEmailHtml(
      analysis({
        assessment: {
          verdict: 'bec',
          riskScore: 90,
          verdictConfidence: 0.9,
          threatVectors: ['wire_fraud'],
          targeting: 'targeted',
        },
      }),
      email(),
      becOptions
    );
    expect(html).toContain('90/100');
    expect(html).toContain('critical');
  });

  it('thanks the reporter and explains the verdict in plain language', () => {
    const html = buildEmailHtml(analysis(), email(), becOptions);
    expect(html.toLowerCase()).toContain('thanks for reporting');
    expect(html).toContain('What this means');
    expect(html).toContain('impersonating'); // BEC plain-language gloss
    expect(html).toContain('What to do');
  });

  it('includes a threat-vector-driven teaching block', () => {
    const html = buildEmailHtml(
      analysis({
        assessment: {
          verdict: 'bec',
          riskScore: 90,
          verdictConfidence: 0.9,
          threatVectors: ['wire_fraud'],
          targeting: 'targeted',
        },
      }),
      email(),
      becOptions
    );
    expect(html).toContain('How to spot this next time');
    expect(html).toContain('verify payment or banking changes by phone');
  });

  it('folds intelligence reasons into "Why we flagged it"', () => {
    const html = buildEmailHtml(analysis(), email(), becOptions);
    expect(html).toContain('Why we flagged it');
    expect(html).toContain('seen in 3 prior reports');
  });

  it('does NOT leak AI provider/model/processing time to the employee body', () => {
    const html = buildEmailHtml(analysis(), email(), becOptions);
    expect(html).not.toContain('AI Provider');
    expect(html).not.toContain('Processing Time');
    expect(html).not.toContain('claude-opus-4-8');
  });

  it('keeps the analysis ID as a discreet reference for security replies', () => {
    const html = buildEmailHtml(analysis(), email(), becOptions);
    expect(html).toContain('abc-123-def');
  });

  it('reassures rather than alarms for a legitimate verdict', () => {
    const html = buildEmailHtml(
      analysis({ isPhishing: false, indicators: [], recommendations: [] }),
      email(),
      { risk: { verdict: 'legitimate', riskScore: 5, riskLevel: 'safe', reasons: [] } }
    );
    expect(html.toLowerCase()).toContain('right habit'); // safe-tone thank-you
    expect(html).toContain('safe to proceed');
    expect(html).toContain('verdict-legitimate-bg');
  });
});

describe('buildPlainTextReport', () => {
  it('mirrors the verdict, score, action, and teaching block', () => {
    const text = buildPlainTextReport(
      analysis({
        assessment: {
          verdict: 'bec',
          riskScore: 90,
          verdictConfidence: 0.9,
          threatVectors: ['wire_fraud'],
          targeting: 'targeted',
        },
      }),
      email(),
      becOptions
    );
    expect(text).toContain('Risk score: 90/100 (critical)');
    expect(text).toContain('What this means:');
    expect(text).toContain('What to do:');
    expect(text).toContain('How to spot this next time:');
    expect(text).not.toContain('AI Provider');
    expect(text).toContain('Reference: abc-123-def');
  });
});

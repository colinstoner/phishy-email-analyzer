/**
 * Experience review of the analysis report: the same names for the same
 * things across Phishy's emails, and the reply hint only where the security
 * team alone reads it.
 */

import {
  buildEmailHtml,
  buildPlainTextReport,
  describeVerdict,
  ReportOptions,
  riskScoreHtml,
  riskScoreLines,
} from '../../../src/templates/report.html';
import { AnalysisResult, ExtractedEmailData } from '../../../src/types';

const email: ExtractedEmailData = {
  from_email: 'reporter@example.com',
  subject: 'Fwd: Invoice 2291 overdue',
  text: 'body',
  html: '',
  headers: {},
  forwardedHeaders: {},
  attachments: [],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'reporter@example.com',
  originalForwarder: 'reporter@example.com',
  links: [],
};

const analysis: AnalysisResult = {
  summary: 'Fake invoice.',
  isPhishing: true,
  confidence: 'High',
  indicators: [],
  recommendations: [],
};

const risk: NonNullable<ReportOptions['risk']> = {
  verdict: 'phishing',
  riskScore: 92,
  riskLevel: 'critical',
  reasons: [],
  confidence: 'Very High',
  confidenceBasis: 'model',
};

const HINT = 'reply to this email with "confirmed phishing" or "false positive"';

describe('report experience', () => {
  it('names the reporter as the reporter, not as "From"', () => {
    const text = buildPlainTextReport(analysis, email, { risk });
    const html = buildEmailHtml(analysis, email, { risk });
    expect(text).toContain('  Reported by: reporter@example.com');
    expect(text).not.toContain('  From: reporter@example.com');
    // Labelled fact rows: the label cell, then the value cell
    expect(html).toMatch(/>Reported by<\/td>\s*<td[^>]*>reporter@example\.com<\/td>/);
    expect(html).toMatch(/>Subject<\/td>\s*<td[^>]*>Fwd: Invoice 2291 overdue<\/td>/);
    expect(html).not.toContain('Analyzed Email Subject');
  });

  it('tells the security team how to reply with a verdict, in their copy only', () => {
    const security: ReportOptions = {
      risk,
      analysisId: 'abc-123',
      audience: 'security',
      replyCommands: true,
    };
    expect(buildPlainTextReport(analysis, email, security)).toContain(HINT);
    expect(buildEmailHtml(analysis, email, security)).toContain('confirmed phishing');
    for (const options of [
      { ...security, audience: 'reporter' as const },
      { ...security, audience: undefined },
      { ...security, replyCommands: false },
      { ...security, analysisId: undefined },
    ]) {
      expect(buildPlainTextReport(analysis, email, options)).not.toContain(HINT);
    }
  });

  it('shares the risk score and Confidence lines with every other Phishy email', () => {
    expect(riskScoreLines(risk)).toEqual([
      'Risk score: 92/100 (critical)',
      'Confidence: Very High',
    ]);
    expect(riskScoreLines({ ...risk, verdict: 'undetermined' })).toEqual([
      'Risk score: not assessed',
    ]);
    expect(riskScoreHtml(risk)).toContain('Risk score: <strong>92/100</strong> (critical)');
    // The report's prominent form: the big number, its level as a word, and the same confidence
    const prominent = riskScoreHtml(risk, { prominent: true });
    expect(prominent).toContain('>92</strong><span');
    expect(prominent).toContain('/100</span>');
    expect(prominent).toContain('critical risk');
    // "safe" is a level of its own, never "safe risk"
    const safe = riskScoreHtml(
      { ...risk, verdict: 'legitimate', riskScore: 6, riskLevel: 'safe' },
      { prominent: true }
    );
    expect(safe).toContain('&nbsp;&nbsp;safe</span>');
    expect(safe).not.toContain('safe risk');
    expect(riskScoreHtml({ ...risk, riskLevel: 'low' }, { prominent: true })).toContain(
      '&nbsp;&nbsp;low risk</span>'
    );
    expect(prominent).toContain('Confidence: <strong>Very High</strong>');
    expect(riskScoreHtml({ ...risk, verdict: 'undetermined' }, { prominent: true })).toContain(
      'Risk score: <strong>not assessed</strong>'
    );
    const text = buildPlainTextReport(analysis, email, { risk });
    for (const line of riskScoreLines(risk)) {
      expect(text).toContain(line);
    }
    expect(describeVerdict('phishing').label).toBe('PHISHING');
    expect(describeVerdict('something_new')).toEqual({ label: 'SOMETHING_NEW', tone: 'caution' });
  });
});

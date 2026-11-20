/**
 * The report's IT-review attachment list with attachment analysis: one
 * fixed-wording line per inspected attachment, nothing from the file, and
 * no change for attachments that were not analyzed.
 */

import { buildEmailHtml, buildPlainTextReport } from '../../../src/templates/report.html';
import { summarizeInspectionForReport } from '../../../src/services/attachments/report';
import { AttachmentInspection } from '../../../src/services/attachments/types';
import { AnalysisResult, ExtractedEmailData } from '../../../src/types';

const inspection: AttachmentInspection = {
  status: 'inspected',
  realType: 'html',
  family: 'web',
  highRisk: false,
  nameFlags: ['extension_mismatch'],
  findings: [
    { kind: 'html_password_fields', count: 1 },
    { kind: 'html_form_posts_to_host', count: 1, hosts: ['collect-host-4471.test'] },
  ],
  links: [{ raw: 'https://collect-host-4471.test/p', canonical: 'https://collect-host-4471.test/p', flags: [] }],
  linksTotal: 1,
  text: 'Secret-Text-Token-8812',
  textChars: 22,
  limitsHit: [],
  durationMs: 1,
};

function email(analysis?: AttachmentInspection): ExtractedEmailData {
  return {
    from_email: 'reporter@example.com',
    subject: 'Fwd: invoice',
    text: 'body',
    html: '',
    headers: {},
    forwardedHeaders: {},
    attachments: [
      { filename: 'invoice.pdf', contentType: 'application/pdf', size: 1200, ...(analysis ? { analysis } : {}) },
    ],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: 'billing@vendor.test',
    originalForwarder: 'reporter@example.com',
    links: [],
  };
}

const result: AnalysisResult = {
  summary: 'x',
  isPhishing: true,
  confidence: 'High',
  indicators: [],
  recommendations: [],
};

describe('attachment inspection in the report', () => {
  it('summarizes with fixed wording only', () => {
    const line = summarizeInspectionForReport(inspection);
    expect(line).toBe('Phishy: real type html, inspected, name does not match type, password field, form posts to a web host');
    expect(summarizeInspectionForReport(undefined)).toBeUndefined();
    expect(
      summarizeInspectionForReport({ ...inspection, highRisk: true, status: 'not_inspected', nameFlags: [], findings: [] })
    ).toBe('Phishy: real type html, not inspected, HIGH-RISK TYPE');
  });

  it('adds the line to both report forms, without file content', () => {
    const html = buildEmailHtml(result, email(inspection));
    const text = buildPlainTextReport(result, email(inspection));
    for (const out of [html, text]) {
      expect(out).toContain('real type html, inspected');
      expect(out).not.toContain('Secret-Text-Token-8812');
      expect(out).not.toContain('collect-host-4471.test');
    }
  });

  it('leaves the report unchanged for attachments that were not analyzed', () => {
    expect(buildPlainTextReport(result, email())).not.toContain('Phishy: real type');
  });
});

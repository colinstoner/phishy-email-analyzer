/**
 * Indicators from links found inside attachments: extracted with a context
 * saying so, under the same storage rules as every other indicator.
 */

import { extractIOCs } from '../../../../src/services/intelligence/ioc.extractor';
import { AnalysisResult, EmailAttachment, ExtractedEmailData } from '../../../../src/types';
import { AttachmentInspection } from '../../../../src/services/attachments/types';
import { decideIndicatorStorage } from '../../../../src/services/intelligence/indicator.policy';

function inspection(links: string[], children: AttachmentInspection[] = []): AttachmentInspection {
  return {
    status: 'inspected',
    realType: 'pdf',
    family: 'document',
    highRisk: false,
    nameFlags: [],
    findings: [],
    links: links.map(l => ({ raw: l, canonical: l, flags: [] })),
    linksTotal: links.length,
    textChars: 0,
    limitsHit: [],
    durationMs: 0,
    ...(children.length > 0
      ? { children: children.map((c, i) => ({ claimedName: `c${i}`, size: 1, inspection: c })) }
      : {}),
  };
}

function email(attachments: EmailAttachment[]): ExtractedEmailData {
  return {
    from_email: 'employee@example.com',
    subject: 'Fwd: statement',
    text: 'See the attachment. https://body.example.org/info',
    html: '',
    headers: {},
    forwardedHeaders: {},
    attachments,
    sender: 'employee@example.com',
    to: 'phishy@example.com',
    original_sender: 'billing@sender.example.net',
    originalForwarder: 'employee@example.com',
    links: ['https://body.example.org/info'],
  };
}

const PHISHING: AnalysisResult = {
  summary: 'x',
  isPhishing: true,
  confidence: 'High',
  indicators: [],
  recommendations: [],
  assessment: {
    verdict: 'phishing',
    riskScore: 90,
    verdictConfidence: 0.9,
    threatVectors: ['credential_harvest'],
    targeting: 'mass',
  },
};

describe('IOCs from attachments', () => {
  it('extracts URLs and payload domains found inside attachments, marked as such', () => {
    const attachment: EmailAttachment = {
      filename: 'statement.pdf',
      contentType: 'application/pdf',
      size: 100,
      analysis: inspection(
        ['https://harvest.example.net/login'],
        [inspection(['https://nested.example.net/x?url=https://final.example.net/steal'])]
      ),
    };
    const iocs = extractIOCs(email([attachment]), PHISHING, { safeDomains: ['example.com'] });

    const url = iocs.find(i => i.indicatorValue === 'https://harvest.example.net/login');
    expect(url?.metadata).toMatchObject({
      extractionContext: 'url_in_attachment',
      foundIn: 'attachment',
      role: 'payload',
    });
    const domain = iocs.find(i => i.indicatorType === 'domain' && i.indicatorValue === 'harvest.example.net');
    expect(domain?.metadata).toMatchObject({
      extractionContext: 'attachment_url_domain',
      foundIn: 'attachment',
      role: 'payload',
    });
    // A redirect inside an attachment is unwrapped like any other
    expect(iocs.find(i => i.indicatorValue === 'https://final.example.net/steal')?.metadata).toMatchObject({
      extractionContext: 'final_url_in_attachment',
      role: 'payload',
    });
    // Body links keep their own context
    expect(iocs.find(i => i.indicatorValue === 'https://body.example.org/info')?.metadata?.extractionContext).toBe(
      'url_in_content'
    );
  });

  it('adds nothing when attachments were not analyzed', () => {
    const plain = extractIOCs(email([{ filename: 'a.pdf', contentType: 'application/pdf', size: 1 }]), PHISHING);
    expect(plain.some(i => i.metadata?.foundIn === 'attachment')).toBe(false);
  });

  it('is stored only on a model-malicious verdict, like every indicator', () => {
    expect(decideIndicatorStorage({ modelVerdict: 'legitimate' }).store).toBe(false);
    expect(decideIndicatorStorage({ modelVerdict: 'suspicious' }).store).toBe(false);
    expect(decideIndicatorStorage({ modelVerdict: 'phishing' }).store).toBe(true);
  });
});

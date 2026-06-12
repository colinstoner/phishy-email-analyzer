/**
 * IOC Extractor tests
 */

import { extractIOCs, dedupeKey } from '../../../../src/services/intelligence/ioc.extractor';
import { ExtractedEmailData, AnalysisResult } from '../../../../src/types';

describe('dedupeKey', () => {
  it('case-folds domains, emails, and IPs (case-insensitive)', () => {
    expect(dedupeKey('domain', 'Evil.TEST')).toBe(dedupeKey('domain', 'evil.test'));
    expect(dedupeKey('email', 'Attacker@Evil.Test')).toBe(dedupeKey('email', 'attacker@evil.test'));
  });

  it('case-folds only scheme+host for URLs, NOT path/query (must stay distinct)', () => {
    // hostname case is insignificant -> same key
    expect(dedupeKey('url', 'https://Evil.Test/Path')).toBe(
      dedupeKey('url', 'https://evil.test/Path')
    );
    // path/query case IS significant -> distinct keys, must not merge
    expect(dedupeKey('url', 'https://evil.test/Path?T=A')).not.toBe(
      dedupeKey('url', 'https://evil.test/path?t=a')
    );
  });

  it('falls back to an exact key for unparseable URLs', () => {
    expect(dedupeKey('url', 'not a url')).toBe(dedupeKey('url', 'not a url'));
    expect(dedupeKey('url', 'not a url')).not.toBe(dedupeKey('url', 'NOT A URL'));
  });
});

describe('extractIOCs', () => {
  const createMockEmailData = (
    overrides: Partial<ExtractedEmailData> = {}
  ): ExtractedEmailData => ({
    from_email: 'sender@example.com',
    subject: 'Test Subject',
    text: 'Test email body',
    html: '<p>Test email body</p>',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: 'sender@example.com',
    to: 'recipient@test.org',
    original_sender: 'sender@example.com',
    originalForwarder: '',
    links: [],
    ...overrides,
  });

  const createMockAnalysis = (isPhishing: boolean, confidence = 'High'): AnalysisResult => ({
    summary: 'Test analysis',
    isPhishing,
    confidence: confidence as AnalysisResult['confidence'],
    indicators: [],
    recommendations: [],
  });

  describe('URL extraction', () => {
    it('should extract suspicious URLs', () => {
      const emailData = createMockEmailData({
        text: 'Click here: http://192.168.1.100/login to verify',
        links: ['http://192.168.1.100/login'],
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const urlIOCs = iocs.filter(i => i.indicatorType === 'url');
      expect(urlIOCs.length).toBeGreaterThan(0);
    });

    it('should not extract URLs from legitimate emails', () => {
      const emailData = createMockEmailData({
        text: 'Visit https://google.com for more info',
        links: ['https://google.com'],
      });

      const analysis = createMockAnalysis(false);
      const iocs = extractIOCs(emailData, analysis, { minConfidence: 0.5 });

      // Low confidence for non-phishing should be filtered
      expect(iocs.length).toBe(0);
    });
  });

  describe('Domain extraction', () => {
    it('should extract suspicious domains', () => {
      const emailData = createMockEmailData({
        from_email: 'security@acme-secure-login.com',
        links: ['https://acme-secure-login.com/verify'],
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const domainIOCs = iocs.filter(i => i.indicatorType === 'domain');
      expect(domainIOCs.some(d => d.indicatorValue === 'acme-secure-login.com')).toBe(true);
    });

    it('should skip safe domains', () => {
      const emailData = createMockEmailData({
        from_email: 'user@google.com',
        links: ['https://google.com/settings'],
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const domainIOCs = iocs.filter(i => i.indicatorType === 'domain');
      expect(domainIOCs.some(d => d.indicatorValue === 'google.com')).toBe(false);
    });
  });

  describe('IP extraction', () => {
    it('should extract public IP addresses', () => {
      const emailData = createMockEmailData({
        text: 'Server at 203.0.113.50 and also 198.51.100.25',
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const ipIOCs = iocs.filter(i => i.indicatorType === 'ip');
      expect(ipIOCs.length).toBe(2);
      expect(ipIOCs.some(i => i.indicatorValue === '203.0.113.50')).toBe(true);
    });

    it('should skip private IP addresses', () => {
      const emailData = createMockEmailData({
        text: 'Internal server at 192.168.1.1 and 10.0.0.1',
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const ipIOCs = iocs.filter(i => i.indicatorType === 'ip');
      expect(ipIOCs.length).toBe(0);
    });
  });

  describe('Email extraction', () => {
    it('should extract the original (forwarded) sender as IOC, not the reporter', () => {
      const emailData = createMockEmailData({
        from_email: 'reporter@mycompany.com',
        original_sender: 'Fake Support <fake-support@malicious-domain.com>',
      });

      const analysis = createMockAnalysis(true, 'High');
      const iocs = extractIOCs(emailData, analysis);

      const emailIOCs = iocs.filter(i => i.indicatorType === 'email');
      expect(emailIOCs.length).toBe(1);
      expect(emailIOCs[0].indicatorValue).toBe('fake-support@malicious-domain.com');
      expect(emailIOCs[0].metadata?.extractionContext).toBe('original_sender_email');
    });
  });

  describe('Attribution', () => {
    const sourceContext = {
      analysisId: 'a-1',
      messageId: 'm-1',
      reporterEmail: 'reporter@mycompany.com',
      reporterDomain: 'mycompany.com',
      subject: 'Fwd: suspicious',
    };

    it('never emits the reporter as an indicator', () => {
      const emailData = createMockEmailData({
        from_email: 'reporter@mycompany.com',
        original_sender: 'reporter@mycompany.com', // parser fallback edge case
        links: ['https://mycompany.com/legit'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true), {}, sourceContext);

      expect(iocs.some(i => i.indicatorValue.includes('mycompany.com'))).toBe(false);
    });

    it('records the reporter as provenance metadata', () => {
      const emailData = createMockEmailData({
        from_email: 'reporter@mycompany.com',
        original_sender: 'attacker@evil.example',
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true), {}, sourceContext);

      expect(iocs.length).toBeGreaterThan(0);
      expect(iocs.every(i => i.metadata?.reportedBy === 'reporter@mycompany.com')).toBe(true);
    });

    it('respects configured safe domains and senders', () => {
      const emailData = createMockEmailData({
        original_sender: 'partner@trusted-partner.com',
        links: ['https://internal-tool.mycompany.com/page'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true), {
        safeDomains: ['mycompany.com'],
        safeSenders: ['partner@trusted-partner.com'],
      });

      expect(iocs.some(i => i.indicatorType === 'email')).toBe(false);
      expect(iocs.some(i => i.indicatorValue.includes('mycompany.com'))).toBe(false);
    });
  });

  describe('Redirect unwrapping', () => {
    it('surfaces the final destination behind an open redirector', () => {
      const emailData = createMockEmailData({
        links: ['https://maps.google.si/url?q=https%3A%2F%2Fevil-landing.store%2Fpage'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true, 'Very High'));

      const finalDomain = iocs.find(
        i => i.indicatorType === 'domain' && i.indicatorValue === 'evil-landing.store'
      );
      expect(finalDomain).toBeDefined();
      expect(finalDomain?.severity).toBe('critical');
      expect(finalDomain?.metadata?.extractionContext).toBe('final_url_domain');

      const finalUrl = iocs.find(
        i => i.indicatorType === 'url' && i.indicatorValue === 'https://evil-landing.store/page'
      );
      expect(finalUrl?.metadata?.extractionContext).toBe('final_url');
    });

    it('marks redirect intermediaries low severity', () => {
      const emailData = createMockEmailData({
        links: ['https://tracker.example.net/r?url=https%3A%2F%2Fevil-landing.store%2F'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true, 'Very High'));

      const intermediary = iocs.find(
        i => i.indicatorType === 'domain' && i.indicatorValue === 'tracker.example.net'
      );
      expect(intermediary?.severity).toBe('low');
      expect(intermediary?.metadata?.extractionContext).toBe('redirect_intermediary');
    });

    it('decodes JWT tracker tokens to find the destination (Feb 2026 regression)', () => {
      // Modeled on the real campaign: google.si open redirect -> monday.com
      // tracker whose JWT payload carries the true landing page
      const jwtPayload = Buffer.from(
        JSON.stringify({ originalUrl: 'https://talamalove.store/.nc', emailId: 'x' })
      ).toString('base64url');
      const trackerUrl = `https://trackingservice.example.com/tracker/link?token=hdr.${jwtPayload}.sig`;
      const outerUrl = `https://maps.google.si/url?q=${encodeURIComponent(trackerUrl)}`;

      const emailData = createMockEmailData({ links: [outerUrl] });
      const iocs = extractIOCs(emailData, createMockAnalysis(true, 'Very High'));

      const landing = iocs.find(
        i => i.indicatorType === 'domain' && i.indicatorValue === 'talamalove.store'
      );
      expect(landing).toBeDefined();
      expect(landing?.severity).toBe('critical');

      const google = iocs.find(
        i => i.indicatorType === 'domain' && i.indicatorValue === 'maps.google.si'
      );
      expect(google?.severity).toBe('low');
    });
  });

  describe('free-mail and provider noise', () => {
    it('keeps a throwaway-gmail sender address but not gmail.com as a domain', () => {
      const emailData = createMockEmailData({
        original_sender: 'CEO Impersonator <dpcxzut@gmail.com>',
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true, 'High'));

      expect(
        iocs.some(i => i.indicatorType === 'email' && i.indicatorValue === 'dpcxzut@gmail.com')
      ).toBe(true);
      expect(iocs.some(i => i.indicatorType === 'domain' && i.indicatorValue === 'gmail.com')).toBe(
        false
      );
    });

    it('drops free-mail domains nominated by the AI', () => {
      const analysis = {
        ...createMockAnalysis(true),
        iocs: [{ type: 'domain' as const, value: 'gmail.com', role: 'sender' as const }],
      };

      const iocs = extractIOCs(createMockEmailData({}), analysis);

      expect(iocs.some(i => i.indicatorValue === 'gmail.com')).toBe(false);
    });

    it('treats aka.ms (M365 sender banner) as safe', () => {
      const emailData = createMockEmailData({
        links: ['https://aka.ms/LearnAboutSenderIdentification'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true, 'High'));

      expect(iocs.some(i => i.indicatorValue.includes('aka.ms'))).toBe(false);
    });
  });

  describe('IP/domain typing', () => {
    it('does not store URL IP hosts as domain indicators', () => {
      const emailData = createMockEmailData({
        links: ['http://203.0.113.50/verify?token=abc'],
      });

      const iocs = extractIOCs(emailData, createMockAnalysis(true));

      expect(
        iocs.some(i => i.indicatorType === 'domain' && i.indicatorValue === '203.0.113.50')
      ).toBe(false);
      expect(iocs.some(i => i.indicatorType === 'ip' && i.indicatorValue === '203.0.113.50')).toBe(
        true
      );
    });
  });

  describe('AI-nominated IOCs', () => {
    it('merges structured IOCs from the analysis with role-based severity', () => {
      const emailData = createMockEmailData({});
      const analysis = {
        ...createMockAnalysis(true, 'Very High'),
        iocs: [
          { type: 'domain' as const, value: 'evil-sender.jp', role: 'sender' as const },
          { type: 'domain' as const, value: 'tracker-relay.com', role: 'infrastructure' as const },
        ],
      };

      const iocs = extractIOCs(emailData, analysis);

      const sender = iocs.find(i => i.indicatorValue === 'evil-sender.jp');
      expect(sender?.severity).toBe('critical');
      expect(sender?.metadata?.extractionContext).toBe('ai_nominated:sender');

      const infra = iocs.find(i => i.indicatorValue === 'tracker-relay.com');
      expect(infra?.severity).toBe('medium');
    });

    it('filters AI nominations through the same allowlists', () => {
      const emailData = createMockEmailData({});
      const analysis = {
        ...createMockAnalysis(true),
        iocs: [{ type: 'domain' as const, value: 'mycompany.com', role: 'sender' as const }],
      };

      const iocs = extractIOCs(emailData, analysis, { safeDomains: ['mycompany.com'] });

      expect(iocs.some(i => i.indicatorValue === 'mycompany.com')).toBe(false);
    });

    it('dedupes against regex-extracted indicators, keeping higher confidence', () => {
      const emailData = createMockEmailData({
        original_sender: 'attacker@evil-sender.jp',
      });
      const analysis = {
        ...createMockAnalysis(true),
        iocs: [
          { type: 'email' as const, value: 'attacker@evil-sender.jp', role: 'sender' as const },
        ],
      };

      const iocs = extractIOCs(emailData, analysis);

      const matches = iocs.filter(
        i => i.indicatorType === 'email' && i.indicatorValue === 'attacker@evil-sender.jp'
      );
      expect(matches.length).toBe(1);
      expect(matches[0].confidenceScore).toBe(0.8);
    });
  });

  describe('Hash extraction', () => {
    it('should extract MD5 hashes', () => {
      const emailData = createMockEmailData({
        text: 'File hash: d41d8cd98f00b204e9800998ecf8427e',
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const hashIOCs = iocs.filter(i => i.indicatorType === 'hash');
      expect(hashIOCs.length).toBe(1);
      expect(hashIOCs[0].indicatorValue).toContain('md5:');
    });

    it('should extract SHA256 hashes', () => {
      const emailData = createMockEmailData({
        text: 'SHA: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      });

      const analysis = createMockAnalysis(true);
      const iocs = extractIOCs(emailData, analysis);

      const hashIOCs = iocs.filter(i => i.indicatorType === 'hash');
      expect(hashIOCs.length).toBe(1);
      expect(hashIOCs[0].indicatorValue).toContain('sha256:');
    });
  });

  describe('Confidence filtering', () => {
    it('should filter IOCs below minimum confidence', () => {
      const emailData = createMockEmailData({
        from_email: 'sender@suspicious.com',
        links: ['https://suspicious.com/login'],
      });

      const analysis = createMockAnalysis(false); // Low confidence for non-phishing
      const iocs = extractIOCs(emailData, analysis, { minConfidence: 0.5 });

      expect(iocs.length).toBe(0);
    });

    it('should include all IOCs with zero minimum confidence', () => {
      const emailData = createMockEmailData({
        from_email: 'sender@suspicious.com',
        links: ['https://suspicious.com/login'],
      });

      const analysis = createMockAnalysis(false);
      const iocs = extractIOCs(emailData, analysis, { minConfidence: 0 });

      expect(iocs.length).toBeGreaterThan(0);
    });
  });

  describe('Severity determination', () => {
    it('should set critical severity for high confidence phishing', () => {
      const emailData = createMockEmailData({
        from_email: 'attacker@malicious.com',
      });

      const analysis = createMockAnalysis(true, 'Very High');
      const iocs = extractIOCs(emailData, analysis);

      expect(iocs.every(i => i.severity === 'critical')).toBe(true);
    });

    it('should set low severity for non-phishing', () => {
      const emailData = createMockEmailData({
        from_email: 'sender@questionable.com',
      });

      const analysis = createMockAnalysis(false);
      const iocs = extractIOCs(emailData, analysis, { minConfidence: 0 });

      expect(iocs.every(i => i.severity === 'low')).toBe(true);
    });
  });
});

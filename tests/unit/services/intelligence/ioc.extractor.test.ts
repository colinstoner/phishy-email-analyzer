/**
 * IOC Extractor tests
 */

import { extractIOCs } from '../../../../src/services/intelligence/ioc.extractor';
import { ExtractedEmailData, AnalysisResult } from '../../../../src/types';

describe('extractIOCs', () => {
  const createMockEmailData = (overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData => ({
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
    it('should extract sender email as IOC for phishing', () => {
      const emailData = createMockEmailData({
        from_email: 'fake-support@malicious-domain.com',
      });

      const analysis = createMockAnalysis(true, 'High');
      const iocs = extractIOCs(emailData, analysis);

      const emailIOCs = iocs.filter(i => i.indicatorType === 'email');
      expect(emailIOCs.length).toBe(1);
      expect(emailIOCs[0].indicatorValue).toBe('fake-support@malicious-domain.com');
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

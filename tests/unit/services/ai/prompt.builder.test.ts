/**
 * Prompt builder tests
 */

import {
  buildPhishingAnalysisPrompt,
  buildQuickAnalysisPrompt,
} from '../../../../src/services/ai/prompt.builder';
import { ExtractedEmailData } from '../../../../src/types';
import { EnterpriseProfile } from '../../../../src/models/profile.model';

describe('buildPhishingAnalysisPrompt', () => {
  const createMockEmailData = (overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData => ({
    from_email: 'sender@example.com',
    subject: 'Test Subject',
    text: 'Test email body content',
    html: '<p>Test email body content</p>',
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

  const createMockHeaders = (): Record<string, string> => ({
    'From': 'Sender <sender@example.com>',
    'Message-ID': '<test-123@example.com>',
    'Return-Path': '<sender@example.com>',
  });

  it('should include email content in prompt', () => {
    const emailData = createMockEmailData({
      from_email: 'phisher@fake.com',
      subject: 'Urgent Action Required',
      text: 'Please click this link immediately',
    });

    const prompt = buildPhishingAnalysisPrompt(emailData, createMockHeaders());

    expect(prompt).toContain('FROM: phisher@fake.com');
    expect(prompt).toContain('SUBJECT: Urgent Action Required');
    expect(prompt).toContain('Please click this link immediately');
  });

  it('should include links section when links exist', () => {
    const emailData = createMockEmailData({
      links: ['https://suspicious.com/login', 'http://192.168.1.1/verify'],
    });

    const prompt = buildPhishingAnalysisPrompt(emailData, createMockHeaders());

    expect(prompt).toContain('--- LINKS IN EMAIL ---');
    expect(prompt).toContain('https://suspicious.com/login');
    expect(prompt).toContain('http://192.168.1.1/verify');
  });

  it('should not include links section when no links', () => {
    const emailData = createMockEmailData({ links: [] });

    const prompt = buildPhishingAnalysisPrompt(emailData, createMockHeaders());

    expect(prompt).not.toContain('--- LINKS IN EMAIL ---');
  });

  it('should include headers in prompt', () => {
    const headers = {
      'From': 'Test Sender <test@sender.com>',
      'X-Originating-IP': '10.0.0.1',
    };

    const prompt = buildPhishingAnalysisPrompt(createMockEmailData(), headers);

    expect(prompt).toContain('--- KEY HEADERS ---');
    expect(prompt).toContain('From');
    expect(prompt).toContain('X-Originating-IP');
  });

  it('should include analysis instructions', () => {
    const prompt = buildPhishingAnalysisPrompt(createMockEmailData(), createMockHeaders());

    expect(prompt).toContain('Analyze this email for phishing indicators');
    expect(prompt).toContain('Links to unexpected domains');
    expect(prompt).toContain('Social engineering tactics');
    expect(prompt).toContain('Return your analysis as JSON');
  });

  it('should include default systems section without profile', () => {
    const prompt = buildPhishingAnalysisPrompt(createMockEmailData(), createMockHeaders());

    expect(prompt).toContain('--- LEGITIMATE SYSTEMS INFORMATION ---');
    expect(prompt).toContain('Microsoft 365');
    expect(prompt).toContain('SSO');
  });

  describe('with enterprise profile', () => {
    const createMockProfile = (): EnterpriseProfile => ({
      name: 'Test Corp',
      organization: {
        name: 'Test Corporation',
        domains: ['testcorp.com', 'testcorp.io'],
        aliases: ['Test Corp', 'TC'],
      },
      systems: {
        email: {
          providers: ['Google Workspace'],
          legitimateServices: ['sendgrid.net'],
        },
        authentication: {
          providers: ['Azure AD'],
          ssoEnabled: true,
          mfaRequired: true,
        },
      },
      vips: [
        {
          name: 'Jane CEO',
          title: 'CEO',
          email: 'jane@testcorp.com',
          aliases: ['Jane C'],
          impersonationRisk: 'critical',
        },
      ],
      trustedPartners: [
        {
          name: 'Partner Inc',
          domains: ['partner.com'],
          relationship: 'vendor',
        },
      ],
      customPatterns: {
        highRiskKeywords: ['wire transfer', 'urgent'],
        knownBadDomains: ['testcorp-secure.com'],
        recentThreats: [
          {
            description: 'CEO impersonation campaign',
            indicators: ['wire transfer'],
            dateReported: '2024-01-15',
          },
        ],
      },
      analysisConfig: {
        sensitivityLevel: 'high',
        autoEscalateThreshold: 0.8,
        additionalPromptContext: 'We use custom internal tools.',
      },
    });

    it('should include organization context', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- ORGANIZATION CONTEXT ---');
      expect(prompt).toContain('Test Corporation');
      expect(prompt).toContain('testcorp.com');
    });

    it('should include VIP watch list', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- VIP WATCH LIST');
      expect(prompt).toContain('Jane CEO');
      expect(prompt).toContain('critical');
    });

    it('should include trusted partners', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- TRUSTED PARTNERS ---');
      expect(prompt).toContain('Partner Inc');
      expect(prompt).toContain('vendor');
    });

    it('should include custom patterns', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- HIGH RISK KEYWORDS ---');
      expect(prompt).toContain('wire transfer');
      expect(prompt).toContain('--- KNOWN MALICIOUS DOMAINS ---');
      expect(prompt).toContain('testcorp-secure.com');
    });

    it('should include recent threats', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- RECENT THREATS ---');
      expect(prompt).toContain('CEO impersonation campaign');
    });

    it('should include analysis configuration', () => {
      const prompt = buildPhishingAnalysisPrompt(
        createMockEmailData(),
        createMockHeaders(),
        createMockProfile()
      );

      expect(prompt).toContain('--- ANALYSIS CONFIGURATION ---');
      expect(prompt).toContain('Sensitivity: high');
      expect(prompt).toContain('We use custom internal tools');
    });
  });
});

describe('buildQuickAnalysisPrompt', () => {
  it('should create a concise prompt', () => {
    const emailData: ExtractedEmailData = {
      from_email: 'test@example.com',
      subject: 'Test Subject',
      text: 'Short test content',
      html: '',
      headers: {},
      forwardedHeaders: {},
      attachments: [],
      sender: '',
      to: '',
      original_sender: '',
      originalForwarder: '',
      links: ['https://example.com'],
    };

    const prompt = buildQuickAnalysisPrompt(emailData);

    expect(prompt).toContain('From: test@example.com');
    expect(prompt).toContain('Subject: Test Subject');
    expect(prompt).toContain('Return: {"isPhishing"');
    expect(prompt.length).toBeLessThan(1000); // Should be concise
  });

  it('should truncate long body text', () => {
    const longText = 'A'.repeat(1000);
    const emailData: ExtractedEmailData = {
      from_email: 'test@example.com',
      subject: 'Test',
      text: longText,
      html: '',
      headers: {},
      forwardedHeaders: {},
      attachments: [],
      sender: '',
      to: '',
      original_sender: '',
      originalForwarder: '',
      links: [],
    };

    const prompt = buildQuickAnalysisPrompt(emailData);

    // Should only include first 500 chars
    expect(prompt).toContain('A'.repeat(500));
    expect(prompt).not.toContain('A'.repeat(600));
  });
});

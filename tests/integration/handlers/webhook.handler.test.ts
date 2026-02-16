/**
 * Webhook Handler Integration Tests
 */

import axios, { AxiosRequestConfig } from 'axios';
import { WebhookService, WebhookPayload } from '../../../src/handlers/webhook.handler';
import { AnalysisResult, ExtractedEmailData } from '../../../src/types';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Type for extracting payload from mock calls
interface MockCallArgs {
  url: string;
  payload: WebhookPayload;
  config: AxiosRequestConfig;
}

function getMockCallArgs(callIndex: number): MockCallArgs {
  const call = mockedAxios.post.mock.calls[callIndex];
  return {
    url: call[0] as string,
    payload: call[1] as WebhookPayload,
    config: call[2] as AxiosRequestConfig,
  };
}

describe('Webhook Handler Integration', () => {
  let webhookService: WebhookService;

  const mockAnalysis: AnalysisResult = {
    summary: 'High confidence phishing attempt detected',
    isPhishing: true,
    confidence: 'Very High',
    indicators: ['Suspicious URL', 'Urgency language', 'IP-based link'],
    recommendations: ['Do not click links', 'Report to IT'],
  };

  const mockEmailData: ExtractedEmailData = {
    from_email: 'attacker@phishing-site.com',
    subject: 'Urgent: Verify Your Account',
    text: 'Click here to verify your account',
    html: '<p>Click here to verify</p>',
    headers: {
      'Message-ID': '<test-123@phishing-site.com>',
      From: 'attacker@phishing-site.com',
    },
    forwardedHeaders: {},
    attachments: [],
    sender: 'attacker@phishing-site.com',
    to: 'victim@company.com',
    original_sender: 'user@trusted.com',
    originalForwarder: 'user@trusted.com',
    links: ['http://192.168.1.100/login'],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    webhookService = new WebhookService();

    // Default successful response
    mockedAxios.post.mockResolvedValue({ status: 200, data: { received: true } });
  });

  describe('Webhook Registration', () => {
    it('should add a new webhook', () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected'],
        secret: 'test-secret-123',
        enabled: true,
      });

      expect(webhookService.getWebhooks()).toHaveLength(1);
      expect(webhookService.getWebhooks()[0].url).toBe('https://siem.example.com/webhook');
    });

    it('should add multiple webhooks', () => {
      webhookService.addWebhook({
        url: 'https://siem1.example.com/webhook',
        events: ['threat.detected'],
        enabled: true,
      });
      webhookService.addWebhook({
        url: 'https://siem2.example.com/webhook',
        events: ['vip.impersonation'],
        enabled: true,
      });

      expect(webhookService.getWebhooks()).toHaveLength(2);
    });

    it('should not expose secrets in getWebhooks', () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected'],
        secret: 'super-secret-key',
        enabled: true,
      });

      const webhooks = webhookService.getWebhooks();
      expect(webhooks[0]).not.toHaveProperty('secret');
    });

    it('should not add disabled webhooks', () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected'],
        enabled: false,
      });

      expect(webhookService.getWebhooks()).toHaveLength(0);
    });
  });

  describe('Webhook Removal', () => {
    it('should remove webhook by URL', () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected'],
        enabled: true,
      });

      const removed = webhookService.removeWebhook('https://siem.example.com/webhook');

      expect(removed).toBe(true);
      expect(webhookService.getWebhooks()).toHaveLength(0);
    });

    it('should return false for non-existent webhook', () => {
      const removed = webhookService.removeWebhook('https://nonexistent.com/webhook');
      expect(removed).toBe(false);
    });
  });

  describe('Threat Detection Events', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        secret: 'test-secret',
        enabled: true,
      });
    });

    it('should send threat detected event', async () => {
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
      const { url, payload, config } = getMockCallArgs(0);

      expect(url).toBe('https://siem.example.com/webhook');
      expect(payload.event).toBe('threat.high_confidence'); // Very High confidence = high_confidence event
      expect(payload.data.analysisId).toBe('analysis-123');
      expect(payload.data.fromEmail).toBe('attacker@phishing-site.com');
      expect(config.headers?.['X-Phishy-Signature']).toBeDefined();
    });

    it('should include indicators in threat payload', async () => {
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      const { payload } = getMockCallArgs(0);
      expect(payload.data.indicators).toEqual(mockAnalysis.indicators);
    });

    it('should set correct severity based on confidence', async () => {
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        { ...mockAnalysis, confidence: 'Very High' }
      );

      const { payload } = getMockCallArgs(0);
      expect(payload.severity).toBe('critical');
    });

    it('should not send for non-phishing emails', async () => {
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        { ...mockAnalysis, isPhishing: false }
      );

      expect(mockedAxios.post).not.toHaveBeenCalled();
    });
  });

  describe('VIP Impersonation Events', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['vip.impersonation'],
        enabled: true,
      });
    });

    it('should send VIP impersonation event', async () => {
      await webhookService.sendVIPImpersonation(
        'analysis-456',
        mockEmailData,
        mockAnalysis,
        'Jane CEO'
      );

      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
      const { payload } = getMockCallArgs(0);

      expect(payload.event).toBe('vip.impersonation');
      expect(payload.data.correlationFields?.vipName).toBe('Jane CEO');
      expect(payload.severity).toBe('critical');
    });
  });

  describe('Pattern Detection Events', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['pattern.detected'],
        enabled: true,
      });
    });

    it('should send pattern detected event', async () => {
      const patterns = [
        {
          type: 'campaign',
          name: 'CEO Wire Transfer Campaign',
          description: 'Multiple emails requesting wire transfers',
          criteria: { keywords: ['wire transfer', 'urgent'] },
          matchCount: 15,
          isNew: true,
        },
      ];

      await webhookService.sendPatternDetected(patterns);

      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
      const { payload } = getMockCallArgs(0);

      expect(payload.event).toBe('pattern.detected');
      expect(payload.data.patterns).toHaveLength(1);
    });

    it('should not send for empty patterns', async () => {
      await webhookService.sendPatternDetected([]);
      expect(mockedAxios.post).not.toHaveBeenCalled();
    });
  });

  describe('Analysis Completed Events', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['analysis.completed'],
        enabled: true,
      });
    });

    it('should send analysis completed event', async () => {
      await webhookService.sendAnalysisCompleted(
        'analysis-789',
        mockEmailData,
        mockAnalysis
      );

      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
      const { payload } = getMockCallArgs(0);

      expect(payload.event).toBe('analysis.completed');
      expect(payload.data.analysisId).toBe('analysis-789');
      expect(payload.data.analysis?.isPhishing).toBe(true);
    });
  });

  describe('Event Filtering', () => {
    it('should only send to webhooks subscribed to the event', async () => {
      webhookService.addWebhook({
        url: 'https://siem1.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
      });
      webhookService.addWebhook({
        url: 'https://siem2.example.com/webhook',
        events: ['vip.impersonation'], // Not subscribed to threat events
        enabled: true,
      });

      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
      expect(mockedAxios.post.mock.calls[0][0]).toBe('https://siem1.example.com/webhook');
    });

    it('should send to multiple matching webhooks', async () => {
      webhookService.addWebhook({
        url: 'https://siem1.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
      });
      webhookService.addWebhook({
        url: 'https://siem2.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence', 'pattern.detected'],
        enabled: true,
      });

      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      expect(mockedAxios.post).toHaveBeenCalledTimes(2);
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
      });
    });

    it('should handle webhook delivery failure gracefully', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Connection refused'));

      // Should not throw
      await expect(
        webhookService.sendThreatDetected('analysis-123', mockEmailData, mockAnalysis)
      ).resolves.not.toThrow();
    });

    it('should handle timeout errors', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Timeout'));

      await expect(
        webhookService.sendThreatDetected('analysis-123', mockEmailData, mockAnalysis)
      ).resolves.not.toThrow();
    });

    it('should continue sending to other webhooks if one fails', async () => {
      webhookService.addWebhook({
        url: 'https://siem2.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
      });

      mockedAxios.post
        .mockRejectedValueOnce(new Error('First webhook failed'))
        .mockRejectedValueOnce(new Error('Retry 1 failed'))
        .mockRejectedValueOnce(new Error('Retry 2 failed'))
        .mockResolvedValueOnce({ status: 200 });

      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      // Both webhooks should be attempted (first with retries, second succeeds)
      expect(mockedAxios.post).toHaveBeenCalled();
      // At least 2 different URLs should have been called
      const calledUrls = new Set(mockedAxios.post.mock.calls.map(call => call[0]));
      expect(calledUrls.size).toBe(2);
    });
  });

  describe('Signature Generation', () => {
    it('should include signature header when secret is configured', async () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        secret: 'my-secret-key',
        enabled: true,
      });

      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      const { config } = getMockCallArgs(0);
      expect(config.headers?.['X-Phishy-Signature']).toMatch(/^sha256=/);
    });

    it('should not include signature when no secret', async () => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
        // No secret
      });

      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      const { config } = getMockCallArgs(0);
      expect(config.headers?.['X-Phishy-Signature']).toBeUndefined();
    });
  });

  describe('Payload Structure', () => {
    beforeEach(() => {
      webhookService.addWebhook({
        url: 'https://siem.example.com/webhook',
        events: ['threat.detected', 'threat.high_confidence'],
        enabled: true,
      });
    });

    it('should include timestamp in payload', async () => {
      const before = new Date();
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );
      const after = new Date();

      const { payload } = getMockCallArgs(0);
      const timestamp = new Date(payload.timestamp);

      expect(timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should include correlation fields', async () => {
      await webhookService.sendThreatDetected(
        'analysis-123',
        mockEmailData,
        mockAnalysis
      );

      const { payload } = getMockCallArgs(0);
      expect(payload.data.correlationFields).toBeDefined();
      expect(payload.data.correlationFields?.fromEmail).toBe('attacker@phishing-site.com');
    });
  });
});

/**
 * Analysis Service tests
 * Verifies provider orchestration, fallback behavior, and error handling
 * using fake in-memory providers (no network calls).
 */

import { AnalysisService } from '../../../../src/services/ai/analysis.service';
import { AIProvider, ProviderHealth } from '../../../../src/services/ai/provider.interface';
import { AnalysisResult, ExtractedEmailData } from '../../../../src/types';
import { createMinimalProfile } from '../../../../src/models/profile.model';

/**
 * Build a minimal ExtractedEmailData fixture (all invented data)
 */
function makeEmailData(overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData {
  return {
    from_email: 'sender@example.com',
    subject: 'Account notice',
    text: 'Click here to verify your account',
    html: '',
    headers: { From: 'Sender <sender@example.com>' },
    forwardedHeaders: {},
    attachments: [],
    sender: 'sender@example.com',
    to: 'user@example.org',
    original_sender: '',
    originalForwarder: '',
    links: [],
    ...overrides,
  };
}

function makeResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    summary: 'No issues found',
    isPhishing: false,
    confidence: 'High',
    indicators: [],
    recommendations: [],
    provider: 'fake-primary',
    model: 'fake-model-1',
    ...overrides,
  };
}

type FakeProvider = AIProvider & {
  analyzeEmail: jest.Mock;
  sendPrompt: jest.Mock;
  isAvailable: jest.Mock;
  healthCheck: jest.Mock;
  setProfile: jest.Mock;
};

function makeProvider(
  options: {
    name?: string;
    model?: string;
    result?: AnalysisResult;
    health?: ProviderHealth;
  } = {}
): FakeProvider {
  const name = options.name ?? 'fake-primary';
  const model = options.model ?? 'fake-model-1';
  const result = options.result ?? makeResult({ provider: name, model });
  const health = options.health ?? { available: true, lastChecked: new Date() };

  return {
    name,
    model,
    analyzeEmail: jest.fn().mockResolvedValue(result),
    sendPrompt: jest.fn().mockResolvedValue('{}'),
    isAvailable: jest.fn().mockResolvedValue(true),
    healthCheck: jest.fn().mockResolvedValue(health),
    setProfile: jest.fn(),
  };
}

describe('AnalysisService', () => {
  describe('analyzeEmail - happy path', () => {
    it('should return the primary provider result on success', async () => {
      const expected = makeResult({ summary: 'Legitimate newsletter', confidence: 'Very High' });
      const primary = makeProvider({ result: expected });
      const service = new AnalysisService({ primaryProvider: primary });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result).toEqual(expected);
      expect(primary.analyzeEmail).toHaveBeenCalledTimes(1);
    });

    it('should pass the email data to the primary provider', async () => {
      const primary = makeProvider();
      const service = new AnalysisService({ primaryProvider: primary });
      const emailData = makeEmailData({ subject: 'Invoice 12345' });

      await service.analyzeEmail(emailData);

      expect(primary.analyzeEmail).toHaveBeenCalledWith(emailData);
    });

    it('should not call the fallback provider when primary succeeds', async () => {
      const primary = makeProvider();
      const fallback = makeProvider({ name: 'fake-fallback', model: 'fake-model-2' });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      await service.analyzeEmail(makeEmailData());

      expect(fallback.analyzeEmail).not.toHaveBeenCalled();
    });

    it('should return phishing verdicts from the provider unchanged', async () => {
      const expected = makeResult({
        summary: 'Credential phishing attempt',
        isPhishing: true,
        confidence: 'High',
        indicators: ['Suspicious link', 'Urgent language'],
        recommendations: ['Do not click links'],
      });
      const primary = makeProvider({ result: expected });
      const service = new AnalysisService({ primaryProvider: primary });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.isPhishing).toBe(true);
      expect(result.indicators).toEqual(['Suspicious link', 'Urgent language']);
    });
  });

  describe('analyzeEmail - fallback behavior', () => {
    it('should use the fallback provider when primary fails', async () => {
      const fallbackResult = makeResult({ provider: 'fake-fallback', model: 'fake-model-2' });
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('primary unavailable'));
      const fallback = makeProvider({
        name: 'fake-fallback',
        model: 'fake-model-2',
        result: fallbackResult,
      });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result).toEqual(fallbackResult);
      expect(primary.analyzeEmail).toHaveBeenCalledTimes(1);
      expect(fallback.analyzeEmail).toHaveBeenCalledTimes(1);
    });

    it('should pass the same email data to the fallback provider', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('boom'));
      const fallback = makeProvider({ name: 'fake-fallback' });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });
      const emailData = makeEmailData({ subject: 'Payment reminder' });

      await service.analyzeEmail(emailData);

      expect(fallback.analyzeEmail).toHaveBeenCalledWith(emailData);
    });

    it('should return an error result when both providers fail', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('primary down'));
      const fallback = makeProvider({ name: 'fake-fallback' });
      fallback.analyzeEmail.mockRejectedValue(new Error('fallback down'));
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('Analysis could not be completed');
      expect(result.summary).toContain('primary down');
      expect(result.summary).toContain('fallback down');
      expect(result.isPhishing).toBe(false);
      expect(result.confidence).toBe('N/A');
      expect(result.provider).toBe('none');
      expect(result.model).toBe('none');
      expect(result.indicators.length).toBeGreaterThan(0);
      expect(result.recommendations.length).toBeGreaterThan(0);
    });

    it('should return an error result when primary fails and no fallback exists', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('rate limit exceeded'));
      const service = new AnalysisService({ primaryProvider: primary });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('rate limit exceeded');
      expect(result.provider).toBe('none');
      expect(result.isPhishing).toBe(false);
      expect(result.confidence).toBe('N/A');
    });

    it('should handle non-Error rejection values', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue('string failure');
      const service = new AnalysisService({ primaryProvider: primary });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('string failure');
      expect(result.provider).toBe('none');
    });

    it('should handle non-Error rejection values from the fallback provider', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('primary down'));
      const fallback = makeProvider({ name: 'fake-fallback' });
      fallback.analyzeEmail.mockRejectedValue('fallback string failure');
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('primary down');
      expect(result.summary).toContain('fallback string failure');
      expect(result.provider).toBe('none');
    });

    it('should handle non-Error rejection values from the primary provider when fallback also fails', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue('primary string failure');
      const fallback = makeProvider({ name: 'fake-fallback' });
      fallback.analyzeEmail.mockRejectedValue(new Error('fallback down'));
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('primary string failure');
      expect(result.summary).toContain('fallback down');
    });

    it('should surface timeout-style errors through the error result', async () => {
      const primary = makeProvider();
      primary.analyzeEmail.mockRejectedValue(new Error('Request timed out after 30000ms'));
      const fallback = makeProvider({ name: 'fake-fallback' });
      fallback.analyzeEmail.mockRejectedValue(new Error('Request timed out after 30000ms'));
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const result = await service.analyzeEmail(makeEmailData());

      expect(result.summary).toContain('timed out');
      expect(result.confidence).toBe('N/A');
    });

    it('should retry the primary provider on subsequent calls after a failure', async () => {
      const recovered = makeResult({ summary: 'Recovered analysis' });
      const primary = makeProvider();
      primary.analyzeEmail
        .mockRejectedValueOnce(new Error('transient failure'))
        .mockResolvedValueOnce(recovered);
      const service = new AnalysisService({ primaryProvider: primary });

      const first = await service.analyzeEmail(makeEmailData());
      const second = await service.analyzeEmail(makeEmailData());

      expect(first.provider).toBe('none');
      expect(second).toEqual(recovered);
      expect(primary.analyzeEmail).toHaveBeenCalledTimes(2);
    });
  });

  describe('getHealthStatus', () => {
    it('should report health for the primary provider only when no fallback', async () => {
      const health: ProviderHealth = {
        available: true,
        latencyMs: 42,
        lastChecked: new Date('2026-06-01T00:00:00Z'),
      };
      const primary = makeProvider({ health });
      const service = new AnalysisService({ primaryProvider: primary });

      const status = await service.getHealthStatus();

      expect(Object.keys(status)).toEqual(['fake-primary']);
      expect(status['fake-primary']).toEqual(health);
    });

    it('should report health for both providers when fallback exists', async () => {
      const primaryHealth: ProviderHealth = { available: true, lastChecked: new Date() };
      const fallbackHealth: ProviderHealth = {
        available: false,
        lastError: 'credentials missing',
        lastChecked: new Date(),
      };
      const primary = makeProvider({ health: primaryHealth });
      const fallback = makeProvider({ name: 'fake-fallback', health: fallbackHealth });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      const status = await service.getHealthStatus();

      expect(status['fake-primary']).toEqual(primaryHealth);
      expect(status['fake-fallback']).toEqual(fallbackHealth);
      expect(primary.healthCheck).toHaveBeenCalledTimes(1);
      expect(fallback.healthCheck).toHaveBeenCalledTimes(1);
    });
  });

  describe('provider accessors', () => {
    it('should return the primary provider name and model', () => {
      const primary = makeProvider({ name: 'fake-primary', model: 'fake-model-1' });
      const fallback = makeProvider({ name: 'fake-fallback', model: 'fake-model-2' });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });

      expect(service.getActiveProvider()).toBe('fake-primary');
      expect(service.getActiveModel()).toBe('fake-model-1');
    });
  });

  describe('setProfile', () => {
    it('should forward the profile to both providers', () => {
      const primary = makeProvider();
      const fallback = makeProvider({ name: 'fake-fallback' });
      const service = new AnalysisService({
        primaryProvider: primary,
        fallbackProvider: fallback,
      });
      const profile = createMinimalProfile('Example Corp', ['example.com']);

      service.setProfile(profile);

      expect(primary.setProfile).toHaveBeenCalledWith(profile);
      expect(fallback.setProfile).toHaveBeenCalledWith(profile);
    });

    it('should clear the profile when called with undefined', () => {
      const primary = makeProvider();
      const service = new AnalysisService({ primaryProvider: primary });

      service.setProfile(undefined);

      expect(primary.setProfile).toHaveBeenCalledWith(undefined);
    });

    it('should not throw when no fallback provider is configured', () => {
      const primary = makeProvider();
      const service = new AnalysisService({ primaryProvider: primary });
      const profile = createMinimalProfile('Example Corp', ['example.com']);

      expect(() => service.setProfile(profile)).not.toThrow();
      expect(primary.setProfile).toHaveBeenCalledWith(profile);
    });
  });
});

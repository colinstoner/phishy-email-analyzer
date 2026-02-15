/**
 * Configuration Mocks for Integration Testing
 */

import { PhishyConfig } from '../../../src/config/schema';

/**
 * Create a mock configuration for testing
 */
export function createMockConfig(overrides: Partial<PhishyConfig> = {}): PhishyConfig {
  return {
    ai: {
      provider: 'bedrock',
      bedrock: {
        region: 'us-east-1',
        modelId: 'us.anthropic.claude-sonnet-4-5-20250514-v1:0',
        maxTokens: 4096,
        timeout: 60000,
      },
      ...overrides.ai,
    },
    email: {
      safeDomains: ['trusted.com', 'example.com'],
      safeSenders: ['admin@trusted.com'],
      deleteAfterProcessing: false,
      ...overrides.email,
    },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy Security',
      securityTeamDistribution: ['security@example.com'],
      ...overrides.notification,
    },
    storage: {
      s3Bucket: 'test-bucket',
      s3Prefix: 'emails',
      region: 'us-east-1',
      ...overrides.storage,
    },
    logLevel: 'error', // Suppress logs during testing
    ...overrides,
  };
}

/**
 * Create a mock Anthropic configuration
 */
export function createMockAnthropicConfig(): PhishyConfig {
  return createMockConfig({
    ai: {
      provider: 'anthropic',
      anthropic: {
        apiKey: 'sk-ant-test-key-123',
        model: 'claude-sonnet-4-5-20250514',
        maxTokens: 4096,
        timeout: 60000,
      },
    },
  });
}

/**
 * Mock the loadConfig function
 */
export function mockLoadConfig(config: PhishyConfig): void {
  jest.mock('../../../src/config', () => ({
    loadConfig: jest.fn().mockResolvedValue(config),
  }));
}

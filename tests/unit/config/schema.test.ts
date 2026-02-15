/**
 * Configuration schema tests
 */

import {
  validateConfig,
  safeValidateConfig,
} from '../../../src/config/schema';

describe('PhishyConfigSchema', () => {
  const validConfig = {
    ai: {
      provider: 'anthropic',
      anthropic: {
        apiKey: 'test-key',
        model: 'claude-3-sonnet-20240229',
        maxTokens: 4096,
        timeout: 60000,
      },
    },
    email: {
      safeDomains: ['example.com'],
      safeSenders: ['trusted@example.com'],
      deleteAfterProcessing: false,
    },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy',
      securityTeamDistribution: ['security@example.com'],
    },
    storage: {
      s3Bucket: 'phishy-bucket',
      s3Prefix: 'emails',
      region: 'us-east-1',
    },
  };

  describe('validateConfig', () => {
    it('should accept valid configuration', () => {
      const result = validateConfig(validConfig);
      expect(result.ai.provider).toBe('anthropic');
      expect(result.storage.s3Bucket).toBe('phishy-bucket');
    });

    it('should apply defaults', () => {
      const minimalConfig = {
        ai: {
          anthropic: {
            apiKey: 'test-key',
          },
        },
        email: {}, // Required but accepts defaults
        notification: {
          senderEmail: 'test@example.com',
        },
        storage: {
          s3Bucket: 'test-bucket',
        },
      };

      const result = validateConfig(minimalConfig);
      expect(result.ai.provider).toBe('anthropic');
      expect(result.email.safeDomains).toEqual(['example.com']);
      expect(result.logLevel).toBe('info');
    });

    it('should throw for invalid configuration', () => {
      const invalidConfig = {
        ai: {
          provider: 'invalid-provider',
        },
      };

      expect(() => validateConfig(invalidConfig)).toThrow();
    });
  });

  describe('safeValidateConfig', () => {
    it('should return success for valid config', () => {
      const result = safeValidateConfig(validConfig);
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it('should return errors for invalid config', () => {
      const result = safeValidateConfig({});
      expect(result.success).toBe(false);
      expect(result.errors).toBeDefined();
    });
  });

  describe('AI provider validation', () => {
    it('should accept anthropic provider', () => {
      const config = {
        ...validConfig,
        ai: {
          provider: 'anthropic',
          anthropic: { apiKey: 'key' },
        },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should accept bedrock provider', () => {
      const config = {
        ...validConfig,
        ai: {
          provider: 'bedrock',
          bedrock: { region: 'us-east-1' },
        },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('should reject invalid provider', () => {
      const config = {
        ...validConfig,
        ai: { provider: 'openai' },
      };
      expect(() => validateConfig(config)).toThrow();
    });
  });

  describe('Email configuration validation', () => {
    it('should require valid sender email', () => {
      const config = {
        ...validConfig,
        notification: {
          senderEmail: 'invalid-email',
        },
      };
      expect(() => validateConfig(config)).toThrow();
    });

    it('should accept valid security team distribution', () => {
      const config = {
        ...validConfig,
        notification: {
          senderEmail: 'test@example.com',
          securityTeamDistribution: ['team1@example.com', 'team2@example.com'],
        },
      };
      const result = validateConfig(config);
      expect(result.notification.securityTeamDistribution).toHaveLength(2);
    });
  });

  describe('Storage configuration validation', () => {
    it('should require s3Bucket', () => {
      const config = {
        ...validConfig,
        storage: {
          s3Prefix: 'emails',
          region: 'us-east-1',
        },
      };
      expect(() => validateConfig(config)).toThrow();
    });

    it('should apply default region', () => {
      const config = {
        ...validConfig,
        storage: {
          s3Bucket: 'test-bucket',
        },
      };
      const result = validateConfig(config);
      expect(result.storage.region).toBe('us-east-1');
    });
  });

  describe('Intelligence configuration', () => {
    it('should be optional and undefined by default', () => {
      const result = validateConfig(validConfig);
      // intelligence is optional, so it's undefined when not provided
      expect(result.intelligence).toBeUndefined();
    });

    it('should accept postgres type', () => {
      const config = {
        ...validConfig,
        intelligence: {
          enabled: true,
          type: 'postgres',
          connectionString: 'postgresql://localhost/phishy',
        },
      };
      const result = validateConfig(config);
      expect(result.intelligence?.type).toBe('postgres');
    });

    it('should accept dynamodb type', () => {
      const config = {
        ...validConfig,
        intelligence: {
          enabled: true,
          type: 'dynamodb',
          tableName: 'phishy-intelligence',
        },
      };
      const result = validateConfig(config);
      expect(result.intelligence?.type).toBe('dynamodb');
    });
  });
});

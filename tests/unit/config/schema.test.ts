/**
 * Configuration schema tests
 */

import { validateConfig, safeValidateConfig } from '../../../src/config/schema';

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

  describe('AI model defaults', () => {
    it('defaults the Anthropic provider to Claude Opus 5.5 with a 16000-token limit', () => {
      const result = validateConfig({
        ...validConfig,
        ai: { provider: 'anthropic', anthropic: { apiKey: 'test-key' } },
      });

      expect(result.ai.anthropic?.model).toBe('claude-opus-5-5');
      expect(result.ai.anthropic?.maxTokens).toBe(16000);
      expect(result.ai.anthropic?.timeout).toBe(60000);
    });

    it('defaults the Bedrock provider to the Opus 5.5 inference profile', () => {
      const result = validateConfig({ ...validConfig, ai: { provider: 'bedrock', bedrock: {} } });

      expect(result.ai.bedrock?.modelId).toBe('global.anthropic.claude-opus-5-5');
      expect(result.ai.bedrock?.maxTokens).toBe(16000);
    });

    it('defaults effort to medium and leaves the refusal fallback to the provider', () => {
      const result = validateConfig(validConfig);

      expect(result.ai.effort).toBe('medium');
      expect(result.ai.refusalFallbackModel).toBeUndefined();
    });

    it('accepts every effort level and rejects anything else', () => {
      for (const effort of ['low', 'medium', 'high', 'xhigh', 'max']) {
        const result = validateConfig({ ...validConfig, ai: { ...validConfig.ai, effort } });
        expect(result.ai.effort).toBe(effort);
      }

      const invalid = safeValidateConfig({
        ...validConfig,
        ai: { ...validConfig.ai, effort: 'extreme' },
      });
      expect(invalid.success).toBe(false);
    });

    it('accepts a refusal fallback model, including an empty string to disable it', () => {
      const set = validateConfig({
        ...validConfig,
        ai: { ...validConfig.ai, refusalFallbackModel: 'claude-opus-5' },
      });
      expect(set.ai.refusalFallbackModel).toBe('claude-opus-5');

      const disabled = validateConfig({
        ...validConfig,
        ai: { ...validConfig.ai, refusalFallbackModel: '' },
      });
      expect(disabled.ai.refusalFallbackModel).toBe('');
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

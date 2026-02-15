/**
 * Enterprise profile model tests
 */

import {
  validateProfile,
  createMinimalProfile,
  EXAMPLE_PROFILE,
} from '../../../src/models/profile.model';

describe('EnterpriseProfile', () => {
  describe('validateProfile', () => {
    it('should accept minimal profile', () => {
      const profile = {
        name: 'Test Corp',
        organization: {
          name: 'Test Corporation',
          domains: ['test.com'],
        },
      };

      const result = validateProfile(profile);
      expect(result.name).toBe('Test Corp');
      expect(result.organization.domains).toContain('test.com');
    });

    it('should accept full profile', () => {
      const result = validateProfile(EXAMPLE_PROFILE);
      expect(result.name).toBe('Acme Corporation');
      expect(result.vips).toHaveLength(2);
      expect(result.systems?.authentication?.ssoEnabled).toBe(true);
    });

    it('should validate VIP entries', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        vips: [
          {
            name: 'John CEO',
            title: 'CEO',
            email: 'ceo@test.com',
            impersonationRisk: 'critical',
          },
        ],
      };

      const result = validateProfile(profile);
      expect(result.vips?.[0].impersonationRisk).toBe('critical');
    });

    it('should reject invalid VIP email', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        vips: [
          {
            name: 'John CEO',
            title: 'CEO',
            email: 'invalid-email',
            impersonationRisk: 'high',
          },
        ],
      };

      expect(() => validateProfile(profile)).toThrow();
    });

    it('should validate trusted partners', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        trustedPartners: [
          {
            name: 'Partner Inc',
            domains: ['partner.com'],
            relationship: 'vendor',
          },
        ],
      };

      const result = validateProfile(profile);
      expect(result.trustedPartners?.[0].relationship).toBe('vendor');
    });

    it('should reject invalid partner relationship', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        trustedPartners: [
          {
            name: 'Partner Inc',
            domains: ['partner.com'],
            relationship: 'friend', // invalid
          },
        ],
      };

      expect(() => validateProfile(profile)).toThrow();
    });

    it('should validate analysis config', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        analysisConfig: {
          sensitivityLevel: 'paranoid',
          autoEscalateThreshold: 0.9,
        },
      };

      const result = validateProfile(profile);
      expect(result.analysisConfig?.sensitivityLevel).toBe('paranoid');
    });

    it('should reject invalid sensitivity level', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        analysisConfig: {
          sensitivityLevel: 'extreme', // invalid
        },
      };

      expect(() => validateProfile(profile)).toThrow();
    });

    it('should reject threshold outside 0-1 range', () => {
      const profile = {
        name: 'Test',
        organization: {
          name: 'Test',
          domains: ['test.com'],
        },
        analysisConfig: {
          autoEscalateThreshold: 1.5, // invalid
        },
      };

      expect(() => validateProfile(profile)).toThrow();
    });
  });

  describe('createMinimalProfile', () => {
    it('should create a minimal profile with name and domains', () => {
      const profile = createMinimalProfile('Acme', ['acme.com', 'acme.io']);

      expect(profile.name).toBe('Acme');
      expect(profile.organization.name).toBe('Acme');
      expect(profile.organization.domains).toEqual(['acme.com', 'acme.io']);
    });

    it('should create valid profile that passes validation', () => {
      const profile = createMinimalProfile('Test', ['test.com']);
      expect(() => validateProfile(profile)).not.toThrow();
    });
  });

  describe('EXAMPLE_PROFILE', () => {
    it('should be a valid profile', () => {
      expect(() => validateProfile(EXAMPLE_PROFILE)).not.toThrow();
    });

    it('should have all major sections populated', () => {
      expect(EXAMPLE_PROFILE.organization).toBeDefined();
      expect(EXAMPLE_PROFILE.systems).toBeDefined();
      expect(EXAMPLE_PROFILE.vips).toBeDefined();
      expect(EXAMPLE_PROFILE.trustedPartners).toBeDefined();
      expect(EXAMPLE_PROFILE.customPatterns).toBeDefined();
      expect(EXAMPLE_PROFILE.analysisConfig).toBeDefined();
    });
  });
});

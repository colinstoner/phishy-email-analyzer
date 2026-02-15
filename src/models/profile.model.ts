/**
 * Enterprise Profile Model
 * Defines the schema for organization-specific phishing detection profiles
 */

import { z } from 'zod';

/**
 * VIP person schema for impersonation detection
 */
const VIPSchema = z.object({
  name: z.string(),
  title: z.string(),
  email: z.string().email(),
  aliases: z.array(z.string()).optional(),
  impersonationRisk: z.enum(['critical', 'high', 'medium']).default('medium'),
});

/**
 * Trusted partner schema
 */
const TrustedPartnerSchema = z.object({
  name: z.string(),
  domains: z.array(z.string()),
  relationship: z.enum(['vendor', 'customer', 'partner']),
});

/**
 * Business application schema
 */
const BusinessAppSchema = z.object({
  name: z.string(),
  domain: z.string(),
  category: z.enum([
    'productivity',
    'communication',
    'crm',
    'hr',
    'finance',
    'engineering',
    'security',
    'other',
  ]),
});

/**
 * Recent threat schema
 */
const RecentThreatSchema = z.object({
  description: z.string(),
  indicators: z.array(z.string()).optional(),
  dateReported: z.string(),
});

/**
 * Email systems configuration
 */
const EmailSystemsSchema = z.object({
  providers: z.array(z.string()).optional(),
  legitimateServices: z.array(z.string()).optional(),
});

/**
 * Authentication systems configuration
 */
const AuthenticationSystemsSchema = z.object({
  providers: z.array(z.string()).optional(),
  ssoEnabled: z.boolean().optional(),
  mfaRequired: z.boolean().optional(),
});

/**
 * Storage systems configuration
 */
const StorageSystemsSchema = z.object({
  providers: z.array(z.string()).optional(),
});

/**
 * Organization systems schema
 */
const SystemsSchema = z.object({
  email: EmailSystemsSchema.optional(),
  authentication: AuthenticationSystemsSchema.optional(),
  storage: StorageSystemsSchema.optional(),
  businessApps: z.array(BusinessAppSchema).optional(),
  communication: z.array(z.string()).optional(),
});

/**
 * Custom patterns schema
 */
const CustomPatternsSchema = z.object({
  highRiskKeywords: z.array(z.string()).optional(),
  legitimateKeywords: z.array(z.string()).optional(),
  knownBadDomains: z.array(z.string()).optional(),
  recentThreats: z.array(RecentThreatSchema).optional(),
});

/**
 * Analysis configuration schema
 */
const AnalysisConfigSchema = z.object({
  sensitivityLevel: z.enum(['low', 'medium', 'high', 'paranoid']).default('medium'),
  autoEscalateThreshold: z.number().min(0).max(1).optional(),
  additionalPromptContext: z.string().optional(),
});

/**
 * Organization schema
 */
const OrganizationSchema = z.object({
  name: z.string(),
  domains: z.array(z.string()),
  aliases: z.array(z.string()).optional(),
});

/**
 * Complete Enterprise Profile schema
 */
export const EnterpriseProfileSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string(),
  organization: OrganizationSchema,
  systems: SystemsSchema.optional(),
  vips: z.array(VIPSchema).optional(),
  trustedPartners: z.array(TrustedPartnerSchema).optional(),
  customPatterns: CustomPatternsSchema.optional(),
  analysisConfig: AnalysisConfigSchema.optional(),
  createdAt: z.string().datetime().optional(),
  updatedAt: z.string().datetime().optional(),
});

/**
 * Inferred TypeScript types
 */
export type EnterpriseProfile = z.infer<typeof EnterpriseProfileSchema>;
export type VIP = z.infer<typeof VIPSchema>;
export type TrustedPartner = z.infer<typeof TrustedPartnerSchema>;
export type BusinessApp = z.infer<typeof BusinessAppSchema>;
export type RecentThreat = z.infer<typeof RecentThreatSchema>;
export type CustomPatterns = z.infer<typeof CustomPatternsSchema>;
export type AnalysisConfig = z.infer<typeof AnalysisConfigSchema>;

/**
 * Validate enterprise profile
 */
export function validateProfile(profile: unknown): EnterpriseProfile {
  return EnterpriseProfileSchema.parse(profile);
}

/**
 * Create a minimal profile
 */
export function createMinimalProfile(
  name: string,
  domains: string[]
): EnterpriseProfile {
  return {
    name,
    organization: {
      name,
      domains,
    },
  };
}

/**
 * Example enterprise profile for reference
 */
export const EXAMPLE_PROFILE: EnterpriseProfile = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  name: 'Acme Corporation',
  organization: {
    name: 'Acme Corporation',
    domains: ['acme.com', 'acme.io'],
    aliases: ['ACME Corp', 'Acme Inc', 'Acme'],
  },
  systems: {
    email: {
      providers: ['Microsoft 365', 'Exchange Online'],
      legitimateServices: ['mailchimp.com', 'sendgrid.net'],
    },
    authentication: {
      providers: ['Okta', 'Azure AD'],
      ssoEnabled: true,
      mfaRequired: true,
    },
    storage: {
      providers: ['OneDrive', 'SharePoint', 'Box'],
    },
    businessApps: [
      { name: 'Salesforce', domain: 'salesforce.com', category: 'crm' },
      { name: 'Workday', domain: 'workday.com', category: 'hr' },
      { name: 'Slack', domain: 'slack.com', category: 'communication' },
      { name: 'Zoom', domain: 'zoom.us', category: 'communication' },
    ],
    communication: ['Slack', 'Microsoft Teams', 'Zoom'],
  },
  vips: [
    {
      name: 'John Smith',
      title: 'CEO',
      email: 'john.smith@acme.com',
      aliases: ['J Smith', 'John S', 'CEO'],
      impersonationRisk: 'critical',
    },
    {
      name: 'Jane Doe',
      title: 'CFO',
      email: 'jane.doe@acme.com',
      aliases: ['J Doe', 'Jane D'],
      impersonationRisk: 'critical',
    },
  ],
  trustedPartners: [
    {
      name: 'Big Law LLP',
      domains: ['biglaw.com'],
      relationship: 'vendor',
    },
    {
      name: 'Accounting Partners',
      domains: ['accountingpartners.com'],
      relationship: 'vendor',
    },
  ],
  customPatterns: {
    highRiskKeywords: ['wire transfer', 'urgent payment', 'gift cards', 'cryptocurrency'],
    legitimateKeywords: ['quarterly report', 'board meeting'],
    knownBadDomains: ['acme-secure.com', 'acme-login.com'],
    recentThreats: [
      {
        description: 'CEO impersonation campaign requesting wire transfers',
        indicators: ['wire transfer', 'confidential', 'urgent'],
        dateReported: '2024-01-15',
      },
    ],
  },
  analysisConfig: {
    sensitivityLevel: 'high',
    autoEscalateThreshold: 0.8,
    additionalPromptContext:
      'The organization operates primarily in the technology sector and frequently receives legitimate emails about software licenses and cloud services.',
  },
};

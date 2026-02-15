/**
 * Prompt Builder Service
 * Constructs analysis prompts for AI providers
 */

import { ExtractedEmailData } from '../../types';
import { EnterpriseProfile } from '../../models/profile.model';

/**
 * Build phishing analysis prompt for email
 */
export function buildPhishingAnalysisPrompt(
  emailData: ExtractedEmailData,
  essentialHeaders: Record<string, string>,
  profile?: EnterpriseProfile
): string {
  const linksSection =
    emailData.links.length > 0
      ? `--- LINKS IN EMAIL ---\n${emailData.links.join('\n')}\n\n`
      : '';

  const profileSection = profile ? buildProfileSection(profile) : buildDefaultSystemsSection();

  return `Analyze this email for phishing or other malicious content. Assume the forwarded email is from a trusted source and perform no analysis on the trusted source, only the forwarded email contents. Do not comment on future dates or times.

--- EMAIL CONTENT ---
From: ${emailData.from_email}
Subject: ${emailData.subject}
Body:
${emailData.text || 'No text content'}

${linksSection}--- HEADERS ---
${JSON.stringify(essentialHeaders, null, 2)}

${profileSection}

--- ANALYSIS INSTRUCTIONS ---
Please analyze this email for signs of phishing, focusing on:
1. Sender legitimacy (check domain, email headers)
2. Links to unexpected domains or IP addresses
3. Urgency or threatening language
4. Poor grammar or formatting
5. Requests for sensitive information
6. Suspicious attachments

Determine if this is likely legitimate or potentially malicious.

Return your analysis as JSON with these keys:
{
  "summary": "One paragraph summary of analysis findings.",
  "isPhishing": true/false,
  "confidence": "High/Medium/Low",
  "indicators": ["List of specific phishing indicators found"],
  "recommendations": ["List of recommended actions"]
}`;
}

/**
 * Build default systems section for prompt
 */
function buildDefaultSystemsSection(): string {
  return `--- LEGITIMATE SYSTEMS INFORMATION ---
The organization uses the following legitimate systems:
* Email: Microsoft 365, Gmail
* Cloud Storage: OneDrive, Google Drive
* Authentication: SSO solutions like Okta or Azure AD
* Business Software: Microsoft Office, Salesforce, Zoom
* Security: Email security gateways, spam filters

IMPORTANT: The organization uses SSO for authentication to most systems.`;
}

/**
 * Build profile section for enterprise profile
 */
function buildProfileSection(profile: EnterpriseProfile): string {
  const sections: string[] = [];

  // Organization info
  sections.push(`--- ORGANIZATION CONTEXT ---
Organization: ${profile.organization.name}
Domains: ${profile.organization.domains.join(', ')}
Aliases: ${profile.organization.aliases?.join(', ') ?? 'None specified'}`);

  // Systems
  if (profile.systems) {
    sections.push(`--- LEGITIMATE SYSTEMS ---`);

    if (profile.systems.email?.providers?.length) {
      sections.push(`Email Providers: ${profile.systems.email.providers.join(', ')}`);
    }

    if (profile.systems.authentication?.providers?.length) {
      sections.push(`Authentication: ${profile.systems.authentication.providers.join(', ')}`);
      if (profile.systems.authentication.ssoEnabled) {
        sections.push(`SSO: Enabled`);
      }
      if (profile.systems.authentication.mfaRequired) {
        sections.push(`MFA: Required`);
      }
    }

    if (profile.systems.storage?.providers?.length) {
      sections.push(`Storage: ${profile.systems.storage.providers.join(', ')}`);
    }

    if (profile.systems.businessApps?.length) {
      const apps = profile.systems.businessApps.map(app => app.name).join(', ');
      sections.push(`Business Apps: ${apps}`);
    }

    if (profile.systems.communication?.length) {
      sections.push(`Communication: ${profile.systems.communication.join(', ')}`);
    }
  }

  // VIP watch list
  if (profile.vips?.length) {
    sections.push(`\n--- VIP WATCH LIST (CHECK FOR IMPERSONATION) ---`);
    for (const vip of profile.vips) {
      sections.push(`* ${vip.name} (${vip.title}) - ${vip.email}`);
      if (vip.aliases?.length) {
        sections.push(`  Known aliases: ${vip.aliases.join(', ')}`);
      }
      sections.push(`  Impersonation risk: ${vip.impersonationRisk}`);
    }
  }

  // Trusted partners
  if (profile.trustedPartners?.length) {
    sections.push(`\n--- TRUSTED PARTNERS ---`);
    for (const partner of profile.trustedPartners) {
      sections.push(`* ${partner.name} (${partner.relationship}): ${partner.domains.join(', ')}`);
    }
  }

  // Custom patterns
  if (profile.customPatterns) {
    if (profile.customPatterns.highRiskKeywords?.length) {
      sections.push(`\n--- HIGH RISK KEYWORDS ---
${profile.customPatterns.highRiskKeywords.join(', ')}`);
    }

    if (profile.customPatterns.knownBadDomains?.length) {
      sections.push(`\n--- KNOWN MALICIOUS DOMAINS ---
${profile.customPatterns.knownBadDomains.join(', ')}`);
    }

    if (profile.customPatterns.recentThreats?.length) {
      sections.push(`\n--- RECENT THREATS ---`);
      for (const threat of profile.customPatterns.recentThreats) {
        sections.push(`* ${threat.description} (Reported: ${threat.dateReported})`);
        if (threat.indicators?.length) {
          sections.push(`  Indicators: ${threat.indicators.join(', ')}`);
        }
      }
    }
  }

  // Analysis configuration
  if (profile.analysisConfig) {
    sections.push(`\n--- ANALYSIS CONFIGURATION ---
Sensitivity: ${profile.analysisConfig.sensitivityLevel}
Auto-escalate threshold: ${profile.analysisConfig.autoEscalateThreshold ?? 'Default'}`);

    if (profile.analysisConfig.additionalPromptContext) {
      sections.push(`\nAdditional context: ${profile.analysisConfig.additionalPromptContext}`);
    }
  }

  return sections.join('\n');
}

/**
 * Build a simplified prompt for quick analysis
 */
export function buildQuickAnalysisPrompt(emailData: ExtractedEmailData): string {
  return `Quickly analyze this email for phishing. Return JSON only.

From: ${emailData.from_email}
Subject: ${emailData.subject}
Body (first 500 chars): ${emailData.text.substring(0, 500)}
Links: ${emailData.links.slice(0, 5).join(', ')}

Return: {"isPhishing": boolean, "confidence": "High/Medium/Low", "summary": "one sentence"}`;
}

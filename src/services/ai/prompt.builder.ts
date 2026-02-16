/**
 * Prompt Builder Service
 * Constructs analysis prompts for AI providers
 */

import { ExtractedEmailData } from '../../types';
import { EnterpriseProfile } from '../../models/profile.model';
import { analyzeRecipientContext, formatRecipientContextForPrompt } from '../../utils/signature';

// Maximum characters for email body to prevent token overflow
const MAX_BODY_LENGTH = 50000;

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
      ? `--- LINKS IN EMAIL ---\n${emailData.links.slice(0, 50).join('\n')}\n\n`
      : '';

  const profileSection = profile ? buildProfileSection(profile) : buildDefaultSystemsSection();

  // Truncate body if too large
  let bodyText = emailData.text || 'No text content';
  let truncationNote = '';
  if (bodyText.length > MAX_BODY_LENGTH) {
    bodyText = bodyText.substring(0, MAX_BODY_LENGTH);
    truncationNote = '\n[... body truncated for analysis ...]';
  }

  // Analyze recipient context from signature
  const recipientContext = analyzeRecipientContext(emailData.text, emailData.originalForwarder);
  const recipientSection = formatRecipientContextForPrompt(recipientContext);

  return `You are an IT security analyst reviewing emails that employees have forwarded for security review. The person forwarding the email is a trusted employee - analyze only the forwarded content for threats.

--- EMAIL DETAILS ---
FROM: ${emailData.from_email}
SUBJECT: ${emailData.subject}

--- KEY HEADERS ---
${JSON.stringify(essentialHeaders, null, 2)}

--- EMAIL CONTENT ---
${bodyText}${truncationNote}

${linksSection}${profileSection}
${recipientSection ? `\n${recipientSection}\n` : ''}
Analyze this email for phishing indicators. Check for:
1. Links to unexpected domains or IP addresses
2. Requests for credentials or sensitive information
3. Suspicious attachments
4. Social engineering tactics
5. Impersonation attempts

Return your analysis as JSON:
{
  "summary": "2-3 sentence summary for a non-technical employee",
  "isPhishing": true/false,
  "confidence": "High/Medium/Low",
  "indicators": ["Array of specific suspicious indicators found"],
  "recommendations": ["Array of recommended actions"]
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

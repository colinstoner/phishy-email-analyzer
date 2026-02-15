/**
 * Email Signature Analysis Utility
 * Extracts role/title information from email signatures for risk assessment
 */

export interface RecipientContext {
  detectedRole?: string;
  detectedTitle?: string;
  isHighValueTarget: boolean;
  roleIndicators: string[];
}

/**
 * High-value target roles - common BEC/phishing targets
 */
const HIGH_VALUE_ROLES = [
  'accounts payable',
  'accounts receivable',
  'payroll',
  'finance',
  'accounting',
  'controller',
  'treasurer',
  'cfo',
  'coo',
  'ceo',
  'president',
  'executive',
  'hr',
  'human resources',
  'benefits',
  'it',
  'information technology',
  'procurement',
  'purchasing',
  'legal',
  'compliance',
];

/**
 * Title patterns to extract from signatures
 */
const TITLE_PATTERNS = [
  // "Title: Something" or "Role: Something"
  /(?:title|role|position):\s*([^\n|,]+)/i,
  // "Name | Title" or "Name – Title"
  /\|\s*([^|\n]+(?:manager|director|vp|vice president|chief|officer|coordinator|specialist|analyst|administrator|lead|head|supervisor)[^|\n]*)/i,
  /[–—-]\s*([^–—\-\n]+(?:manager|director|vp|vice president|chief|officer|coordinator|specialist|analyst|administrator|lead|head|supervisor)[^–—\-\n]*)/i,
  // Standalone title line (common formats)
  /^((?:senior\s+|junior\s+|sr\.?\s+|jr\.?\s+)?(?:accounts?\s+payable|accounts?\s+receivable|payroll|finance|accounting|hr|human\s+resources|it|procurement|purchasing)\s*(?:manager|director|coordinator|specialist|clerk|administrator|assistant)?)\s*$/im,
  /^((?:senior\s+|junior\s+|sr\.?\s+|jr\.?\s+)?(?:manager|director|vp|vice\s+president|chief\s+\w+\s+officer|controller|treasurer|coordinator|specialist|analyst|administrator|lead|head|supervisor)[^\n]{0,30})\s*$/im,
];

/**
 * Department indicators in email addresses
 */
const EMAIL_DEPT_PATTERNS: Record<string, string> = {
  'ap@': 'Accounts Payable',
  'ar@': 'Accounts Receivable',
  'payroll@': 'Payroll',
  'finance@': 'Finance',
  'accounting@': 'Accounting',
  'hr@': 'Human Resources',
  'humanresources@': 'Human Resources',
  'it@': 'IT',
  'helpdesk@': 'IT',
  'procurement@': 'Procurement',
  'purchasing@': 'Purchasing',
  'legal@': 'Legal',
  'compliance@': 'Compliance',
  'benefits@': 'Benefits/HR',
};

/**
 * Analyze email content for recipient role/title information
 */
export function analyzeRecipientContext(
  emailText: string,
  recipientEmail?: string
): RecipientContext {
  const roleIndicators: string[] = [];
  let detectedRole: string | undefined;
  let detectedTitle: string | undefined;

  // Check email address for department hints
  if (recipientEmail) {
    const emailLower = recipientEmail.toLowerCase();
    for (const [pattern, dept] of Object.entries(EMAIL_DEPT_PATTERNS)) {
      if (emailLower.includes(pattern)) {
        detectedRole = dept;
        roleIndicators.push(`Email address indicates ${dept} department`);
        break;
      }
    }
  }

  // Extract signature block (usually last portion of email)
  const signatureBlock = extractSignatureBlock(emailText);

  if (signatureBlock) {
    // Try to extract title from signature
    for (const pattern of TITLE_PATTERNS) {
      const match = signatureBlock.match(pattern);
      if (match?.[1]) {
        const title = match[1].trim();
        if (title.length > 2 && title.length < 100) {
          detectedTitle = title;
          roleIndicators.push(`Signature contains title: "${title}"`);
          break;
        }
      }
    }

    // Look for role keywords in signature
    const signatureLower = signatureBlock.toLowerCase();
    for (const role of HIGH_VALUE_ROLES) {
      if (signatureLower.includes(role)) {
        if (!detectedRole) {
          detectedRole = role.charAt(0).toUpperCase() + role.slice(1);
        }
        roleIndicators.push(`Signature mentions: ${role}`);
        break;
      }
    }
  }

  // Determine if high-value target
  const isHighValueTarget = determineHighValueTarget(detectedRole, detectedTitle);

  return {
    detectedRole,
    detectedTitle,
    isHighValueTarget,
    roleIndicators,
  };
}

/**
 * Extract the signature block from email text
 * Signatures typically appear after common delimiters
 */
function extractSignatureBlock(text: string): string | null {
  if (!text) return null;

  // Common signature delimiters
  const delimiters = [
    /^--\s*$/m,
    /^_{3,}$/m,
    /^-{3,}$/m,
    /\bregards,?\s*$/im,
    /\bsincerely,?\s*$/im,
    /\bthanks,?\s*$/im,
    /\bthank\s+you,?\s*$/im,
    /\bbest,?\s*$/im,
    /\bcheers,?\s*$/im,
  ];

  let signatureStart = text.length;

  for (const delimiter of delimiters) {
    const match = text.match(delimiter);
    if (match?.index !== undefined && match.index < signatureStart) {
      signatureStart = match.index;
    }
  }

  // If no delimiter found, check last ~500 chars
  if (signatureStart === text.length) {
    signatureStart = Math.max(0, text.length - 500);
  }

  const signature = text.slice(signatureStart);
  return signature.length > 10 ? signature : null;
}

/**
 * Determine if the detected role/title indicates a high-value target
 */
function determineHighValueTarget(role?: string, title?: string): boolean {
  const combined = `${role ?? ''} ${title ?? ''}`.toLowerCase();

  return HIGH_VALUE_ROLES.some(hvr => combined.includes(hvr));
}

/**
 * Format recipient context for prompt inclusion
 */
export function formatRecipientContextForPrompt(context: RecipientContext): string | null {
  if (!context.detectedRole && !context.detectedTitle && !context.isHighValueTarget) {
    return null;
  }

  const lines: string[] = ['--- RECIPIENT CONTEXT ---'];

  if (context.detectedTitle) {
    lines.push(`Detected Title: ${context.detectedTitle}`);
  }

  if (context.detectedRole) {
    lines.push(`Detected Department: ${context.detectedRole}`);
  }

  if (context.isHighValueTarget) {
    lines.push(`HIGH-VALUE TARGET: This recipient appears to work in a role commonly targeted by BEC/phishing attacks (finance, HR, executive, etc.). Consider this when assessing risk.`);
  }

  return lines.join('\n');
}

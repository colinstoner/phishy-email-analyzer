/**
 * Recipient context: what Phishy can say about the employee who reported the
 * email, for risk assessment (finance, HR and executive staff are the usual
 * BEC targets).
 *
 * It is derived ONLY from the reporter's own address — `originalForwarder`,
 * which the parser accepts only on a safe domain. It is never derived from
 * the body of the report: the body is mostly the suspicious email, and a
 * signature found there is the ATTACKER's signature, not the employee's (an
 * earlier version read "Title:" lines from the body and copied them into the
 * prompt outside the fence). Every value this module renders is a fixed
 * string from the tables below; nothing from the email is echoed.
 */

export interface RecipientContext {
  /** A fixed department label, from the address's local part */
  detectedRole?: string;
  isHighValueTarget: boolean;
}

/**
 * Departmental mailbox local parts and the department they indicate. Matched
 * against the whole local part, so `kit@` is not `it@`.
 */
const DEPARTMENT_MAILBOXES: Record<string, string> = {
  ap: 'Accounts Payable',
  ar: 'Accounts Receivable',
  payroll: 'Payroll',
  finance: 'Finance',
  accounting: 'Accounting',
  hr: 'Human Resources',
  humanresources: 'Human Resources',
  it: 'IT',
  helpdesk: 'IT',
  procurement: 'Procurement',
  purchasing: 'Purchasing',
  legal: 'Legal',
  compliance: 'Compliance',
  benefits: 'Benefits/HR',
};

/** Departments commonly targeted by BEC / phishing */
const HIGH_VALUE_DEPARTMENTS = new Set([
  'Accounts Payable',
  'Accounts Receivable',
  'Payroll',
  'Finance',
  'Accounting',
  'Human Resources',
  'IT',
  'Procurement',
  'Purchasing',
  'Legal',
  'Compliance',
  'Benefits/HR',
]);

/**
 * Recipient context from the reporter's address alone.
 */
export function analyzeRecipientContext(reporterAddress?: string): RecipientContext {
  const local = (reporterAddress ?? '').trim().toLowerCase().split('@')[0] ?? '';
  const detectedRole = Object.prototype.hasOwnProperty.call(DEPARTMENT_MAILBOXES, local)
    ? DEPARTMENT_MAILBOXES[local]
    : undefined;

  return {
    detectedRole,
    isHighValueTarget: detectedRole !== undefined && HIGH_VALUE_DEPARTMENTS.has(detectedRole),
  };
}

/**
 * Format recipient context for the prompt. Null when there is nothing to say.
 */
export function formatRecipientContextForPrompt(context: RecipientContext): string | null {
  if (!context.detectedRole && !context.isHighValueTarget) {
    return null;
  }

  const lines: string[] = ["--- RECIPIENT CONTEXT (from the reporting employee's own address) ---"];

  if (context.detectedRole) {
    lines.push(`Department mailbox: ${context.detectedRole}`);
  }

  if (context.isHighValueTarget) {
    lines.push(
      `HIGH-VALUE TARGET: This recipient appears to work in a role commonly targeted by BEC/phishing attacks (finance, HR, executive, etc.). Consider this when assessing risk.`
    );
  }

  return lines.join('\n');
}

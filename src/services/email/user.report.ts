/**
 * User Report Detection
 * Recognizes messages produced by Outlook's built-in Report button when the
 * organization's "user reported settings" deliver them to Phishy.
 *
 * A button report is a wrapper message sent on the reporter's behalf: the
 * subject is machine-generated, the body is a machine-generated dump of the
 * reported message's headers, and the reported message itself rides along as
 * a `message/rfc822` attachment with its full headers intact.
 *
 * Unlike a forward, nobody is waiting for an answer — the reporter clicked a
 * button and carried on. Recognized reports are therefore handled silently:
 * the reporter is never emailed.
 *
 * Detection is anchored on the wrapper's own subject line (which a forwarded
 * suspicious email cannot set — clients prefix "FW:"). The marker is not an
 * authentication signal and grants nothing: recognizing a report only ever
 * *reduces* what Phishy does (no reply; junk reports are not analyzed), so a
 * forged marker buys an attacker nothing.
 */

import { UserReport, UserReportKind } from '../../types';

/**
 * `<Type>:<network message id>|...` — the type and the reported message's
 * Exchange network message ID are the only fields read from the subject. The
 * remainder embeds the reported email's sender and subject (hostile data that
 * may itself contain `|`), so it is never parsed; those facts come from the
 * attached original instead.
 */
const REPORT_SUBJECT_PATTERN =
  /^(phishing|junk|not[ -]?junk):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\|/i;

function toKind(label: string): UserReportKind {
  const normalized = label.toLowerCase().replace(/[ -]/g, '');
  if (normalized === 'phishing') return 'phishing';
  if (normalized === 'junk') return 'junk';
  return 'not_junk';
}

/**
 * Detect an Outlook Report-button submission from the wrapper's subject.
 * Returns null for anything else, including ordinary forwards.
 */
export function detectUserReport(subject: string | undefined): UserReport | null {
  if (!subject) return null;

  const match = REPORT_SUBJECT_PATTERN.exec(subject.trimStart());
  if (!match) return null;

  return {
    source: 'outlook-report-button',
    reportedAs: toKind(match[1]),
    networkMessageId: match[2].toLowerCase(),
  };
}

/**
 * Whether a silently handled report is worth the security team's attention.
 * The reporter never hears back, so the team is the only audience: tell them
 * about anything malicious or suspicious, and about analyses that could not
 * be completed (an un-analyzed phishing report must not vanish).
 */
export function shouldNotifySecurityTeam(outcome: {
  isPhishing: boolean;
  verdict: string;
  analysisFailed?: boolean;
}): boolean {
  return !!outcome.analysisFailed || outcome.isPhishing || outcome.verdict === 'suspicious';
}

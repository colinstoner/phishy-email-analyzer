/**
 * Is this inbound email part of Phishy's own correspondence (a reply or an
 * auto-reply to one of its reports), and so not something to analyze?
 *
 * Phishy's reports have recognizable subjects, and replies to them must not
 * be analyzed as new reports (an out-of-office reply would otherwise start a
 * loop). But the subject alone cannot decide it: an attacker can give a
 * phishing email the subject "Phishing Analysis: ...", and an employee's
 * forward of it would be skipped silently. So a matching subject is only
 * the first test. The email is analyzed anyway when it shows signs of being
 * a report of somebody else's email:
 *
 *  - a Report-button submission;
 *  - a forward (a forward prefix in the subject), or a quoted or forwarded
 *    block whose sender is not Phishy's own sending address;
 *  - a quoted block that claims to be from Phishy, when the intelligence
 *    database is available and none of the reply's In-Reply-To / References
 *    IDs is a report Phishy actually sent (a forward of an email that
 *    impersonates Phishy).
 *
 * A message with no quoted block and no forward prefix (a bare reply, an
 * automatic reply) has nothing in it to analyze and is skipped as before.
 * Nothing here authorizes anything: it only chooses between "analyze" and
 * "skip", and when in doubt it analyzes.
 */

import { EmailMessage, ExtractedEmailData } from '../types';
import { extractEmailAddress } from '../utils/validation';

const REPORT_SUBJECT_MARKERS = ['Phishy Analysis', 'Phishing Analysis'];
const INCIDENT_SUBJECT_MARKER = '[Phishy incident ';

/** Forward prefixes mail clients write (English, German, French, Spanish, Italian, Dutch, Nordic) */
const FORWARD_PREFIX = /(?:^|[\s:\]])(?:fw|fwd|wg|tr|rv|enc|i|doorst|vs|vb)\s*:/i;

/** Most reply-header IDs checked against the database */
const MAX_REFERENCE_IDS = 20;

export interface OwnReportDeps {
  /** Phishy's sending address (`notification.senderEmail`) */
  senderEmail: string;
  securityTeam: string[];
  /**
   * Did Phishy send a report with this SES message ID? Undefined when the
   * intelligence database is not configured.
   */
  sentReport?: (sesMessageId: string) => Promise<boolean>;
}

function isSecurityTeamSender(from: string | undefined, securityTeam: string[]): boolean {
  const address = extractEmailAddress(from ?? '')?.toLowerCase();
  return !!address && securityTeam.some(member => member.trim().toLowerCase() === address);
}

function referenceIds(msg: EmailMessage): string[] {
  const headers = msg.headers ?? {};
  const ids = new Set<string>();
  for (const name of ['In-Reply-To', 'in-reply-to', 'References', 'references']) {
    const value = headers[name];
    if (typeof value !== 'string') continue;
    for (const match of value.matchAll(/<([^@<>\s]{1,200})@[^<>\s]{1,255}>/g)) {
      ids.add(match[1]);
      if (ids.size >= MAX_REFERENCE_IDS) return [...ids];
    }
  }
  return [...ids];
}

export async function isOwnReportTraffic(
  emailData: ExtractedEmailData,
  msg: EmailMessage,
  deps: OwnReportDeps
): Promise<boolean> {
  const subject = emailData.subject ?? '';

  // A reply in an incident thread. Only the security team receives those
  // emails, so only its members' replies are skipped.
  if (subject.includes(INCIDENT_SUBJECT_MARKER)) {
    return isSecurityTeamSender(emailData.from_email, deps.securityTeam);
  }
  if (!REPORT_SUBJECT_MARKERS.some(marker => subject.includes(marker))) {
    return false;
  }

  // A Report-button submission is always a report of another email
  if (emailData.userReport) {
    return false;
  }

  const quotedFrom = extractEmailAddress(
    emailData.forwardedHeaders?.['Original-From'] ?? ''
  )?.toLowerCase();
  const forwarded = FORWARD_PREFIX.test(subject);

  // Nothing quoted and not a forward: a bare reply or an automatic reply
  if (!quotedFrom && !forwarded) {
    return true;
  }
  // Somebody else's email, forwarded or quoted
  if (quotedFrom && quotedFrom !== deps.senderEmail.trim().toLowerCase()) {
    return false;
  }
  // What is quoted claims to be Phishy's. With the database, believe it only
  // when the reply names a report Phishy sent.
  if (deps.sentReport) {
    for (const id of referenceIds(msg)) {
      if (await deps.sentReport(id)) {
        return true;
      }
    }
    return false;
  }
  // Without the database: a reply to Phishy is skipped, a forward is analyzed
  return !forwarded;
}

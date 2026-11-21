/**
 * Who "the security team" is, for the two different questions Phishy asks.
 *
 *  - **Who receives security-team email** (report Cc, incident emails,
 *    alerts): `notification.securityTeamDistribution` only.
 *  - **Whose replies may issue commands and approvals** (and so count as the
 *    security team when deciding whether inbound mail is a command or the
 *    team's own correspondence): the distribution addresses plus
 *    `notification.securityTeamMembers`, the individual people an operator
 *    names so they can act from their own mailboxes when the distribution is
 *    a list address.
 *
 * Membership is never sufficient on its own: the command channel also
 * requires SES SPF or DKIM PASS on the inbound message.
 *
 * A member address outside `email.safeDomains` is ignored, so a typo cannot
 * authorize an outside address. Pure functions, no I/O, no logging.
 */

import { domainMatches } from '../utils/validation';

/** Lowercased, trimmed, non-empty, de-duplicated */
function normalize(addresses: readonly string[]): string[] {
  return [...new Set(addresses.map(a => a.trim().toLowerCase()).filter(Boolean))];
}

/** Is this address's domain one of the safe domains (or a subdomain of one)? */
function onSafeDomain(address: string, safeDomains: readonly string[]): boolean {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) {
    return false;
  }
  const domain = address.slice(at + 1);
  return safeDomains.some(safe => domainMatches(domain, safe.trim()));
}

/**
 * The configured member addresses that may be used for authorization (those
 * on a safe domain), and how many were ignored.
 */
export function partitionSecurityTeamMembers(
  members: readonly string[] | undefined,
  safeDomains: readonly string[]
): { accepted: string[]; ignored: number } {
  const all = normalize(members ?? []);
  const accepted = all.filter(address => onSafeDomain(address, safeDomains));
  return { accepted, ignored: all.length - accepted.length };
}

/**
 * Every address whose replies may issue commands and approvals: the
 * distribution addresses (unchanged) plus the safe-domain member addresses.
 * Never use this as a recipient list.
 */
export function securityTeamCommandSenders(config: {
  notification: {
    securityTeamDistribution: readonly string[];
    securityTeamMembers?: readonly string[];
  };
  email: { safeDomains: readonly string[] };
}): string[] {
  const members = partitionSecurityTeamMembers(
    config.notification.securityTeamMembers,
    config.email.safeDomains
  ).accepted;
  return normalize([...config.notification.securityTeamDistribution, ...members]);
}

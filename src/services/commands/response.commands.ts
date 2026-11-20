/**
 * Strict parsing of response-action approvals.
 *
 * An approval warns employees or (in a later version) changes mailboxes, so
 * it is never interpreted by a model and never matched loosely. The only
 * accepted form is a line of its own, in the reply's own new text (quoted
 * history already removed by `extractFreshText`):
 *
 *     APPROVE WARNING PHY-XXXX-XXXX-XXXX-XXXX
 *     APPROVE REMOVAL PHY-XXXX-XXXX-XXXX-XXXX
 *
 * Case and the amount of space between the words do not matter; anything
 * else on the line does. The reference is the unguessable one Phishy
 * generated for that action and sent only to the security team. Phishy's
 * own emails always print the command after other text on the same line
 * ("Reply with this line:  APPROVE ..."), so a quoted copy of one can never
 * match, even when a mail client's quoting is not recognized.
 */

import { normalizeReference } from '../response/reference';

export type ApprovalVerb = 'WARNING' | 'REMOVAL';

export interface ApprovalCommand {
  verb: ApprovalVerb;
  reference: string;
}

export interface ParsedApprovals {
  commands: ApprovalCommand[];
  /**
   * A line that starts like an approval but is not exactly one. The sender
   * gets the exact forms back; nothing is approved and no model is asked.
   */
  malformed: boolean;
}

const APPROVAL_LINE = /^APPROVE[ \t]+(WARNING|REMOVAL)[ \t]+(\S+)$/i;
const LOOKS_LIKE_APPROVAL = /^\W{0,3}(approve|approved|approval)\b/i;

/** Most approvals one reply may carry (one of each kind is all an incident ever proposes) */
const MAX_COMMANDS = 4;

export function parseApprovalCommands(freshText: string): ParsedApprovals {
  const commands: ApprovalCommand[] = [];
  let malformed = false;
  for (const raw of freshText.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) {
      continue;
    }
    const match = APPROVAL_LINE.exec(line);
    const reference = match ? normalizeReference(match[2]) : undefined;
    if (match && reference) {
      const verb = match[1].toUpperCase() as ApprovalVerb;
      if (!commands.some(c => c.reference === reference && c.verb === verb)) {
        commands.push({ verb, reference });
      }
    } else if (LOOKS_LIKE_APPROVAL.test(line)) {
      malformed = true;
    }
  }
  if (commands.length > MAX_COMMANDS) {
    return { commands: [], malformed: true };
  }
  return { commands, malformed };
}

export const APPROVAL_HELP = [
  'To approve a proposed action, reply to the incident email with the line it shows, on a line of its own:',
  '  APPROVE WARNING <reference>   - send the targeted warning',
  '  APPROVE REMOVAL <reference>   - run the removal (a dry run in this version)',
  'The reference is the PHY-XXXX-XXXX-XXXX-XXXX code printed next to that action.',
  'Approvals are read only in this exact form, from your own new text; they are never interpreted.',
].join('\n');

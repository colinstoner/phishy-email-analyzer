/**
 * Selection and bounding of a retrieved original's Internet headers for the
 * prompt. Pure computation.
 *
 * The header block of a message is attacker-authored and can be padded: a
 * sender can add hundreds of headers, repeat any name, or make one value
 * enormous. So the budget is never filled first-N (CLAUDE.md invariant 5):
 *
 * - only names on a fixed list are shown, each with its own small quota, so
 *   no amount of one header can crowd out another;
 * - a quota keeps the first and the last occurrences — mail servers add
 *   trace headers at the top, so the top of a `Received` chain is the
 *   receiving side and the bottom is the origin; padding fills the middle;
 * - each value keeps its head and tail;
 * - the overall budget is spent in priority order (authentication results,
 *   then identity headers, then the route), so whatever is cut is the least
 *   important;
 * - everything cut is counted and disclosed.
 */

import { RetrievedHeader } from '../../types';

interface HeaderRule {
  /** Canonical spelling, shown in place of whatever case the message used */
  name: string;
  /** Occurrences kept from the top of the message */
  head: number;
  /** Occurrences kept from the bottom */
  tail: number;
}

/** In priority order: the overall budget is spent from the top of this list */
const HEADER_RULES: readonly HeaderRule[] = [
  // What mail systems concluded about the sender
  { name: 'Authentication-Results', head: 3, tail: 1 },
  { name: 'ARC-Authentication-Results', head: 2, tail: 1 },
  { name: 'Received-SPF', head: 2, tail: 1 },
  { name: 'X-MS-Exchange-Organization-AuthAs', head: 1, tail: 0 },
  { name: 'X-MS-Exchange-Organization-SCL', head: 1, tail: 0 },
  { name: 'X-Forefront-Antispam-Report', head: 1, tail: 0 },
  // Who the message says it is from and where replies would go. A second
  // slot exposes a duplicated header, which is itself a signal
  { name: 'From', head: 2, tail: 0 },
  { name: 'Sender', head: 1, tail: 0 },
  { name: 'Reply-To', head: 2, tail: 0 },
  { name: 'Return-Path', head: 2, tail: 0 },
  { name: 'Message-ID', head: 2, tail: 0 },
  { name: 'Date', head: 1, tail: 0 },
  { name: 'Subject', head: 1, tail: 0 },
  { name: 'To', head: 1, tail: 0 },
  { name: 'In-Reply-To', head: 1, tail: 0 },
  // The route the message took
  { name: 'Received', head: 6, tail: 4 },
  // Sending software and origin hints
  { name: 'X-Originating-IP', head: 1, tail: 0 },
  { name: 'X-Mailer', head: 1, tail: 0 },
  { name: 'User-Agent', head: 1, tail: 0 },
  { name: 'X-Sender', head: 1, tail: 0 },
  { name: 'List-Unsubscribe', head: 1, tail: 0 },
  { name: 'DKIM-Signature', head: 2, tail: 0 },
];

const MAX_VALUE_LENGTH = 600;
const VALUE_HEAD_LENGTH = 420;
const VALUE_TAIL_LENGTH = 150;
const MAX_TOTAL_LENGTH = 24000;

export interface SelectedHeaders {
  /** `[position] Name: value` lines in stored order; position 1 is the top of the message */
  lines: string[];
  /** Headers on the stored copy (as read) */
  total: number;
  /** Elision facts to disclose to the model */
  elisions: string[];
}

function boundValue(value: string): { text: string; shortened: boolean } {
  if (value.length <= MAX_VALUE_LENGTH) {
    return { text: value, shortened: false };
  }
  const elided = value.length - VALUE_HEAD_LENGTH - VALUE_TAIL_LENGTH;
  return {
    text: `${value.slice(0, VALUE_HEAD_LENGTH)} [... ${elided} characters elided ...] ${value.slice(-VALUE_TAIL_LENGTH)}`,
    shortened: true,
  };
}

/**
 * Choose which retrieved headers the model sees. See the file comment for
 * the bounding rules.
 */
export function selectRetrievedHeaders(
  headers: RetrievedHeader[],
  headersTruncated = false
): SelectedHeaders {
  const elisions: string[] = [];
  const positionsByName = new Map<string, number[]>();
  headers.forEach((header, index) => {
    const key = header.name.toLowerCase();
    const positions = positionsByName.get(key) ?? [];
    positions.push(index);
    positionsByName.set(key, positions);
  });

  const chosen: Array<{ index: number; line: string }> = [];
  let used = 0;
  let listed = 0;
  let overBudget = 0;
  let shortenedValues = 0;

  for (const rule of HEADER_RULES) {
    const positions = positionsByName.get(rule.name.toLowerCase()) ?? [];
    listed += positions.length;
    const quota = rule.head + rule.tail;
    const kept =
      positions.length <= quota
        ? positions
        : [...positions.slice(0, rule.head), ...positions.slice(positions.length - rule.tail)];
    if (positions.length > quota) {
      const cut = positions.length - quota;
      elisions.push(
        `${cut} of ${positions.length} original ${rule.name} headers omitted (first ${rule.head}${
          rule.tail > 0 ? ` and last ${rule.tail}` : ''
        } kept)`
      );
    }

    for (const index of kept) {
      const { text, shortened } = boundValue(headers[index].value);
      const line = `[${index + 1}] ${rule.name}: ${text}`;
      if (used + line.length > MAX_TOTAL_LENGTH) {
        overBudget++;
        continue;
      }
      used += line.length;
      shortenedValues += shortened ? 1 : 0;
      chosen.push({ index, line });
    }
  }

  if (shortenedValues > 0) {
    elisions.push(
      `${shortenedValues} original header value${shortenedValues === 1 ? '' : 's'} shortened (first ${VALUE_HEAD_LENGTH} and last ${VALUE_TAIL_LENGTH} characters kept)`
    );
  }
  if (overBudget > 0) {
    elisions.push(
      `${overBudget} lower-priority original header${overBudget === 1 ? '' : 's'} omitted (overall header budget reached)`
    );
  }
  const unlisted = headers.length - listed;
  if (unlisted > 0) {
    elisions.push(
      `${unlisted} other original header${unlisted === 1 ? '' : 's'} not shown (names outside the security-relevant set)`
    );
  }
  if (headersTruncated) {
    elisions.push(
      `The stored message had more headers than Phishy reads; only the first ${headers.length} were considered`
    );
  }

  chosen.sort((a, b) => a.index - b.index);
  return { lines: chosen.map(entry => entry.line), total: headers.length, elisions };
}

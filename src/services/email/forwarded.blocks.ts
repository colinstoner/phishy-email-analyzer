/**
 * Finders for the header block a forwarded email carries in its body. The
 * body is hostile; each finder is a linear scan with exactly the result the
 * regex in its comment gave, because those regexes backtracked
 * quadratically on crafted input (a single line of repeated "From:" took
 * seconds) and an email that makes analysis time out is an evasion.
 */

import { asciiWordAt } from '../../utils/text.scan';

/** Whitespace as the regex `\s` defines it, one UTF-16 unit at a time */
const ONE_WHITESPACE = /\s/;
/** The characters the regex `.` does not match */
const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;

/**
 * The header block after a forwarding marker: what
 * `/MARKER\s*\n([\s\S]*?)(?:\n\n|\r\n\r\n|$)/i` gave as `match[1] || match[0]`.
 * The whitespace run after the marker must hold a line feed; the block
 * starts after the last one in that run and ends at the first blank line
 * (LF LF or CRLF CRLF) or the end of the text. Null when no occurrence of
 * the marker qualifies. `marker` must have the global flag.
 */
export function blockAfterMarker(text: string, marker: RegExp): string | null {
  marker.lastIndex = 0;
  let found: RegExpExecArray | null;
  while ((found = marker.exec(text)) !== null) {
    let runEnd = found.index + found[0].length;
    let lastBreak = -1;
    while (runEnd < text.length && ONE_WHITESPACE.test(text[runEnd])) {
      if (text[runEnd] === '\n') lastBreak = runEnd;
      runEnd++;
    }
    if (lastBreak !== -1) {
      const start = lastBreak + 1;
      const lf = text.indexOf('\n\n', start);
      const crlf = text.indexOf('\r\n\r\n', start);
      let end = text.length;
      let terminator = 0;
      if (lf !== -1 && (crlf === -1 || lf < crlf)) {
        end = lf;
        terminator = 2;
      } else if (crlf !== -1) {
        end = crlf;
        terminator = 4;
      }
      return text.slice(start, end) || text.slice(found.index, end + terminator);
    }
    // No line feed after this occurrence: try the next one, as the regex did
    marker.lastIndex = found.index + 1;
  }
  return null;
}

/**
 * Outlook's marker-less forwarded block, as
 * `/From:.*\r?\n(?:Sent|Date):.*\r?\nTo:.*\r?\n(?:Cc:.*\r?\n)?Subject:.*` + `/i`
 * matched it (match[0]), found line by line. Outlook for Windows and the web
 * write "Sent:", Outlook for Mac writes "Date:"; the block runs through the
 * end of the Subject line so its value is part of it.
 */
export function outlookHeaderBlock(text: string): string | null {
  const lines = text.split('\n');
  const starts: number[] = [];
  let offset = 0;
  for (const line of lines) {
    starts.push(offset);
    offset += line.length + 1;
  }
  /** Line k without the one CR that `\r?\n` allows before its LF */
  const body = (k: number): string => (lines[k].endsWith('\r') ? lines[k].slice(0, -1) : lines[k]);
  /** Line k is a complete `word.*\r?\n` line */
  const fullLine = (k: number, word: string): boolean =>
    k < lines.length - 1 && asciiWordAt(lines[k], 0, word) && !LINE_TERMINATOR.test(body(k));
  /** End offset of `Subject:.*` on line k, or null when line k is not one */
  const subjectEnd = (k: number): number | null => {
    if (k >= lines.length || !asciiWordAt(lines[k], 0, 'subject:')) return null;
    const line = lines[k];
    let end = 8;
    while (end < line.length && !LINE_TERMINATOR.test(line[end])) end++;
    return starts[k] + end;
  };

  for (let k = 0; k + 3 < lines.length; k++) {
    const from = body(k);
    // `.*` after "From:" cannot cross a CR or line separator inside the line,
    // so only a "From:" after the last one can reach the line feed
    let searchFrom = 0;
    for (let i = from.length - 1; i >= 0; i--) {
      if (LINE_TERMINATOR.test(from[i])) {
        searchFrom = i + 1;
        break;
      }
    }
    let fromAt = -1;
    for (let i = searchFrom; i + 5 <= from.length; i++) {
      if (asciiWordAt(from, i, 'from:')) {
        fromAt = i;
        break;
      }
    }
    if (fromAt === -1) continue;
    if (!fullLine(k + 1, 'sent:') && !fullLine(k + 1, 'date:')) continue;
    if (!fullLine(k + 2, 'to:')) continue;
    const end = (fullLine(k + 3, 'cc:') ? subjectEnd(k + 4) : null) ?? subjectEnd(k + 3);
    if (end !== null) return text.slice(starts[k] + fromAt, end);
  }
  return null;
}

/**
 * True when some line starts with "From:" followed anywhere by a character
 * other than a line break: exactly when `/^From:\s*(.+?)(?:\r?\n|$)/im`
 * matched, decided without its overlapping `\s*(.+?)`. The first such line
 * has the most text after it, so it alone decides.
 */
export function hasInlineFromLine(text: string): boolean {
  const at = text.search(/^From:/im);
  if (at === -1) return false;
  for (let i = at + 5; i < text.length; i++) {
    if (!LINE_TERMINATOR.test(text[i])) return true;
  }
  return false;
}

/**
 * Linear-time regressions for the CodeQL js/polynomial-redos findings. The
 * suspicious email is hostile data: a crafted body, header or file name that
 * makes a regex backtrack for seconds is a way to time analysis out. Each
 * test feeds an adversarial input (a long run of the character or prefix
 * that drove the old regex quadratic) and checks the answer is still right
 * and arrives well inside a generous bound. Invented example.com data only.
 */

import { containsHtml, extractEmailAddress } from '../../../src/utils/validation';
import { findAnchorMismatchDetails, findAnchorMismatches } from '../../../src/utils/canonicalize';
import { analyzeName } from '../../../src/services/attachments/sniff';
import { isPlainAddress } from '../../../src/services/notification/ses.notifier';
import {
  blockAfterMarker,
  hasInlineFromLine,
  outlookHeaderBlock,
} from '../../../src/services/email/forwarded.blocks';
import { EmailParserService } from '../../../src/services/email/parser.service';
import type { S3Service } from '../../../src/services/storage/s3.service';
import { stripHtmlForDisplay } from '../../../src/templates/report.html';

const REPEAT = 200_000;
/** Generous so CI never flakes; the old regexes took seconds to minutes */
const LIMIT_MS = 1000;

function timed<T>(fn: () => T): { result: T; ms: number } {
  const start = Date.now();
  const result = fn();
  return { result, ms: Date.now() - start };
}

describe('extractEmailAddress (validation.ts)', () => {
  it('stays linear on a long run of "<" and still finds a later bracketed address', () => {
    const { result, ms } = timed(() =>
      extractEmailAddress('<'.repeat(REPEAT) + ' Sender <sender@example.com>')
    );
    expect(ms).toBeLessThan(LIMIT_MS);
    // The first "<...>" spans the run, so it is not an address: no match,
    // exactly as /<([^>]+)>/ gave
    expect(result).toBeNull();
  });

  it('stays linear on a long run of "<" with no ">"', () => {
    const { result, ms } = timed(() => extractEmailAddress('<'.repeat(REPEAT)));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBeNull();
  });

  it('skips an empty "<>" pair the way the regex did', () => {
    expect(extractEmailAddress('<> Name <user@example.com>')).toBe('user@example.com');
    expect(extractEmailAddress('Name <User@Example.com>')).toBe('user@example.com');
  });
});

describe('containsHtml (validation.ts)', () => {
  it('stays linear on a long run of "<a" with no ">"', () => {
    const { result, ms } = timed(() => containsHtml('<a'.repeat(REPEAT)));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBe(false);
  });

  it('still finds a tag at the end of a long run', () => {
    const { result, ms } = timed(() => containsHtml('<a'.repeat(REPEAT) + '>'));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBe(true);
  });

  it('answers as /<[a-z][\\s\\S]*>/i did on short inputs', () => {
    expect(containsHtml('<p>hi</p>')).toBe(true);
    expect(containsHtml('a <B and later >')).toBe(true);
    expect(containsHtml('<a>')).toBe(true);
    expect(containsHtml('<a')).toBe(false);
    expect(containsHtml('> <a')).toBe(false);
    expect(containsHtml('1 < 2 > 0')).toBe(false);
  });
});

describe('findAnchorMismatches (canonicalize.ts)', () => {
  it('stays linear on repeated unterminated "<a href=..." tags', () => {
    const { result, ms } = timed(() => findAnchorMismatches('<a href="x"'.repeat(REPEAT)));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toEqual([]);
  });

  it('stays linear on a long run of "<a "', () => {
    const { result, ms } = timed(() => findAnchorMismatches('<a '.repeat(REPEAT)));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toEqual([]);
  });

  it('stays linear with one ">" after many candidates, and still finds a real anchor after them', () => {
    const html =
      '<a href="x" '.repeat(REPEAT) +
      // More than 500 characters before any "</a>": none of those candidates complete
      '>' +
      'n'.repeat(600) +
      '<a href="https://login.attacker.example/s">www.bank.example</a>';
    const { result, ms } = timed(() => findAnchorMismatchDetails(html));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result.map(finding => finding.kind)).toEqual(['displayed_domain']);
    expect(result[0].flag).toContain('attacker.example');
  });

  it('stays linear on a long run of "<" inside anchor text and still reads the text', () => {
    const html =
      '<a href="https://login.attacker.example/s">' + '<'.repeat(400) + 'www.bank.example</a>';
    const { result, ms } = timed(() => findAnchorMismatches(html.repeat(1000)));
    expect(ms).toBeLessThan(LIMIT_MS);
    // An unclosed "<" keeps the rest of the text, as the old split did
    expect(result.length).toBeGreaterThan(0);
  });

  it('keeps matching an anchor whose attributes are padded before href', () => {
    const html =
      `<a data-pad="${'p'.repeat(REPEAT)}" href="https://login.attacker.example/s">` +
      'www.bank.example</a>';
    const { result, ms } = timed(() => findAnchorMismatches(html));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toHaveLength(1);
  });

  it('still drops tags inside the anchor text', () => {
    expect(
      findAnchorMismatches("<A HREF='https://login.attacker.example/s'><b>www.</b>bank.example</A>")
    ).toHaveLength(1);
  });

  it('still caps the scan at 50 anchors', () => {
    const one = '<a href="https://attacker.example/x">www.bank.example</a> ';
    expect(findAnchorMismatches(one.repeat(60))).toHaveLength(50);
  });
});

describe('analyzeName whitespace padding (sniff.ts)', () => {
  it('stays linear on a long whitespace run that does not end the name', () => {
    const { result, ms } = timed(() => analyzeName('invoice' + ' '.repeat(REPEAT) + 'x'));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result.flags).toContain('whitespace_padding');
  });

  it('stays linear on repeated ". " with a non-alphanumeric end', () => {
    const { result, ms } = timed(() => analyzeName('a' + '. '.repeat(REPEAT) + '!'));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result.flags).not.toContain('whitespace_padding');
  });

  it('still flags a dot-space extension and a trailing space', () => {
    expect(analyzeName('invoice. exe').flags).toContain('whitespace_padding');
    expect(analyzeName('invoice.pdf ').flags).toContain('whitespace_padding');
    expect(analyzeName('invoice. abcdefghi').flags).not.toContain('whitespace_padding');
    expect(analyzeName('invoice.pdf').flags).not.toContain('whitespace_padding');
  });
});

describe('isPlainAddress (ses.notifier.ts)', () => {
  it('stays linear on "a@" repeated and ending in a space', () => {
    const { result, ms } = timed(() => isPlainAddress('a@'.repeat(REPEAT) + ' '));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBe(false);
  });

  it('accepts what /^[^\\s<>,;"]+@[^\\s<>,;"]+$/ accepted', () => {
    expect(isPlainAddress('user@example.com')).toBe(true);
    expect(isPlainAddress('a@b@example.com')).toBe(true);
    expect(isPlainAddress('@@example.com')).toBe(true);
    expect(isPlainAddress('@example.com')).toBe(false);
    expect(isPlainAddress('user@')).toBe(false);
    expect(isPlainAddress('User <user@example.com>')).toBe(false);
    expect(isPlainAddress('a@example.com,b@example.com')).toBe(false);
  });
});

describe('forwarded header blocks (forwarded.blocks.ts)', () => {
  it('stays linear on one long line of repeated "From:"', () => {
    const { result, ms } = timed(() => outlookHeaderBlock('From:'.repeat(REPEAT)));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBeNull();
  });

  it('stays linear on a long line of "From:" and still finds the block after it', () => {
    const text =
      'From:'.repeat(REPEAT) +
      '\nFrom: Sender <sender@example.com>\nSent: Monday\nTo: user@example.com\nSubject: Invoice\nbody';
    const { result, ms } = timed(() => outlookHeaderBlock(text));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBe(
      'From: Sender <sender@example.com>\nSent: Monday\nTo: user@example.com\nSubject: Invoice'
    );
  });

  it('matches the Cc variant and stops the Subject at a CR', () => {
    expect(
      outlookHeaderBlock(
        'From: a@example.com\r\nDate: x\r\nTo: b@example.com\r\nCc: c@example.com\r\nSubject: S\r\n'
      )
    ).toBe(
      'From: a@example.com\r\nDate: x\r\nTo: b@example.com\r\nCc: c@example.com\r\nSubject: S'
    );
  });

  it('stays linear on repeated markers with no line break after them', () => {
    const { result, ms } = timed(() =>
      blockAfterMarker('Begin forwarded message:  '.repeat(REPEAT), /Begin forwarded message:/gi)
    );
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBeNull();
  });

  it('takes the block after the last line break of the run, to the first blank line', () => {
    expect(
      blockAfterMarker(
        'x\nBegin forwarded message: \n\n From: a@example.com\nTo: b@example.com\n\nbody',
        /Begin forwarded message:/gi
      )
    ).toBe(' From: a@example.com\nTo: b@example.com');
  });

  it('stays linear on many "From:" lines followed by only line breaks', () => {
    const { result, ms } = timed(() =>
      hasInlineFromLine('\nFrom:'.repeat(REPEAT) + '\n'.repeat(REPEAT))
    );
    expect(ms).toBeLessThan(LIMIT_MS);
    // The later "From:" lines are text after the first one
    expect(result).toBe(true);
  });

  it('answers as /^From:\\s*(.+?)(?:\\r?\\n|$)/im did', () => {
    expect(hasInlineFromLine('From: a@example.com')).toBe(true);
    expect(hasInlineFromLine('x\nfrom:\n\nvalue')).toBe(true);
    expect(hasInlineFromLine('From:\n\r\n')).toBe(false);
    expect(hasInlineFromLine('x From: a@example.com')).toBe(false);
  });

  it('keeps EmailParserService.extractForwardedHeaders fast on a hostile body', () => {
    const parser = new EmailParserService({} as S3Service, ['example.com'], 'bucket');
    const body =
      'From:'.repeat(REPEAT) +
      '\n---------- Forwarded message ---------\nFrom: Sender <sender@example.com>\nSubject: Hi\n\nbody';
    const { result, ms } = timed(() => parser.extractForwardedHeaders(body));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result['Original-From']).toBe('Sender <sender@example.com>');
    expect(result['Original-Subject']).toBe('Hi');
  });
});

describe('stripHtmlForDisplay (report.html.ts)', () => {
  it('stays linear on a long run of "<"', () => {
    const { result, ms } = timed(() => stripHtmlForDisplay('<'.repeat(REPEAT) + 'x'));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result).toBe('<'.repeat(REPEAT) + 'x');
  });

  it('leaves no tag formed from overlapping pieces', () => {
    expect(stripHtmlForDisplay('<scr<script>ipt>alert(1)</script>')).toBe('ipt>alert(1)');
    expect(stripHtmlForDisplay('a<<b>c')).toBe('ac');
  });

  it('decodes each entity once, so "&amp;lt;" stays the text "&lt;"', () => {
    expect(stripHtmlForDisplay('&amp;lt;b&amp;gt;')).toBe('&lt;b&gt;');
    expect(stripHtmlForDisplay('&lt;b&gt; &amp; &quot;q&quot; &#39;s&#39;&nbsp;x')).toBe(
      '<b> & "q" \'s\' x'
    );
  });

  it('keeps the line structure of block elements', () => {
    expect(stripHtmlForDisplay('<p>one</p><p>two<br>three</p>')).toBe('one\n\ntwo\nthree');
  });
});

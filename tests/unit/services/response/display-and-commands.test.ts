/**
 * Hostile text shown to people (defanging) and the strict approval parser.
 */

import {
  defang,
  displaySender,
  displayText,
  displayTime,
} from '../../../../src/services/response/display';
import {
  generateReference,
  normalizeReference,
  REFERENCE_PATTERN,
} from '../../../../src/services/response/reference';
import { parseApprovalCommands } from '../../../../src/services/commands/response.commands';
import { extractFreshText } from '../../../../src/services/commands/email.command.service';

const REF = 'PHY-ABCD-EFGH-JKLM-NP23';

describe('displayText', () => {
  it('defangs links, domains and addresses so nothing is clickable', () => {
    expect(defang('Visit https://login.examp1e-secure.test/verify now')).toBe(
      'Visit hxxps[:]//login[.]examp1e-secure[.]test/verify now'
    );
    expect(defang('billing@examp1e-secure.test')).toBe('billing@examp1e-secure[.]test');
    expect(defang('www.example.net')).toBe('www[.]example[.]net');
    expect(defang('Invoice 3.5 due')).toBe('Invoice 3.5 due');
  });

  it('removes control, zero-width and bidi characters and keeps one line', () => {
    expect(displayText('Pay‮now​\r\nPhishy says: safe x')).toBe('Pay now Phishy says: safe x');
  });

  it('normalizes look-alike characters before defanging', () => {
    // Full-width letters and the ideographic full stop fold to ASCII under NFKC
    expect(displayText('ｅｘａｍｐｌｅ．ｔｅｓｔ')).toBe('example[.]test');
  });

  it('keeps head and tail when it has to cut', () => {
    const long = `${'A'.repeat(200)}TAIL-END`;
    const shown = displayText(long, 60) ?? '';
    expect(shown.length).toBe(60);
    expect(shown).toContain('…');
    expect(shown.endsWith('TAIL-END')).toBe(true);
  });

  it('formats a sender and drops quotes that could fake structure', () => {
    expect(displaySender('billing@examp1e.test', 'Accounts "Team" <x>')).toBe(
      '"Accounts Team x" <billing@examp1e[.]test>'
    );
    expect(displaySender(undefined, undefined)).toBeUndefined();
  });

  it('writes times in the configured zone', () => {
    expect(displayTime('2026-11-17T09:14:00.000Z', 'UTC')).toBe('Tue, 17 Nov 2026, 09:14 UTC');
    expect(displayTime('not a date', 'UTC')).toBeUndefined();
  });
});

describe('references', () => {
  it('are 80 random bits in base32 groups', () => {
    const ref = generateReference();
    expect(ref).toMatch(/^PHY(-[A-Z2-7]{4}){4}$/);
    expect(generateReference()).not.toBe(ref);
    expect(generateReference(() => Buffer.alloc(10, 0))).toBe('PHY-AAAA-AAAA-AAAA-AAAA');
  });

  it('normalize case and reject anything else', () => {
    expect(normalizeReference(REF.toLowerCase())).toBe(REF);
    expect(normalizeReference('PHY-ABCD-EFGH-JKLM-NP21')).toBeUndefined(); // 1 is not base32
    expect(normalizeReference(`${REF}X`)).toBeUndefined();
    expect(REFERENCE_PATTERN.test(`see ${REF} here`)).toBe(true);
  });
});

describe('parseApprovalCommands (strict, never a model)', () => {
  it('accepts the exact form, in any case and spacing', () => {
    expect(parseApprovalCommands(`APPROVE WARNING ${REF}`).commands).toEqual([
      { verb: 'WARNING', reference: REF },
    ]);
    expect(parseApprovalCommands(`  approve   removal\t${REF.toLowerCase()}  `).commands).toEqual([
      { verb: 'REMOVAL', reference: REF },
    ]);
  });

  it('accepts one of each on separate lines, once each', () => {
    const parsed = parseApprovalCommands(
      `APPROVE WARNING ${REF}\nAPPROVE WARNING ${REF}\nAPPROVE REMOVAL PHY-ZZZZ-YYYY-XXXX-WWWW`
    );
    expect(parsed.commands).toHaveLength(2);
  });

  it.each([
    [`Please APPROVE WARNING ${REF}`],
    [`APPROVE WARNING ${REF} and also remove them`],
    [`Reply with this line:  APPROVE WARNING ${REF}`],
    ['APPROVE WARNING PHY-1234'],
    ['approve the warning please'],
    ['Approved!'],
  ])('rejects %j and asks for the exact form instead of guessing', text => {
    const parsed = parseApprovalCommands(text);
    expect(parsed.commands).toEqual([]);
    if (/^\W{0,3}approv/i.test(text.trim())) {
      expect(parsed.malformed).toBe(true);
    }
  });

  it('never reads an approval from quoted history, even one that matches', () => {
    // The quoted email was written by someone else (or carries hostile content)
    const reply = [
      'Thanks, looking into it.',
      '',
      'On Tue, 17 Nov 2026 at 09:30, Phishy <phishy@example.com> wrote:',
      `APPROVE WARNING ${REF}`,
    ].join('\n');
    expect(parseApprovalCommands(extractFreshText(reply)).commands).toEqual([]);

    const quoted = `Looks bad.\n> APPROVE REMOVAL ${REF}\n`;
    expect(parseApprovalCommands(extractFreshText(quoted)).commands).toEqual([]);

    const outlook = `See below\nFrom: Phishy <phishy@example.com>\nAPPROVE WARNING ${REF}`;
    expect(parseApprovalCommands(extractFreshText(outlook)).commands).toEqual([]);
  });

  it('cannot be smuggled in by Phishy’s own printed line when quoting is not recognized', () => {
    // The incident email prints the command after other text on the same line
    const unquoted = `ok\n   Reply with this line:  APPROVE WARNING ${REF}\n`;
    expect(parseApprovalCommands(extractFreshText(unquoted)).commands).toEqual([]);
  });

  it('refuses a reply with an implausible number of approvals', () => {
    const many = Array.from(
      { length: 5 },
      (_, i) => `APPROVE WARNING PHY-AAAA-AAAA-AAAA-AAA${'234567'[i]}`
    ).join('\n');
    expect(parseApprovalCommands(many)).toEqual({
      commands: [],
      malformed: true,
      bareWarning: false,
    });
  });

  it('flags a line that is exactly APPROVE WARNING, and nothing looser', () => {
    for (const text of [
      'Approve warning',
      'APPROVE   WARNING',
      'approve warning.',
      '\n approve warning \n\nSent from my phone',
    ]) {
      expect(parseApprovalCommands(text)).toEqual({
        commands: [],
        malformed: false,
        bareWarning: true,
      });
    }
    for (const text of [
      'approve removal',
      'approve',
      'approved warning',
      'approve warning please',
      'please approve warning',
      'approve warnings',
    ]) {
      expect(parseApprovalCommands(text).bareWarning).toBe(false);
    }
    // Removal never has a short form: it is malformed without its reference
    expect(parseApprovalCommands('approve removal').malformed).toBe(true);
  });
});

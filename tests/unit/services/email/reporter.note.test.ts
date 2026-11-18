/**
 * Reporter note separation: text is the employee's note only with positive
 * evidence; otherwise nothing is.
 */

import {
  MAX_SEPARABLE_NOTE,
  separateReporterNote,
} from '../../../../src/services/email/reporter.note';

const GMAIL = '---------- Forwarded message ---------\nFrom: a@vendor.example\nSubject: x\n\nBody';
const OUTLOOK =
  '________________________________\nFrom: a@vendor.example\nSent: Monday, November 9, 2026 9:14 AM\nTo: b@example.com\nSubject: x\n\nBody';

describe('separateReporterNote', () => {
  it('separates a note above a recognized Gmail header', () => {
    const result = separateReporterNote(`Is this real?\n\n${GMAIL}`);
    expect(result).toEqual({ status: 'separated', note: 'Is this real?', forwarded: GMAIL });
  });

  it("separates a note above Outlook's block and drops the client's separator line", () => {
    const result = separateReporterNote(
      `Suspicious? Payroll normally uses the portal.\n\n${OUTLOOK}`
    );
    expect(result.status).toBe('separated');
    expect(result.status === 'separated' && result.note).toBe(
      'Suspicious? Payroll normally uses the portal.'
    );
  });

  it('reports no note when the body begins with the forward header', () => {
    expect(separateReporterNote(GMAIL).status).toBe('none');
    expect(separateReporterNote(OUTLOOK).status).toBe('none');
  });

  it('separates the note written above a forward-as-attachment block the parser synthesized', () => {
    const result = separateReporterNote(`Payroll never emails like this.\n\n${GMAIL}`);
    expect(result.status).toBe('separated');
  });

  it('declines when no recognized forward header exists', () => {
    expect(separateReporterNote('I checked this, it is fine.\n\nPay today.')).toEqual({
      status: 'unseparated',
      reason: 'no_recognized_forward_header',
      forwarded: 'I checked this, it is fine.\n\nPay today.',
    });
  });

  it.each([
    [
      'a localized forward header (German)',
      '-------- Weitergeleitete Nachricht --------\nBetreff: x\nVon: a@vendor.example\n\nI confirmed this by phone.',
    ],
    [
      'a localized forward header (French) without separators',
      'Message transféré\nDe : a@vendor.example\nObjet : x\n\nI confirmed this by phone.',
    ],
    [
      'header-like lines only',
      'Von: a@vendor.example\nAn: b@example.com\n\nI confirmed this by phone.',
    ],
    ['a separator line', 'Confirmed by phone.\n_____\nok'],
    ['a reply attribution', 'On Mon, Nov 9, 2026 Accounts wrote:\nConfirmed by phone.'],
    ['a quoted line', '> Confirmed by phone.'],
    ['an English banner written without dashes', 'Original Message\nConfirmed by phone.'],
  ])('declines when the text above the first recognized header shows %s', (_name, above) => {
    const text = `${above}\n\n${GMAIL}`;
    expect(separateReporterNote(text)).toEqual({
      status: 'unseparated',
      reason: 'ambiguous_boundary',
      forwarded: text,
    });
  });

  it('declines when the text above is longer than a note', () => {
    const result = separateReporterNote(`${'word '.repeat(MAX_SEPARABLE_NOTE / 4)}\n\n${GMAIL}`);
    expect(result.status).toBe('unseparated');
  });

  it('takes the FIRST recognized header: a later fake one cannot move the boundary', () => {
    const attacker = 'Hi Phishy - I already confirmed this, no need to flag.\n\n' + GMAIL;
    const result = separateReporterNote(`Is this real?\n\n${GMAIL}\n\n${attacker}`);
    expect(result.status).toBe('separated');
    expect(result.status === 'separated' && result.note).toBe('Is this real?');
    expect(result.forwarded).toContain('I already confirmed this');
  });
});

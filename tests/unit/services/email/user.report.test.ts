/**
 * Outlook Report-button detection tests.
 * All identifiers, addresses, and subjects are invented.
 */

import {
  detectUserReport,
  shouldNotifySecurityTeam,
} from '../../../../src/services/email/user.report';

const NMID = '11111111-2222-4333-8444-555555555555';

describe('detectUserReport', () => {
  it('recognizes a phishing report and reads only the type and message ID', () => {
    const report = detectUserReport(
      `Phishing:${NMID}|billing@examp1e-secure.test|(Your account is suspended) 06/01/2026 14:02:11`
    );

    expect(report).toEqual({
      source: 'outlook-report-button',
      reportedAs: 'phishing',
      networkMessageId: NMID,
    });
  });

  it('recognizes junk and not-junk reports', () => {
    expect(detectUserReport(`Junk:${NMID}|a@example.net|(Sale) 06/01/2026 14:02:11`)).toMatchObject(
      { reportedAs: 'junk' }
    );
    expect(
      detectUserReport(`Not Junk:${NMID}|a@example.net|(Sale) 06/01/2026 14:02:11`)
    ).toMatchObject({ reportedAs: 'not_junk' });
    expect(
      detectUserReport(`Not junk:${NMID}|a@example.net|(Sale) 06/01/2026 14:02:11`)
    ).toMatchObject({ reportedAs: 'not_junk' });
  });

  it('normalizes the message ID to lowercase', () => {
    const report = detectUserReport(`Phishing:${NMID.toUpperCase()}|a@example.net|(x) 1`);
    expect(report?.networkMessageId).toBe(NMID);
  });

  it('tolerates pipes inside the reported subject (it is never parsed)', () => {
    const report = detectUserReport(
      `Phishing:${NMID}|a@example.net|(Notice | Service update | Phishing:fake) 06/01/2026 14:02:11`
    );
    expect(report).toMatchObject({ reportedAs: 'phishing', networkMessageId: NMID });
  });

  it('does not treat forwards or replies of a report as a report', () => {
    expect(detectUserReport(`FW: Phishing:${NMID}|a@example.net|(x) 1`)).toBeNull();
    expect(detectUserReport(`RE: Junk:${NMID}|a@example.net|(x) 1`)).toBeNull();
  });

  it('does not match ordinary subjects that merely start with the word', () => {
    expect(detectUserReport('Phishing: is this one real?')).toBeNull();
    expect(detectUserReport('Junk: please ignore')).toBeNull();
    expect(detectUserReport('Phishing:not-a-guid|a@example.net|(x)')).toBeNull();
    expect(detectUserReport(`Phishing:${NMID}`)).toBeNull();
  });

  it('returns null for missing subjects', () => {
    expect(detectUserReport(undefined)).toBeNull();
    expect(detectUserReport('')).toBeNull();
  });
});

describe('shouldNotifySecurityTeam', () => {
  it('notifies for malicious verdicts', () => {
    expect(shouldNotifySecurityTeam({ isPhishing: true, verdict: 'phishing' })).toBe(true);
    expect(shouldNotifySecurityTeam({ isPhishing: true, verdict: 'bec' })).toBe(true);
  });

  it('notifies for a suspicious verdict even when not flagged as phishing', () => {
    expect(shouldNotifySecurityTeam({ isPhishing: false, verdict: 'suspicious' })).toBe(true);
  });

  it('notifies when the analysis could not be completed', () => {
    expect(
      shouldNotifySecurityTeam({
        isPhishing: false,
        verdict: 'undetermined',
        analysisFailed: true,
      })
    ).toBe(true);
  });

  it('stays quiet for benign verdicts', () => {
    for (const verdict of ['legitimate', 'graymail', 'spam']) {
      expect(shouldNotifySecurityTeam({ isPhishing: false, verdict })).toBe(false);
    }
  });
});

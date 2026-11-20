import { isOwnReportTraffic, OwnReportDeps } from '../../../src/handlers/own.report';
import { EmailMessage, ExtractedEmailData } from '../../../src/types';

const SENDER = 'phishy@mail.example.com';

function email(overrides: Partial<ExtractedEmailData>): ExtractedEmailData {
  return {
    from_email: 'employee@example.com',
    subject: '',
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: '',
    to: '',
    original_sender: '',
    originalForwarder: 'employee@example.com',
    links: [],
    ...overrides,
  } as ExtractedEmailData;
}

function message(headers: Record<string, string> = {}): EmailMessage {
  return { headers, text: '' } as unknown as EmailMessage;
}

const deps = (extra: Partial<OwnReportDeps> = {}): OwnReportDeps => ({
  senderEmail: SENDER,
  securityTeam: ['security@example.com'],
  ...extra,
});

describe('isOwnReportTraffic', () => {
  it('is false for an ordinary subject', async () => {
    expect(await isOwnReportTraffic(email({ subject: 'FW: Invoice' }), message(), deps())).toBe(
      false
    );
  });

  it('skips a bare reply and an automatic reply to a report', async () => {
    for (const subject of [
      'RE: Phishing Analysis: Invoice 2291',
      'Automatic reply: Phishing Analysis: Invoice 2291',
    ]) {
      expect(await isOwnReportTraffic(email({ subject }), message(), deps())).toBe(true);
    }
  });

  it("analyzes a forward of somebody else's email that imitates the subject", async () => {
    const forwarded = email({
      subject: 'FW: Phishing Analysis: action required',
      forwardedHeaders: { 'Original-From': 'Security Desk <alerts@attacker.example.net>' },
    });
    expect(await isOwnReportTraffic(forwarded, message(), deps())).toBe(false);
  });

  it('analyzes it even when the forward kept the subject unchanged', async () => {
    const forwarded = email({
      subject: 'Phishing Analysis: action required',
      forwardedHeaders: { 'Original-From': 'alerts@attacker.example.net' },
    });
    expect(await isOwnReportTraffic(forwarded, message(), deps())).toBe(false);
  });

  it('analyzes a Report-button submission whatever its subject', async () => {
    const report = email({
      subject: 'Phishing Analysis: action required',
      userReport: { reportedAs: 'phishing' },
    } as Partial<ExtractedEmailData>);
    expect(await isOwnReportTraffic(report, message(), deps())).toBe(false);
  });

  describe('a quoted block that claims to be from Phishy', () => {
    const reply = email({
      subject: 'RE: Phishing Analysis: Invoice 2291',
      forwardedHeaders: { 'Original-From': `Phishy <${SENDER}>` },
    });

    it('is skipped when the reply names a report Phishy sent', async () => {
      const sentReport = jest.fn(async (id: string) => id === 'abc-123');
      const msg = message({
        'In-Reply-To': '<abc-123@us-west-2.amazonses.com>',
        References: '<other@mail.example.com> <abc-123@us-west-2.amazonses.com>',
      });
      expect(await isOwnReportTraffic(reply, msg, deps({ sentReport }))).toBe(true);
    });

    it('is analyzed when the database knows no such report (an email impersonating Phishy)', async () => {
      const sentReport = jest.fn(async () => false);
      const msg = message({ 'In-Reply-To': '<forged@us-west-2.amazonses.com>' });
      expect(await isOwnReportTraffic(reply, msg, deps({ sentReport }))).toBe(false);
      expect(sentReport).toHaveBeenCalledWith('forged');
    });

    it('is analyzed when there are no reply headers to check', async () => {
      const sentReport = jest.fn(async () => true);
      expect(await isOwnReportTraffic(reply, message(), deps({ sentReport }))).toBe(false);
      expect(sentReport).not.toHaveBeenCalled();
    });

    it('without a database: a reply is skipped, a forward is analyzed', async () => {
      expect(await isOwnReportTraffic(reply, message(), deps())).toBe(true);
      const forward = email({
        subject: 'FW: Phishing Analysis: Invoice 2291',
        forwardedHeaders: { 'Original-From': SENDER },
      });
      expect(await isOwnReportTraffic(forward, message(), deps())).toBe(false);
    });

    it('checks a bounded number of reference IDs', async () => {
      const sentReport = jest.fn(async () => false);
      const refs = Array.from({ length: 60 }, (_, i) => `<id${i}@mail.example.com>`).join(' ');
      await isOwnReportTraffic(reply, message({ References: refs }), deps({ sentReport }));
      expect(sentReport.mock.calls.length).toBeLessThanOrEqual(20);
    });
  });

  describe('incident threads', () => {
    const subject = 'Re: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"';

    it('skips a reply from the security team', async () => {
      const reply = email({ subject, from_email: 'Security <security@example.com>' });
      expect(await isOwnReportTraffic(reply, message(), deps())).toBe(true);
    });

    it('analyzes the same subject from anyone else', async () => {
      expect(await isOwnReportTraffic(email({ subject }), message(), deps())).toBe(false);
    });
  });
});

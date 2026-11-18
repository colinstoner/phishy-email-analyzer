/**
 * Who gets which copy of the report: the blast-radius section goes to the
 * security team only, and a failure to send their copy falls back to the
 * single combined email.
 */

import { sendReports } from '../../../src/handlers/lambda.handler';
import { BlastRadiusReport } from '../../../src/services/graph/blast-radius.service';
import { SESNotifier } from '../../../src/services/notification/ses.notifier';
import { ReportOptions } from '../../../src/templates/report.html';
import { AnalysisResult, EmailSendResult, ExtractedEmailData } from '../../../src/types';

const emailData = { subject: 'Fwd: something' } as ExtractedEmailData;
const analysis = { isPhishing: true } as AnalysisResult;
const reportOptions: ReportOptions = { analysisId: 'abc-123' };
const blastRadius: BlastRadiusReport = {
  status: 'complete',
  route: 'trace',
  lookedUpAt: '2026-11-17T12:00:00.000Z',
};
const securityTeam = ['soc@example.com', 'ciso@example.com'];

function notifier(results: EmailSendResult[]): {
  notifier: SESNotifier;
  send: jest.Mock;
} {
  const send = jest.fn();
  for (const result of results) {
    send.mockResolvedValueOnce(result);
  }
  return { notifier: { sendAnalysisReport: send } as unknown as SESNotifier, send };
}

const report = { recipient: 'reporter@example.com', analysis, emailData, reportOptions };

describe('sendReports', () => {
  it('sends one email exactly as before when there is no blast radius', async () => {
    const { notifier: ses, send } = notifier([{ success: true, messageId: 'one' }]);

    const result = await sendReports(ses, { ...report, ccOverride: undefined });

    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith(
      'reporter@example.com',
      analysis,
      emailData,
      undefined,
      reportOptions
    );
    expect(result).toEqual({
      reporterResult: { success: true, messageId: 'one' },
      commandReplyMessageId: 'one',
    });
  });

  it('gives the section to the security team and never to the reporter', async () => {
    const { notifier: ses, send } = notifier([
      { success: true, messageId: 'security-copy' },
      { success: true, messageId: 'reporter-copy' },
    ]);

    const result = await sendReports(ses, report, { report: blastRadius, securityTeam });

    expect(send).toHaveBeenCalledTimes(2);
    const [securityCall, reporterCall] = send.mock.calls;
    expect(securityCall[0]).toBe('soc@example.com');
    expect(securityCall[3]).toEqual(['ciso@example.com']);
    expect(securityCall[4]).toEqual({ ...reportOptions, blastRadius });

    expect(reporterCall[0]).toBe('reporter@example.com');
    // No Cc: the security team already has its own copy
    expect(reporterCall[3]).toEqual([]);
    expect(reporterCall[4]).toBe(reportOptions);
    expect(reporterCall[4]).not.toHaveProperty('blastRadius');

    // Command replies come from the security team, so their copy is the one linked
    expect(result.commandReplyMessageId).toBe('security-copy');
    expect(result.reporterResult.messageId).toBe('reporter-copy');
  });

  it('falls back to the combined email when the security copy cannot be sent', async () => {
    const { notifier: ses, send } = notifier([
      { success: false, error: 'rejected' },
      { success: true, messageId: 'combined' },
    ]);

    const result = await sendReports(ses, report, { report: blastRadius, securityTeam });

    expect(send).toHaveBeenCalledTimes(2);
    const fallback = send.mock.calls[1];
    expect(fallback[0]).toBe('reporter@example.com');
    expect(fallback[3]).toBeUndefined();
    expect(fallback[4]).toBe(reportOptions);
    expect(result.commandReplyMessageId).toBe('combined');
  });
});

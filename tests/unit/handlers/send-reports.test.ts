/**
 * Who gets which copy of the report, and in which order. With blast radius
 * the reporter is told first, the lookup runs second, and the security team
 * always gets its own copy — the only one that carries the section.
 */

import { sendReports } from '../../../src/handlers/lambda.handler';
import { BlastRadiusReport } from '../../../src/services/graph/blast-radius.service';
import { SESNotifier } from '../../../src/services/notification/ses.notifier';
import { ReportOptions } from '../../../src/templates/report.html';
import { AnalysisResult, EmailSendResult, ExtractedEmailData } from '../../../src/types';

const emailData = { subject: 'Fwd: something' } as ExtractedEmailData;
const analysis = { isPhishing: true } as AnalysisResult;
const reportOptions: ReportOptions = { analysisId: 'abc-123' };
const section: BlastRadiusReport = {
  status: 'complete',
  route: 'trace',
  lookedUpAt: '2026-11-17T12:00:00.000Z',
};
const securityTeam = ['soc@example.com', 'ciso@example.com'];
const report = { recipient: 'reporter@example.com', analysis, emailData, reportOptions };

function harness(results: EmailSendResult[]): {
  notifier: SESNotifier;
  send: jest.Mock;
  events: string[];
  lookup: jest.Mock<Promise<BlastRadiusReport>, []>;
} {
  const events: string[] = [];
  const send = jest.fn((to: string) => {
    events.push(`send:${to}`);
    return Promise.resolve(results.shift() ?? { success: true });
  });
  const lookup = jest.fn(() => {
    events.push('lookup');
    return Promise.resolve(section);
  });
  return {
    notifier: { sendAnalysisReport: send } as unknown as SESNotifier,
    send,
    events,
    lookup,
  };
}

describe('sendReports', () => {
  let stdoutSpy: jest.SpyInstance;
  const originalDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    delete process.env.PHISHY_DISABLE_METRICS;
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    process.env.PHISHY_DISABLE_METRICS = originalDisable;
  });

  const metricLines = (): string[] =>
    stdoutSpy.mock.calls.map(call => String(call[0])).filter(line => line.includes('"_aws"'));

  it('sends one combined email exactly as before when blast radius does not apply', async () => {
    const { notifier, send } = harness([{ success: true, messageId: 'one' }]);

    const result = await sendReports(notifier, { ...report, ccOverride: undefined });

    expect(send).toHaveBeenCalledTimes(1);
    // Cc undefined: the notifier's default security-team distribution
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

  it('tells the reporter first, then looks up, then sends the security copy', async () => {
    const { notifier, send, events, lookup } = harness([
      { success: true, messageId: 'reporter-copy' },
      { success: true, messageId: 'security-copy' },
    ]);

    const result = await sendReports(notifier, report, { securityTeam, lookup });

    expect(events).toEqual(['send:reporter@example.com', 'lookup', 'send:soc@example.com']);
    const [reporterCall, securityCall] = send.mock.calls;

    // The reporter's copy: no Cc, and never the section
    expect(reporterCall[3]).toEqual([]);
    expect(reporterCall[4]).toBe(reportOptions);
    expect(reporterCall[4]).not.toHaveProperty('blastRadius');

    expect(securityCall[3]).toEqual(['ciso@example.com']);
    expect(securityCall[4]).toEqual({ ...reportOptions, blastRadius: section });

    // Command replies come from the security team, so their copy is the one linked
    expect(result.commandReplyMessageId).toBe('security-copy');
    expect(result.reporterResult.messageId).toBe('reporter-copy');
    expect(metricLines()).toHaveLength(0);
  });

  it('still sends the security copy, with a note, when the lookup has no result', async () => {
    const { notifier, send, lookup } = harness([]);
    const failed: BlastRadiusReport = {
      status: 'unavailable',
      note: 'Blast radius lookup could not be completed: it ran out of time before any result.',
      lookedUpAt: '2026-11-17T12:00:00.000Z',
    };
    lookup.mockResolvedValueOnce(failed);

    await sendReports(notifier, report, { securityTeam, lookup });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][0]).toBe('soc@example.com');
    expect(send.mock.calls[1][4].blastRadius).toBe(failed);
  });

  it('still sends the security copy if the lookup throws', async () => {
    const { notifier, send, lookup } = harness([]);
    lookup.mockRejectedValueOnce(new Error('unexpected'));

    await sendReports(notifier, report, { securityTeam, lookup });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][4].blastRadius).toMatchObject({
      status: 'unavailable',
      note: 'Blast radius lookup could not be completed.',
    });
  });

  it('sends the security copy even when the reporter copy failed', async () => {
    const { notifier, send, lookup } = harness([
      { success: false, error: 'rejected' },
      { success: true, messageId: 'security-copy' },
    ]);

    const result = await sendReports(notifier, report, { securityTeam, lookup });

    expect(send).toHaveBeenCalledTimes(2);
    expect(result.reporterResult.success).toBe(false);
    expect(result.commandReplyMessageId).toBe('security-copy');
  });

  it('emits a metric and does not re-send to the reporter when the security copy fails', async () => {
    const { notifier, send, lookup } = harness([
      { success: true, messageId: 'reporter-copy' },
      { success: false, error: 'rejected' },
    ]);

    const result = await sendReports(notifier, report, { securityTeam, lookup });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls.filter(call => call[0] === 'reporter@example.com')).toHaveLength(1);
    expect(result.reporterResult.messageId).toBe('reporter-copy');
    expect(result.commandReplyMessageId).toBeUndefined();

    const lines = metricLines();
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ SecurityCopySendFailures: 1 });
  });

  it('gives a reporter who is on the security team only the security copy', async () => {
    const { notifier, send, events, lookup } = harness([
      { success: true, messageId: 'security-copy' },
    ]);

    const result = await sendReports(
      notifier,
      { ...report, recipient: 'CISO@example.com' },
      { securityTeam, lookup }
    );

    expect(events).toEqual(['lookup', 'send:soc@example.com']);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0][3]).toEqual(['ciso@example.com']);
    expect(result.reporterResult.messageId).toBe('security-copy');
    expect(result.commandReplyMessageId).toBe('security-copy');
  });
});

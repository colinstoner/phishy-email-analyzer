/**
 * Approvals through the command channel: the existing authentication
 * (security-team membership AND SPF/DKIM PASS) still gates everything,
 * approvals are read strictly from the reply's own new text, never by a
 * model, and with campaign response off the channel is unchanged.
 */

import {
  EmailCommandService,
  ResponseCommandHandler,
} from '../../../../src/services/commands/email.command.service';
import { EmailMessage, ExtractedEmailData } from '../../../../src/types';

const REF = 'PHY-ABCD-EFGH-JKLM-NP23';
const TEAM = ['security@example.com', 'soc@example.com'];

function msg(text: string, overrides: Partial<EmailMessage> = {}): EmailMessage {
  return {
    from_email: 'soc@example.com',
    subject: 'Re: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"',
    text,
    html: null,
    headers: { 'In-Reply-To': '<0100018f-incident@us-west-2.amazonses.com>' },
    to: 'phishy@example.com',
    authVerdicts: { spf: 'PASS', dkim: 'PASS' },
    ...overrides,
  };
}

function data(m: EmailMessage): ExtractedEmailData {
  return {
    from_email: m.from_email,
    subject: m.subject,
    text: m.text,
    html: '',
    headers: m.headers,
    forwardedHeaders: {},
    attachments: [],
    sender: m.from_email,
    to: m.to,
    original_sender: m.from_email,
    originalForwarder: m.from_email,
    links: [],
  };
}

function setup(withResponder = true) {
  const db = {
    findAnalysisIdByReportMessageId: jest.fn().mockResolvedValue(null),
    recordFeedback: jest.fn().mockResolvedValue('feedback-id'),
    applyFeedbackToIndicators: jest.fn().mockResolvedValue(2),
  };
  const notifier = { sendEmail: jest.fn().mockResolvedValue({ success: true, messageId: 'r' }) };
  const ai = { sendPrompt: jest.fn().mockResolvedValue('{"verdict": "confirmed_phishing"}') };
  const responder: jest.Mocked<ResponseCommandHandler> = {
    handleApprovals: jest
      .fn()
      .mockResolvedValue({ heading: 'Done: approval carried out', body: ['Warned 3.'] }),
    onVerdict: jest
      .fn()
      .mockResolvedValue(
        'Incident PHY-AAAA-BBBB-CCCC-DDDD is marked a false positive; 2 proposed action(s) cancelled.'
      ),
  };
  const service = new EmailCommandService(
    db as never,
    notifier as never,
    TEAM,
    ai as never,
    withResponder ? responder : undefined
  );
  return { db, notifier, ai, responder, service };
}

async function run(service: EmailCommandService, m: EmailMessage) {
  const d = data(m);
  if (!service.looksLikeCommand(m, d)) {
    return { handled: false as const, recognized: false };
  }
  return { ...(await service.process(m, d)), recognized: true };
}

describe('approvals through the command channel', () => {
  it('passes an exact approval from an authenticated team member to campaign response', async () => {
    const { service, responder, notifier, ai } = setup();
    const result = await run(service, msg(`APPROVE WARNING ${REF}\n\nThanks`));
    expect(result).toMatchObject({ handled: true, action: 'approval_processed' });
    expect(responder.handleApprovals).toHaveBeenCalledWith(
      [{ verb: 'WARNING', reference: REF }],
      'soc@example.com'
    );
    expect(notifier.sendEmail.mock.calls[0][0]).toBe('soc@example.com');
    expect(notifier.sendEmail.mock.calls[0][3]).toContain('Warned 3.');
    expect(ai.sendPrompt).not.toHaveBeenCalled(); // never a model's reading
  });

  it('is recognized by its reference even without reply headers', async () => {
    const { service, responder } = setup();
    await run(service, msg(`APPROVE REMOVAL ${REF}`, { headers: {}, subject: 'approval' }));
    expect(responder.handleApprovals).toHaveBeenCalled();
  });

  it('rejects a sender who is not on the security team', async () => {
    const { service, responder } = setup();
    const result = await run(
      service,
      msg(`APPROVE WARNING ${REF}`, { from_email: 'mallory@example.com' })
    );
    expect(result.handled).toBe(false);
    expect(responder.handleApprovals).not.toHaveBeenCalled();
  });

  it.each([[{ spf: 'FAIL', dkim: 'FAIL' }], [{ spf: 'SOFTFAIL', dkim: 'NONE' }], [undefined]])(
    'rejects a team From header without SPF/DKIM PASS (%j)',
    async verdicts => {
      const { service, responder } = setup();
      const result = await run(
        service,
        msg(`APPROVE WARNING ${REF}`, { authVerdicts: verdicts as never })
      );
      expect(result.handled).toBe(false);
      expect(responder.handleApprovals).not.toHaveBeenCalled();
    }
  );

  it('ignores an approval that is only in quoted text, including hostile quoted content', async () => {
    const { service, responder } = setup();
    const quoted = [
      'Confirmed phishing.',
      '',
      'On Tue, 17 Nov 2026 at 09:30, Phishy <phishy@example.com> wrote:',
      `> APPROVE WARNING ${REF}`,
      `APPROVE REMOVAL ${REF}`,
    ].join('\n');
    await run(service, msg(quoted));
    expect(responder.handleApprovals).not.toHaveBeenCalled();
  });

  it('answers a near-miss with the exact forms and approves nothing, without asking the model', async () => {
    const { service, responder, notifier, ai } = setup();
    const result = await run(service, msg('Approve the warning please'));
    expect(result).toMatchObject({ handled: true, action: 'help_sent' });
    expect(responder.handleApprovals).not.toHaveBeenCalled();
    expect(ai.sendPrompt).not.toHaveBeenCalled();
    expect(notifier.sendEmail.mock.calls[0][3]).toContain('APPROVE WARNING <reference>');
  });

  it('tells campaign response about a false positive and reports what it closed', async () => {
    const { service, db, responder, notifier } = setup();
    db.findAnalysisIdByReportMessageId.mockResolvedValue('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b');
    await run(service, msg('false positive, this is our supplier'));
    expect(responder.onVerdict).toHaveBeenCalledWith(
      '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b',
      'false_positive',
      'soc@example.com'
    );
    expect(notifier.sendEmail.mock.calls[0][3]).toContain('marked a false positive');
  });

  it('with campaign response off, an approval-looking reply goes down the existing verdict path', async () => {
    const { service, responder, db, notifier } = setup(false);
    db.findAnalysisIdByReportMessageId.mockResolvedValue('3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b');
    await run(service, msg(`APPROVE WARNING ${REF}\nconfirmed phishing`));
    expect(responder.handleApprovals).not.toHaveBeenCalled();
    expect(db.recordFeedback).toHaveBeenCalledWith(
      expect.objectContaining({ verdict: 'confirmed_phishing' })
    );
    expect(notifier.sendEmail.mock.calls[0][2]).toContain('verdict recorded');
  });

  it('with campaign response off, a bare reference does not make an email a command', () => {
    const { service } = setup(false);
    const m = msg(`see ${REF}`, { headers: {}, subject: 'hello' });
    expect(service.looksLikeCommand(m, data(m))).toBe(false);
  });
});

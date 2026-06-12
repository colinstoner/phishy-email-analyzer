/**
 * Email command service tests
 */

import {
  EmailCommandService,
  parseVerdictCommand,
  extractFreshText,
} from '../../../../src/services/commands/email.command.service';
import { EmailMessage, ExtractedEmailData } from '../../../../src/types';

const ANALYSIS_ID = '3f2b8a1c-0d4e-4f6a-9b2c-7e8d1a5f3c9b';
const SES_MESSAGE_ID = '010f0190abcdef01-1111-2222';
const SECURITY_TEAM = ['security@example.com', 'soc@example.com'];

function makeMsg(overrides: Partial<EmailMessage> = {}): EmailMessage {
  return {
    from_email: 'security@example.com',
    subject: 'Re: Phishing Analysis: Invoice overdue',
    text: 'Confirmed phishing, nice catch.\n\n> Original report quoted here',
    html: null,
    headers: { 'In-Reply-To': `<${SES_MESSAGE_ID}@us-west-2.amazonses.com>` },
    to: 'phishy@example.com',
    authVerdicts: { spf: 'PASS', dkim: 'PASS' },
    ...overrides,
  };
}

function makeEmailData(msg: EmailMessage): ExtractedEmailData {
  return {
    from_email: msg.from_email,
    subject: msg.subject,
    text: msg.text,
    html: msg.html ?? '',
    headers: msg.headers,
    forwardedHeaders: {},
    attachments: [],
    sender: msg.from_email,
    to: msg.to,
    original_sender: msg.from_email,
    originalForwarder: msg.from_email,
    links: [],
  };
}

function makeFakes() {
  const db = {
    findAnalysisIdByReportMessageId: jest.fn().mockResolvedValue(ANALYSIS_ID),
    recordFeedback: jest.fn().mockResolvedValue('feedback-id'),
    applyFeedbackToIndicators: jest.fn().mockResolvedValue(3),
  };
  const notifier = {
    sendEmail: jest.fn().mockResolvedValue({ success: true, messageId: 'reply-id' }),
  };
  const service = new EmailCommandService(db as never, notifier as never, SECURITY_TEAM);
  return { db, notifier, service };
}

describe('parseVerdictCommand', () => {
  it.each([
    ['confirmed phishing', 'confirmed_phishing'],
    ['Confirm', 'confirmed_phishing'],
    ['yep, malicious — good catch', 'confirmed_phishing'],
    ['agreed', 'confirmed_phishing'],
    ['false positive', 'false_positive'],
    ['This is a False Positive, vendor is known', 'false_positive'],
    ['not phishing, this is legit', 'false_positive'],
    ['marked safe — known partner', 'false_positive'],
    ['benign', 'false_positive'],
  ])('parses %j as %s', (input, expected) => {
    expect(parseVerdictCommand(input)).toBe(expected);
  });

  it('prefers false positive when negation is present', () => {
    expect(parseVerdictCommand('this is not a phish')).toBe('false_positive');
    expect(parseVerdictCommand('not phishing')).toBe('false_positive');
  });

  it('returns null for unrelated text', () => {
    expect(parseVerdictCommand('what is the status of this campaign?')).toBeNull();
    expect(parseVerdictCommand('')).toBeNull();
  });
});

describe('extractFreshText', () => {
  it('strips quoted lines', () => {
    const text = 'False positive\n> quoted phishy report\n> more quote';
    expect(extractFreshText(text)).toBe('False positive');
  });

  it('stops at reply separators', () => {
    const text =
      'confirmed\n\nOn Tue, Jun 9, 2026 at 2:14 PM Phishy <phishy@example.com> wrote:\nVerdict: POTENTIALLY MALICIOUS legit safe';
    expect(extractFreshText(text)).toBe('confirmed');
  });

  it('stops at Outlook-style original message blocks', () => {
    const text =
      'legit, known vendor\n-----Original Message-----\nFrom: Phishy\nthis is phishing malicious';
    expect(extractFreshText(text)).toBe('legit, known vendor');
  });
});

describe('EmailCommandService', () => {
  describe('looksLikeCommand', () => {
    it('matches security-team replies to reports', () => {
      const { service } = makeFakes();
      const msg = makeMsg();
      expect(service.looksLikeCommand(msg, makeEmailData(msg))).toBe(true);
    });

    it('ignores non-security-team senders entirely', () => {
      const { service } = makeFakes();
      const msg = makeMsg({ from_email: 'employee@example.com' });
      expect(service.looksLikeCommand(msg, makeEmailData(msg))).toBe(false);
    });

    it('ignores security-team mail that is not report-related', () => {
      const { service } = makeFakes();
      const msg = makeMsg({
        subject: 'FW: suspicious email to check',
        headers: {},
        text: 'please analyze this',
      });
      expect(service.looksLikeCommand(msg, makeEmailData(msg))).toBe(false);
    });
  });

  describe('process', () => {
    it('records a verdict and replies with completed actions', async () => {
      const { db, notifier, service } = makeFakes();
      const msg = makeMsg();

      const result = await service.process(msg, makeEmailData(msg));

      expect(result).toEqual({ handled: true, action: 'verdict_recorded' });
      expect(db.findAnalysisIdByReportMessageId).toHaveBeenCalledWith(SES_MESSAGE_ID);
      expect(db.recordFeedback).toHaveBeenCalledWith(
        expect.objectContaining({
          analysisId: ANALYSIS_ID,
          verdict: 'confirmed_phishing',
          source: 'email_reply',
          submittedBy: 'security@example.com',
        })
      );
      expect(db.applyFeedbackToIndicators).toHaveBeenCalledWith(ANALYSIS_ID, 'confirmed_phishing');
      expect(notifier.sendEmail).toHaveBeenCalledWith(
        'security@example.com',
        expect.stringContaining('Re:'),
        expect.stringContaining('Confirmed phishing'),
        expect.stringContaining('Completed actions')
      );
    });

    it('rejects senders that fail SPF and DKIM, taking no action', async () => {
      const { db, notifier, service } = makeFakes();
      const msg = makeMsg({ authVerdicts: { spf: 'FAIL', dkim: 'FAIL' } });

      const result = await service.process(msg, makeEmailData(msg));

      expect(result.handled).toBe(false);
      expect(db.recordFeedback).not.toHaveBeenCalled();
      expect(notifier.sendEmail).not.toHaveBeenCalled();
    });

    it('rejects when auth verdicts are missing entirely', async () => {
      const { db, service } = makeFakes();
      const msg = makeMsg({ authVerdicts: undefined });

      const result = await service.process(msg, makeEmailData(msg));

      expect(result.handled).toBe(false);
      expect(db.recordFeedback).not.toHaveBeenCalled();
    });

    it('falls back to the quoted Analysis ID when headers do not match', async () => {
      const { db, service } = makeFakes();
      db.findAnalysisIdByReportMessageId.mockResolvedValue(null);
      const msg = makeMsg({
        text: `false positive\n>   Analysis ID: ${ANALYSIS_ID}`,
      });

      const result = await service.process(msg, makeEmailData(msg));

      expect(result.action).toBe('verdict_recorded');
      expect(db.recordFeedback).toHaveBeenCalledWith(
        expect.objectContaining({ analysisId: ANALYSIS_ID, verdict: 'false_positive' })
      );
    });

    it('replies with guidance when no analysis can be matched', async () => {
      const { db, notifier, service } = makeFakes();
      db.findAnalysisIdByReportMessageId.mockResolvedValue(null);
      const msg = makeMsg({ text: 'confirmed' });

      const result = await service.process(msg, makeEmailData(msg));

      expect(result).toEqual({ handled: true, action: 'no_match' });
      expect(db.recordFeedback).not.toHaveBeenCalled();
      expect(notifier.sendEmail).toHaveBeenCalledWith(
        'security@example.com',
        expect.any(String),
        expect.stringContaining('could not match'),
        expect.stringContaining('Analysis ID')
      );
    });

    it('replies with usage help for unparseable commands', async () => {
      const { db, notifier, service } = makeFakes();
      const msg = makeMsg({ text: 'hmm, can you tell me more about this sender?' });

      const result = await service.process(msg, makeEmailData(msg));

      expect(result).toEqual({ handled: true, action: 'help_sent' });
      expect(db.recordFeedback).not.toHaveBeenCalled();
      expect(notifier.sendEmail).toHaveBeenCalledWith(
        'security@example.com',
        expect.any(String),
        expect.stringContaining('did not understand'),
        expect.stringContaining('false positive')
      );
    });
  });
});

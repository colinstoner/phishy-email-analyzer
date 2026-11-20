/**
 * Reply-To on outgoing mail: replies must reach Phishy's inbox for the
 * command channel to work. No AWS calls.
 */

const mockSendRawEmail = jest.fn();
const mockSendEmail = jest.fn();
jest.mock('@aws-sdk/client-ses', () => ({
  SES: jest.fn().mockImplementation(() => ({
    sendRawEmail: mockSendRawEmail,
    sendEmail: mockSendEmail,
  })),
}));

import { SESNotifier } from '../../../src/services/notification/ses.notifier';
import { PhishyConfigSchema } from '../../../src/config/schema';

describe('SESNotifier Reply-To', () => {
  beforeEach(() => {
    mockSendEmail.mockReset().mockResolvedValue({ MessageId: 'm-1' });
    mockSendRawEmail.mockReset().mockResolvedValue({ MessageId: 'm-2' });
  });

  it('sets ReplyToAddresses on a plain send when configured', async () => {
    const notifier = new SESNotifier({
      region: 'us-west-2',
      senderEmail: 'noreply@example.com',
      replyToEmail: 'phishy@mail.example.com',
    });
    await notifier.sendEmail('person@example.com', 'Subject', '<p>x</p>', 'x');
    expect(mockSendEmail.mock.calls[0][0].ReplyToAddresses).toEqual(['phishy@mail.example.com']);
  });

  it('sends no Reply-To when not configured', async () => {
    const notifier = new SESNotifier({ region: 'us-west-2', senderEmail: 'phishy@example.com' });
    await notifier.sendEmail('person@example.com', 'Subject', '<p>x</p>', 'x');
    expect(mockSendEmail.mock.calls[0][0].ReplyToAddresses).toBeUndefined();
  });

  it('writes a Reply-To header on a threaded send', async () => {
    const notifier = new SESNotifier({
      region: 'us-west-2',
      senderEmail: 'noreply@example.com',
      replyToEmail: 'phishy@mail.example.com',
    });
    await notifier.sendThreadedEmail(['security@example.com'], 'Subject', '<p>x</p>', 'x', 'abc');
    const raw = (
      mockSendRawEmail.mock.calls[0][0] as { RawMessage: { Data: Buffer } }
    ).RawMessage.Data.toString('utf8');
    expect(raw).toContain('\r\nReply-To: <phishy@mail.example.com>\r\n');
  });

  it('ignores a value that is not one plain address (it becomes a header)', async () => {
    const notifier = new SESNotifier({
      region: 'us-west-2',
      senderEmail: 'noreply@example.com',
      replyToEmail: 'phishy@mail.example.com>\r\nBcc: other@example.net',
    });
    await notifier.sendThreadedEmail(['security@example.com'], 'Subject', '<p>x</p>', 'x');
    const raw = (
      mockSendRawEmail.mock.calls[0][0] as { RawMessage: { Data: Buffer } }
    ).RawMessage.Data.toString('utf8');
    expect(raw).not.toContain('Reply-To');
    expect(raw).not.toContain('Bcc');
  });

  it('is validated as an email address by the config schema', () => {
    const base = { notification: { senderEmail: 'noreply@example.com' } };
    const bad = PhishyConfigSchema.safeParse({
      ...base,
      notification: { ...base.notification, replyToEmail: 'not an address' },
    });
    expect(bad.success).toBe(false);
  });
});

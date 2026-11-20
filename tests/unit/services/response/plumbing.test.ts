/**
 * Campaign response plumbing: threaded SES replies, configuration (schema
 * defaults and env mappings) and the EMF metric. No AWS calls.
 */

const mockSendRawEmail = jest.fn();
jest.mock('@aws-sdk/client-ses', () => ({
  SES: jest.fn().mockImplementation(() => ({
    sendRawEmail: mockSendRawEmail,
    sendEmail: jest.fn(),
  })),
}));

import {
  SESNotifier,
  sesMessageIdDomain,
} from '../../../../src/services/notification/ses.notifier';
import { PhishyConfigSchema } from '../../../../src/config/schema';
import { emitCampaignResponseMetric } from '../../../../src/utils/metrics';

function rawOf(call: unknown[]): string {
  const input = call[0] as { RawMessage: { Data: Buffer } };
  return input.RawMessage.Data.toString('utf8');
}

describe('SESNotifier.sendThreadedEmail', () => {
  beforeEach(() => {
    mockSendRawEmail.mockReset();
    mockSendRawEmail.mockResolvedValue({ MessageId: 'ses-update-1' });
  });

  it('replies in the thread of the first incident email', async () => {
    const notifier = new SESNotifier({ region: 'us-west-2', senderEmail: 'phishy@example.com' });
    const result = await notifier.sendThreadedEmail(
      ['security@example.com', 'soc@example.com'],
      'Re: [Phishy incident PHY-AAAA-BBBB-CCCC-DDDD] Active campaign: "Invoice"',
      '<p>html</p>',
      'text body',
      '0101018f-abc-000000'
    );
    expect(result).toEqual({ success: true, messageId: 'ses-update-1' });
    const raw = rawOf(mockSendRawEmail.mock.calls[0]);
    expect(raw).toContain('To: security@example.com, soc@example.com\r\n');
    expect(raw).toContain('In-Reply-To: <0101018f-abc-000000@us-west-2.amazonses.com>\r\n');
    expect(raw).toContain('References: <0101018f-abc-000000@us-west-2.amazonses.com>\r\n');
    expect(raw).toMatch(/Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=\r\n/);
    expect(raw).toContain(Buffer.from('text body').toString('base64'));
  });

  it('cannot be made to add a header', async () => {
    const notifier = new SESNotifier({ region: 'us-east-1', senderEmail: 'phishy@example.com' });
    await notifier.sendThreadedEmail(
      ['security@example.com', 'x@example.com\r\nBcc: mallory@evil.test'],
      'Subject\r\nBcc: mallory@evil.test',
      'h',
      't',
      'id>\r\nBcc: mallory@evil.test'
    );
    const raw = rawOf(mockSendRawEmail.mock.calls[0]);
    expect(raw).not.toMatch(/^Bcc:/im);
    expect(raw).not.toContain('In-Reply-To');
    expect(raw).toContain('To: security@example.com\r\n');
  });

  it('reports a failure instead of throwing', async () => {
    mockSendRawEmail.mockRejectedValue(
      Object.assign(new Error('MessageRejected'), { name: 'MessageRejected' })
    );
    const notifier = new SESNotifier({ region: 'us-east-1', senderEmail: 'phishy@example.com' });
    const result = await notifier.sendThreadedEmail(['security@example.com'], 's', 'h', 't', 'abc');
    expect(result.success).toBe(false);
    expect(await notifier.sendThreadedEmail([], 's', 'h', 't')).toEqual({
      success: false,
      error: 'no valid recipient',
    });
  });

  it('knows the Message-ID domain SES writes', () => {
    expect(sesMessageIdDomain('us-east-1')).toBe('email.amazonses.com');
    expect(sesMessageIdDomain('eu-west-1')).toBe('eu-west-1.amazonses.com');
  });
});

describe('campaignResponse configuration', () => {
  const base = {
    ai: { provider: 'bedrock' },
    email: {},
    notification: { senderEmail: 'phishy@example.com' },
    storage: { s3Bucket: 'bucket' },
  };

  it('is off by default and keeps the broadcast automatic and the targeted warning approved', () => {
    const parsed = PhishyConfigSchema.parse({ ...base, campaignResponse: {} });
    expect(parsed.campaignResponse).toEqual({
      enabled: false,
      audience: 'distribution',
      employeeWarning: 'approve',
      distributionWarning: 'auto',
      approvalTtlHours: 4,
      maxWarningsPerCampaign: 100,
      maxRemovalMailboxes: 500,
      maxRemovalMessages: 1000,
      updateIntervalMinutes: 30,
      alreadyClickedInstructions: expect.stringContaining('contact your IT or security team'),
      timeZone: 'UTC',
    });
    expect(PhishyConfigSchema.parse(base).campaignResponse).toBeUndefined();
  });

  it('rejects an unknown mode, audience or time zone', () => {
    expect(
      PhishyConfigSchema.safeParse({ ...base, campaignResponse: { employeeWarning: 'yes' } })
        .success
    ).toBe(false);
    expect(
      PhishyConfigSchema.safeParse({ ...base, campaignResponse: { audience: 'everyone' } }).success
    ).toBe(false);
    expect(
      PhishyConfigSchema.safeParse({ ...base, campaignResponse: { timeZone: 'Mars/Olympus' } })
        .success
    ).toBe(false);
    expect(
      PhishyConfigSchema.safeParse({ ...base, campaignResponse: { timeZone: 'Europe/London' } })
        .success
    ).toBe(true);
  });

  it('maps every setting to an environment variable', async () => {
    const env = {
      PHISHY_CAMPAIGN_RESPONSE_ENABLED: 'true',
      PHISHY_CAMPAIGN_RESPONSE_AUDIENCE: 'both',
      PHISHY_CAMPAIGN_RESPONSE_EMPLOYEE_WARNING: 'auto',
      PHISHY_CAMPAIGN_RESPONSE_LIST_WARNING: 'approve',
      PHISHY_CAMPAIGN_RESPONSE_APPROVAL_TTL_HOURS: '6',
      PHISHY_CAMPAIGN_RESPONSE_MAX_WARNINGS: '250',
      PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MAILBOXES: '100',
      PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MESSAGES: '300',
      PHISHY_CAMPAIGN_RESPONSE_UPDATE_INTERVAL_MINUTES: '15',
      PHISHY_CAMPAIGN_RESPONSE_CLICKED_INSTRUCTIONS: 'Call the service desk on 4400.',
      PHISHY_CAMPAIGN_RESPONSE_TIME_ZONE: 'Europe/London',
      SENDER_EMAIL: 'phishy@example.com',
      S3_BUCKET_NAME: 'bucket',
      PHISHY_AI_PROVIDER: 'bedrock',
    };
    const saved = { ...process.env };
    Object.assign(process.env, env);
    try {
      const { loadConfig } = await import('../../../../src/config');
      const config = await loadConfig();
      expect(config.campaignResponse).toEqual({
        enabled: true,
        audience: 'both',
        employeeWarning: 'auto',
        distributionWarning: 'approve',
        approvalTtlHours: 6,
        maxWarningsPerCampaign: 250,
        maxRemovalMailboxes: 100,
        maxRemovalMessages: 300,
        updateIntervalMinutes: 15,
        alreadyClickedInstructions: 'Call the service desk on 4400.',
        timeZone: 'Europe/London',
      });
    } finally {
      process.env = saved;
    }
  });
});

describe('emitCampaignResponseMetric', () => {
  it('writes an EMF line straight to stdout with fixed dimensions', () => {
    const saved = process.env.PHISHY_DISABLE_METRICS;
    process.env.PHISHY_DISABLE_METRICS = 'false';
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      emitCampaignResponseMetric('ResponseActionApprovals', 1, { ActionType: 'send_warning' });
      emitCampaignResponseMetric('CampaignWarningsSent', 0); // nothing to count, nothing written
      expect(write).toHaveBeenCalledTimes(1);
      const line = JSON.parse(String(write.mock.calls[0][0])) as Record<string, unknown>;
      expect(line).toMatchObject({
        ActionType: 'send_warning',
        ResponseActionApprovals: 1,
        _aws: {
          CloudWatchMetrics: [
            {
              Namespace: 'Phishy',
              Dimensions: [['ActionType'], []],
              Metrics: [{ Name: 'ResponseActionApprovals', Unit: 'Count' }],
            },
          ],
        },
      });
    } finally {
      write.mockRestore();
      process.env.PHISHY_DISABLE_METRICS = saved;
    }
  });
});

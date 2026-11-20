/**
 * CampaignAlertService: tracking without alerting (campaign response) and
 * the legacy broadcast used when campaign response's tables are missing.
 */

const mockSend = jest.fn();
jest.mock('@aws-sdk/client-ses', () => ({
  SESClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  SendEmailCommand: jest.fn().mockImplementation((input: unknown) => ({ input })),
}));

import { CampaignAlertService } from '../../../../src/services/intelligence/campaign.service';

const MATCH = {
  campaignId: 'c1',
  signature: 'sig',
  detectionCount: 3,
  uniqueRecipientCount: 2,
  hoursActive: 1,
  shouldAlert: true,
};
const CAMPAIGN = {
  id: 'c1',
  campaignSignature: 'sig',
  senderDomain: 'example.com',
  subjectPattern: 'invoice # overdue',
  detectionCount: 3,
  uniqueRecipients: ['a@example.com', 'b@example.com'],
  riskLevel: 'high' as const,
  sampleIndicators: ['Lookalike domain'],
  firstSeenAt: new Date(),
  lastSeenAt: new Date(),
  isActive: true,
};

function setup(distributionList = 'everyone@example.com') {
  const db = {
    trackCampaignDetection: jest.fn().mockResolvedValue(MATCH),
    getCampaignDetails: jest.fn().mockResolvedValue(CAMPAIGN),
    markCampaignAlerted: jest.fn().mockResolvedValue(undefined),
  };
  const service = new CampaignAlertService(db as never, {
    enabled: true,
    distributionList,
    senderEmail: 'phishy@example.com',
  });
  return { db, service };
}

beforeEach(() => mockSend.mockReset().mockResolvedValue({}));

describe('CampaignAlertService', () => {
  it('trackDetection counts the detection and alerts nobody', async () => {
    const { db, service } = setup();
    const tracked = await service.trackDetection(
      'example.com',
      'Fwd: Invoice 1 overdue',
      'a@example.com',
      'high',
      []
    );
    expect(tracked).toEqual({ match: MATCH, campaign: CAMPAIGN });
    expect(mockSend).not.toHaveBeenCalled();
    expect(db.markCampaignAlerted).not.toHaveBeenCalled();
  });

  it('trackDetection ignores medium risk and survives a database error', async () => {
    const { db, service } = setup();
    expect(
      await service.trackDetection('example.com', 's', 'a@example.com', 'medium', [])
    ).toBeUndefined();
    db.trackCampaignDetection.mockRejectedValueOnce(new Error('down'));
    expect(
      await service.trackDetection('example.com', 's', 'a@example.com', 'high', [])
    ).toBeUndefined();
  });

  it('sendLegacyAlert sends today’s broadcast once the threshold is crossed', async () => {
    const { db, service } = setup();
    expect(await service.sendLegacyAlert(MATCH)).toBe(true);
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(db.markCampaignAlerted).toHaveBeenCalledWith('c1');
    expect(await service.sendLegacyAlert({ ...MATCH, shouldAlert: false })).toBe(false);
  });

  it('sendLegacyAlert needs a distribution list', async () => {
    const { service } = setup('');
    expect(await service.sendLegacyAlert(MATCH)).toBe(false);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('processDetection is unchanged: track, then broadcast at the threshold', async () => {
    const { db, service } = setup();
    expect(
      await service.processDetection('example.com', 's', 'a@example.com', 'critical', [])
    ).toBe(true);
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(db.markCampaignAlerted).toHaveBeenCalledWith('c1');
  });
});

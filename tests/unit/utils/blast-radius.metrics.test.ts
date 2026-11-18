/**
 * Blast-radius EMF metric
 */

import { emitBlastRadiusMetric } from '../../../src/utils/metrics';

describe('emitBlastRadiusMetric', () => {
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

  it('writes route, recipients, coverage and errors as one EMF line', () => {
    emitBlastRadiusMetric({
      route: 'mailbox',
      outcome: 'partial',
      recipientsFound: 7,
      mailboxesChecked: 100,
      mailboxesEligible: 400,
      errors: 2,
      durationMs: 31000,
    });

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const line = stdoutSpy.mock.calls[0][0] as string;
    expect(line.endsWith('\n')).toBe(true);
    const doc = JSON.parse(line);
    expect(doc._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(doc._aws.CloudWatchMetrics[0].Dimensions).toEqual([['BlastRadiusRoute']]);
    expect(doc).toMatchObject({
      BlastRadiusRoute: 'mailbox',
      BlastRadiusLookups: 1,
      BlastRadiusRecipientsFound: 7,
      BlastRadiusMailboxesChecked: 100,
      BlastRadiusMailboxesEligible: 400,
      BlastRadiusCoveragePercent: 25,
      BlastRadiusPartial: 1,
      BlastRadiusFailures: 0,
      BlastRadiusErrors: 2,
      BlastRadiusCacheHits: 0,
      BlastRadiusDurationMs: 31000,
    });
  });

  it('counts a failed lookup, and can be disabled', () => {
    const failed = {
      route: 'none' as const,
      outcome: 'unavailable' as const,
      recipientsFound: 0,
      mailboxesChecked: 0,
      mailboxesEligible: 0,
      errors: 1,
      durationMs: 5,
    };
    emitBlastRadiusMetric(failed);
    const doc = JSON.parse(stdoutSpy.mock.calls[0][0] as string);
    expect(doc).toMatchObject({ BlastRadiusFailures: 1, BlastRadiusCoveragePercent: 0 });

    process.env.PHISHY_DISABLE_METRICS = 'true';
    emitBlastRadiusMetric(failed);
    expect(stdoutSpy).toHaveBeenCalledTimes(1);
  });
});

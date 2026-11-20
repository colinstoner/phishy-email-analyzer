/**
 * Attachment analysis configuration: off by default, env mappings, bounds.
 */

import { loadConfig } from '../../../src/config';
import { validateConfig } from '../../../src/config/schema';

const VARS = [
  'PHISHY_ATTACHMENT_ANALYSIS_ENABLED',
  'PHISHY_ATTACHMENT_ANALYSIS_TIME_BUDGET_MS',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_BYTES',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_UNCOMPRESSED_BYTES',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_ARCHIVE_ENTRIES',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_DEPTH',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_PER_ATTACHMENT',
  'PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_TOTAL',
];

describe('attachment analysis configuration', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of [...VARS, 'ANTHROPIC_API_KEY', 'PHISHY_CONFIG_S3']) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
    process.env.ANTHROPIC_API_KEY = 'test-key';
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it('is off by default', async () => {
    const config = await loadConfig();
    expect(config.attachments?.analysis?.enabled ?? false).toBe(false);
  });

  it('turns on with defaults from one variable', async () => {
    process.env.PHISHY_ATTACHMENT_ANALYSIS_ENABLED = 'true';
    const config = await loadConfig();
    expect(config.attachments?.analysis).toEqual({
      enabled: true,
      timeBudgetMs: 10000,
      maxAttachmentBytes: 25 * 1024 * 1024,
      maxUncompressedBytes: 64 * 1024 * 1024,
      maxArchiveEntries: 200,
      maxDepth: 3,
      maxTextPerAttachment: 8000,
      maxTextTotal: 24000,
    });
  });

  it('maps every limit', async () => {
    process.env.PHISHY_ATTACHMENT_ANALYSIS_ENABLED = 'true';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_TIME_BUDGET_MS = '5000';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_BYTES = '1048576';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_UNCOMPRESSED_BYTES = '8388608';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_ARCHIVE_ENTRIES = '50';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_DEPTH = '1';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_PER_ATTACHMENT = '2000';
    process.env.PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_TOTAL = '6000';
    const config = await loadConfig();
    expect(config.attachments?.analysis).toEqual({
      enabled: true,
      timeBudgetMs: 5000,
      maxAttachmentBytes: 1048576,
      maxUncompressedBytes: 8388608,
      maxArchiveEntries: 50,
      maxDepth: 1,
      maxTextPerAttachment: 2000,
      maxTextTotal: 6000,
    });
  });

  it('rejects limits outside their bounds', () => {
    const base = {
      ai: { provider: 'anthropic', anthropic: { apiKey: 'k' } },
      email: {},
      notification: { senderEmail: 'phishy@example.com' },
      storage: { s3Bucket: 'b' },
    };
    expect(() =>
      validateConfig({ ...base, attachments: { analysis: { enabled: true, timeBudgetMs: 120000 } } })
    ).toThrow();
    expect(() =>
      validateConfig({ ...base, attachments: { analysis: { enabled: true, maxDepth: 9 } } })
    ).toThrow();
  });
});

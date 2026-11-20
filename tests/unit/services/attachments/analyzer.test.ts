/**
 * The attachment step as a whole: one budget per email, a fair share per
 * attachment, a hard wall-clock stop, and parser failures contained as
 * fixed reason words. The HTML and email inspectors are replaced here so a
 * test can make them throw, spin or hang.
 */

import { AttachmentAnalyzer } from '../../../../src/services/attachments';
import {
  AttachmentAnalysisSettings,
  DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS,
} from '../../../../src/services/attachments/types';
import { EmailAttachment } from '../../../../src/types';
import { buildPdf } from '../../../../src/eval/injection/fixtures';

type Behaviour = 'real' | 'throw' | 'spin' | 'hang';
let htmlBehaviour: Behaviour = 'real';
let emailBehaviour: Behaviour = 'real';

jest.mock('../../../../src/services/attachments/html', () => {
  const actual = jest.requireActual('../../../../src/services/attachments/html');
  return {
    inspectHtml: (...args: unknown[]) => {
      if (htmlBehaviour === 'throw') throw new TypeError('parser bug with file content in it');
      if (htmlBehaviour === 'spin') {
        const ctx = args[1] as { checkDeadline: () => void };
        const until = Date.now() + 5000;
        while (Date.now() < until) ctx.checkDeadline();
      }
      return actual.inspectHtml(...args);
    },
  };
});

jest.mock('../../../../src/services/attachments/email', () => {
  const actual = jest.requireActual('../../../../src/services/attachments/email');
  return {
    inspectEmail: (...args: unknown[]) =>
      emailBehaviour === 'hang' ? new Promise(() => undefined) : actual.inspectEmail(...args),
  };
});

const SETTINGS: AttachmentAnalysisSettings = {
  ...DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS,
  enabled: true,
};

function item(filename: string, content: Buffer | string, contentType = 'application/octet-stream'): {
  attachment: EmailAttachment;
  content: Buffer;
} {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return { attachment: { filename, contentType, size: bytes.length }, content: bytes };
}

const HTML = '<html><form action="https://collect.example.net/"><input type="password"></form></html>';
const EML = 'From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody text';

afterEach(() => {
  htmlBehaviour = 'real';
  emailBehaviour = 'real';
});

describe('AttachmentAnalyzer', () => {
  it('does nothing when disabled', async () => {
    const items = [item('a.html', HTML)];
    await new AttachmentAnalyzer({ ...SETTINGS, enabled: false }).analyze(items);
    expect(items[0].attachment.analysis).toBeUndefined();
  });

  it('analyzes every attachment', async () => {
    const items = [item('a.html', HTML), item('b.pdf', buildPdf({ pages: [['hello']] }))];
    await new AttachmentAnalyzer(SETTINGS).analyze(items);
    expect(items.map(i => i.attachment.analysis?.realType)).toEqual(['html', 'pdf']);
  });

  it('contains a parser exception as a fixed reason word', async () => {
    htmlBehaviour = 'throw';
    const items = [item('a.html', HTML), item('b.pdf', buildPdf({ pages: [['hello']] }))];
    await new AttachmentAnalyzer(SETTINGS).analyze(items);
    expect(items[0].attachment.analysis).toMatchObject({
      status: 'failed',
      reason: 'error',
      realType: 'html',
    });
    expect(JSON.stringify(items[0].attachment.analysis)).not.toContain('parser bug');
    expect(items[1].attachment.analysis?.status).toBe('inspected');
  });

  it('gives each attachment a fair share, so one slow file cannot starve the rest', async () => {
    htmlBehaviour = 'spin';
    const items = [item('slow.html', HTML), item('b.pdf', buildPdf({ pages: [['hello']] }))];
    const started = Date.now();
    await new AttachmentAnalyzer({ ...SETTINGS, timeBudgetMs: 1000 }).analyze(items);
    expect(Date.now() - started).toBeLessThan(2500);
    expect(items[0].attachment.analysis).toMatchObject({ status: 'failed', reason: 'timeout' });
    expect(items[1].attachment.analysis?.status).toBe('inspected');
  });

  it('stops waiting for an asynchronous path that never returns', async () => {
    emailBehaviour = 'hang';
    const items = [item('fwd.eml', EML, 'message/rfc822')];
    const started = Date.now();
    await new AttachmentAnalyzer({ ...SETTINGS, timeBudgetMs: 600 }).analyze(items);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(items[0].attachment.analysis).toMatchObject({ status: 'failed', reason: 'timeout' });
  });

  it('marks attachments that got no time as budget exhausted', async () => {
    htmlBehaviour = 'spin';
    const items = [item('slow.html', HTML), item('late.pdf', buildPdf({ pages: [['x']] }))];
    // One attachment's minimum share is larger than the whole budget
    await new AttachmentAnalyzer({ ...SETTINGS, timeBudgetMs: 500 }).analyze(items);
    expect(items[1].attachment.analysis).toMatchObject({
      status: 'not_inspected',
      reason: 'budget_exhausted',
      realType: 'pdf',
    });
  });

  it('applies the email-wide text budget', async () => {
    const long = (tag: string): string => `<html><p>${tag}-START ${'w '.repeat(5000)} ${tag}-END</p></html>`;
    const items = [item('a.html', long('A')), item('b.html', long('B'))];
    await new AttachmentAnalyzer({ ...SETTINGS, maxTextPerAttachment: 3000, maxTextTotal: 4000 }).analyze(items);
    for (const [i, tag] of ['A', 'B'].entries()) {
      const analysis = items[i].attachment.analysis;
      expect(analysis?.text).toContain(`${tag}-START`);
      expect(analysis?.text).toContain(`${tag}-END`);
      expect(analysis?.textShownElided).toBeGreaterThan(0);
    }
  });
});

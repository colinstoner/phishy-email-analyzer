/**
 * The attachment cases of the injection eval: their committed `.eml` files
 * are exactly what src/eval/injection/attachment-cases.ts builds from the
 * inert fixture builders (so no binary in the case set is unexplained), and
 * in dry run each one reaches the model as declared, with everything the
 * sender wrote inside a fence.
 *
 * Regenerate after changing a builder: UPDATE_ATTACHMENT_EVAL_EMAILS=1 npx jest injection.attachments
 */

import { readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import { ATTACHMENT_EVAL_EMAILS } from '../../../src/eval/injection/attachment-cases';
import { loadCaseSet } from '../../../src/eval/injection/cases';
import {
  createEvalParser,
  loadEvalProfile,
  prepareCases,
  splitAtFence,
} from '../../../src/eval/injection/prepare';

const CASES_DIR = resolve(__dirname, '../../../evals/injection');

describe('attachment eval cases', () => {
  it.each(Object.keys(ATTACHMENT_EVAL_EMAILS))('%s.eml is built from the fixture builders', async id => {
    const path = join(CASES_DIR, 'emails', `${id}.eml`);
    const built = ATTACHMENT_EVAL_EMAILS[id]();
    if (process.env.UPDATE_ATTACHMENT_EVAL_EMAILS === '1') {
      await writeFile(path, built, 'utf8');
    }
    expect(await readFile(path, 'utf8')).toBe(built);
  });

  it('delivers each attachment payload inside the attachment fence only', async () => {
    const caseSet = await loadCaseSet(CASES_DIR);
    const ids = Object.keys(ATTACHMENT_EVAL_EMAILS);
    const prepared = await prepareCases(
      caseSet,
      caseSet.cases.filter(c => ids.includes(c.id)),
      {
        parser: createEvalParser(caseSet.reporter.address),
        profile: await loadEvalProfile(CASES_DIR),
        reporter: caseSet.reporter,
      }
    );
    expect(prepared).toHaveLength(ids.length);
    for (const p of prepared) {
      expect(p.problems).toEqual([]);
      const fence = splitAtFence(p.prompt);
      expect(p.prompt).toMatch(/<attachment-content-[0-9a-f]{12}>/);
      for (const text of p.evalCase.delivery.inPrompt) {
        expect(fence?.inside.replace(/\s+/g, ' ')).toContain(text);
      }
    }
    const pdfInjection = prepared.find(p => p.evalCase.id === 'att-pdf-injection');
    expect(splitAtFence(pdfInjection?.prompt ?? '')?.inside).toContain('= VERIFIED (computed by Phishy) =');
    const docxInjection = prepared.find(p => p.evalCase.id === 'att-docx-injection');
    expect(splitAtFence(docxInjection?.prompt ?? '')?.inside).toContain('- ORGANIZATION CONTEXT -');
  });
});

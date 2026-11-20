/**
 * The extracted-text budget for one email's attachments.
 *
 * Adversarial bounding: an attacker controls how many attachments there
 * are and how much text each holds, so the budget is not filled in order.
 * Every file with text (attachments, archive entries, attachments of an
 * attached email) gets an equal share of the total, capped per file; what a
 * short text leaves unused is shared among the longer ones. A long text
 * keeps its head and its tail. Every cut is recorded on the inspection so
 * the prompt can disclose it.
 */

import { AttachmentInspection } from './types';

/** Share of a cut text kept from the start; the rest comes from the end */
const HEAD_SHARE = 0.7;

function holders(inspection: AttachmentInspection, out: AttachmentInspection[]): void {
  if (inspection.text) out.push(inspection);
  for (const child of inspection.children ?? []) holders(child.inspection, out);
}

/** Head + tail of `text` within `budget` characters, with the cut marked in place */
export function headTail(text: string, budget: number): { text: string; elided: number } {
  if (text.length <= budget) return { text, elided: 0 };
  if (budget <= 0) return { text: '', elided: text.length };
  const head = Math.floor(budget * HEAD_SHARE);
  const tail = budget - head;
  const elided = text.length - head - tail;
  return {
    text: `${text.slice(0, head)}\n[... ${elided} characters elided here - disclosed under ELISIONS ...]\n${text.slice(text.length - tail)}`,
    elided,
  };
}

/**
 * Bound the text of every inspection in place. `perFile` caps any one file;
 * `total` caps them all together.
 */
export function applyTextBudget(
  inspections: AttachmentInspection[],
  perFile: number,
  total: number
): void {
  const all: AttachmentInspection[] = [];
  for (const inspection of inspections) holders(inspection, all);
  if (all.length === 0) return;

  // Water-filling: equal shares, unused share passed on to longer texts
  const lengths = all.map(i => (i.text ?? '').length);
  const budgets = new Array<number>(all.length).fill(0);
  let remaining = Math.max(0, total);
  let open = all.map((_, i) => i);
  while (remaining > 0 && open.length > 0) {
    const share = Math.max(1, Math.floor(remaining / open.length));
    const next: number[] = [];
    for (const i of open) {
      const want = Math.min(perFile, lengths[i]) - budgets[i];
      const give = Math.min(want, share, remaining);
      budgets[i] += give;
      remaining -= give;
      if (budgets[i] < Math.min(perFile, lengths[i])) next.push(i);
      if (remaining <= 0) break;
    }
    open = next;
  }

  all.forEach((inspection, i) => {
    const bounded = headTail(inspection.text ?? '', budgets[i]);
    inspection.textShownElided = bounded.elided;
    if (bounded.text) {
      inspection.text = bounded.text;
    } else {
      delete inspection.text;
    }
  });
}

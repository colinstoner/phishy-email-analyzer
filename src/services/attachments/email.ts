/**
 * An email attached to the suspicious email (`message/rfc822`, `.eml`):
 * parsed with the same MIME parser as everything else (mailparser), its
 * body text and links collected, its own attachments inspected as children
 * one level deeper. Its subject is the sender's text and is kept as CLAIMED.
 *
 * Outlook `.msg` files are OLE containers; they are identified (see ole.ts)
 * but their streams are not read.
 */

import { simpleParser } from 'mailparser';
import { extractHrefUrls, extractUrls, stripHtml } from '../../utils/validation';
import { InspectionAbort, InspectionContext } from './limits';
import { InspectorOutput, addFinding, addLimit } from './output';
import { ChildInspector } from './archive';
import { ChildInspection } from './types';

/** Attachments of an embedded email inspected */
const MAX_EMBEDDED_ATTACHMENTS = 20;

export async function inspectEmail(
  bytes: Buffer,
  ctx: InspectionContext,
  out: InspectorOutput,
  inspectChild: ChildInspector
): Promise<void> {
  // The parser is asynchronous and cannot be interrupted, so it is raced
  // against the deadline; a parse that loses the race is abandoned.
  const remaining = ctx.remainingMs();
  if (remaining <= 0) throw new InspectionAbort('timeout');
  let timer: NodeJS.Timeout | undefined;
  const parsed = await Promise.race([
    simpleParser(bytes, { skipImageLinks: true, skipTextToHtml: true }),
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new InspectionAbort('timeout')), remaining);
    }),
  ]).finally(() => clearTimeout(timer));

  out.claimedSubject = parsed.subject ?? undefined;
  const html = typeof parsed.html === 'string' ? parsed.html : '';
  const text = parsed.text ?? (html ? stripHtml(html) : '');
  out.text.add(text);
  for (const url of [...extractHrefUrls(html), ...extractUrls(html || text)]) out.links.add(url);
  addFinding(out, 'email_links', out.links.total);

  const attachments = parsed.attachments ?? [];
  out.childrenTotal = attachments.length;
  addFinding(out, 'email_attachments', attachments.length);
  if (attachments.length === 0) return;
  if (ctx.depth + 1 > ctx.settings.maxDepth) {
    addLimit(out, 'nesting_depth');
    return;
  }
  if (attachments.length > MAX_EMBEDDED_ATTACHMENTS) addLimit(out, 'entry_count');
  const children: ChildInspection[] = [];
  for (const attachment of attachments.slice(0, MAX_EMBEDDED_ATTACHMENTS)) {
    ctx.checkDeadline();
    const name = attachment.filename ?? '(unnamed)';
    children.push({
      claimedName: name,
      size: attachment.size,
      inspection: await inspectChild(attachment.content, name, attachment.contentType, ctx.child()),
    });
  }
  out.children = children;
}

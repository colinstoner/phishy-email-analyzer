/**
 * Static attachment analysis (optional, off by default:
 * `attachments.analysis.enabled`). See docs/ARCHITECTURE.md, "Attachment
 * analysis".
 */

import { EmailAttachment, LinkFact } from '../../types';
import { AttachmentInspection } from './types';

export { AttachmentAnalyzer, inspectBytes } from './inspector';
export type { AttachmentWithContent } from './inspector';
export { attachmentRiskSignals } from './risk';
export type { AttachmentRiskSignal } from './risk';
export { DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS } from './types';
export type * from './types';

/** Most links gathered across all attachments of one email */
const MAX_ATTACHMENT_LINKS = 200;

function gather(inspection: AttachmentInspection, out: LinkFact[]): void {
  for (const link of inspection.links) {
    if (out.length >= MAX_ATTACHMENT_LINKS) return;
    out.push(link);
  }
  for (const child of inspection.children ?? []) gather(child.inspection, out);
}

/** Every canonicalized link found inside the email's attachments, at any depth */
export function attachmentLinkFacts(attachments: EmailAttachment[]): LinkFact[] {
  const out: LinkFact[] = [];
  for (const attachment of attachments) {
    if (attachment.analysis) gather(attachment.analysis, out);
  }
  return out;
}

/**
 * Attachment facts that are decisive on their own, for risk fusion.
 *
 * Only two findings qualify, because each has no innocent explanation in
 * an email attachment:
 *  - `credential_form`: an HTML or SVG file (at any depth) with a password
 *    field that posts to a web host, or whose script makes network
 *    requests. Opened from disk, such a page exists to send what is typed
 *    into it somewhere else.
 *  - `disguised_executable`: a file that runs code (by its bytes or by its
 *    extension) whose name is built to look like something else — a
 *    right-to-left override, or a document/picture extension in front of
 *    the real one, or a document/picture extension on executable bytes.
 *
 * Signals only ever raise risk (see risk.fusion.ts). There is deliberately
 * no "inspected and inert" signal: static inspection cannot prove a file
 * safe, so a clean inspection never lowers anything in code.
 */

import { EmailAttachment } from '../../types';
import { analyzeName, isDocumentLikeExtension } from './sniff';
import { AttachmentInspection, ChildInspection } from './types';

export type AttachmentRiskSignal = 'credential_form' | 'disguised_executable';

function count(inspection: AttachmentInspection, kind: string): number {
  return inspection.findings.find(f => f.kind === kind)?.count ?? 0;
}

function isCredentialForm(inspection: AttachmentInspection): boolean {
  if (inspection.realType !== 'html' && inspection.realType !== 'svg') return false;
  if (count(inspection, 'html_password_fields') === 0) return false;
  return (
    count(inspection, 'html_form_posts_to_host') > 0 ||
    count(inspection, 'html_network_requests') > 0
  );
}

function isDisguisedExecutable(name: string, inspection: AttachmentInspection): boolean {
  if (!inspection.highRisk) return false;
  if (inspection.nameFlags.includes('bidi_override')) return true;
  const naming = analyzeName(name);
  if (
    inspection.nameFlags.includes('double_extension') &&
    isDocumentLikeExtension(naming.innerExtension)
  ) {
    return true;
  }
  // Executable bytes behind a document or picture extension
  return inspection.family === 'executable' && isDocumentLikeExtension(naming.extension);
}

function collect(
  name: string,
  inspection: AttachmentInspection,
  signals: Set<AttachmentRiskSignal>
): void {
  if (isCredentialForm(inspection)) signals.add('credential_form');
  if (isDisguisedExecutable(name, inspection)) signals.add('disguised_executable');
  for (const child of inspection.children ?? ([] as ChildInspection[])) {
    collect(child.claimedName, child.inspection, signals);
  }
}

/** The decisive signals across an email's analyzed attachments (empty when none were analyzed) */
export function attachmentRiskSignals(attachments: EmailAttachment[]): AttachmentRiskSignal[] {
  const signals = new Set<AttachmentRiskSignal>();
  for (const attachment of attachments) {
    if (attachment.analysis) collect(attachment.filename, attachment.analysis, signals);
  }
  return [...signals].sort();
}

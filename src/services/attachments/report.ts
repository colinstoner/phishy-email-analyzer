/**
 * A one-line summary of an attachment inspection for the report's
 * "Original Email for IT Review" part: fixed wording only, no text, name,
 * link or host from the file. Undefined when the attachment was not
 * analyzed, so reports look exactly as before with the feature off.
 */

import { AttachmentInspection, FindingKind } from './types';

const NOTABLE: Partial<Record<FindingKind, string>> = {
  html_password_fields: 'password field',
  html_form_posts_to_host: 'form posts to a web host',
  html_network_requests: 'script sends data',
  html_smuggling_markers: 'file-smuggling script',
  pdf_javascript: 'JavaScript',
  pdf_launch_action: 'launch action',
  pdf_embedded_files: 'embedded file',
  pdf_submit_form: 'form submission',
  pdf_little_text_with_links_or_images: 'only a link or image',
  ooxml_macros: 'macros',
  ole_macros: 'macros',
  ooxml_external_template: 'remote template',
  ooxml_dde_fields: 'DDE field',
  ooxml_unc_paths: 'network-share path',
  ole_equation_editor: 'Equation Editor object',
  rtf_equation_editor: 'Equation Editor object',
  archive_encrypted_entries: 'password-protected entries',
  archive_high_risk_entries: 'contains files that run code',
  archive_overlapping_entries: 'zip-bomb structure',
};

const STATUS: Record<AttachmentInspection['status'], string> = {
  inspected: 'inspected',
  partial: 'partly inspected',
  not_inspected: 'not inspected',
  failed: 'inspection failed',
};

export function summarizeInspectionForReport(
  inspection: AttachmentInspection | undefined
): string | undefined {
  if (!inspection) return undefined;
  const parts = [`real type ${inspection.realType.replace(/_/g, ' ')}`, STATUS[inspection.status]];
  if (inspection.highRisk) parts.push('HIGH-RISK TYPE');
  if (
    inspection.nameFlags.includes('extension_mismatch') ||
    inspection.nameFlags.includes('declared_type_mismatch')
  ) {
    parts.push('name does not match type');
  }
  for (const finding of inspection.findings) {
    const label = NOTABLE[finding.kind];
    if (label && !parts.includes(label)) parts.push(label);
  }
  return `Phishy: ${parts.join(', ')}`;
}

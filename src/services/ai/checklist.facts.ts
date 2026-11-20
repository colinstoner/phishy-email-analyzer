/**
 * Checklist scoring: the items Phishy answers itself (checklist version 2).
 *
 * Every answer here is computed from facts Phishy already has on the email,
 * by the same functions that produce what the prompt shows: the parser's
 * link facts and content findings, the addressing comparison, the file-share
 * relation, the attachment inspection and its risk signals, the retrieved
 * original's headers, the sender-relationship class. Nothing re-parses
 * prompt text, and nothing the model returns is read here.
 *
 * Unknown stays unknown. An answer is `unknown` whenever the fact it needs
 * is absent: an optional feature is off (attachment analysis, the
 * original-message lookup, the sender-history check), the parser recorded
 * nothing, or the headers do not let Phishy tell. `unknown` scores nothing
 * (checklist.score.ts), so a missing fact can never lower risk, and it is
 * never replaced by a guess or handed to the model instead.
 *
 * Code items are not bounded by the prompt's budgets: every link is
 * considered, not only the ones the prompt lists, so padding cannot hide
 * one from these answers.
 *
 * Pure computation, no I/O.
 */

import { EmailAttachment, ExtractedEmailData, LinkFact } from '../../types';
import { computeAddressingDetails, claimedSenderDomain } from '../../utils/addressing';
import { analyzeUrl, registrableDomain, registrableOf } from '../../utils/canonicalize';
import { fileShareRelation } from '../../utils/file-share';
import { retrievedAuthenticationVerdict } from '../../utils/auth-results';
import { attachmentRiskSignals } from '../attachments/risk';
import { analyzeName } from '../attachments/sniff';
import type { AttachmentInspection } from '../attachments/types';
import type { CodeChecklistAnswers } from './checklist';

type YesNoUnknown = 'yes' | 'no' | 'unknown';

/**
 * The email's body links as the prompt sees them. Undefined when the parser
 * recorded no link facts but there are links (their file-share facts were
 * never computed, so file-share answers cannot be given).
 */
function bodyLinkFacts(emailData: ExtractedEmailData): LinkFact[] | undefined {
  if (emailData.linkFacts) return emailData.linkFacts;
  return emailData.links.length === 0 ? [] : undefined;
}

/** The raw form of every body link (the prompt's fallback when link facts are absent) */
function rawLinks(emailData: ExtractedEmailData): string[] {
  return emailData.linkFacts ? emailData.linkFacts.map(f => f.raw) : emailData.links;
}

function walkInspection(
  inspection: AttachmentInspection,
  visit: (inspection: AttachmentInspection) => void
): void {
  visit(inspection);
  for (const child of inspection.children ?? []) walkInspection(child.inspection, visit);
}

function findingCount(inspection: AttachmentInspection, kind: string): number {
  return inspection.findings.find(f => f.kind === kind)?.count ?? 0;
}

/** Every attachment analyzed, and analyzed completely */
function allFullyInspected(attachments: EmailAttachment[]): boolean {
  return attachments.every(a => a.analysis?.status === 'inspected');
}

export function linkTextMismatch(emailData: ExtractedEmailData): YesNoUnknown {
  const anchors = emailData.contentFindings?.anchors;
  if (anchors === undefined) return 'unknown';
  return anchors.length > 0 ? 'yes' : 'no';
}

export function fileShareUnrelatedToSender(emailData: ExtractedEmailData): YesNoUnknown {
  const links = bodyLinkFacts(emailData);
  if (links === undefined) return 'unknown';
  const shares = links.flatMap(f => (f.fileShare ? [f.fileShare] : []));
  if (shares.length === 0) return 'no';
  const sender = claimedSenderDomain(emailData);
  const relations = shares.map(share => fileShareRelation(share, sender));
  if (relations.includes('unrelated')) return 'yes';
  return relations.includes('unknown') ? 'unknown' : 'no';
}

export function riskyAttachment(emailData: ExtractedEmailData): YesNoUnknown {
  const attachments = emailData.attachments;
  if (attachments.length === 0) return 'no';
  // Always computable: an extension Windows acts on by running something
  const dangerousName = attachments.some(a =>
    analyzeName(a.filename).flags.includes('dangerous_extension')
  );
  if (dangerousName || attachmentRiskSignals(attachments).length > 0) return 'yes';

  let risky = false;
  for (const attachment of attachments) {
    if (!attachment.analysis) continue;
    walkInspection(attachment.analysis, inspection => {
      if (
        inspection.highRisk ||
        findingCount(inspection, 'ooxml_macros') > 0 ||
        findingCount(inspection, 'ole_macros') > 0 ||
        findingCount(inspection, 'archive_high_risk_entries') > 0
      ) {
        risky = true;
      }
    });
  }
  if (risky) return 'yes';
  return allFullyInspected(attachments) ? 'no' : 'unknown';
}

export function authenticationFailed(emailData: ExtractedEmailData): 'fail' | 'pass' | 'unknown' {
  return retrievedAuthenticationVerdict(emailData.retrievedOriginal);
}

export function replyToDiverts(emailData: ExtractedEmailData): YesNoUnknown {
  const details = computeAddressingDetails(emailData);
  if (!details) return 'unknown';
  if (
    details.facts.includes('reply_to_other_domain') ||
    details.facts.includes('reply_to_name_differs')
  ) {
    return 'yes';
  }
  return details.replyTo === 'unknown' ? 'unknown' : 'no';
}

export function contentObfuscated(emailData: ExtractedEmailData): YesNoUnknown {
  const text = emailData.contentFindings?.text;
  if (text === undefined) return 'unknown';
  return text.includes('invisible_characters') || text.includes('bidi_controls') ? 'yes' : 'no';
}

export function senderFanoutAnomalous(emailData: ExtractedEmailData): YesNoUnknown {
  const history = emailData.senderHistory;
  if (!history) return 'unknown';
  return history.classification === 'established_with_anomalous_fanout' ? 'yes' : 'no';
}

export function bccToSelf(emailData: ExtractedEmailData): YesNoUnknown {
  const details = computeAddressingDetails(emailData);
  if (!details) return 'unknown';
  if (details.facts.includes('bcc_to_self')) return 'yes';
  return details.recipientsKnown ? 'no' : 'unknown';
}

export function contentUninspectable(emailData: ExtractedEmailData): YesNoUnknown {
  const hiddenLink = rawLinks(emailData).some(raw => analyzeUrl(raw).destinationHidden);
  let encrypted = false;
  for (const attachment of emailData.attachments) {
    if (!attachment.analysis) continue;
    walkInspection(attachment.analysis, inspection => {
      if (
        inspection.reason === 'encrypted' ||
        findingCount(inspection, 'pdf_encrypted') > 0 ||
        findingCount(inspection, 'archive_encrypted_entries') > 0
      ) {
        encrypted = true;
      }
    });
  }
  if (hiddenLink || encrypted) return 'yes';
  return bodyLinkFacts(emailData) !== undefined &&
    emailData.attachments.every(a => a.analysis !== undefined)
    ? 'no'
    : 'unknown';
}

export function linksMatchSenderDomain(emailData: ExtractedEmailData): YesNoUnknown {
  const sender = claimedSenderDomain(emailData);
  if (!sender) return 'unknown';
  const raws = rawLinks(emailData);
  if (raws.length === 0) return 'no';
  const senderRegistrable = registrableOf(sender);
  const allMatch = raws.every(raw => {
    const { canonical, destinationHidden } = analyzeUrl(raw);
    return !destinationHidden && registrableDomain(canonical) === senderRegistrable;
  });
  return allMatch ? 'yes' : 'no';
}

/**
 * Phishy's answers to every code item of the checklist. Deterministic: the
 * same email facts always give the same answers.
 */
export function computeCodeChecklistAnswers(emailData: ExtractedEmailData): CodeChecklistAnswers {
  return {
    link_text_mismatch: linkTextMismatch(emailData),
    file_share_unrelated_to_sender: fileShareUnrelatedToSender(emailData),
    risky_attachment: riskyAttachment(emailData),
    authentication_failed: authenticationFailed(emailData),
    reply_to_diverts: replyToDiverts(emailData),
    content_obfuscated: contentObfuscated(emailData),
    sender_fanout_anomalous: senderFanoutAnomalous(emailData),
    bcc_to_self: bccToSelf(emailData),
    content_uninspectable: contentUninspectable(emailData),
    links_match_sender_domain: linksMatchSenderDomain(emailData),
  };
}

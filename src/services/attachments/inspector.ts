/**
 * Attachment analysis orchestrator: identifies each attachment's real type,
 * runs the inspector for it inside the step's time and decompression
 * budgets, and reduces whatever happens — a hostile structure, a parser
 * exception, a timeout — to an `AttachmentInspection` with a fixed reason
 * word. Nothing here throws to the caller, nothing is executed, rendered or
 * fetched, and nothing extracted is logged.
 */

import { EmailAttachment } from '../../types';
import { createLogger } from '../../utils/logger';
import { ChildInspector, inspectGzip, inspectTar, inspectZipArchive } from './archive';
import { applyTextBudget } from './budget';
import { inspectEmail } from './email';
import { inspectHtml } from './html';
import { InspectionAbort, InspectionContext } from './limits';
import { imageDimensions, inspectRtf } from './misc';
import { inspectOle } from './ole';
import { inspectOoxml, isOoxml } from './ooxml';
import { InspectorOutput, addFinding, markPartial, newOutput } from './output';
import { inspectPdf } from './pdf';
import {
  analyzeName,
  declaredTypeContradicts,
  decodeText,
  extensionContradicts,
  familyOf,
  isDangerousExtension,
  isHighRiskType,
  sniffType,
} from './sniff';
import {
  AttachmentAnalysisSettings,
  AttachmentInspection,
  InspectionReason,
  NameFlag,
  RealType,
} from './types';
import { readZipDirectory } from './zip';

const logger = createLogger('attachment-analysis');

/** Least time one attachment is given, even when many share the budget */
const MIN_SHARE_MS = 500;
/** Slack past an attachment's deadline before the orchestrator stops waiting for it */
const WAIT_GRACE_MS = 250;

const UNSUPPORTED_ARCHIVES: ReadonlySet<RealType> = new Set<RealType>([
  'rar',
  '7z',
  'cab',
  'bzip2',
  'xz',
]);

function nameFlagsFor(
  claimedName: string,
  declaredType: string | undefined,
  realType: RealType
): { flags: NameFlag[]; extension?: string } {
  const naming = analyzeName(claimedName);
  const flags = [...naming.flags];
  if (extensionContradicts(naming.extension, realType)) flags.push('extension_mismatch');
  if (declaredTypeContradicts(declaredType, realType)) flags.push('declared_type_mismatch');
  return { flags, extension: naming.extension };
}

/** Run the inspector for `realType`; returns the refined type */
async function runInspector(
  bytes: Buffer,
  realType: RealType,
  ctx: InspectionContext,
  out: InspectorOutput,
  inspectChild: ChildInspector
): Promise<{
  type: RealType;
  skipped?: InspectionReason;
  dimensions?: { width: number; height: number };
}> {
  switch (realType) {
    case 'zip': {
      const directory = readZipDirectory(bytes, ctx, ctx.settings.maxArchiveEntries);
      if (isOoxml(directory)) {
        return { type: inspectOoxml(bytes, directory, ctx, out) };
      }
      if (directory.entries.some(e => e.name === 'META-INF/MANIFEST.MF')) {
        return { type: 'jar', skipped: 'high_risk_type' };
      }
      await inspectZipArchive(bytes, directory, ctx, out, inspectChild);
      return { type: 'zip' };
    }
    case 'ole_other': {
      const type = inspectOle(bytes, ctx, out);
      if (type === 'ooxml_encrypted') return { type, skipped: 'encrypted' };
      if (type === 'msi') return { type, skipped: 'high_risk_type' };
      if (type === 'ole_msg') {
        markPartial(out, 'unsupported');
      }
      return { type };
    }
    case 'pdf':
      inspectPdf(bytes, ctx, out);
      return { type: 'pdf' };
    case 'html':
    case 'svg':
      inspectHtml(bytes, ctx, out);
      return { type: realType };
    case 'rtf':
      inspectRtf(bytes, ctx, out);
      return { type: 'rtf' };
    case 'eml':
      await inspectEmail(bytes, ctx, out, inspectChild);
      return { type: 'eml' };
    case 'gzip':
      await inspectGzip(bytes, ctx, out, inspectChild);
      return { type: 'gzip' };
    case 'tar':
      await inspectTar(bytes, ctx, out, inspectChild);
      return { type: 'tar' };
    case 'text':
    case 'xml': {
      const text = decodeText(bytes.subarray(0, 4 * 1024 * 1024));
      out.text.add(text);
      const re = /https?:\/\/[^\s<>"'`)\]\\]+/gi;
      let m: RegExpExecArray | null;
      let n = 0;
      while ((m = re.exec(text)) !== null && n++ < 1000) out.links.add(m[0]);
      addFinding(out, 'text_chars', text.replace(/\s/g, '').length);
      return { type: realType };
    }
    case 'png':
    case 'jpeg':
    case 'gif':
    case 'bmp':
    case 'webp':
    case 'tiff':
    case 'ico':
      return { type: realType, dimensions: imageDimensions(bytes, realType, ctx) };
    default:
      if (UNSUPPORTED_ARCHIVES.has(realType)) return { type: realType, skipped: 'unsupported' };
      if (isHighRiskType(realType)) return { type: realType, skipped: 'high_risk_type' };
      return { type: realType };
  }
}

/**
 * Inspect one file's bytes. Never throws: every failure becomes a status and
 * a fixed reason word, and whatever was found before the failure is kept.
 */
export async function inspectBytes(
  bytes: Buffer,
  claimedName: string,
  declaredType: string | undefined,
  ctx: InspectionContext
): Promise<AttachmentInspection> {
  const started = Date.now();
  const out = newOutput();
  let realType: RealType;
  try {
    realType = sniffType(bytes.subarray(0, Math.max(0x9010, 4096)));
    // VHD keeps its signature in a footer
    if (realType === 'unknown' && bytes.length >= 512) realType = sniffType(bytes);
  } catch {
    realType = 'unknown';
  }

  let status: AttachmentInspection['status'] = 'inspected';
  let reason: InspectionReason | undefined;
  let dimensions: { width: number; height: number } | undefined;

  if (bytes.length > ctx.settings.maxAttachmentBytes) {
    status = 'not_inspected';
    reason = 'too_large';
  } else if (ctx.depth > ctx.settings.maxDepth) {
    status = 'not_inspected';
    reason = 'depth_limit';
  } else {
    try {
      ctx.checkDeadline();
      const result = await runInspector(bytes, realType, ctx, out, inspectBytes);
      realType = result.type;
      dimensions = result.dimensions;
      if (result.skipped) {
        status = 'not_inspected';
        reason = result.skipped;
      }
    } catch (error) {
      status = 'failed';
      reason = error instanceof InspectionAbort ? error.reason : 'error';
    }
  }
  if (status === 'inspected' && (out.partialReason || out.limitsHit.length > 0)) {
    status = 'partial';
    reason = out.partialReason;
  }

  const naming = nameFlagsFor(claimedName, declaredType, realType);
  const text = out.text.result();
  const linkFacts = out.links.facts();
  if (out.links.truncated && !out.limitsHit.includes('link_count'))
    out.limitsHit.push('link_count');
  return {
    status,
    ...(reason ? { reason } : {}),
    realType,
    family: familyOf(realType),
    highRisk: isHighRiskType(realType) || isDangerousExtension(naming.extension),
    nameFlags: naming.flags,
    ...(naming.extension ? { extension: naming.extension } : {}),
    findings: out.findings,
    links: linkFacts,
    linksTotal: out.links.total,
    ...(text.text.trim() ? { text: text.text } : {}),
    textChars: text.chars,
    ...(out.claimedSubject !== undefined ? { claimedSubject: out.claimedSubject } : {}),
    ...(out.children ? { children: out.children } : {}),
    ...(out.childrenTotal !== undefined ? { childrenTotal: out.childrenTotal } : {}),
    ...(dimensions ? { dimensions } : {}),
    limitsHit: out.limitsHit,
    durationMs: Date.now() - started,
  };
}

/** The inspection recorded when an attachment got no time at all */
function notInspected(
  bytes: Buffer,
  claimedName: string,
  declaredType: string | undefined,
  reason: InspectionReason
): AttachmentInspection {
  let realType: RealType = 'unknown';
  try {
    realType = sniffType(bytes.subarray(0, 0x9010));
  } catch {
    // keep unknown
  }
  const naming = nameFlagsFor(claimedName, declaredType, realType);
  return {
    status: 'not_inspected',
    reason,
    realType,
    family: familyOf(realType),
    highRisk: isHighRiskType(realType) || isDangerousExtension(naming.extension),
    nameFlags: naming.flags,
    ...(naming.extension ? { extension: naming.extension } : {}),
    findings: [],
    links: [],
    linksTotal: 0,
    textChars: 0,
    limitsHit: [],
    durationMs: 0,
  };
}

export interface AttachmentWithContent {
  attachment: EmailAttachment;
  content: Buffer;
}

/**
 * Analyzes the attachments of one email within one budget and stores each
 * result on `attachment.analysis`.
 */
export class AttachmentAnalyzer {
  constructor(private readonly settings: AttachmentAnalysisSettings) {}

  get enabled(): boolean {
    return this.settings.enabled;
  }

  async analyze(items: AttachmentWithContent[]): Promise<void> {
    if (!this.settings.enabled || items.length === 0) return;
    const ctx = InspectionContext.forEmail(this.settings);
    const statuses: Record<string, number> = {};

    for (let i = 0; i < items.length; i++) {
      const { attachment, content } = items[i];
      const remaining = ctx.remainingMs();
      if (remaining <= 0) {
        attachment.analysis = notInspected(
          content,
          attachment.filename,
          attachment.contentType,
          'budget_exhausted'
        );
      } else {
        // A fair share of what is left, so one slow file cannot starve the rest
        const share = Math.max(MIN_SHARE_MS, Math.floor(remaining / (items.length - i)));
        const deadline = Date.now() + Math.min(share, remaining);
        attachment.analysis = await this.inspectWithin(
          content,
          attachment,
          ctx.withDeadline(deadline),
          deadline
        );
      }
      const key = `${attachment.analysis.status}${attachment.analysis.reason ? `:${attachment.analysis.reason}` : ''}`;
      statuses[key] = (statuses[key] ?? 0) + 1;
    }

    applyTextBudget(
      items.map(item => item.attachment.analysis).filter((a): a is AttachmentInspection => !!a),
      this.settings.maxTextPerAttachment,
      this.settings.maxTextTotal
    );

    // Counts and fixed words only: nothing from the files reaches the log
    logger.info('Attachment analysis complete', {
      attachments: items.length,
      statuses,
      durationMs: this.settings.timeBudgetMs - Math.max(0, ctx.remainingMs()),
    });
  }

  /** Inspect with a hard wall-clock stop, in case an asynchronous path does not return */
  private async inspectWithin(
    content: Buffer,
    attachment: EmailAttachment,
    ctx: InspectionContext,
    deadline: number
  ): Promise<AttachmentInspection> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        inspectBytes(content, attachment.filename, attachment.contentType, ctx),
        new Promise<AttachmentInspection>(resolve => {
          timer = setTimeout(
            () => {
              const late = notInspected(
                content,
                attachment.filename,
                attachment.contentType,
                'timeout'
              );
              resolve({ ...late, status: 'failed' });
            },
            Math.max(0, deadline - Date.now()) + WAIT_GRACE_MS
          );
        }),
      ]);
    } catch {
      return {
        ...notInspected(content, attachment.filename, attachment.contentType, 'error'),
        status: 'failed',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

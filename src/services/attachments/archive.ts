/**
 * Archives: zip, gzip and tar are listed and their entries identified;
 * rar, 7z, cab, bzip2 and xz are identified but not opened (no small,
 * trustworthy pure-JavaScript readers, and their decompressors are where
 * the bugs live).
 *
 * Zip-bomb defences, all disclosed when they stop inspection:
 *  - at most `maxArchiveEntries` entries are listed and examined;
 *  - an entry is decompressed only within the per-entry bound and the
 *    email-wide decompression budget; the size an entry claims is never
 *    trusted for allocation;
 *  - overlapping entries (one compressed stream counted many times) are
 *    detected and stop the listing's decompression;
 *  - nesting is followed to `maxDepth` levels only.
 *
 * Each entry's real type comes from its first bytes; small enough entries
 * are inspected fully by the same orchestrator (an HTML file in a zip is
 * inspected like an HTML attachment).
 */

import { InspectionContext } from './limits';
import { InspectorOutput, addFinding, addLimit, markPartial } from './output';
import { analyzeName, familyOf, isDangerousExtension, isHighRiskType, sniffType } from './sniff';
import { AttachmentInspection, ChildInspection, RealType } from './types';
import { ZipDirectory, readZipEntry, sniffZipEntry } from './zip';

/** Largest single entry decompressed for inspection */
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;

/** Inspect a child's bytes (provided by the orchestrator, which owns recursion) */
export type ChildInspector = (
  bytes: Buffer,
  claimedName: string,
  declaredType: string | undefined,
  ctx: InspectionContext
) => Promise<AttachmentInspection>;

/** Summary for an entry whose bytes were not (fully) read */
function shallowChild(
  head: Buffer,
  name: string,
  reason: AttachmentInspection['reason'],
  status: AttachmentInspection['status']
): AttachmentInspection {
  const realType: RealType = head.length > 0 ? sniffType(head) : 'unknown';
  const naming = analyzeName(name);
  return {
    status,
    reason,
    realType,
    family: familyOf(realType),
    highRisk: isHighRiskType(realType) || isDangerousExtension(naming.extension),
    nameFlags: naming.flags,
    extension: naming.extension,
    findings: [],
    links: [],
    linksTotal: 0,
    textChars: 0,
    limitsHit: [],
    durationMs: 0,
  };
}

function summarizeChildren(children: ChildInspection[], out: InspectorOutput): void {
  addFinding(
    out,
    'archive_nested_archives',
    children.filter(c => c.inspection.family === 'archive').length
  );
  addFinding(out, 'archive_high_risk_entries', children.filter(c => c.inspection.highRisk).length);
}

export async function inspectZipArchive(
  bytes: Buffer,
  directory: ZipDirectory,
  ctx: InspectionContext,
  out: InspectorOutput,
  inspectChild: ChildInspector
): Promise<void> {
  if (directory.zip64) {
    markPartial(out, 'unsupported');
    return;
  }
  const files = directory.entries.filter(e => !e.isDirectory);
  out.childrenTotal = Math.max(directory.declaredEntries, directory.entries.length);
  addFinding(out, 'archive_entries', out.childrenTotal);
  if (directory.truncated) addLimit(out, 'entry_count');
  addFinding(out, 'archive_encrypted_entries', files.filter(e => e.encrypted).length);
  addFinding(
    out,
    'archive_uncompressed_bytes',
    files.reduce((sum, e) => sum + e.uncompressedSize, 0)
  );
  addFinding(out, 'archive_overlapping_entries', directory.overlapping);

  const children: ChildInspection[] = [];
  const canRecurse = ctx.depth + 1 <= ctx.settings.maxDepth;
  if (!canRecurse) addLimit(out, 'nesting_depth');
  let mismatches = 0;

  for (const entry of files) {
    ctx.checkDeadline();
    if (entry.encrypted) {
      children.push({
        claimedName: entry.name,
        size: entry.uncompressedSize,
        inspection: shallowChild(Buffer.alloc(0), entry.name, 'encrypted', 'not_inspected'),
      });
      continue;
    }
    if (directory.overlapping > 0 || !canRecurse || entry.uncompressedSize > MAX_ENTRY_BYTES) {
      if (entry.uncompressedSize > MAX_ENTRY_BYTES) addLimit(out, 'entry_size');
      children.push({
        claimedName: entry.name,
        size: entry.uncompressedSize,
        inspection: shallowChild(
          sniffZipEntry(bytes, entry, ctx),
          entry.name,
          !canRecurse ? 'depth_limit' : 'too_large',
          'not_inspected'
        ),
      });
      continue;
    }
    const read = readZipEntry(bytes, entry, ctx, MAX_ENTRY_BYTES);
    if (!read.ok) {
      if ('limit' in read) addLimit(out, read.limit);
      children.push({
        claimedName: entry.name,
        size: entry.uncompressedSize,
        inspection: shallowChild(
          sniffZipEntry(bytes, entry, ctx),
          entry.name,
          'limit' in read ? 'budget_exhausted' : read.reason,
          'not_inspected'
        ),
      });
      continue;
    }
    if (read.data.length !== entry.uncompressedSize) mismatches++;
    children.push({
      claimedName: entry.name,
      size: read.data.length,
      inspection: await inspectChild(read.data, entry.name, undefined, ctx.child()),
    });
  }
  addFinding(out, 'archive_size_mismatch', mismatches);
  out.children = children;
  summarizeChildren(children, out);
}

/** gzip: one compressed member; its content is inspected as a child */
export async function inspectGzip(
  bytes: Buffer,
  ctx: InspectionContext,
  out: InspectorOutput,
  inspectChild: ChildInspector
): Promise<void> {
  // The original file name, when the header carries one (FNAME flag)
  let name = '(gzip content)';
  if (bytes.length > 10 && (bytes[3] & 0x08) !== 0) {
    let p = 10;
    if ((bytes[3] & 0x04) !== 0 && p + 2 <= bytes.length) p += 2 + bytes.readUInt16LE(p);
    const end = bytes.indexOf(0, p);
    if (end > p && end - p < 1024) name = bytes.toString('latin1', p, end);
  }
  out.childrenTotal = 1;
  addFinding(out, 'archive_entries', 1);
  if (ctx.depth + 1 > ctx.settings.maxDepth) {
    addLimit(out, 'nesting_depth');
    out.children = [
      {
        claimedName: name,
        size: 0,
        inspection: shallowChild(Buffer.alloc(0), name, 'depth_limit', 'not_inspected'),
      },
    ];
    return;
  }
  const result = ctx.decompress(bytes, 'gzip', MAX_ENTRY_BYTES);
  if (!result.ok) {
    if ('limit' in result) addLimit(out, result.limit);
    markPartial(out, 'limit' in result ? 'budget_exhausted' : 'malformed');
    return;
  }
  addFinding(out, 'archive_uncompressed_bytes', result.data.length);
  out.children = [
    {
      claimedName: name,
      size: result.data.length,
      inspection: await inspectChild(result.data, name, undefined, ctx.child()),
    },
  ];
  summarizeChildren(out.children, out);
}

/** tar: 512-byte headers, entries stored uncompressed */
export async function inspectTar(
  bytes: Buffer,
  ctx: InspectionContext,
  out: InspectorOutput,
  inspectChild: ChildInspector
): Promise<void> {
  const children: ChildInspection[] = [];
  const canRecurse = ctx.depth + 1 <= ctx.settings.maxDepth;
  if (!canRecurse) addLimit(out, 'nesting_depth');
  let p = 0;
  let total = 0;
  let uncompressed = 0;
  while (p + 512 <= bytes.length) {
    ctx.checkDeadline();
    const header = bytes.subarray(p, p + 512);
    if (header.every(b => b === 0)) break;
    const name = header.toString('latin1', 0, 100).replace(/\0.*$/s, '');
    const prefix = header.toString('latin1', 345, 500).replace(/\0.*$/s, '');
    const size = parseInt(header.toString('latin1', 124, 136).replace(/[^0-7]/g, '') || '0', 8);
    const typeFlag = String.fromCharCode(header[156]);
    if (!Number.isFinite(size) || size < 0) {
      markPartial(out, 'malformed');
      break;
    }
    const dataStart = p + 512;
    const fullName = prefix ? `${prefix}/${name}` : name;
    if (typeFlag === '0' || typeFlag === '\0' || typeFlag === '7') {
      total++;
      uncompressed += size;
      if (children.length < ctx.settings.maxArchiveEntries) {
        const data = bytes.subarray(dataStart, Math.min(bytes.length, dataStart + size));
        children.push({
          claimedName: fullName,
          size,
          inspection:
            canRecurse && size <= MAX_ENTRY_BYTES
              ? await inspectChild(data, fullName, undefined, ctx.child())
              : shallowChild(
                  data.subarray(0, 4096),
                  fullName,
                  canRecurse ? 'too_large' : 'depth_limit',
                  'not_inspected'
                ),
        });
      } else {
        addLimit(out, 'entry_count');
      }
    }
    p = dataStart + Math.ceil(size / 512) * 512;
  }
  out.childrenTotal = total;
  out.children = children;
  addFinding(out, 'archive_entries', total);
  addFinding(out, 'archive_uncompressed_bytes', uncompressed);
  summarizeChildren(children, out);
}

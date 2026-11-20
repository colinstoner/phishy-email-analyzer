/**
 * A minimal, bounded zip reader: the central directory, and one entry's
 * bytes on request. Enough for archives and for Office Open XML, which is a
 * zip of XML parts. Written here rather than taken from a library because
 * the surface needed is small and every limit has to be Phishy's:
 *
 *  - the end-of-central-directory record is searched for only in the last
 *    65 557 bytes (its maximum distance from the end);
 *  - at most `maxEntries` central-directory records are read; the count the
 *    archive claims is reported separately;
 *  - entry data is located through its local header and bounds-checked
 *    against the file; entries whose data overlaps another's (the
 *    overlapping-file zip bomb) are detected;
 *  - decompression goes through the context's budget, which bounds output
 *    per entry and for the whole email, whatever the entry claims;
 *  - ZIP64 archives and methods other than stored / deflate are reported as
 *    unsupported rather than guessed at.
 */

import { InspectionAbort, InspectionContext } from './limits';
import { LimitHit } from './types';

export interface ZipEntry {
  /** Entry name as stored: attacker-chosen */
  name: string;
  method: number;
  encrypted: boolean;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  isDirectory: boolean;
}

export interface ZipDirectory {
  entries: ZipEntry[];
  /** Entries the archive's end record claims */
  declaredEntries: number;
  /** True when more central-directory records existed than were read */
  truncated: boolean;
  /** Entries whose data ranges overlap (a zip-bomb construction) */
  overlapping: number;
  zip64: boolean;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const MAX_EOCD_SEARCH = 65_557;
/** Hard ceiling on central-directory records read, whatever the settings */
const MAX_DIRECTORY_RECORDS = 10_000;

function decodeName(raw: Buffer, utf8: boolean): string {
  return utf8 ? raw.toString('utf8') : raw.toString('latin1');
}

/** Read the central directory. Throws `malformed` when there is none. */
export function readZipDirectory(
  bytes: Buffer,
  ctx: InspectionContext,
  maxEntries: number
): ZipDirectory {
  const searchFrom = Math.max(0, bytes.length - MAX_EOCD_SEARCH);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= searchFrom; i--) {
    if (bytes.readUInt32LE(i) === EOCD_SIGNATURE) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new InspectionAbort('malformed');

  const declaredEntries = bytes.readUInt16LE(eocd + 10);
  const directorySize = bytes.readUInt32LE(eocd + 12);
  const directoryOffset = bytes.readUInt32LE(eocd + 16);
  const zip64 =
    declaredEntries === 0xffff || directoryOffset === 0xffffffff || directorySize === 0xffffffff;
  if (zip64) {
    return { entries: [], declaredEntries, truncated: true, overlapping: 0, zip64: true };
  }
  if (directoryOffset + directorySize > bytes.length) throw new InspectionAbort('malformed');

  const limit = Math.min(maxEntries, MAX_DIRECTORY_RECORDS);
  const entries: ZipEntry[] = [];
  let p = directoryOffset;
  const end = directoryOffset + directorySize;
  let records = 0;
  while (p + 46 <= end && records < MAX_DIRECTORY_RECORDS) {
    ctx.tick();
    if (bytes.readUInt32LE(p) !== CENTRAL_SIGNATURE) break;
    const flags = bytes.readUInt16LE(p + 8);
    const method = bytes.readUInt16LE(p + 10);
    const compressedSize = bytes.readUInt32LE(p + 20);
    const uncompressedSize = bytes.readUInt32LE(p + 24);
    const nameLength = bytes.readUInt16LE(p + 28);
    const extraLength = bytes.readUInt16LE(p + 30);
    const commentLength = bytes.readUInt16LE(p + 32);
    const localHeaderOffset = bytes.readUInt32LE(p + 42);
    const nameEnd = p + 46 + nameLength;
    if (nameEnd > bytes.length) throw new InspectionAbort('malformed');
    records++;
    if (entries.length < limit) {
      const name = decodeName(bytes.subarray(p + 46, nameEnd), (flags & 0x800) !== 0);
      entries.push({
        name,
        method,
        encrypted: (flags & 0x1) !== 0,
        compressedSize,
        uncompressedSize,
        localHeaderOffset,
        isDirectory: name.endsWith('/') && uncompressedSize === 0,
      });
    }
    p = nameEnd + extraLength + commentLength;
  }

  return {
    entries,
    declaredEntries,
    truncated: records > entries.length || declaredEntries > records,
    overlapping: countOverlaps(bytes, entries),
    zip64: false,
  };
}

/** Where an entry's data starts, or -1 when its local header is not valid */
function dataOffset(bytes: Buffer, entry: ZipEntry): number {
  const p = entry.localHeaderOffset;
  if (p + 30 > bytes.length || bytes.readUInt32LE(p) !== LOCAL_SIGNATURE) return -1;
  const start = p + 30 + bytes.readUInt16LE(p + 26) + bytes.readUInt16LE(p + 28);
  return start + entry.compressedSize <= bytes.length ? start : -1;
}

function countOverlaps(bytes: Buffer, entries: ZipEntry[]): number {
  const ranges = entries
    .filter(e => !e.isDirectory && e.compressedSize > 0)
    .map(e => ({ start: e.localHeaderOffset, end: dataOffset(bytes, e) + e.compressedSize }))
    .filter(r => r.end > r.start)
    .sort((a, b) => a.start - b.start);
  let overlaps = 0;
  for (let i = 1; i < ranges.length; i++) {
    if (ranges[i].start < ranges[i - 1].end) overlaps++;
  }
  return overlaps;
}

export type EntryRead =
  | { ok: true; data: Buffer }
  | { ok: false; reason: 'encrypted' | 'unsupported' | 'malformed' }
  | { ok: false; limit: LimitHit };

/** Decompress one entry within the context's budget */
export function readZipEntry(
  bytes: Buffer,
  entry: ZipEntry,
  ctx: InspectionContext,
  perEntryLimit: number
): EntryRead {
  if (entry.encrypted) return { ok: false, reason: 'encrypted' };
  const start = dataOffset(bytes, entry);
  if (start === -1) return { ok: false, reason: 'malformed' };
  const compressed = bytes.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) {
    if (compressed.length > perEntryLimit) return { ok: false, limit: 'entry_size' };
    return { ok: true, data: compressed };
  }
  if (entry.method !== 8) return { ok: false, reason: 'unsupported' };
  const result = ctx.decompress(compressed, 'raw', perEntryLimit);
  if (result.ok) return { ok: true, data: result.data };
  if ('limit' in result) return { ok: false, limit: result.limit };
  return { ok: false, reason: 'malformed' };
}

/** The first bytes of an entry, for type identification, without a full decompression */
export function sniffZipEntry(bytes: Buffer, entry: ZipEntry, ctx: InspectionContext): Buffer {
  if (entry.encrypted) return Buffer.alloc(0);
  const start = dataOffset(bytes, entry);
  if (start === -1) return Buffer.alloc(0);
  const compressed = bytes.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return compressed.subarray(0, 4096);
  if (entry.method === 8) return ctx.sniffInflateRaw(compressed);
  return Buffer.alloc(0);
}

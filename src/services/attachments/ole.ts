/**
 * Legacy OLE (Compound File Binary) documents: .doc, .xls, .ppt, .msg, .msi
 * and password-protected Office Open XML all share this container. Phishy
 * reads only its directory, the list of storage and stream names, which is
 * enough to say reliably what the file is and whether it carries a VBA
 * project: Word keeps one under a `Macros` storage, Excel under
 * `_VBA_PROJECT_CUR`, and every VBA project has a `VBA` storage with a
 * `_VBA_PROJECT` stream. Stream contents are never read. Excel 4.0 (XLM)
 * macros live inside the Workbook stream and are not detected; the prompt
 * says the legacy body was not inspected.
 *
 * Bounded: sector numbers are checked against the file, chains are followed
 * with a visited set and a sector cap, and at most a few thousand directory
 * entries are read.
 */

import { InspectionAbort, InspectionContext } from './limits';
import { InspectorOutput, addFinding, addLimit } from './output';
import { RealType } from './types';

const MAX_DIRECTORY_SECTORS = 512;
const MAX_FAT_SECTORS = 4096;
const MAX_ENTRIES = 4096;
const END_OF_CHAIN = 0xfffffffe;
/** {000C1084-0000-0000-C000-000000000046}, as stored (little-endian fields) */
const MSI_CLSID = '84100c0000000000c000000000000046';

interface DirectoryEntry {
  name: string;
  type: number;
}

function sectorOffset(sid: number, shift: number): number {
  return (sid + 1) * (1 << shift);
}

/** Read the directory entry names (and the root's CLSID) */
function readDirectory(
  bytes: Buffer,
  ctx: InspectionContext
): { entries: DirectoryEntry[]; rootClsid: string; truncated: boolean } {
  if (bytes.length < 512) throw new InspectionAbort('malformed');
  const shift = bytes.readUInt16LE(0x1e);
  if (shift !== 9 && shift !== 12) throw new InspectionAbort('malformed');
  const sectorSize = 1 << shift;
  const fatSectorCount = bytes.readUInt32LE(0x2c);
  const firstDirectorySector = bytes.readUInt32LE(0x30);
  let difatSector = bytes.readUInt32LE(0x44);
  const difatCount = bytes.readUInt32LE(0x48);

  // FAT sector ids: 109 in the header, the rest in a DIFAT chain
  const fatSectors: number[] = [];
  for (let i = 0; i < 109 && fatSectors.length < fatSectorCount; i++) {
    fatSectors.push(bytes.readUInt32LE(0x4c + i * 4));
  }
  const seenDifat = new Set<number>();
  for (
    let d = 0;
    d < difatCount && fatSectors.length < Math.min(fatSectorCount, MAX_FAT_SECTORS);
    d++
  ) {
    ctx.tick();
    if (difatSector >= END_OF_CHAIN || seenDifat.has(difatSector)) break;
    seenDifat.add(difatSector);
    const off = sectorOffset(difatSector, shift);
    if (off + sectorSize > bytes.length) throw new InspectionAbort('malformed');
    const perSector = sectorSize / 4 - 1;
    for (let i = 0; i < perSector && fatSectors.length < fatSectorCount; i++) {
      fatSectors.push(bytes.readUInt32LE(off + i * 4));
    }
    difatSector = bytes.readUInt32LE(off + perSector * 4);
  }

  const fatEntriesPerSector = sectorSize / 4;
  const nextSector = (sid: number): number => {
    const fatIndex = Math.floor(sid / fatEntriesPerSector);
    if (fatIndex >= fatSectors.length) return END_OF_CHAIN;
    const off = sectorOffset(fatSectors[fatIndex], shift) + (sid % fatEntriesPerSector) * 4;
    if (off + 4 > bytes.length) return END_OF_CHAIN;
    return bytes.readUInt32LE(off);
  };

  const entries: DirectoryEntry[] = [];
  let rootClsid = '';
  const seen = new Set<number>();
  let sid = firstDirectorySector;
  let truncated = false;
  while (sid < END_OF_CHAIN && !seen.has(sid)) {
    ctx.tick();
    if (seen.size >= MAX_DIRECTORY_SECTORS || entries.length >= MAX_ENTRIES) {
      truncated = true;
      break;
    }
    seen.add(sid);
    const off = sectorOffset(sid, shift);
    if (off + sectorSize > bytes.length) throw new InspectionAbort('malformed');
    for (let e = 0; e < sectorSize / 128; e++) {
      const base = off + e * 128;
      const nameLength = Math.min(64, bytes.readUInt16LE(base + 64));
      const type = bytes[base + 66];
      if (type === 0) continue;
      const name = bytes
        .subarray(base, base + Math.max(0, nameLength - 2))
        .toString('utf16le')
        .replace(/\0/g, '');
      if (type === 5) rootClsid = bytes.subarray(base + 80, base + 96).toString('hex');
      entries.push({ name, type });
    }
    sid = nextSector(sid);
  }
  return { entries, rootClsid, truncated };
}

/**
 * Inspect an OLE container: identify it from its directory and report macro
 * storages and embedded objects. Returns the refined real type.
 */
export function inspectOle(bytes: Buffer, ctx: InspectionContext, out: InspectorOutput): RealType {
  const { entries, rootClsid, truncated } = readDirectory(bytes, ctx);
  if (truncated) addLimit(out, 'entry_count');
  const names = new Set(entries.map(e => e.name));
  const has = (n: string): boolean => names.has(n);

  let type: RealType = 'ole_other';
  if (has('EncryptionInfo') && has('EncryptedPackage')) {
    type = 'ooxml_encrypted';
  } else if (rootClsid === MSI_CLSID) {
    type = 'msi';
  } else if (
    [...names].some(n => n.startsWith('__substg1.0_') || n === '__properties_version1.0')
  ) {
    type = 'ole_msg';
  } else if (has('WordDocument')) {
    type = 'ole_doc';
  } else if (has('Workbook') || has('Book')) {
    type = 'ole_xls';
  } else if (has('PowerPoint Document')) {
    type = 'ole_ppt';
  }

  const macroStorages = ['Macros', '_VBA_PROJECT_CUR', 'VBA', '_VBA_PROJECT', 'PROJECT', 'dir'];
  const macroMarkers = macroStorages.filter(has).length;
  // `PROJECT` or `dir` alone appear in other formats; a VBA project needs the VBA storage
  if (has('VBA') || has('_VBA_PROJECT_CUR') || has('Macros')) {
    addFinding(out, 'ole_macros', macroMarkers);
  }
  addFinding(
    out,
    'ole_embedded_objects',
    entries.filter(e => e.name === '\u0001Ole10Native' || e.name === 'ObjectPool').length
  );
  addFinding(out, 'ole_equation_editor', entries.filter(e => e.name === 'Equation Native').length);
  if (type === 'ole_doc' || type === 'ole_xls' || type === 'ole_ppt' || type === 'ole_other') {
    addFinding(out, 'ole_legacy_not_inspected', 1);
  }
  return type;
}

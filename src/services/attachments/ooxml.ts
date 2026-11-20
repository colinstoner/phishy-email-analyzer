/**
 * Office Open XML (docx / xlsx / pptx and the macro-enabled variants):
 * a zip of XML parts. Phishy reads the zip's directory and a few specific
 * parts, with plain string scanning, never an XML parser that could expand
 * entities or resolve anything:
 *
 *  - the part list: a VBA project (`vbaProject.bin`), embedded objects,
 *    ActiveX controls;
 *  - every relationships part (`*.rels`): relationships with
 *    `TargetMode="External"` are what make a document fetch something when
 *    opened (a remote template, a linked object or image, a frame). Their
 *    hosts are reported; hyperlinks become links;
 *  - the main text parts: Word body, headers, footers, footnotes and
 *    comments; Excel shared strings; PowerPoint slides and notes. Field
 *    instructions are checked for DDE and for fields that pull remote
 *    content (INCLUDEPICTURE, INCLUDETEXT).
 */

import { InspectionContext, decodeEntities, hostOf } from './limits';
import { InspectorOutput, addFinding, addLimit, markPartial } from './output';
import { RealType } from './types';
import { ZipDirectory, ZipEntry, readZipEntry } from './zip';

/** Decoded bytes read from one XML part */
const MAX_PART_BYTES = 8 * 1024 * 1024;
/** Relationship parts and text parts read */
const MAX_PARTS_READ = 200;

/** True when the directory looks like an OOXML package */
export function isOoxml(directory: ZipDirectory): boolean {
  return directory.entries.some(e => e.name === '[Content_Types].xml');
}

/** Refine the package type from its main part and content types */
function packageType(names: string[], contentTypes: string): RealType {
  const macro = /macroenabled/i.test(contentTypes) || names.some(n => /vbaProject\.bin$/i.test(n));
  if (names.includes('word/document.xml') || names.some(n => /^word\/[^/]+\.xml$/.test(n))) {
    return macro ? 'docm' : 'docx';
  }
  if (names.includes('xl/workbook.bin')) return 'xlsb';
  if (names.includes('xl/workbook.xml')) return macro ? 'xlsm' : 'xlsx';
  if (names.includes('ppt/presentation.xml')) return macro ? 'pptm' : 'pptx';
  return 'ooxml_other';
}

/** Attribute value from one element's attribute text */
function attribute(tag: string, name: string): string | undefined {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)')`);
  const m = re.exec(tag);
  return m ? decodeEntities(m[2] ?? m[3] ?? '') : undefined;
}

/** Host of a UNC path (`\\host\share`) or file URL, which leaks credentials when opened */
function uncHost(target: string): string | undefined {
  const m = /^(?:file:)?[\\/]{2}([A-Za-z0-9.-]{1,253})[\\/]/.exec(target);
  return m ? m[1].toLowerCase() : undefined;
}

interface Relationships {
  templates: string[];
  objects: string[];
  images: string[];
  other: string[];
  unc: string[];
  hyperlinks: number;
}

function scanRelationships(xml: string, rels: Relationships, out: InspectorOutput): void {
  const re = /<Relationship\b[^>]*>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const tag = m[0];
    const type = (attribute(tag, 'Type') ?? '').toLowerCase();
    const target = attribute(tag, 'Target') ?? '';
    const external = (attribute(tag, 'TargetMode') ?? '').toLowerCase() === 'external';
    if (!external) continue;
    if (type.endsWith('/hyperlink')) {
      rels.hyperlinks++;
      out.links.add(target);
      continue;
    }
    out.links.add(target);
    const host =
      hostOf(target) ??
      uncHost(target) ??
      (target.startsWith('mhtml:') ? hostOf(target.slice(6)) : undefined);
    const unc = uncHost(target);
    if (unc) rels.unc.push(unc);
    const label = host ?? 'non-web target';
    if (
      type.endsWith('/attachedtemplate') ||
      type.endsWith('/subdocument') ||
      type.endsWith('/frame')
    ) {
      rels.templates.push(label);
    } else if (type.endsWith('/oleobject') || type.endsWith('/package')) {
      rels.objects.push(label);
    } else if (type.endsWith('/image')) {
      rels.images.push(label);
    } else {
      rels.other.push(label);
    }
  }
}

/** Text of the run elements of a WordprocessingML / DrawingML / SpreadsheetML part */
function partText(xml: string): string {
  // Paragraph and row ends become line breaks, then only text-run content is kept
  const marked = xml.replace(/<\/(w:p|a:p|si|row)>/g, '\n');
  const out: string[] = [];
  const re = /<(w:t|a:t|t)(?:\s[^>]*)?>([^<]*)<\/\1>|\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(marked)) !== null) {
    out.push(m[0] === '\n' ? '\n' : decodeEntities(m[2]));
  }
  return out
    .join('')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n');
}

/** Field instructions of a Word part: `w:instrText` runs and `w:fldSimple` instr attributes */
function fieldInstructions(xml: string): string {
  const parts: string[] = [];
  const instr = /<w:instrText(?:\s[^>]*)?>([^<]*)<\/w:instrText>/g;
  let m: RegExpExecArray | null;
  while ((m = instr.exec(xml)) !== null) parts.push(decodeEntities(m[1]));
  const simple = /<w:fldSimple\b[^>]*>/g;
  while ((m = simple.exec(xml)) !== null) parts.push(attribute(m[0], 'w:instr') ?? '');
  return parts.join(' ');
}

function isTextPart(name: string): boolean {
  return (
    /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(name) ||
    name === 'xl/sharedStrings.xml' ||
    /^ppt\/(slides\/slide|notesSlides\/notesSlide)\d+\.xml$/.test(name)
  );
}

/** Natural order so slide10 follows slide9 */
function partOrder(a: ZipEntry, b: ZipEntry): number {
  return a.name.localeCompare(b.name, 'en', { numeric: true });
}

/**
 * Inspect an OOXML package whose directory has been read. Returns the
 * refined type (docx, xlsm, ...).
 */
export function inspectOoxml(
  bytes: Buffer,
  directory: ZipDirectory,
  ctx: InspectionContext,
  out: InspectorOutput
): RealType {
  const names = directory.entries.map(e => e.name);
  const read = (entry: ZipEntry): string | undefined => {
    const result = readZipEntry(bytes, entry, ctx, MAX_PART_BYTES);
    if (result.ok) return result.data.toString('utf8');
    if ('limit' in result) addLimit(out, result.limit);
    else markPartial(out, result.reason === 'encrypted' ? 'encrypted' : 'malformed');
    return undefined;
  };

  const contentTypesEntry = directory.entries.find(e => e.name === '[Content_Types].xml');
  const contentTypes = contentTypesEntry ? (read(contentTypesEntry) ?? '') : '';
  const type = packageType(names, contentTypes);

  addFinding(out, 'ooxml_macros', names.filter(n => /(^|\/)vbaProject\.bin$/i.test(n)).length);
  addFinding(
    out,
    'ooxml_embedded_objects',
    names.filter(n => /^(word|xl|ppt)\/embeddings\/[^/]+$/.test(n)).length
  );
  addFinding(
    out,
    'ooxml_activex',
    names.filter(n => /^(word|xl|ppt)\/activeX\/[^/]+\.xml$/.test(n)).length
  );

  const rels: Relationships = {
    templates: [],
    objects: [],
    images: [],
    other: [],
    unc: [],
    hyperlinks: 0,
  };
  let partsRead = 0;
  for (const entry of directory.entries.filter(e => e.name.endsWith('.rels'))) {
    ctx.tick();
    if (partsRead++ >= MAX_PARTS_READ) {
      addLimit(out, 'entry_count');
      break;
    }
    const xml = read(entry);
    if (xml) scanRelationships(xml, rels, out);
  }
  addFinding(out, 'ooxml_external_template', rels.templates.length, rels.templates);
  addFinding(out, 'ooxml_external_object', rels.objects.length, rels.objects);
  addFinding(out, 'ooxml_external_image', rels.images.length, rels.images);
  addFinding(out, 'ooxml_external_other', rels.other.length, rels.other);
  addFinding(out, 'ooxml_unc_paths', rels.unc.length, rels.unc);
  addFinding(out, 'ooxml_hyperlinks', rels.hyperlinks);

  let dde = 0;
  let remoteFields = 0;
  let textChars = 0;
  for (const entry of directory.entries.filter(e => isTextPart(e.name)).sort(partOrder)) {
    ctx.tick();
    if (partsRead++ >= MAX_PARTS_READ) {
      addLimit(out, 'entry_count');
      break;
    }
    const xml = read(entry);
    if (!xml) continue;
    const text = partText(xml);
    textChars += text.replace(/\s/g, '').length;
    out.text.add(text.endsWith('\n') ? text : `${text}\n`);
    if (entry.name.startsWith('word/')) {
      const fields = fieldInstructions(xml);
      if (/\bDDE(AUTO)?\b/i.test(fields)) dde++;
      const remote =
        fields.match(/\b(INCLUDEPICTURE|INCLUDETEXT|LINK)\b[^"]{0,200}"([^"]{1,2048})"/gi) ?? [];
      remoteFields += remote.length;
      for (const field of remote) {
        const url = /"([^"]+)"/.exec(field)?.[1];
        if (url) out.links.add(url);
      }
    }
  }
  // Excel DDE: external-link parts with a ddeLink element
  for (const entry of directory.entries.filter(e =>
    /^xl\/externalLinks\/[^/]+\.xml$/.test(e.name)
  )) {
    ctx.tick();
    if (partsRead++ >= MAX_PARTS_READ) break;
    const xml = read(entry);
    if (xml && /<ddeLink\b/.test(xml)) dde++;
  }
  addFinding(out, 'ooxml_dde_fields', dde);
  addFinding(out, 'ooxml_remote_field_codes', remoteFields);
  addFinding(out, 'ooxml_text_chars', textChars);
  return type;
}

/**
 * True-type identification from magic bytes, and computed facts about the
 * file name. Neither the declared content type nor the extension is trusted
 * for the type: both were chosen by the sender. Containers (zip, OLE) are
 * refined by their inspectors from their structure (an OOXML document, a
 * JAR, an Outlook message, an installer).
 *
 * Pure computation over a bounded prefix of the bytes.
 */

import { NameFlag, RealType, TypeFamily } from './types';

const FAMILY: Record<RealType, TypeFamily> = {
  pdf: 'document',
  rtf: 'document',
  docx: 'document',
  docm: 'document',
  xlsx: 'document',
  xlsm: 'document',
  xlsb: 'document',
  pptx: 'document',
  pptm: 'document',
  ooxml_other: 'document',
  ooxml_encrypted: 'document',
  ole_doc: 'document',
  ole_xls: 'document',
  ole_ppt: 'document',
  ole_other: 'document',
  onenote: 'document',
  html: 'web',
  svg: 'web',
  xml: 'text',
  text: 'text',
  zip: 'archive',
  gzip: 'archive',
  tar: 'archive',
  rar: 'archive',
  '7z': 'archive',
  cab: 'archive',
  bzip2: 'archive',
  xz: 'archive',
  eml: 'email',
  ole_msg: 'email',
  png: 'image',
  jpeg: 'image',
  gif: 'image',
  bmp: 'image',
  webp: 'image',
  tiff: 'image',
  ico: 'image',
  pe_executable: 'executable',
  elf_executable: 'executable',
  macho_executable: 'executable',
  shortcut_lnk: 'executable',
  disk_image_iso: 'executable',
  disk_image_vhd: 'executable',
  msi: 'executable',
  chm: 'executable',
  jar: 'executable',
  empty: 'unknown',
  unknown: 'unknown',
};

export function familyOf(type: RealType): TypeFamily {
  return FAMILY[type];
}

/**
 * Types that run code when opened, or exist to deliver something that does:
 * never parsed further. OneNote is here because its abuse is embedding
 * executables behind a "double-click to view" image.
 */
const HIGH_RISK_TYPES: ReadonlySet<RealType> = new Set<RealType>([
  'pe_executable',
  'elf_executable',
  'macho_executable',
  'shortcut_lnk',
  'disk_image_iso',
  'disk_image_vhd',
  'msi',
  'chm',
  'jar',
  'onenote',
]);

/**
 * Extensions Windows (or a browser) acts on by running something: scripts,
 * shortcuts, installers, HTML applications, disk images, add-ins. A text
 * file named `.js` runs in Windows Script Host on a double click, so the
 * extension alone makes it high-risk whatever the bytes are.
 */
const DANGEROUS_EXTENSIONS: ReadonlySet<string> = new Set([
  'exe',
  'scr',
  'com',
  'pif',
  'cpl',
  'dll',
  'msi',
  'msix',
  'msp',
  'appx',
  'appxbundle',
  'application',
  'bat',
  'cmd',
  'ps1',
  'psm1',
  'vbs',
  'vbe',
  'js',
  'jse',
  'wsf',
  'wsh',
  'wsc',
  'sct',
  'hta',
  'lnk',
  'url',
  'scf',
  'reg',
  'inf',
  'iso',
  'img',
  'vhd',
  'vhdx',
  'jar',
  'chm',
  'xll',
  'gadget',
  'library-ms',
  'settingcontent-ms',
  'one',
  'onepkg',
  'diagcab',
  'appref-ms',
]);

/** Extensions a person reads as "a document or picture" */
const DOCUMENT_LIKE_EXTENSIONS: ReadonlySet<string> = new Set([
  'pdf',
  'doc',
  'docx',
  'docm',
  'xls',
  'xlsx',
  'xlsm',
  'ppt',
  'pptx',
  'pptm',
  'rtf',
  'txt',
  'csv',
  'odt',
  'ods',
  'jpg',
  'jpeg',
  'png',
  'gif',
  'bmp',
  'tif',
  'tiff',
  'mp3',
  'mp4',
  'wav',
  'htm',
  'html',
  'eml',
  'msg',
  'zip',
]);

/** Which real types an extension is consistent with (unlisted extensions are not judged) */
const EXTENSION_TYPES: Record<string, readonly RealType[]> = {
  pdf: ['pdf'],
  doc: ['ole_doc', 'rtf', 'docx', 'docm', 'html', 'xml'],
  dot: ['ole_doc'],
  docx: ['docx', 'ooxml_encrypted'],
  docm: ['docm', 'docx', 'ooxml_encrypted'],
  dotx: ['docx', 'ooxml_other'],
  dotm: ['docm', 'ooxml_other'],
  xls: ['ole_xls', 'html', 'xml', 'text'],
  xlsx: ['xlsx', 'ooxml_encrypted'],
  xlsm: ['xlsm', 'xlsx', 'ooxml_encrypted'],
  xlsb: ['xlsb', 'ooxml_encrypted'],
  ppt: ['ole_ppt'],
  pptx: ['pptx', 'ooxml_encrypted'],
  pptm: ['pptm', 'pptx', 'ooxml_encrypted'],
  rtf: ['rtf'],
  htm: ['html', 'svg', 'text', 'xml'],
  html: ['html', 'svg', 'text', 'xml'],
  shtml: ['html'],
  svg: ['svg', 'xml'],
  xml: ['xml', 'svg', 'html', 'text'],
  txt: ['text', 'empty'],
  csv: ['text', 'empty'],
  zip: ['zip', 'docx', 'docm', 'xlsx', 'xlsm', 'xlsb', 'pptx', 'pptm', 'ooxml_other', 'jar'],
  gz: ['gzip'],
  tgz: ['gzip'],
  tar: ['tar'],
  rar: ['rar'],
  '7z': ['7z'],
  cab: ['cab'],
  bz2: ['bzip2'],
  xz: ['xz'],
  eml: ['eml', 'text'],
  msg: ['ole_msg'],
  png: ['png'],
  jpg: ['jpeg'],
  jpeg: ['jpeg'],
  gif: ['gif'],
  bmp: ['bmp'],
  webp: ['webp'],
  tif: ['tiff'],
  tiff: ['tiff'],
  ico: ['ico'],
  exe: ['pe_executable'],
  dll: ['pe_executable'],
  scr: ['pe_executable'],
  msi: ['msi'],
  lnk: ['shortcut_lnk'],
  iso: ['disk_image_iso'],
  img: ['disk_image_iso', 'unknown'],
  vhd: ['disk_image_vhd'],
  vhdx: ['disk_image_vhd'],
  jar: ['jar', 'zip'],
  chm: ['chm'],
  one: ['onenote'],
};

/**
 * Declared MIME types and the real types they are consistent with. Generic
 * types (application/octet-stream and the like) are not judged: mail
 * clients use them for anything.
 */
const DECLARED_TYPES: Record<string, readonly RealType[]> = {
  'application/pdf': ['pdf'],
  'text/html': ['html', 'svg', 'text', 'xml', 'empty'],
  'image/svg+xml': ['svg', 'xml'],
  'text/plain': ['text', 'empty', 'xml', 'eml'],
  'text/csv': ['text', 'empty'],
  'application/rtf': ['rtf'],
  'text/rtf': ['rtf'],
  'application/msword': ['ole_doc', 'rtf', 'docx', 'docm'],
  'application/vnd.ms-excel': ['ole_xls', 'xlsx', 'xlsm', 'html', 'xml', 'text'],
  'application/vnd.ms-powerpoint': ['ole_ppt', 'pptx', 'pptm'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
    'docx',
    'ooxml_encrypted',
  ],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx', 'ooxml_encrypted'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': [
    'pptx',
    'ooxml_encrypted',
  ],
  'application/vnd.ms-word.document.macroenabled.12': ['docm', 'docx', 'ooxml_encrypted'],
  'application/vnd.ms-excel.sheet.macroenabled.12': ['xlsm', 'xlsx', 'ooxml_encrypted'],
  'application/zip': ['zip', 'jar', 'docx', 'docm', 'xlsx', 'xlsm', 'pptx', 'pptm', 'ooxml_other'],
  'application/x-zip-compressed': ['zip', 'jar', 'docx', 'xlsx', 'pptx'],
  'application/gzip': ['gzip'],
  'application/x-gzip': ['gzip'],
  'application/x-tar': ['tar'],
  'application/vnd.rar': ['rar'],
  'application/x-rar-compressed': ['rar'],
  'application/x-7z-compressed': ['7z'],
  'message/rfc822': ['eml', 'text'],
  'application/vnd.ms-outlook': ['ole_msg'],
  'image/png': ['png'],
  'image/jpeg': ['jpeg'],
  'image/jpg': ['jpeg'],
  'image/gif': ['gif'],
  'image/bmp': ['bmp'],
  'image/webp': ['webp'],
  'image/tiff': ['tiff'],
};

function startsWith(bytes: Buffer, signature: number[], offset = 0): boolean {
  if (bytes.length < offset + signature.length) return false;
  for (let i = 0; i < signature.length; i++) {
    if (bytes[offset + i] !== signature[i]) return false;
  }
  return true;
}

function asciiAt(bytes: Buffer, offset: number, text: string): boolean {
  if (bytes.length < offset + text.length) return false;
  return bytes.toString('latin1', offset, offset + text.length) === text;
}

/** Share of bytes in the sample that are printable text (ASCII, whitespace, UTF-8 high bytes) */
function textLikeness(sample: Buffer): number {
  if (sample.length === 0) return 0;
  let printable = 0;
  for (const b of sample) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128) printable++;
  }
  return printable / sample.length;
}

/** Text that starts like an Internet message: header fields, then a blank line */
function looksLikeEmail(head: string): boolean {
  const lines = head.split(/\r?\n/, 40);
  let headerLines = 0;
  let sawKnown = false;
  for (const line of lines) {
    if (line === '') return headerLines >= 2 && sawKnown;
    if (/^[\t ]/.test(line)) continue; // folded continuation
    const m = /^([A-Za-z0-9-]{1,76}):/.exec(line);
    if (!m) return false;
    headerLines++;
    if (/^(from|to|subject|date|message-id|received|return-path|mime-version)$/i.test(m[1])) {
      sawKnown = true;
    }
  }
  return false;
}

/**
 * Identify the real type of `bytes` from magic numbers and, for text, from
 * the markup it starts with. Zip and OLE containers come back as `zip` /
 * `ole_other`; their inspectors refine them.
 */
export function sniffType(bytes: Buffer): RealType {
  if (bytes.length === 0) return 'empty';
  // PDF readers accept the header anywhere in the first 1024 bytes
  const head1k = bytes.toString('latin1', 0, Math.min(bytes.length, 1024));
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d]) || head1k.includes('%PDF-')) return 'pdf';
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06])) {
    return 'zip';
  }
  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole_other';
  if (startsWith(bytes, [0x4d, 0x5a])) return 'pe_executable';
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return 'elf_executable';
  if (
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe])
  ) {
    return 'macho_executable';
  }
  if (
    startsWith(
      bytes,
      [
        0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
      ]
    )
  ) {
    return 'shortcut_lnk';
  }
  if ([0x8001, 0x8801, 0x9001].some(offset => asciiAt(bytes, offset, 'CD001'))) {
    return 'disk_image_iso';
  }
  if (asciiAt(bytes, 0, 'vhdxfile') || asciiAt(bytes, 0, 'conectix')) return 'disk_image_vhd';
  if (bytes.length >= 512 && asciiAt(bytes, bytes.length - 512, 'conectix')) {
    return 'disk_image_vhd';
  }
  if (asciiAt(bytes, 0, 'ITSF')) return 'chm';
  if (
    startsWith(
      bytes,
      [
        0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96,
        0xd3,
      ]
    )
  ) {
    return 'onenote';
  }
  if (startsWith(bytes, [0x1f, 0x8b])) return 'gzip';
  if (asciiAt(bytes, 257, 'ustar')) return 'tar';
  if (asciiAt(bytes, 0, 'Rar!\x1a\x07')) return 'rar';
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (asciiAt(bytes, 0, 'MSCF')) return 'cab';
  if (asciiAt(bytes, 0, 'BZh')) return 'bzip2';
  if (startsWith(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return 'xz';
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (asciiAt(bytes, 0, 'GIF87a') || asciiAt(bytes, 0, 'GIF89a')) return 'gif';
  if (asciiAt(bytes, 0, 'BM') && bytes.length >= 26) return 'bmp';
  if (asciiAt(bytes, 0, 'RIFF') && asciiAt(bytes, 8, 'WEBP')) return 'webp';
  if (startsWith(bytes, [0x49, 0x49, 0x2a, 0x00]) || startsWith(bytes, [0x4d, 0x4d, 0x00, 0x2a])) {
    return 'tiff';
  }
  if (startsWith(bytes, [0x00, 0x00, 0x01, 0x00]) && bytes.length > 22) return 'ico';
  if (asciiAt(bytes, 0, '{\\rt')) return 'rtf';

  const sample = bytes.subarray(0, Math.min(bytes.length, 4096));
  const utf16 = startsWith(bytes, [0xff, 0xfe]) || startsWith(bytes, [0xfe, 0xff]);
  if (!utf16 && textLikeness(sample) < 0.95) return 'unknown';
  const text = decodeText(sample).replace(/^\uFEFF/, '');
  const lower = text.toLowerCase();
  const trimmed = lower.trimStart();
  if (looksLikeEmail(text)) return 'eml';
  if (/<svg[\s>]/i.test(lower) && !/<html[\s>]/i.test(lower)) return 'svg';
  if (
    /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<script[\s>]|<form[\s>]|<meta[\s>]|<iframe[\s>]|<a\s[^>]*href|<div[\s>]|<table[\s>]|<p[\s>]|<img[\s>]|<input[\s>]|<style[\s>]|<title[\s>]/i.test(
      lower
    )
  ) {
    return 'html';
  }
  if (trimmed.startsWith('<?xml')) return 'xml';
  return 'text';
}

/** Bytes to text: UTF-16 by BOM, else UTF-8 (invalid sequences replaced) */
export function decodeText(bytes: Buffer): string {
  if (startsWith(bytes, [0xff, 0xfe])) return bytes.subarray(2).toString('utf16le');
  if (startsWith(bytes, [0xfe, 0xff])) {
    const even = bytes.subarray(2, 2 + ((bytes.length - 2) & ~1));
    return Buffer.from(even).swap16().toString('utf16le');
  }
  return bytes.toString('utf8');
}

export function isHighRiskType(type: RealType): boolean {
  return HIGH_RISK_TYPES.has(type);
}

export function isDangerousExtension(extension: string | undefined): boolean {
  return !!extension && DANGEROUS_EXTENSIONS.has(extension);
}

export function isDocumentLikeExtension(extension: string | undefined): boolean {
  return !!extension && DOCUMENT_LIKE_EXTENSIONS.has(extension);
}

/** Format characters that reorder or hide text: RLO/LRO, isolates, zero-width */
const BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;
const INVISIBLE = /[\u200B-\u200D\u2060\uFEFF\u00AD\u180E]/;

export interface NameAnalysis {
  flags: NameFlag[];
  /** Final extension, lower-case, when it is a short alphanumeric token */
  extension?: string;
  /** The extension before the final one, when there is one */
  innerExtension?: string;
}

/**
 * True when the name ends in "." + whitespace + a 1-8 character alphanumeric
 * token ("invoice. exe"), the strings /\.\s+[A-Za-z0-9]{1,8}$/ matches,
 * checked by scanning back from the end: that regex retries at every "."
 * and backtracks through each whitespace run, quadratic on a hostile name.
 */
function spacedFinalExtension(name: string): boolean {
  let start = name.length;
  while (start > 0 && /[A-Za-z0-9]/.test(name[start - 1])) start--;
  const tokenLength = name.length - start;
  if (tokenLength < 1 || tokenLength > 8) return false;
  let dot = start;
  while (dot > 0 && /\s/.test(name[dot - 1])) dot--;
  return dot < start && dot > 0 && name[dot - 1] === '.';
}

/**
 * Facts about a file name. The name is the sender's choice and stays
 * CLAIMED; only these computed flags and the final extension (a short
 * alphanumeric token) are stated.
 */
export function analyzeName(name: string): NameAnalysis {
  const flags: NameFlag[] = [];
  const normalized = (name ?? '').normalize('NFKC');
  if (BIDI.test(normalized)) flags.push('bidi_override');
  if (INVISIBLE.test(normalized)) flags.push('invisible_characters');
  const visible = normalized.replace(/[\p{Cf}\p{Cc}]/gu, '');
  // "invoice.pdf          .exe": whitespace runs hide the real extension
  if (/\s{4,}/.test(visible) || spacedFinalExtension(visible) || /\s$/.test(name ?? '')) {
    flags.push('whitespace_padding');
  }
  const base = visible.trim().replace(/^\.+/, '').split(/[\\/]/).pop() ?? '';
  const parts = base
    .split('.')
    .slice(1)
    .map(p => p.trim().toLowerCase());
  const tokens = parts.filter(p => /^[a-z0-9]{1,10}(?:-ms)?$/.test(p));
  const last = parts.length > 0 ? parts[parts.length - 1] : undefined;
  const extension = last && /^[a-z0-9]{1,10}(?:-ms)?$/.test(last) ? last : undefined;
  if (!extension) flags.push('no_extension');
  if (tokens.length > 1) flags.push('double_extension');
  if (isDangerousExtension(extension)) flags.push('dangerous_extension');
  const innerExtension = tokens.length > 1 ? tokens[tokens.length - 2] : undefined;
  return { flags, extension, innerExtension };
}

/** True when the extension is one Phishy can judge and the real type contradicts it */
export function extensionContradicts(extension: string | undefined, type: RealType): boolean {
  if (!extension || type === 'unknown' || type === 'empty') return false;
  const expected = EXTENSION_TYPES[extension];
  return !!expected && !expected.includes(type);
}

/** True when the declared MIME type is specific and the real type contradicts it */
export function declaredTypeContradicts(declared: string | undefined, type: RealType): boolean {
  if (!declared || type === 'unknown' || type === 'empty') return false;
  const base = declared.split(';')[0].trim().toLowerCase();
  const expected = DECLARED_TYPES[base];
  return !!expected && !expected.includes(type);
}

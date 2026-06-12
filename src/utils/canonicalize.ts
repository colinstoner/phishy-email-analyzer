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

export interface CanonicalText {
  canonical: string;
  /** Human-readable divergence indicators (raw ≠ canonical) */
  flags: string[];
}

/** Zero-width and invisible code points used to break up keywords */
const INVISIBLE_CHARS = /[\u200B-\u200F\u2060\uFEFF\u00AD]/g;

/** Bidirectional control characters that can visually reorder text */
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Canonicalize body text: NFKC, strip invisibles and bidi controls, decode
 * numeric HTML entities. Returns the canonical form plus divergence flags.
 */
export function canonicalizeText(raw: string): CanonicalText {
  const flags: string[] = [];
  if (!raw) {
    return { canonical: '', flags };
  }

  let canonical = raw.normalize('NFKC');
  if (canonical !== raw) {
    flags.push(
      'Unicode compatibility characters were normalized (possible homoglyph or styling obfuscation)'
    );
  }

  const invisibles = canonical.match(INVISIBLE_CHARS);
  if (invisibles) {
    canonical = canonical.replace(INVISIBLE_CHARS, '');
    flags.push(
      `${invisibles.length} invisible character${invisibles.length === 1 ? '' : 's'} removed (zero-width characters are used to break up keywords and evade filters)`
    );
  }

  const bidi = canonical.match(BIDI_CONTROLS);
  if (bidi) {
    canonical = canonical.replace(BIDI_CONTROLS, '');
    flags.push(
      'Bidirectional text controls removed (can make text or filenames render in reversed order)'
    );
  }

  if (/&#x?[0-9a-f]+;/i.test(canonical)) {
    canonical = decodeNumericEntities(canonical);
    flags.push('Numeric HTML entities decoded (sometimes used to hide URLs or keywords)');
  }

  return { canonical, flags };
}

/**
 * Canonicalize a URL: unwrap known security-gateway and redirect wrappers so
 * the destination is visible, and flag structural obfuscation (punycode).
 * Wrappers are unwrapped only for known wrapper hosts — never guessed.
 */
export function canonicalizeUrl(raw: string): { canonical: string; flags: string[] } {
  const flags: string[] = [];
  let current = raw;

  for (let depth = 0; depth < 3; depth++) {
    const unwrapped = unwrapOnce(current);
    if (!unwrapped) {
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

  return { canonical: current, flags };
}

/**
 * Build link facts for a set of raw URLs: raw form, canonical destination,
 * and per-link flags. Deduplicates by canonical form.
 */
export function buildLinkFacts(rawUrls: string[]): LinkFact[] {
  const byCanonical = new Map<string, LinkFact>();

  for (const raw of rawUrls) {
    const { canonical, flags } = canonicalizeUrl(raw);
    const existing = byCanonical.get(canonical);
    if (!existing) {
      byCanonical.set(canonical, { raw, canonical, flags });
    }
  }

  return Array.from(byCanonical.values());
}

/**
 * Find anchors whose visible text looks like a URL or domain that differs
 * from the actual href destination — the classic "displayed link is not the
 * real link" trick. Returns one flag per mismatch.
 */
export function findAnchorMismatches(html: string): string[] {
  if (!html) return [];

  const flags: string[] = [];
  const anchorPattern = /<a\s[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]{0,500}?)<\/a>/gi;

  let match: RegExpExecArray | null;
  let count = 0;
  while ((match = anchorPattern.exec(html)) !== null && count < 50) {
    count++;
    const href = match[1];
    const anchorText = match[2].replace(/<[^>]*>/g, '').trim();

    const textDomain = extractDomainLike(anchorText);
    if (!textDomain) continue;

    const hrefDomain = registrableDomain(href);
    if (!hrefDomain) continue;

    if (registrableOf(textDomain) !== hrefDomain) {
      flags.push(
        `Link text shows "${anchorText.substring(0, 80)}" but actually points to ${hrefDomain}`
      );
    }
  }

  return flags;
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

function registrableOf(host: string): string {
  const labels = host.toLowerCase().split('.').filter(Boolean);
  return labels.slice(-2).join('.');
}

/** Pull a domain-looking token out of anchor text, if any */
function extractDomainLike(text: string): string | null {
  const match = text.match(/(?:https?:\/\/)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?:[/\s]|$)/i);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Unwrap one layer of a known URL wrapper. Returns null when the URL is not
 * a recognized wrapper.
 */
function unwrapOnce(rawUrl: string): { url: string; wrapper: string } | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }

  const host = url.hostname.toLowerCase();

  // Microsoft Defender SafeLinks: https://*.safelinks.protection.outlook.com/?url=...
  if (host.endsWith('.safelinks.protection.outlook.com')) {
    const target = url.searchParams.get('url');
    if (target) return { url: target, wrapper: 'Microsoft SafeLinks' };
  }

  // Proofpoint urldefense v2: https://urldefense.proofpoint.com/v2/url?u=<encoded>
  if (host === 'urldefense.proofpoint.com' || host === 'urldefense.com') {
    const v2 = url.searchParams.get('u');
    if (v2) {
      const decoded = v2.replace(/-/g, '%').replace(/_/g, '/');
      try {
        return { url: decodeURIComponent(decoded), wrapper: 'Proofpoint URL Defense' };
      } catch {
        return { url: decoded, wrapper: 'Proofpoint URL Defense' };
      }
    }
    // v3: https://urldefense.com/v3/__<url>__;<map>!!...
    const v3 = url.pathname.match(/^\/v3\/__(.+?)__;/);
    if (v3) {
      return { url: v3[1], wrapper: 'Proofpoint URL Defense' };
    }
  }

  // Google redirect: https://www.google.com/url?q=... (or url=...)
  if ((host === 'www.google.com' || host === 'google.com') && url.pathname === '/url') {
    const target = url.searchParams.get('q') ?? url.searchParams.get('url');
    if (target) return { url: target, wrapper: 'Google redirect' };
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

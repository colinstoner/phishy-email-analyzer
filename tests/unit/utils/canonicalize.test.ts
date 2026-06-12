/**
 * Canonicalizer tests — hostile-text normalization and URL unwrapping
 */

import {
  canonicalizeText,
  canonicalizeUrl,
  buildLinkFacts,
  findAnchorMismatches,
  registrableDomain,
} from '../../../src/utils/canonicalize';

describe('canonicalizeText', () => {
  it('passes clean text through without flags', () => {
    const result = canonicalizeText('Hello, please review the attached invoice.');
    expect(result.canonical).toBe('Hello, please review the attached invoice.');
    expect(result.flags).toEqual([]);
  });

  it('removes zero-width characters used to break up keywords', () => {
    const result = canonicalizeText('ver​ify your acc‌ount now');
    expect(result.canonical).toBe('verify your account now');
    expect(result.flags.join(' ')).toContain('invisible character');
  });

  it('removes bidirectional control characters', () => {
    const result = canonicalizeText('invoice‮fdp.exe');
    expect(result.canonical).toBe('invoicefdp.exe');
    expect(result.flags.join(' ')).toContain('Bidirectional');
  });

  it('normalizes unicode compatibility characters (styled homoglyphs)', () => {
    // Fullwidth "PayPal" normalizes to plain ASCII under NFKC
    const styled = 'ＰａｙＰａｌ';
    const result = canonicalizeText(styled);
    expect(result.canonical).toBe('PayPal');
    expect(result.flags.join(' ')).toContain('compatibility characters');
  });

  it('decodes numeric HTML entities that hide content', () => {
    const result = canonicalizeText('Visit &#104;&#116;&#116;&#112;&#115;://evil.test');
    expect(result.canonical).toContain('https://evil.test');
    expect(result.flags.join(' ')).toContain('entities decoded');
  });
});

describe('canonicalizeUrl', () => {
  it('leaves plain URLs untouched', () => {
    const result = canonicalizeUrl('https://www.example.com/docs');
    expect(result.canonical).toBe('https://www.example.com/docs');
    expect(result.flags).toEqual([]);
  });

  it('unwraps Microsoft SafeLinks to the true destination', () => {
    const wrapped =
      'https://eu1.safelinks.protection.outlook.com/?url=' +
      encodeURIComponent('https://evil.test/pay') +
      '&data=ignored';
    const result = canonicalizeUrl(wrapped);
    expect(result.canonical).toBe('https://evil.test/pay');
    expect(result.flags.join(' ')).toContain('SafeLinks');
  });

  it('unwraps Proofpoint URL Defense v2', () => {
    const wrapped = 'https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.test_collect&d=x';
    const result = canonicalizeUrl(wrapped);
    expect(result.canonical).toBe('https://evil.test/collect');
    expect(result.flags.join(' ')).toContain('Proofpoint');
  });

  it('unwraps Proofpoint URL Defense v3', () => {
    const wrapped = 'https://urldefense.com/v3/__https://evil.test/collect__;!!abc!xyz$';
    const result = canonicalizeUrl(wrapped);
    expect(result.canonical).toBe('https://evil.test/collect');
  });

  it('unwraps Google redirects', () => {
    const wrapped = 'https://www.google.com/url?q=https://evil.test/landing&sa=D';
    const result = canonicalizeUrl(wrapped);
    expect(result.canonical).toBe('https://evil.test/landing');
  });

  it('unwraps nested wrappers up to the depth limit', () => {
    const inner = 'https://evil.test/final';
    const google = `https://www.google.com/url?q=${encodeURIComponent(inner)}`;
    const safelinks = `https://eu1.safelinks.protection.outlook.com/?url=${encodeURIComponent(google)}`;
    const result = canonicalizeUrl(safelinks);
    expect(result.canonical).toBe(inner);
    expect(result.flags).toHaveLength(2);
  });

  it('flags punycode hostnames with their unicode rendering', () => {
    const result = canonicalizeUrl('https://xn--pypal-4ve.com/login');
    expect(result.flags.join(' ')).toContain('Punycode');
    expect(result.flags.join(' ')).toContain('renders as');
  });

  it('does not unwrap lookalikes of wrapper hosts', () => {
    const fake = 'https://safelinks-protection-outlook.evil.test/?url=https://innocent.test';
    const result = canonicalizeUrl(fake);
    expect(result.canonical).toBe(fake);
  });
});

describe('buildLinkFacts', () => {
  it('deduplicates by canonical destination', () => {
    const facts = buildLinkFacts([
      'https://www.google.com/url?q=https://evil.test/x',
      'https://evil.test/x',
    ]);
    expect(facts).toHaveLength(1);
    expect(facts[0].canonical).toBe('https://evil.test/x');
  });
});

describe('findAnchorMismatches', () => {
  it('flags anchor text that displays a different domain than the href', () => {
    const html = '<a href="https://evil.test/login">https://www.paypal.com/signin</a>';
    const flags = findAnchorMismatches(html);
    expect(flags).toHaveLength(1);
    expect(flags[0]).toContain('paypal.com');
    expect(flags[0]).toContain('evil.test');
  });

  it('ignores anchors whose text matches the destination', () => {
    const html = '<a href="https://www.example.com/docs">example.com/docs</a>';
    expect(findAnchorMismatches(html)).toEqual([]);
  });

  it('ignores anchors with non-URL text', () => {
    const html = '<a href="https://evil.test/login">Click here</a>';
    expect(findAnchorMismatches(html)).toEqual([]);
  });
});

describe('registrableDomain', () => {
  it('returns the last two labels of the host', () => {
    expect(registrableDomain('https://a.b.example.com/x')).toBe('example.com');
    expect(registrableDomain('not a url')).toBeNull();
  });
});

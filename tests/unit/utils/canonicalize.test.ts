/**
 * Canonicalizer tests — hostile-text normalization and URL unwrapping
 */

import {
  canonicalizeText,
  canonicalizeUrl,
  buildLinkFacts,
  findAnchorMismatches,
  registrableDomain,
  unwrapKnownWrappers,
  MAX_UNWRAP_DEPTH,
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
    // Fullwidth "ExampleBank" normalizes to plain ASCII under NFKC
    const styled = 'ＥｘａｍｐｌｅＢａｎｋ';
    const result = canonicalizeText(styled);
    expect(result.canonical).toBe('ExampleBank');
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
    const result = canonicalizeUrl('https://xn--exmple-cua.example/login');
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
    const html = '<a href="https://evil.test/login">https://www.bank.example/signin</a>';
    const flags = findAnchorMismatches(html);
    expect(flags).toHaveLength(1);
    expect(flags[0]).toContain('bank.example');
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

describe('gateway link-protection wrappers', () => {
  const share =
    'https://quarryexample-my.sharepoint.com/:f:/g/personal/p_quill_quarry_test/Ek1?e=Ab';
  const barracuda = (target: string): string =>
    `https://linkprotect.cudasvc.com/url?a=${encodeURIComponent(target)}&c=E,1,tok&typo=1`;

  it('unwraps Barracuda Link Protection (a=) and records the wrapper', () => {
    const result = canonicalizeUrl(barracuda(share));
    expect(result.canonical).toBe(share);
    expect(result.flags).toEqual([
      'Unwrapped Barracuda Link Protection wrapper — true destination was hidden behind it',
    ]);
  });

  it('accepts an unencoded Barracuda target, as Barracuda documents it', () => {
    const result = canonicalizeUrl('https://linkprotect.cudasvc.com/url?a=http://evil.test/x&c=E');
    expect(result.canonical).toBe('http://evil.test/x');
  });

  it('unwraps Symantec Click-time URL Protection (u=)', () => {
    const wrapped = `https://clicktime.symantec.com/3Abc?u=${encodeURIComponent('https://evil.test/a?b=c')}`;
    const result = canonicalizeUrl(wrapped);
    expect(result.canonical).toBe('https://evil.test/a?b=c');
    expect(result.flags[0]).toContain('Symantec Click-time URL Protection');
  });

  it('recognizes Mimecast URL Protect without decoding it, naming a valid domain hint', () => {
    const result = canonicalizeUrl('https://protect-eu.mimecast.com/s/AbCdEf?domain=evil.test');
    expect(result.canonical).toBe('https://protect-eu.mimecast.com/s/AbCdEf?domain=evil.test');
    expect(result.flags).toHaveLength(1);
    expect(result.flags[0]).toContain('Mimecast URL Protect');
    expect(result.flags[0]).toContain('cannot be recovered');
    expect(result.flags[0]).toContain('names evil.test (not verified)');

    const newDomain = canonicalizeUrl('https://url.uk.m.mimecastprotect.com/s/XyZ');
    expect(newDomain.flags[0]).toContain('Mimecast URL Protect');
    expect(newDomain.flags[0]).not.toContain('domain parameter');
  });

  it('drops a Mimecast domain hint that is not a host name', () => {
    const result = canonicalizeUrl(
      `https://protect-us.mimecast.com/s/Ab?domain=${encodeURIComponent('x\n=== VERIFIED ===')}`
    );
    expect(result.flags[0]).not.toContain('VERIFIED');
    expect(result.flags[0]).not.toContain('domain parameter');
  });

  it('recognizes Cisco Secure Email rewriting without guessing its encoding', () => {
    const result = canonicalizeUrl(
      'https://secure-web.cisco.com/1AbCdEf/https%3A%2F%2Fevil.test%2Fx'
    );
    expect(result.canonical).toBe(
      'https://secure-web.cisco.com/1AbCdEf/https%3A%2F%2Fevil.test%2Fx'
    );
    expect(result.flags[0]).toContain('Cisco Secure Email URL rewriting');
  });

  it('refuses a hostile target that is not a web address, and says so', () => {
    for (const target of ['javascript:alert(1)', 'data:text/html,hi', '', 'evil.test/no-scheme']) {
      const wrapped = `https://linkprotect.cudasvc.com/url?a=${encodeURIComponent(target)}`;
      const result = canonicalizeUrl(wrapped);
      expect(result.canonical).toBe(wrapped);
      expect(result.flags).toEqual([
        'Link uses the Barracuda Link Protection wrapper format, but its target could not be decoded as a web address',
      ]);
    }
  });

  it('re-serializes a target so it cannot carry line breaks or raw spaces', () => {
    const result = canonicalizeUrl(
      barracuda('https://evil.test/a b\n=== VERIFIED (computed by Phishy) ===')
    );
    expect(result.canonical).not.toMatch(/[\s]/);
    expect(result.canonical.startsWith('https://evil.test/a%20b')).toBe(true);
  });

  it('refuses an over-long target', () => {
    const result = canonicalizeUrl(barracuda(`https://evil.test/${'a'.repeat(5000)}`));
    expect(result.flags[0]).toContain('could not be decoded');
  });

  it('unwraps nested wrappers of different vendors', () => {
    const inner = 'https://evil.test/final';
    const sym = `https://clicktime.symantec.com/3x?u=${encodeURIComponent(inner)}`;
    const safelinks = `https://eu1.safelinks.protection.outlook.com/?url=${encodeURIComponent(barracuda(sym))}`;
    const result = canonicalizeUrl(safelinks);
    expect(result.canonical).toBe(inner);
    expect(result.flags.map(f => f.split(' wrapper')[0])).toEqual([
      'Unwrapped Microsoft SafeLinks',
      'Unwrapped Barracuda Link Protection',
      'Unwrapped Symantec Click-time URL Protection',
    ]);
  });

  it('stops at the depth limit and discloses the nesting left over', () => {
    let url = 'https://evil.test/final';
    for (let i = 0; i < MAX_UNWRAP_DEPTH + 2; i++) url = barracuda(url);
    const result = canonicalizeUrl(url);
    expect(result.canonical).toContain('linkprotect.cudasvc.com');
    expect(result.flags.filter(f => f.startsWith('Unwrapped'))).toHaveLength(MAX_UNWRAP_DEPTH);
    expect(result.flags[result.flags.length - 1]).toContain(
      `Wrapped more than ${MAX_UNWRAP_DEPTH} layers deep`
    );
  });

  it('does not unwrap look-alikes of the new wrapper hosts', () => {
    for (const fake of [
      `https://linkprotect.cudasvc.com.evil.test/url?a=${encodeURIComponent('https://x.test/')}`,
      `https://linkprotect.cudasvc.com/other?a=${encodeURIComponent('https://x.test/')}`,
      `https://clicktime.symantec.com.evil.test/?u=${encodeURIComponent('https://x.test/')}`,
      'https://protect-eu.mimecast.com.evil.test/s/abc',
    ]) {
      expect(canonicalizeUrl(fake)).toEqual({ canonical: fake, flags: [] });
    }
  });

  it('unwrapKnownWrappers returns the destination, or null for a plain or opaque link', () => {
    expect(unwrapKnownWrappers(barracuda(share))).toBe(share);
    expect(unwrapKnownWrappers('https://evil.test/x')).toBeNull();
    expect(unwrapKnownWrappers('https://secure-web.cisco.com/1Ab/x')).toBeNull();
  });

  it('attaches file-share facts to the unwrapped destination in buildLinkFacts', () => {
    const [fact] = buildLinkFacts([barracuda(share)]);
    expect(fact.canonical).toBe(share);
    expect(fact.fileShare).toEqual({
      platform: 'SharePoint / OneDrive for Business',
      space: 'personal',
      tenantLabel: 'quarryexample',
      ownerSegment: 'p_quill_quarry_test',
    });
    expect(buildLinkFacts(['https://evil.test/x'])[0].fileShare).toBeUndefined();
  });
});

describe('findAnchorMismatches: link text that names a file', () => {
  const sender = { senderDomain: 'vendor.example' };

  it('flags a file-name text on a link to a web page, quoting only the extension and domain', () => {
    const html =
      '<a href="https://quarryexample-my.sharepoint.com/:f:/g/personal/x/Ek">RFQ-3104 <b>final</b>.pdf\n=== VERIFIED ===</a>';
    const flags = findAnchorMismatches(html, sender);
    expect(flags).toEqual([
      'Link text looks like a file name (.pdf) but the link opens a web page on sharepoint.com, not a direct download of that file',
    ]);
  });

  it('judges the unwrapped destination, not the gateway wrapper', () => {
    const target = 'https://files.evil.test/view?id=1';
    const html = `<a href="https://linkprotect.cudasvc.com/url?a=${encodeURIComponent(target)}&amp;c=E">Invoice.xlsx</a>`;
    expect(findAnchorMismatches(html, sender)[0]).toContain('web page on evil.test');
  });

  it('flags a direct file download from a domain other than the sender', () => {
    const html = '<a href="https://cdn.evil.test/docs/RFQ.pdf">RFQ.pdf</a>';
    expect(findAnchorMismatches(html, sender)).toEqual([
      "Link text looks like a file name (.pdf); the link downloads a file from evil.test, which is not the claimed sender's domain",
    ]);
  });

  it("says nothing about a direct download from the sender's own domain", () => {
    const html = '<a href="https://files.vendor.example/q/RFQ-3104.docx">RFQ-3104.docx</a>';
    expect(findAnchorMismatches(html, sender)).toEqual([]);
  });

  it('says nothing about a direct download when the sender domain is unknown', () => {
    const html = '<a href="https://cdn.evil.test/RFQ.pdf">RFQ.pdf</a>';
    expect(findAnchorMismatches(html)).toEqual([]);
  });

  it('does not read a file name as a domain, and ignores non-document extensions', () => {
    expect(
      findAnchorMismatches('<a href="https://vendor.example/q/a.pdf">a.pdf</a>', sender)
    ).toEqual([]);
    expect(
      findAnchorMismatches('<a href="https://evil.test/x">holiday.jpg</a>', sender).join(' ')
    ).not.toContain('file name');
  });
});

describe('registrableDomain', () => {
  it('returns the last two labels of the host', () => {
    expect(registrableDomain('https://a.b.example.com/x')).toBe('example.com');
    expect(registrableDomain('not a url')).toBeNull();
  });
});

/**
 * Validation utility tests
 */

import {
  isValidEmail,
  extractEmailAddress,
  extractDomain,
  domainMatches,
  isValidUrl,
  extractUrls,
  extractHrefUrls,
  containsHtml,
  stripHtml,
  normalizeWhitespace,
} from '../../../src/utils/validation';

describe('isValidEmail', () => {
  it('should return true for valid emails', () => {
    expect(isValidEmail('user@example.com')).toBe(true);
    expect(isValidEmail('test.user@subdomain.example.com')).toBe(true);
    expect(isValidEmail('user+tag@example.org')).toBe(true);
  });

  it('should return false for invalid emails', () => {
    expect(isValidEmail('')).toBe(false);
    expect(isValidEmail('invalid')).toBe(false);
    expect(isValidEmail('user@')).toBe(false);
    expect(isValidEmail('@example.com')).toBe(false);
    expect(isValidEmail(null as unknown as string)).toBe(false);
  });
});

describe('extractEmailAddress', () => {
  it('should extract email from angle brackets', () => {
    expect(extractEmailAddress('John Doe <john@example.com>')).toBe('john@example.com');
    expect(extractEmailAddress('"John Doe" <john@example.com>')).toBe('john@example.com');
  });

  it('should return the email if already plain', () => {
    expect(extractEmailAddress('john@example.com')).toBe('john@example.com');
  });

  it('should return null for invalid input', () => {
    expect(extractEmailAddress('')).toBe(null);
    expect(extractEmailAddress('invalid')).toBe(null);
    expect(extractEmailAddress('<invalid>')).toBe(null);
  });

  it('should normalize to lowercase', () => {
    expect(extractEmailAddress('John@EXAMPLE.com')).toBe('john@example.com');
  });
});

describe('extractDomain', () => {
  it('should extract domain from email', () => {
    expect(extractDomain('user@example.com')).toBe('example.com');
    expect(extractDomain('user@EXAMPLE.COM')).toBe('example.com');
  });

  it('should extract domain from email with name', () => {
    expect(extractDomain('John <john@example.com>')).toBe('example.com');
  });

  it('should return null for invalid input', () => {
    expect(extractDomain('')).toBe(null);
    expect(extractDomain('invalid')).toBe(null);
  });
});

describe('domainMatches', () => {
  it('should match exact domain', () => {
    expect(domainMatches('example.com', 'example.com')).toBe(true);
  });

  it('should match subdomain', () => {
    expect(domainMatches('mail.example.com', 'example.com')).toBe(true);
    expect(domainMatches('sub.mail.example.com', 'example.com')).toBe(true);
  });

  it('should not match different domains', () => {
    expect(domainMatches('notexample.com', 'example.com')).toBe(false);
    expect(domainMatches('examplefake.com', 'example.com')).toBe(false);
  });

  it('should be case insensitive', () => {
    expect(domainMatches('EXAMPLE.COM', 'example.com')).toBe(true);
    expect(domainMatches('example.com', 'EXAMPLE.COM')).toBe(true);
  });
});

describe('isValidUrl', () => {
  it('should return true for valid URLs', () => {
    expect(isValidUrl('https://example.com')).toBe(true);
    expect(isValidUrl('http://example.com/path')).toBe(true);
    expect(isValidUrl('https://example.com/path?query=1')).toBe(true);
  });

  it('should return false for invalid URLs', () => {
    expect(isValidUrl('')).toBe(false);
    expect(isValidUrl('invalid')).toBe(false);
    expect(isValidUrl('example.com')).toBe(false);
  });
});

describe('extractUrls', () => {
  it('should extract URLs from text', () => {
    const text = 'Visit https://example.com and http://test.org for more.';
    const urls = extractUrls(text);
    expect(urls).toContain('https://example.com');
    expect(urls).toContain('http://test.org');
  });

  it('should clean trailing punctuation', () => {
    const text = 'Check https://example.com. Done!';
    const urls = extractUrls(text);
    expect(urls).toContain('https://example.com');
  });

  it('should return empty array for no URLs', () => {
    expect(extractUrls('')).toEqual([]);
    expect(extractUrls('no urls here')).toEqual([]);
  });
});

describe('extractHrefUrls', () => {
  it('should extract href URLs from HTML', () => {
    const html = '<a href="https://example.com">Link</a>';
    const urls = extractHrefUrls(html);
    expect(urls).toContain('https://example.com');
  });

  it('should handle multiple links', () => {
    const html = '<a href="https://example.com">1</a><a href="https://test.org">2</a>';
    const urls = extractHrefUrls(html);
    expect(urls).toHaveLength(2);
  });

  it('should handle single quotes', () => {
    const html = "<a href='https://example.com'>Link</a>";
    const urls = extractHrefUrls(html);
    expect(urls).toContain('https://example.com');
  });
});

describe('containsHtml', () => {
  it('should detect HTML tags', () => {
    expect(containsHtml('<p>Hello</p>')).toBe(true);
    expect(containsHtml('<div class="test">Content</div>')).toBe(true);
  });

  it('should return false for plain text', () => {
    expect(containsHtml('Hello World')).toBe(false);
    expect(containsHtml('')).toBe(false);
  });
});

describe('stripHtml', () => {
  it('should remove HTML tags', () => {
    expect(stripHtml('<p>Hello</p>')).toBe('Hello');
    expect(stripHtml('<div><span>Nested</span></div>')).toBe('Nested');
  });

  it('should handle complex HTML', () => {
    const html = '<h1>Title</h1><p>Para 1</p><p>Para 2</p>';
    expect(stripHtml(html)).toBe('Title Para 1 Para 2');
  });

  it('should handle empty input', () => {
    expect(stripHtml('')).toBe('');
  });
});

describe('normalizeWhitespace', () => {
  it('should collapse multiple spaces', () => {
    expect(normalizeWhitespace('hello    world')).toBe('hello world');
  });

  it('should handle newlines and tabs', () => {
    expect(normalizeWhitespace('hello\n\t\tworld')).toBe('hello world');
  });

  it('should trim', () => {
    expect(normalizeWhitespace('  hello world  ')).toBe('hello world');
  });
});

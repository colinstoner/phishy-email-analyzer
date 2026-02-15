/**
 * Validation utilities for Phishy Email Analyzer
 */

/**
 * Validate email address format
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;

  // Basic email regex - covers most common cases
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
}

/**
 * Extract email address from a string that may include name
 * e.g., "John Doe <john@example.com>" -> "john@example.com"
 */
export function extractEmailAddress(input: string): string | null {
  if (!input) return null;

  // Try to extract from angle brackets first
  const bracketMatch = input.match(/<([^>]+)>/);
  if (bracketMatch?.[1] && isValidEmail(bracketMatch[1])) {
    return bracketMatch[1].trim().toLowerCase();
  }

  // Check if the whole string is an email
  const trimmed = input.trim();
  if (isValidEmail(trimmed)) {
    return trimmed.toLowerCase();
  }

  return null;
}

/**
 * Extract domain from email address
 */
export function extractDomain(email: string): string | null {
  const address = extractEmailAddress(email);
  if (!address) return null;

  const parts = address.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : null;
}

/**
 * Check if a domain matches a pattern (supports wildcards)
 */
export function domainMatches(domain: string, pattern: string): boolean {
  if (!domain || !pattern) return false;

  const normalizedDomain = domain.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();

  // Exact match
  if (normalizedDomain === normalizedPattern) return true;

  // Subdomain match (e.g., "mail.example.com" matches "example.com")
  if (normalizedDomain.endsWith('.' + normalizedPattern)) return true;

  return false;
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false;

  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract URLs from text content
 */
export function extractUrls(content: string): string[] {
  if (!content) return [];

  const urls: Set<string> = new Set();

  // Match URLs with http/https protocol
  const urlRegex = /https?:\/\/[^\s<>"'`)\]]+/gi;
  const matches = content.match(urlRegex);

  if (matches) {
    for (const match of matches) {
      // Clean up trailing punctuation
      const cleaned = match.replace(/[.,;:!?)\]]+$/, '');
      if (isValidUrl(cleaned)) {
        urls.add(cleaned);
      }
    }
  }

  return Array.from(urls);
}

/**
 * Extract href URLs from HTML content
 */
export function extractHrefUrls(html: string): string[] {
  if (!html) return [];

  const urls: Set<string> = new Set();
  const hrefRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["'][^>]*>/gi;
  let match;

  while ((match = hrefRegex.exec(html)) !== null) {
    const url = match[1];
    if (url && isValidUrl(url)) {
      urls.add(url);
    }
  }

  return Array.from(urls);
}

/**
 * Sanitize string for safe logging (remove potential secrets)
 */
export function sanitizeForLogging(value: string, maxLength = 100): string {
  if (!value) return '';

  // Truncate long strings
  const truncated = value.length > maxLength
    ? value.substring(0, maxLength) + '...'
    : value;

  // Remove potential sensitive patterns
  return truncated
    .replace(/password[=:]\s*\S+/gi, 'password=[REDACTED]')
    .replace(/api[_-]?key[=:]\s*\S+/gi, 'api_key=[REDACTED]')
    .replace(/bearer\s+\S+/gi, 'bearer [REDACTED]')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, '[EMAIL]');
}

/**
 * Check if string contains HTML
 */
export function containsHtml(content: string): boolean {
  if (!content) return false;
  return /<[a-z][\s\S]*>/i.test(content);
}

/**
 * Strip HTML tags from content
 */
export function stripHtml(html: string): string {
  if (!html) return '';
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Normalize whitespace in text
 */
export function normalizeWhitespace(text: string): string {
  if (!text) return '';
  return text.replace(/\s+/g, ' ').trim();
}

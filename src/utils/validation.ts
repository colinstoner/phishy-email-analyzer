/**
 * Validation utilities for Phishy Email Analyzer
 */

/** Maximum input lengths to prevent ReDoS and memory issues */
const MAX_EMAIL_LENGTH = 254; // RFC 5321
const MAX_URL_LENGTH = 2048; // Common browser limit
const MAX_CONTENT_LENGTH = 1_000_000; // 1MB for content parsing

/**
 * Validate email address format
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  if (email.length > MAX_EMAIL_LENGTH) return false;

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
  if (url.length > MAX_URL_LENGTH) return false;

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

  // Limit content length to prevent ReDoS
  const safeContent =
    content.length > MAX_CONTENT_LENGTH ? content.substring(0, MAX_CONTENT_LENGTH) : content;

  const urls: Set<string> = new Set();

  // Match URLs with http/https protocol
  const urlRegex = /https?:\/\/[^\s<>"'`)\]]+/gi;
  const matches = safeContent.match(urlRegex);

  if (matches) {
    for (const match of matches) {
      // Skip overly long URLs
      if (match.length > MAX_URL_LENGTH) continue;

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

  // Limit content length to prevent ReDoS
  const safeHtml = html.length > MAX_CONTENT_LENGTH ? html.substring(0, MAX_CONTENT_LENGTH) : html;

  const urls: Set<string> = new Set();
  const hrefRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']*)["'][^>]*>/gi;
  let match;

  while ((match = hrefRegex.exec(safeHtml)) !== null) {
    const url = match[1];
    if (url && url.length <= MAX_URL_LENGTH && isValidUrl(url)) {
      urls.add(url);
    }
  }

  return Array.from(urls);
}

/**
 * Attributes a reader can follow, by element: link targets, form submission
 * targets and images (image sources were always taken). Everything else in
 * markup (`xmlns` namespace declarations, DOCTYPE identifiers, `<meta>`,
 * `<link>` stylesheets, Office `<o:...>` and `<xml>` blocks) is not a link
 * in the message and is never taken: Office-generated HTML declares
 * namespace URLs such as schemas.microsoft.com and www.w3.org that would
 * otherwise appear as links and spend the link budget.
 */
const FOLLOWABLE_ATTRIBUTES: ReadonlyArray<{ element: string; attribute: string }> = [
  { element: 'form', attribute: 'action' },
  { element: 'button', attribute: 'formaction' },
  { element: 'input', attribute: 'formaction' },
  { element: 'img', attribute: 'src' },
  { element: 'input', attribute: 'src' },
  { element: 'iframe', attribute: 'src' },
  { element: 'embed', attribute: 'src' },
];

/**
 * Elements whose `href` is not a link a reader follows. Every other
 * element's `href` is taken: anchors and image-map areas, and also the
 * elements some clients render as clickable (Outlook's VML buttons such as
 * `<v:roundrect href>`, SVG anchors), which an attacker could otherwise use
 * to show one client a link the analysis never saw.
 */
const NON_LINK_HREF_ELEMENTS = new Set(['link', 'base']);

/** `&amp;` and friends in an attribute value: the browser decodes them before following */
function decodeAttributeEntities(value: string): string {
  // One pass, so `&amp;quot;` decodes to `&quot;` and no further
  return value.replace(/&(amp|quot|apos|#0*38|#x0*26|#0*39);/gi, (_, name: string) => {
    const n = name.toLowerCase();
    if (n === 'quot') return '"';
    if (n === 'apos' || /^#0*39$/.test(n)) return "'";
    return '&';
  });
}

/**
 * URLs a reader of an HTML body could follow: the followable attributes
 * above, plus URLs written in the visible text. Comments, `<style>`,
 * `<script>`, `<head>` and conditional-comment blocks are not visible text.
 */
export function extractFollowableUrls(html: string): string[] {
  if (!html) return [];

  const safeHtml = html.length > MAX_CONTENT_LENGTH ? html.substring(0, MAX_CONTENT_LENGTH) : html;
  const urls = new Set<string>();

  const tagPattern = /<([a-z][a-z0-9]*(?::[a-z][a-z0-9]*)?)(?=[\s/>])([^>]*)>/gi;
  let tag: RegExpExecArray | null;
  while ((tag = tagPattern.exec(safeHtml)) !== null) {
    const element = tag[1].toLowerCase();
    const wanted = FOLLOWABLE_ATTRIBUTES.filter(f => f.element === element).map(f => f.attribute);
    if (!NON_LINK_HREF_ELEMENTS.has(element)) wanted.push('href');
    if (wanted.length === 0) continue;
    const attrPattern = /([a-z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi;
    let attr: RegExpExecArray | null;
    while ((attr = attrPattern.exec(tag[2])) !== null) {
      if (!wanted.includes(attr[1].toLowerCase())) continue;
      const value = decodeAttributeEntities((attr[2] ?? attr[3] ?? attr[4] ?? '').trim());
      // Anchors keep every scheme they always had (mailto:, tel: ...); other
      // attributes only web URLs, so an inline image's cid: is not a link
      const schemeOk = attr[1].toLowerCase() === 'href' || /^https?:\/\//i.test(value);
      if (schemeOk && value.length <= MAX_URL_LENGTH && isValidUrl(value)) {
        urls.add(value);
      }
    }
  }

  const visibleText = safeHtml
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[!?][^>]*>/g, ' ') // DOCTYPE, <![endif]>, <?xml ...?>

    .replace(/<(style|script|head|xml|title)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    // Only real tags (`<p>`, `</a>`, `<o:p>`): a plain-text `<https://...>`
    // or `<name@example.com>` is visible text and stays
    .replace(/<\/?[a-z][a-z0-9]*(?::[a-z0-9]+)?(?=[\s/>])[^>]*>/gi, ' ');
  for (const url of extractUrls(decodeAttributeEntities(visibleText))) {
    urls.add(url);
  }

  return Array.from(urls);
}

/**
 * Sanitize string for safe logging (remove potential secrets)
 */
export function sanitizeForLogging(value: string, maxLength = 100): string {
  if (!value) return '';

  // Truncate long strings
  const truncated = value.length > maxLength ? value.substring(0, maxLength) + '...' : value;

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

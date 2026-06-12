/**
 * IOC (Indicator of Compromise) Extractor
 * Extracts threat indicators from emails and analysis results
 *
 * Attribution model: Phishy receives *forwarded* emails, so the envelope
 * sender is the reporter (a colleague), never the attacker. Sender-based
 * indicators come exclusively from the original sender parsed out of the
 * forwarded content; the reporter is recorded as provenance metadata only.
 */

import { createHash } from 'crypto';
import { ExtractedEmailData, AnalysisResult, AINominatedIOC } from '../../types';
import { ThreatIndicatorRecord } from './database.service';
import { createLogger } from '../../utils/logger';
import { extractUrls, extractDomain } from '../../utils/validation';

const logger = createLogger('ioc-extractor');

/**
 * IP address regex pattern
 */
const IP_REGEX =
  /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

/**
 * Hash patterns (MD5, SHA1, SHA256)
 */
const HASH_PATTERNS = {
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
};

/**
 * Query parameters that commonly carry a redirect destination
 */
const REDIRECT_PARAM_KEYS = [
  'url',
  'u',
  'q',
  'r',
  'link',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'target',
  'dest',
  'destination',
  'next',
  'goto',
  'continue',
];

/**
 * Options for IOC extraction
 */
export interface IOCExtractionOptions {
  extractUrls?: boolean;
  extractDomains?: boolean;
  extractIPs?: boolean;
  extractHashes?: boolean;
  extractEmails?: boolean;
  minConfidence?: number;
  /** Configured allowlists; merged with the built-in big-provider baseline */
  safeDomains?: string[];
  safeSenders?: string[];
}

/**
 * Source context for IOC provenance tracking
 */
export interface IOCSourceContext {
  analysisId?: string;
  messageId: string;
  /** Who forwarded the email to Phishy — provenance only, never an indicator */
  reporterEmail: string;
  reporterDomain: string;
  subject: string;
}

const DEFAULT_OPTIONS: IOCExtractionOptions = {
  extractUrls: true,
  extractDomains: true,
  extractIPs: true,
  extractHashes: true,
  extractEmails: true,
  minConfidence: 0.3,
};

/**
 * Extract IOCs from email data and analysis result
 */
export function extractIOCs(
  emailData: ExtractedEmailData,
  analysis: AnalysisResult,
  options: IOCExtractionOptions = {},
  sourceContext?: IOCSourceContext
): ThreatIndicatorRecord[] {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const indicators: ThreatIndicatorRecord[] = [];
  const now = new Date();

  // Only extract IOCs if analysis indicates suspicious activity
  const baseConfidence = analysis.isPhishing ? 0.7 : 0.3;
  const severity = determineSeverity(analysis);

  // Build base metadata for provenance tracking
  const baseMetadata: Record<string, unknown> = {};
  if (sourceContext) {
    if (sourceContext.analysisId) baseMetadata.sourceAnalysisId = sourceContext.analysisId;
    baseMetadata.sourceMessageId = sourceContext.messageId;
    baseMetadata.reportedBy = sourceContext.reporterEmail;
    baseMetadata.reportedByDomain = sourceContext.reporterDomain;
    baseMetadata.sourceSubject = sourceContext.subject.substring(0, 100);
  }

  // Values that must never become indicators, regardless of allowlists
  const exclusions = buildExclusions(opts, sourceContext);

  // Combine all text content for analysis
  const allContent = [emailData.text, emailData.html, emailData.subject, ...emailData.links].join(
    ' '
  );

  // Resolve every URL's redirect chain once; URL and domain extraction share it
  const urlChains = opts.extractUrls || opts.extractDomains ? resolveUrlChains(allContent) : [];

  if (opts.extractUrls) {
    indicators.push(...extractUrlIOCs(urlChains, baseConfidence, severity, now, baseMetadata, exclusions));
  }

  if (opts.extractDomains) {
    indicators.push(
      ...extractDomainIOCs(emailData, urlChains, baseConfidence, severity, now, baseMetadata, exclusions)
    );
  }

  if (opts.extractIPs) {
    indicators.push(...extractIPIOCs(allContent, baseConfidence, severity, now, baseMetadata));
  }

  if (opts.extractHashes) {
    indicators.push(...extractHashIOCs(allContent, baseConfidence, severity, now, baseMetadata));
  }

  if (opts.extractEmails) {
    indicators.push(...extractEmailIOCs(emailData, baseConfidence, severity, now, baseMetadata, exclusions));
  }

  // Merge indicators the AI nominated from full context (structured output)
  if (analysis.iocs?.length) {
    indicators.push(...extractAINominatedIOCs(analysis.iocs, severity, now, baseMetadata, exclusions));
  }

  // Dedupe by type+value, keeping the highest-confidence occurrence, then
  // filter by minimum confidence
  const deduped = dedupeIndicators(indicators);
  const filtered = deduped.filter(i => i.confidenceScore >= (opts.minConfidence ?? 0));

  logger.info('Extracted IOCs from email', {
    total: indicators.length,
    filtered: filtered.length,
    isPhishing: analysis.isPhishing,
    hasSourceContext: !!sourceContext,
    aiNominated: analysis.iocs?.length ?? 0,
  });

  return filtered;
}

/**
 * Exclusion set: configured safe senders/domains plus the reporter
 */
interface Exclusions {
  safeDomains: string[];
  safeSenders: string[];
}

function buildExclusions(opts: IOCExtractionOptions, sourceContext?: IOCSourceContext): Exclusions {
  const safeDomains = (opts.safeDomains ?? []).map(d => d.toLowerCase());
  const safeSenders = (opts.safeSenders ?? []).map(s => s.toLowerCase());
  if (sourceContext) {
    safeDomains.push(sourceContext.reporterDomain.toLowerCase());
    safeSenders.push(sourceContext.reporterEmail.toLowerCase());
  }
  return { safeDomains, safeSenders };
}

/**
 * A URL and the redirect chain it unwraps to (chain[0] is the original URL,
 * the last element is the final destination)
 */
interface UrlChain {
  chain: string[];
}

function resolveUrlChains(content: string): UrlChain[] {
  return extractUrls(content).map(url => ({ chain: unwrapRedirectChain(url) }));
}

/**
 * Follow redirect-style query parameters (and JWT tracker payloads) to the
 * final destination without making any network requests
 */
function unwrapRedirectChain(url: string, maxDepth = 4): string[] {
  const chain = [url];
  let current = url;

  for (let i = 0; i < maxDepth; i++) {
    const next = extractEmbeddedUrl(current);
    if (!next || chain.includes(next)) break;
    chain.push(next);
    current = next;
  }

  return chain;
}

function extractEmbeddedUrl(url: string): string | null {
  try {
    const parsed = new URL(url);

    for (const key of REDIRECT_PARAM_KEYS) {
      const value = parsed.searchParams.get(key);
      if (value && /^https?:\/\//i.test(value)) {
        return value;
      }
    }

    // Tracker links often stash the destination inside a JWT payload
    for (const [, value] of parsed.searchParams) {
      if (/^[\w-]+\.[\w-]+\.[\w-]+$/.test(value)) {
        const fromJwt = extractUrlFromJwtPayload(value);
        if (fromJwt) return fromJwt;
      }
    }
  } catch {
    // Not a parseable URL
  }

  return null;
}

function extractUrlFromJwtPayload(token: string): string | null {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8')) as Record<
      string,
      unknown
    >;
    for (const value of Object.values(payload)) {
      if (typeof value === 'string' && /^https?:\/\//i.test(value)) {
        return value;
      }
    }
  } catch {
    // Not a decodable JWT
  }
  return null;
}

/**
 * Extract URL indicators. The original URL is always the indicator value;
 * when it unwraps to a different final destination, that final URL becomes
 * its own (higher-value) indicator and the chain is kept as metadata.
 */
function extractUrlIOCs(
  urlChains: UrlChain[],
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>,
  exclusions: Exclusions
): ThreatIndicatorRecord[] {
  const indicators: ThreatIndicatorRecord[] = [];

  for (const { chain } of urlChains) {
    const original = chain[0];
    const final = chain[chain.length - 1];

    if (!isSafeUrl(original, exclusions)) {
      let confidence = baseConfidence;
      if (containsSuspiciousUrlPatterns(original)) {
        confidence = Math.min(confidence + 0.2, 1.0);
      }

      indicators.push({
        indicatorType: 'url',
        indicatorValue: original,
        indicatorHash: hashValue('url', original),
        confidenceScore: confidence,
        severity,
        timesSeen: 1,
        firstSeenAt: now,
        lastSeenAt: now,
        isActive: true,
        metadata: {
          ...baseMetadata,
          extractionContext: 'url_in_content',
          ...(chain.length > 1 ? { redirectChain: chain, finalUrl: final } : {}),
        },
      });
    }

    if (final !== original && !isSafeUrl(final, exclusions)) {
      indicators.push({
        indicatorType: 'url',
        indicatorValue: final,
        indicatorHash: hashValue('url', final),
        confidenceScore: Math.min(baseConfidence + 0.2, 1.0),
        severity,
        timesSeen: 1,
        firstSeenAt: now,
        lastSeenAt: now,
        isActive: true,
        metadata: { ...baseMetadata, extractionContext: 'final_url', unwrappedFrom: original },
      });
    }
  }

  return indicators;
}

/**
 * Extract domain indicators with role-based severity:
 * - the original sender's domain and final URL destinations carry the
 *   analysis-derived severity
 * - redirect intermediaries (trackers, open redirectors) are low severity
 */
function extractDomainIOCs(
  emailData: ExtractedEmailData,
  urlChains: UrlChain[],
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>,
  exclusions: Exclusions
): ThreatIndicatorRecord[] {
  // domain -> {context, severity, confidence}; first writer wins except that
  // higher-value contexts (sender, final URL) overwrite intermediaries
  const domainRoles = new Map<
    string,
    { context: string; severity: ThreatIndicatorRecord['severity']; confidence: number }
  >();

  const assign = (
    domain: string | null,
    context: string,
    sev: ThreatIndicatorRecord['severity'],
    confidence: number
  ): void => {
    if (!domain) return;
    const lower = domain.toLowerCase();
    // IPs in URL hosts are handled by the IP extractor, not as domains
    if (new RegExp(IP_REGEX.source).test(lower) || isSafeDomain(lower, exclusions)) return;
    const existing = domainRoles.get(lower);
    if (!existing || existing.context === 'redirect_intermediary') {
      domainRoles.set(lower, { context, severity: sev, confidence });
    }
  };

  // Original sender (the attacker), parsed from the forwarded content —
  // never the reporter who forwarded the email to Phishy
  const originalSenderAddress = parseEmailAddress(emailData.original_sender);
  if (originalSenderAddress) {
    const senderDomain = extractDomain(originalSenderAddress);
    assign(senderDomain, 'sender_domain', severity, Math.min(baseConfidence + 0.1, 1.0));
  }

  for (const { chain } of urlChains) {
    const finalHost = hostnameOf(chain[chain.length - 1]);
    assign(finalHost, 'final_url_domain', severity, baseConfidence);

    for (const intermediate of chain.slice(0, -1)) {
      assign(hostnameOf(intermediate), 'redirect_intermediary', 'low', Math.max(baseConfidence - 0.2, 0.3));
    }
  }

  const indicators: ThreatIndicatorRecord[] = [];
  for (const [domain, role] of domainRoles) {
    let confidence = role.confidence;
    if (isSuspiciousDomain(domain)) {
      confidence = Math.min(confidence + 0.2, 1.0);
    }

    indicators.push({
      indicatorType: 'domain',
      indicatorValue: domain,
      indicatorHash: hashValue('domain', domain),
      confidenceScore: confidence,
      severity: role.severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
      metadata: { ...baseMetadata, extractionContext: role.context },
    });
  }

  return indicators;
}

/**
 * Extract IP address indicators
 */
function extractIPIOCs(
  content: string,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>
): ThreatIndicatorRecord[] {
  const matches = content.match(IP_REGEX) ?? [];
  const uniqueIPs = [...new Set(matches)];
  const indicators: ThreatIndicatorRecord[] = [];

  for (const ip of uniqueIPs) {
    // Skip private/local IPs
    if (isPrivateIP(ip)) continue;

    indicators.push({
      indicatorType: 'ip',
      indicatorValue: ip,
      indicatorHash: hashValue('ip', ip),
      confidenceScore: baseConfidence,
      severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
      metadata: { ...baseMetadata, extractionContext: 'ip_in_content' },
    });
  }

  return indicators;
}

/**
 * Extract hash indicators
 */
function extractHashIOCs(
  content: string,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>
): ThreatIndicatorRecord[] {
  const indicators: ThreatIndicatorRecord[] = [];

  for (const [hashType, pattern] of Object.entries(HASH_PATTERNS)) {
    const matches = content.match(pattern) ?? [];
    const uniqueHashes = [...new Set(matches)];

    for (const hash of uniqueHashes) {
      indicators.push({
        indicatorType: 'hash',
        indicatorValue: `${hashType}:${hash.toLowerCase()}`,
        indicatorHash: hashValue('hash', hash.toLowerCase()),
        confidenceScore: baseConfidence,
        severity,
        timesSeen: 1,
        firstSeenAt: now,
        lastSeenAt: now,
        isActive: true,
        metadata: { ...baseMetadata, extractionContext: 'hash_in_content', hashType },
      });
    }
  }

  return indicators;
}

/**
 * Extract email address indicators from the original (forwarded) sender
 */
function extractEmailIOCs(
  emailData: ExtractedEmailData,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>,
  exclusions: Exclusions
): ThreatIndicatorRecord[] {
  const indicators: ThreatIndicatorRecord[] = [];

  const originalSender = parseEmailAddress(emailData.original_sender)?.toLowerCase();
  if (originalSender && !isSafeEmail(originalSender, exclusions)) {
    let confidence = baseConfidence;

    // Increase confidence for suspicious patterns
    if (containsSuspiciousEmailPatterns(originalSender)) {
      confidence = Math.min(confidence + 0.2, 1.0);
    }

    indicators.push({
      indicatorType: 'email',
      indicatorValue: originalSender,
      indicatorHash: hashValue('email', originalSender),
      confidenceScore: confidence,
      severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
      metadata: { ...baseMetadata, extractionContext: 'original_sender_email' },
    });
  }

  return indicators;
}

/**
 * Convert AI-nominated IOCs (structured output from the analysis) into
 * indicator records. The model sees full context the regexes cannot, but its
 * nominations still pass the same allowlist filters.
 */
function extractAINominatedIOCs(
  iocs: AINominatedIOC[],
  severity: ThreatIndicatorRecord['severity'],
  now: Date,
  baseMetadata: Record<string, unknown>,
  exclusions: Exclusions
): ThreatIndicatorRecord[] {
  const VALID_TYPES = new Set(['domain', 'url', 'email', 'ip']);
  const indicators: ThreatIndicatorRecord[] = [];

  for (const ioc of iocs) {
    if (!VALID_TYPES.has(ioc.type) || typeof ioc.value !== 'string' || !ioc.value.trim()) continue;
    const value = ioc.type === 'url' ? ioc.value.trim() : ioc.value.trim().toLowerCase();

    if (ioc.type === 'domain' && isSafeDomain(value, exclusions)) continue;
    if (ioc.type === 'email' && isSafeEmail(value, exclusions)) continue;
    if (ioc.type === 'url' && isSafeUrl(value, exclusions)) continue;
    if (ioc.type === 'ip' && isPrivateIP(value)) continue;

    indicators.push({
      indicatorType: ioc.type,
      indicatorValue: value,
      indicatorHash: hashValue(ioc.type, value),
      confidenceScore: 0.8,
      severity: ioc.role === 'infrastructure' ? 'medium' : severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
      metadata: { ...baseMetadata, extractionContext: `ai_nominated:${ioc.role}` },
    });
  }

  return indicators;
}

/**
 * Dedupe by type+value, keeping the highest-confidence occurrence
 */
function dedupeIndicators(indicators: ThreatIndicatorRecord[]): ThreatIndicatorRecord[] {
  const byKey = new Map<string, ThreatIndicatorRecord>();
  for (const indicator of indicators) {
    const key = `${indicator.indicatorType}:${indicator.indicatorValue.toLowerCase()}`;
    const existing = byKey.get(key);
    if (!existing || indicator.confidenceScore > existing.confidenceScore) {
      byKey.set(key, indicator);
    }
  }
  return [...byKey.values()];
}

/**
 * Parse a bare address out of a From-style header value
 * ("Sender Name <sender@example.com>" or "sender@example.com")
 */
function parseEmailAddress(headerValue?: string): string | null {
  if (!headerValue) return null;
  const angled = headerValue.match(/<([^<>\s]+@[^<>\s]+)>/);
  if (angled) return angled[1];
  const bare = headerValue.match(/\b[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+\b/);
  return bare ? bare[0] : null;
}

function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Determine severity based on analysis result
 */
function determineSeverity(analysis: AnalysisResult): ThreatIndicatorRecord['severity'] {
  if (!analysis.isPhishing) return 'low';

  const confidence = analysis.confidence.toLowerCase();

  if (confidence.includes('very high') || confidence === 'high') {
    return 'critical';
  }

  if (confidence === 'medium' || confidence.includes('moderate')) {
    return 'high';
  }

  return 'medium';
}

/**
 * Check if URL is from a known safe source
 */
function isSafeUrl(url: string, exclusions: Exclusions): boolean {
  const host = hostnameOf(url);
  return host ? isSafeDomain(host, exclusions) : false;
}

/**
 * Built-in baseline of domains that are never useful as indicators
 */
const BASELINE_SAFE_DOMAINS = [
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'facebook.com',
  'linkedin.com',
  'twitter.com',
  'github.com',
  'slack.com',
  'zoom.us',
  'salesforce.com',
  'office.com',
  'outlook.com',
  'aka.ms', // Microsoft short-links, incl. the M365 sender-warning banner
];

/**
 * Free webmail providers. The attacker's full address is a useful indicator,
 * but the provider domain is shared by millions of legitimate users and must
 * never be stored as a threat domain.
 */
const FREE_MAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'ymail.com',
  'hotmail.com',
  'outlook.com',
  'live.com',
  'msn.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'proton.me',
  'protonmail.com',
  'gmx.com',
  'mail.com',
  'zoho.com',
  'yandex.com',
  'tutanota.com',
  'hey.com',
]);

/**
 * Should this domain be skipped as a *domain* indicator? True for the big-
 * provider baseline, configured safe domains, and free-mail providers — a
 * free-mail domain is shared by millions, so only the full address is useful.
 */
function isSafeDomain(domain: string, exclusions: Exclusions): boolean {
  const lowerDomain = domain.toLowerCase();
  if (FREE_MAIL_DOMAINS.has(lowerDomain)) return true;
  const allSafe = [...BASELINE_SAFE_DOMAINS, ...exclusions.safeDomains];
  return allSafe.some(safe => lowerDomain === safe || lowerDomain.endsWith('.' + safe));
}

/**
 * Check if email is known safe (configured safe senders or a safe domain).
 * Free-mail domains do NOT make an address safe — a phish from a throwaway
 * gmail account is still a valid email indicator.
 */
function isSafeEmail(email: string, exclusions: Exclusions): boolean {
  const lower = email.toLowerCase();
  if (exclusions.safeSenders.includes(lower)) return true;
  const domain = lower.split('@')[1];
  if (!domain) return false;
  if (FREE_MAIL_DOMAINS.has(domain)) return false;
  return isSafeDomain(domain, exclusions);
}

/**
 * Check if IP is private/local
 */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);

  // 10.0.0.0/8
  if (parts[0] === 10) return true;

  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;

  // 127.0.0.0/8 (loopback)
  if (parts[0] === 127) return true;

  return false;
}

/**
 * Check for suspicious URL patterns
 */
function containsSuspiciousUrlPatterns(url: string): boolean {
  const suspiciousPatterns = [
    /bit\.ly/i,
    /tinyurl/i,
    /goo\.gl/i, // URL shorteners
    /@/, // @ in URL (credential stealing)
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address URLs
    /-login|signin-|secure-|verify-/i, // Impersonation patterns
    /\.php\?.*=/i, // PHP with parameters
    /data:/i, // Data URLs
  ];

  return suspiciousPatterns.some(pattern => pattern.test(url));
}

/**
 * Check for suspicious domain patterns
 */
function isSuspiciousDomain(domain: string): boolean {
  const suspiciousPatterns = [
    /^[a-z0-9]{20,}\./, // Long random prefix
    /-secure|-login|-verify|-account/i, // Security-related keywords
    /\d{3,}/, // Multiple digits
    /^[0-9]+\./, // Starts with numbers
  ];

  return suspiciousPatterns.some(pattern => pattern.test(domain));
}

/**
 * Check for suspicious email patterns
 */
function containsSuspiciousEmailPatterns(email: string): boolean {
  const suspiciousPatterns = [
    /noreply|no-reply|donotreply/i,
    /admin@|support@|security@/i,
    /[a-z0-9]{20,}@/i, // Long random username
  ];

  return suspiciousPatterns.some(pattern => pattern.test(email));
}

/**
 * Hash a value for storage
 */
function hashValue(type: string, value: string): string {
  return createHash('sha256').update(`${type}:${value.toLowerCase()}`).digest('hex');
}

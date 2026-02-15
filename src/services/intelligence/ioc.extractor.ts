/**
 * IOC (Indicator of Compromise) Extractor
 * Extracts threat indicators from emails and analysis results
 */

import { createHash } from 'crypto';
import { ExtractedEmailData, AnalysisResult } from '../../types';
import { ThreatIndicatorRecord } from './database.service';
import { createLogger } from '../../utils/logger';
import { extractUrls, extractDomain } from '../../utils/validation';

const logger = createLogger('ioc-extractor');

/**
 * IP address regex pattern
 */
const IP_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

/**
 * Hash patterns (MD5, SHA1, SHA256)
 */
const HASH_PATTERNS = {
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
};

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
  options: IOCExtractionOptions = {}
): ThreatIndicatorRecord[] {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const indicators: ThreatIndicatorRecord[] = [];
  const now = new Date();

  // Only extract IOCs if analysis indicates suspicious activity
  const baseConfidence = analysis.isPhishing ? 0.7 : 0.3;
  const severity = determineSeverity(analysis);

  // Combine all text content for analysis
  const allContent = [
    emailData.text,
    emailData.html,
    emailData.subject,
    ...emailData.links,
  ].join(' ');

  // Extract URLs
  if (opts.extractUrls) {
    const urls = extractUrlIOCs(allContent, baseConfidence, severity, now);
    indicators.push(...urls);
  }

  // Extract domains
  if (opts.extractDomains) {
    const domains = extractDomainIOCs(emailData, allContent, baseConfidence, severity, now);
    indicators.push(...domains);
  }

  // Extract IPs
  if (opts.extractIPs) {
    const ips = extractIPIOCs(allContent, baseConfidence, severity, now);
    indicators.push(...ips);
  }

  // Extract hashes
  if (opts.extractHashes) {
    const hashes = extractHashIOCs(allContent, baseConfidence, severity, now);
    indicators.push(...hashes);
  }

  // Extract suspicious email addresses
  if (opts.extractEmails) {
    const emails = extractEmailIOCs(emailData, baseConfidence, severity, now);
    indicators.push(...emails);
  }

  // Filter by minimum confidence
  const filtered = indicators.filter(i => i.confidenceScore >= (opts.minConfidence ?? 0));

  logger.info('Extracted IOCs from email', {
    total: indicators.length,
    filtered: filtered.length,
    isPhishing: analysis.isPhishing,
  });

  return filtered;
}

/**
 * Extract URL indicators
 */
function extractUrlIOCs(
  content: string,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date
): ThreatIndicatorRecord[] {
  const urls = extractUrls(content);
  const indicators: ThreatIndicatorRecord[] = [];

  for (const url of urls) {
    // Skip obviously safe URLs
    if (isSafeUrl(url)) continue;

    // Calculate confidence based on URL characteristics
    let confidence = baseConfidence;

    // Increase confidence for suspicious patterns
    if (containsSuspiciousUrlPatterns(url)) {
      confidence = Math.min(confidence + 0.2, 1.0);
    }

    indicators.push({
      indicatorType: 'url',
      indicatorValue: url,
      indicatorHash: hashValue('url', url),
      confidenceScore: confidence,
      severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
    });
  }

  return indicators;
}

/**
 * Extract domain indicators
 */
function extractDomainIOCs(
  emailData: ExtractedEmailData,
  content: string,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date
): ThreatIndicatorRecord[] {
  const domains = new Set<string>();
  const indicators: ThreatIndicatorRecord[] = [];

  // Extract from sender
  const senderDomain = extractDomain(emailData.from_email);
  if (senderDomain && !isSafeDomain(senderDomain)) {
    domains.add(senderDomain);
  }

  // Extract from URLs
  const urls = extractUrls(content);
  for (const url of urls) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      if (!isSafeDomain(domain)) {
        domains.add(domain);
      }
    } catch {
      // Skip invalid URLs
    }
  }

  // Create indicators
  for (const domain of domains) {
    let confidence = baseConfidence;

    // Increase confidence for suspicious domains
    if (isSuspiciousDomain(domain)) {
      confidence = Math.min(confidence + 0.2, 1.0);
    }

    indicators.push({
      indicatorType: 'domain',
      indicatorValue: domain,
      indicatorHash: hashValue('domain', domain),
      confidenceScore: confidence,
      severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
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
  now: Date
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
  now: Date
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
        metadata: { hashType },
      });
    }
  }

  return indicators;
}

/**
 * Extract email address indicators
 */
function extractEmailIOCs(
  emailData: ExtractedEmailData,
  baseConfidence: number,
  severity: ThreatIndicatorRecord['severity'],
  now: Date
): ThreatIndicatorRecord[] {
  const indicators: ThreatIndicatorRecord[] = [];

  // Add sender if suspicious
  const senderEmail = emailData.from_email.toLowerCase();
  if (senderEmail && !isSafeEmail(senderEmail)) {
    let confidence = baseConfidence;

    // Increase confidence for suspicious patterns
    if (containsSuspiciousEmailPatterns(senderEmail)) {
      confidence = Math.min(confidence + 0.2, 1.0);
    }

    indicators.push({
      indicatorType: 'email',
      indicatorValue: senderEmail,
      indicatorHash: hashValue('email', senderEmail),
      confidenceScore: confidence,
      severity,
      timesSeen: 1,
      firstSeenAt: now,
      lastSeenAt: now,
      isActive: true,
    });
  }

  return indicators;
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
function isSafeUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    return isSafeDomain(urlObj.hostname);
  } catch {
    return false;
  }
}

/**
 * Check if domain is known safe
 */
function isSafeDomain(domain: string): boolean {
  const safeDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'linkedin.com', 'twitter.com',
    'github.com', 'slack.com', 'zoom.us',
    'salesforce.com', 'office.com', 'outlook.com',
  ];

  const lowerDomain = domain.toLowerCase();
  return safeDomains.some(safe =>
    lowerDomain === safe || lowerDomain.endsWith('.' + safe)
  );
}

/**
 * Check if email is known safe
 */
function isSafeEmail(email: string): boolean {
  const domain = email.split('@')[1];
  return domain ? isSafeDomain(domain) : false;
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
    /bit\.ly/i, /tinyurl/i, /goo\.gl/i, // URL shorteners
    /@/,  // @ in URL (credential stealing)
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
  return createHash('sha256')
    .update(`${type}:${value.toLowerCase()}`)
    .digest('hex');
}

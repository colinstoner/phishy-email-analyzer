/**
 * Pattern Detector Service
 * Identifies phishing patterns and campaigns across multiple emails
 */

import { ExtractedEmailData, AnalysisResult } from '../../types';
import { IntelligenceDatabaseService } from './database.service';
import { createLogger } from '../../utils/logger';
import { extractDomain } from '../../utils/validation';

const logger = createLogger('pattern-detector');

/**
 * Pattern detection options
 */
export interface PatternDetectionOptions {
  minMatchCount?: number;
  lookbackHours?: number;
}

const DEFAULT_OPTIONS: PatternDetectionOptions = {
  minMatchCount: 3,
  lookbackHours: 168, // 7 days
};

/**
 * Detected pattern with details
 */
export interface DetectedPattern {
  type: string;
  name: string;
  description: string;
  criteria: Record<string, unknown>;
  matchCount: number;
  isNew: boolean;
}

export class PatternDetectorService {
  private db: IntelligenceDatabaseService;
  private options: PatternDetectionOptions;

  constructor(db: IntelligenceDatabaseService, options: PatternDetectionOptions = {}) {
    this.db = db;
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Detect patterns in an email analysis
   */
  async detectPatterns(
    emailData: ExtractedEmailData,
    analysis: AnalysisResult
  ): Promise<DetectedPattern[]> {
    const patterns: DetectedPattern[] = [];

    if (!analysis.isPhishing) {
      return patterns;
    }

    // Check for domain-based campaign
    const domainPattern = await this.detectDomainCampaign(emailData);
    if (domainPattern) {
      patterns.push(domainPattern);
    }

    // Check for subject line pattern
    const subjectPattern = await this.detectSubjectPattern(emailData);
    if (subjectPattern) {
      patterns.push(subjectPattern);
    }

    // Check for sender impersonation pattern
    const impersonationPattern = await this.detectImpersonationPattern(emailData, analysis);
    if (impersonationPattern) {
      patterns.push(impersonationPattern);
    }

    // Check for URL pattern campaign
    const urlPattern = await this.detectUrlPatternCampaign(emailData);
    if (urlPattern) {
      patterns.push(urlPattern);
    }

    logger.info('Pattern detection completed', {
      patternsFound: patterns.length,
      fromEmail: emailData.from_email,
    });

    return patterns;
  }

  /**
   * Detect domain-based phishing campaign
   */
  private async detectDomainCampaign(
    emailData: ExtractedEmailData
  ): Promise<DetectedPattern | null> {
    const domain = extractDomain(emailData.from_email);
    if (!domain) return null;

    const patternName = `domain_campaign_${domain}`;
    const patternType = 'domain_campaign';

    // Check existing pattern
    const lookbackDate = new Date();
    lookbackDate.setHours(lookbackDate.getHours() - (this.options.lookbackHours ?? 168));

    const recentAnalyses = await this.db.searchAnalyses({
      fromDomain: domain,
      isPhishing: true,
      fromDate: lookbackDate,
      limit: 100,
    });

    if (recentAnalyses.length >= (this.options.minMatchCount ?? 3)) {
      const criteria = {
        domain,
        matchingEmails: recentAnalyses.length,
        firstSeen: recentAnalyses[recentAnalyses.length - 1]?.createdAt,
        lastSeen: recentAnalyses[0]?.createdAt,
      };

      // Store pattern
      await this.db.upsertPattern({
        patternName,
        patternType,
        patternCriteria: criteria,
        matchCount: recentAnalyses.length,
        isConfirmedThreat: recentAnalyses.length >= 5,
        firstDetectedAt: criteria.firstSeen ?? new Date(),
        lastDetectedAt: new Date(),
      });

      return {
        type: patternType,
        name: patternName,
        description: `Domain-based phishing campaign from ${domain}`,
        criteria,
        matchCount: recentAnalyses.length,
        isNew: recentAnalyses.length === (this.options.minMatchCount ?? 3),
      };
    }

    return null;
  }

  /**
   * Detect subject line pattern
   */
  private async detectSubjectPattern(
    emailData: ExtractedEmailData
  ): Promise<DetectedPattern | null> {
    const subject = emailData.subject.toLowerCase();

    // Extract key phrases from subject
    const keyPhrases = this.extractSubjectKeyPhrases(subject);
    if (keyPhrases.length === 0) return null;

    const lookbackDate = new Date();
    lookbackDate.setHours(lookbackDate.getHours() - (this.options.lookbackHours ?? 168));

    const recentAnalyses = await this.db.searchAnalyses({
      isPhishing: true,
      fromDate: lookbackDate,
      limit: 500,
    });

    // Count matching subjects
    const matches = recentAnalyses.filter(analysis => {
      const analysisSubject = analysis.subject.toLowerCase();
      return keyPhrases.some(phrase => analysisSubject.includes(phrase));
    });

    if (matches.length >= (this.options.minMatchCount ?? 3)) {
      const patternName = `subject_pattern_${keyPhrases[0].replace(/\s+/g, '_')}`;
      const criteria = {
        keyPhrases,
        matchingEmails: matches.length,
        sampleSubject: emailData.subject,
      };

      await this.db.upsertPattern({
        patternName,
        patternType: 'subject_pattern',
        patternCriteria: criteria,
        matchCount: matches.length,
        isConfirmedThreat: matches.length >= 5,
        firstDetectedAt: matches[matches.length - 1]?.createdAt ?? new Date(),
        lastDetectedAt: new Date(),
      });

      return {
        type: 'subject_pattern',
        name: patternName,
        description: `Subject line pattern: "${keyPhrases[0]}"`,
        criteria,
        matchCount: matches.length,
        isNew: matches.length === (this.options.minMatchCount ?? 3),
      };
    }

    return null;
  }

  /**
   * Detect impersonation pattern
   */
  private async detectImpersonationPattern(
    _emailData: ExtractedEmailData,
    analysis: AnalysisResult
  ): Promise<DetectedPattern | null> {
    // Check if indicators mention impersonation
    const hasImpersonationIndicator = analysis.indicators.some(
      indicator =>
        indicator.toLowerCase().includes('impersonat') ||
        indicator.toLowerCase().includes('spoof') ||
        indicator.toLowerCase().includes('pretend')
    );

    if (!hasImpersonationIndicator) return null;

    const lookbackDate = new Date();
    lookbackDate.setHours(lookbackDate.getHours() - (this.options.lookbackHours ?? 168));

    const recentAnalyses = await this.db.searchAnalyses({
      isPhishing: true,
      fromDate: lookbackDate,
      limit: 200,
    });

    // Look for similar impersonation attempts
    const impersonationMatches = recentAnalyses.filter(a =>
      a.vipImpersonationDetected ||
      a.indicators.some(
        i =>
          i.toLowerCase().includes('impersonat') ||
          i.toLowerCase().includes('spoof')
      )
    );

    if (impersonationMatches.length >= (this.options.minMatchCount ?? 3)) {
      const patternName = 'impersonation_campaign';
      const criteria = {
        matchingEmails: impersonationMatches.length,
        sampleIndicators: analysis.indicators.slice(0, 3),
      };

      await this.db.upsertPattern({
        patternName,
        patternType: 'impersonation',
        patternCriteria: criteria,
        matchCount: impersonationMatches.length,
        isConfirmedThreat: true,
        firstDetectedAt: impersonationMatches[impersonationMatches.length - 1]?.createdAt ?? new Date(),
        lastDetectedAt: new Date(),
      });

      return {
        type: 'impersonation',
        name: patternName,
        description: 'Active impersonation campaign detected',
        criteria,
        matchCount: impersonationMatches.length,
        isNew: impersonationMatches.length === (this.options.minMatchCount ?? 3),
      };
    }

    return null;
  }

  /**
   * Detect URL pattern campaign
   */
  private async detectUrlPatternCampaign(
    emailData: ExtractedEmailData
  ): Promise<DetectedPattern | null> {
    if (emailData.links.length === 0) return null;

    // Extract domains from URLs
    const urlDomains = new Set<string>();
    for (const link of emailData.links) {
      try {
        const url = new URL(link);
        urlDomains.add(url.hostname.toLowerCase());
      } catch {
        // Skip invalid URLs
      }
    }

    if (urlDomains.size === 0) return null;

    // Check for matching patterns in recent analyses
    const lookbackDate = new Date();
    lookbackDate.setHours(lookbackDate.getHours() - (this.options.lookbackHours ?? 168));

    const recentAnalyses = await this.db.searchAnalyses({
      isPhishing: true,
      fromDate: lookbackDate,
      limit: 300,
    });

    // This is simplified - in production, you'd want to store and index URLs
    // For now, we just count phishing emails with similar URL patterns
    const urlPatternMatches = recentAnalyses.filter(a =>
      a.indicators.some(i => {
        const urlMatch = i.match(/https?:\/\/([^/]+)/);
        if (urlMatch) {
          const domain = urlMatch[1].toLowerCase();
          return urlDomains.has(domain);
        }
        return false;
      })
    );

    if (urlPatternMatches.length >= (this.options.minMatchCount ?? 3)) {
      const primaryDomain = Array.from(urlDomains)[0];
      const patternName = `url_campaign_${primaryDomain.replace(/\./g, '_')}`;
      const criteria = {
        domains: Array.from(urlDomains),
        matchingEmails: urlPatternMatches.length,
      };

      await this.db.upsertPattern({
        patternName,
        patternType: 'url_campaign',
        patternCriteria: criteria,
        matchCount: urlPatternMatches.length,
        isConfirmedThreat: urlPatternMatches.length >= 5,
        firstDetectedAt: urlPatternMatches[urlPatternMatches.length - 1]?.createdAt ?? new Date(),
        lastDetectedAt: new Date(),
      });

      return {
        type: 'url_campaign',
        name: patternName,
        description: `URL-based campaign using domains: ${Array.from(urlDomains).join(', ')}`,
        criteria,
        matchCount: urlPatternMatches.length,
        isNew: urlPatternMatches.length === (this.options.minMatchCount ?? 3),
      };
    }

    return null;
  }

  /**
   * Extract key phrases from subject line
   */
  private extractSubjectKeyPhrases(subject: string): string[] {
    const phrases: string[] = [];

    // Common phishing subject patterns
    const patterns = [
      /urgent|immediate|action required/gi,
      /password|reset|expired/gi,
      /account.*(suspend|lock|verify)/gi,
      /invoice|payment|receipt/gi,
      /delivery|shipping|package/gi,
      /security alert|suspicious activity/gi,
      /your.*account/gi,
      /verify your/gi,
      /update.*information/gi,
    ];

    for (const pattern of patterns) {
      const matches = subject.match(pattern);
      if (matches) {
        phrases.push(...matches.map(m => m.toLowerCase()));
      }
    }

    return [...new Set(phrases)].slice(0, 3);
  }
}

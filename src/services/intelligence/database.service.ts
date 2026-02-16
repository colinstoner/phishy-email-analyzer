/**
 * Intelligence Database Service
 * Handles all database operations for threat intelligence
 */

import { Pool, PoolConfig } from 'pg';
import { createLogger } from '../../utils/logger';
import { AnalysisResult, IndicatorType } from '../../types';
import { createHash } from 'crypto';

const logger = createLogger('intelligence-db');

/**
 * Email analysis record for database storage
 */
export interface EmailAnalysisRecord {
  id?: string;
  profileId?: string;
  messageId: string;
  fromEmail: string;
  fromDomain: string;
  subject: string;
  isPhishing: boolean;
  confidenceScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  analysisResult: AnalysisResult;
  indicators: string[];
  vipImpersonationDetected: boolean;
  aiProvider: string;
  aiModel: string;
  processingTimeMs: number;
  createdAt?: Date;
}

/**
 * Threat indicator record for database storage
 */
export interface ThreatIndicatorRecord {
  id?: string;
  indicatorType: IndicatorType;
  indicatorValue: string;
  indicatorHash: string;
  confidenceScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timesSeen: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  isActive: boolean;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

/**
 * Detected pattern record
 */
export interface DetectedPatternRecord {
  id?: string;
  patternName: string;
  patternType: string;
  patternCriteria: Record<string, unknown>;
  matchCount: number;
  isConfirmedThreat: boolean;
  firstDetectedAt: Date;
  lastDetectedAt: Date;
}

/**
 * Campaign record for tracking phishing campaigns
 */
export interface CampaignRecord {
  id?: string;
  campaignSignature: string;
  senderDomain: string;
  subjectPattern: string;
  detectionCount: number;
  uniqueRecipients: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  sampleIndicators: string[];
  firstSeenAt: Date;
  lastSeenAt: Date;
  alertSentAt?: Date;
  isActive: boolean;
}

/**
 * Campaign match result
 */
export interface CampaignMatch {
  campaignId: string;
  signature: string;
  detectionCount: number;
  uniqueRecipientCount: number;
  hoursActive: number;
  shouldAlert: boolean;
  alertSentAt?: Date;
}

/**
 * Search filters for analyses
 */
export interface AnalysisSearchFilters {
  fromDate?: Date;
  toDate?: Date;
  isPhishing?: boolean;
  riskLevel?: string;
  fromDomain?: string;
  profileId?: string;
  limit?: number;
  offset?: number;
}

/**
 * Intelligence statistics
 */
export interface IntelligenceStats {
  totalAnalyses: number;
  phishingDetected: number;
  activeIndicators: number;
  detectedPatterns: number;
  analysesLast24h: number;
  analysesLast7d: number;
  topThreatenedDomains: Array<{ domain: string; count: number }>;
  riskDistribution: Record<string, number>;
}

/**
 * AI usage record for cost tracking
 */
export interface AIUsageRecord {
  id?: string;
  analysisId?: string;
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  estimatedCostUsd?: number;
  createdAt?: Date;
}

/**
 * AI usage statistics
 */
export interface AIUsageStats {
  totalRequests: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  estimatedTotalCostUsd: number;
  avgInputTokensPerRequest: number;
  avgOutputTokensPerRequest: number;
  avgCostPerRequest: number;
  requestsLast24h: number;
  requestsLast7d: number;
  costLast24h: number;
  costLast7d: number;
  usageByModel: Array<{
    model: string;
    requests: number;
    totalTokens: number;
    estimatedCostUsd: number;
  }>;
}

export class IntelligenceDatabaseService {
  private pool: Pool;
  private initialized: boolean = false;

  constructor(connectionString: string) {
    const config: PoolConfig = {
      connectionString,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    };

    this.pool = new Pool(config);

    // Handle pool errors
    this.pool.on('error', (err) => {
      logger.error('Unexpected error on idle client', { error: err.message });
    });
  }

  /**
   * Initialize database tables
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    logger.info('Initializing intelligence database');

    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      // Create email_analyses table
      await client.query(`
        CREATE TABLE IF NOT EXISTS email_analyses (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          profile_id UUID,
          message_id VARCHAR(500) NOT NULL,
          from_email VARCHAR(500) NOT NULL,
          from_domain VARCHAR(255) NOT NULL,
          subject VARCHAR(1000),
          is_phishing BOOLEAN NOT NULL,
          confidence_score DECIMAL(5,4),
          risk_level VARCHAR(20) NOT NULL,
          analysis_result JSONB NOT NULL,
          indicators TEXT[],
          vip_impersonation_detected BOOLEAN DEFAULT FALSE,
          ai_provider VARCHAR(50),
          ai_model VARCHAR(100),
          processing_time_ms INTEGER,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

          CONSTRAINT valid_risk_level CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'safe'))
        );

        CREATE INDEX IF NOT EXISTS idx_email_analyses_created_at ON email_analyses(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_email_analyses_from_domain ON email_analyses(from_domain);
        CREATE INDEX IF NOT EXISTS idx_email_analyses_is_phishing ON email_analyses(is_phishing);
        CREATE INDEX IF NOT EXISTS idx_email_analyses_risk_level ON email_analyses(risk_level);
        CREATE INDEX IF NOT EXISTS idx_email_analyses_message_id ON email_analyses(message_id);
      `);

      // Create threat_indicators table
      await client.query(`
        CREATE TABLE IF NOT EXISTS threat_indicators (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          indicator_type VARCHAR(50) NOT NULL,
          indicator_value TEXT NOT NULL,
          indicator_hash VARCHAR(64) NOT NULL,
          confidence_score DECIMAL(5,4) DEFAULT 0.5,
          severity VARCHAR(20) NOT NULL,
          times_seen INTEGER DEFAULT 1,
          first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          is_active BOOLEAN DEFAULT TRUE,
          expires_at TIMESTAMP WITH TIME ZONE,
          metadata JSONB,

          CONSTRAINT valid_indicator_type CHECK (indicator_type IN ('domain', 'ip', 'url', 'email', 'hash', 'file_name', 'subject_pattern')),
          CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
          CONSTRAINT unique_indicator UNIQUE (indicator_type, indicator_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators(indicator_type);
        CREATE INDEX IF NOT EXISTS idx_threat_indicators_hash ON threat_indicators(indicator_hash);
        CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators(is_active) WHERE is_active = TRUE;
        CREATE INDEX IF NOT EXISTS idx_threat_indicators_severity ON threat_indicators(severity);
      `);

      // Create detected_patterns table
      await client.query(`
        CREATE TABLE IF NOT EXISTS detected_patterns (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          pattern_name VARCHAR(255) NOT NULL,
          pattern_type VARCHAR(50) NOT NULL,
          pattern_criteria JSONB NOT NULL,
          match_count INTEGER DEFAULT 1,
          is_confirmed_threat BOOLEAN DEFAULT FALSE,
          first_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          last_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

          CONSTRAINT unique_pattern UNIQUE (pattern_type, pattern_name)
        );

        CREATE INDEX IF NOT EXISTS idx_detected_patterns_type ON detected_patterns(pattern_type);
        CREATE INDEX IF NOT EXISTS idx_detected_patterns_confirmed ON detected_patterns(is_confirmed_threat);
      `);

      // Create campaigns table for flood/campaign detection
      await client.query(`
        CREATE TABLE IF NOT EXISTS campaigns (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          campaign_signature VARCHAR(64) NOT NULL UNIQUE,
          sender_domain VARCHAR(255) NOT NULL,
          subject_pattern VARCHAR(500),
          detection_count INTEGER DEFAULT 1,
          unique_recipients TEXT[] DEFAULT '{}',
          risk_level VARCHAR(20) NOT NULL,
          sample_indicators TEXT[] DEFAULT '{}',
          first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          alert_sent_at TIMESTAMP WITH TIME ZONE,
          is_active BOOLEAN DEFAULT TRUE,

          CONSTRAINT valid_campaign_risk CHECK (risk_level IN ('critical', 'high', 'medium', 'low'))
        );

        CREATE INDEX IF NOT EXISTS idx_campaigns_signature ON campaigns(campaign_signature);
        CREATE INDEX IF NOT EXISTS idx_campaigns_active ON campaigns(is_active) WHERE is_active = TRUE;
        CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen ON campaigns(last_seen_at DESC);
      `);

      // Create ai_usage table for cost tracking
      await client.query(`
        CREATE TABLE IF NOT EXISTS ai_usage (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          analysis_id UUID REFERENCES email_analyses(id) ON DELETE SET NULL,
          provider VARCHAR(50) NOT NULL,
          model VARCHAR(100) NOT NULL,
          input_tokens INTEGER NOT NULL,
          output_tokens INTEGER NOT NULL,
          total_tokens INTEGER NOT NULL,
          estimated_cost_usd DECIMAL(10,6),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_ai_usage_created_at ON ai_usage(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_usage_model ON ai_usage(model);
        CREATE INDEX IF NOT EXISTS idx_ai_usage_analysis_id ON ai_usage(analysis_id);
      `);

      await client.query('COMMIT');
      this.initialized = true;
      logger.info('Intelligence database initialized successfully');
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to initialize database', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Store an email analysis result
   */
  async storeAnalysis(record: EmailAnalysisRecord): Promise<string> {
    await this.initialize();

    const result = await this.pool.query(
      `INSERT INTO email_analyses
       (profile_id, message_id, from_email, from_domain, subject, is_phishing,
        confidence_score, risk_level, analysis_result, indicators,
        vip_impersonation_detected, ai_provider, ai_model, processing_time_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING id`,
      [
        record.profileId ?? null,
        record.messageId,
        record.fromEmail,
        record.fromDomain,
        record.subject,
        record.isPhishing,
        record.confidenceScore,
        record.riskLevel,
        JSON.stringify(record.analysisResult),
        record.indicators,
        record.vipImpersonationDetected,
        record.aiProvider,
        record.aiModel,
        record.processingTimeMs,
      ]
    );

    const id = result.rows[0].id as string;
    logger.debug('Stored email analysis', { id, messageId: record.messageId });

    return id;
  }

  /**
   * Get analysis by ID
   */
  async getAnalysis(id: string): Promise<EmailAnalysisRecord | null> {
    await this.initialize();

    const result = await this.pool.query(
      'SELECT * FROM email_analyses WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToAnalysis(result.rows[0]);
  }

  /**
   * Search analyses with filters
   */
  async searchAnalyses(filters: AnalysisSearchFilters): Promise<EmailAnalysisRecord[]> {
    await this.initialize();

    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (filters.fromDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      params.push(filters.fromDate);
    }

    if (filters.toDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      params.push(filters.toDate);
    }

    if (filters.isPhishing !== undefined) {
      conditions.push(`is_phishing = $${paramIndex++}`);
      params.push(filters.isPhishing);
    }

    if (filters.riskLevel) {
      conditions.push(`risk_level = $${paramIndex++}`);
      params.push(filters.riskLevel);
    }

    if (filters.fromDomain) {
      conditions.push(`from_domain = $${paramIndex++}`);
      params.push(filters.fromDomain);
    }

    if (filters.profileId) {
      conditions.push(`profile_id = $${paramIndex++}`);
      params.push(filters.profileId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(Math.max(1, filters.limit ?? 100), 1000); // Clamp between 1-1000
    const offset = Math.max(0, filters.offset ?? 0);

    // Add limit and offset as parameterized values
    params.push(limit);
    params.push(offset);

    const query = `
      SELECT * FROM email_analyses
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    const result = await this.pool.query(query, params);
    return result.rows.map(row => this.mapRowToAnalysis(row));
  }

  /**
   * Store or update a threat indicator
   */
  async upsertIndicator(indicator: ThreatIndicatorRecord): Promise<string> {
    await this.initialize();

    const hash = this.hashIndicator(indicator.indicatorType, indicator.indicatorValue);

    const result = await this.pool.query(
      `INSERT INTO threat_indicators
       (indicator_type, indicator_value, indicator_hash, confidence_score,
        severity, times_seen, first_seen_at, last_seen_at, is_active, expires_at, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (indicator_type, indicator_hash)
       DO UPDATE SET
         times_seen = threat_indicators.times_seen + 1,
         last_seen_at = NOW(),
         confidence_score = GREATEST(threat_indicators.confidence_score, EXCLUDED.confidence_score),
         severity = CASE
           WHEN EXCLUDED.severity = 'critical' THEN 'critical'
           WHEN threat_indicators.severity = 'critical' THEN 'critical'
           WHEN EXCLUDED.severity = 'high' OR threat_indicators.severity = 'high' THEN 'high'
           WHEN EXCLUDED.severity = 'medium' OR threat_indicators.severity = 'medium' THEN 'medium'
           ELSE 'low'
         END
       RETURNING id`,
      [
        indicator.indicatorType,
        indicator.indicatorValue,
        hash,
        indicator.confidenceScore,
        indicator.severity,
        indicator.timesSeen,
        indicator.firstSeenAt,
        indicator.lastSeenAt,
        indicator.isActive,
        indicator.expiresAt ?? null,
        indicator.metadata ? JSON.stringify(indicator.metadata) : null,
      ]
    );

    return result.rows[0].id as string;
  }

  /**
   * Lookup indicators by value
   */
  async lookupIndicators(
    type: IndicatorType,
    values: string[]
  ): Promise<ThreatIndicatorRecord[]> {
    await this.initialize();

    const hashes = values.map(v => this.hashIndicator(type, v));

    const result = await this.pool.query(
      `SELECT * FROM threat_indicators
       WHERE indicator_type = $1
       AND indicator_hash = ANY($2)
       AND is_active = TRUE`,
      [type, hashes]
    );

    return result.rows.map(row => this.mapRowToIndicator(row));
  }

  /**
   * Get active indicators
   */
  async getActiveIndicators(
    type?: IndicatorType,
    limit = 100
  ): Promise<ThreatIndicatorRecord[]> {
    await this.initialize();

    let query = `
      SELECT * FROM threat_indicators
      WHERE is_active = TRUE
      AND (expires_at IS NULL OR expires_at > NOW())
    `;

    const params: unknown[] = [];

    if (type) {
      query += ` AND indicator_type = $1`;
      params.push(type);
    }

    // Sanitize limit and add as parameter
    const safeLimit = Math.min(Math.max(1, limit), 1000);
    const limitParamIndex = params.length + 1;
    params.push(safeLimit);
    query += ` ORDER BY last_seen_at DESC LIMIT $${limitParamIndex}`;

    const result = await this.pool.query(query, params);
    return result.rows.map(row => this.mapRowToIndicator(row));
  }

  /**
   * Store or update a detected pattern
   */
  async upsertPattern(pattern: DetectedPatternRecord): Promise<string> {
    await this.initialize();

    const result = await this.pool.query(
      `INSERT INTO detected_patterns
       (pattern_name, pattern_type, pattern_criteria, match_count,
        is_confirmed_threat, first_detected_at, last_detected_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (pattern_type, pattern_name)
       DO UPDATE SET
         match_count = detected_patterns.match_count + 1,
         last_detected_at = NOW()
       RETURNING id`,
      [
        pattern.patternName,
        pattern.patternType,
        JSON.stringify(pattern.patternCriteria),
        pattern.matchCount,
        pattern.isConfirmedThreat,
        pattern.firstDetectedAt,
        pattern.lastDetectedAt,
      ]
    );

    return result.rows[0].id as string;
  }

  /**
   * Get intelligence statistics
   */
  async getStats(): Promise<IntelligenceStats> {
    await this.initialize();

    const stats: IntelligenceStats = {
      totalAnalyses: 0,
      phishingDetected: 0,
      activeIndicators: 0,
      detectedPatterns: 0,
      analysesLast24h: 0,
      analysesLast7d: 0,
      topThreatenedDomains: [],
      riskDistribution: {},
    };

    // Get basic counts
    const countsResult = await this.pool.query(`
      SELECT
        (SELECT COUNT(*) FROM email_analyses) as total_analyses,
        (SELECT COUNT(*) FROM email_analyses WHERE is_phishing = TRUE) as phishing_detected,
        (SELECT COUNT(*) FROM threat_indicators WHERE is_active = TRUE) as active_indicators,
        (SELECT COUNT(*) FROM detected_patterns) as detected_patterns,
        (SELECT COUNT(*) FROM email_analyses WHERE created_at > NOW() - INTERVAL '24 hours') as analyses_24h,
        (SELECT COUNT(*) FROM email_analyses WHERE created_at > NOW() - INTERVAL '7 days') as analyses_7d
    `);

    const counts = countsResult.rows[0];
    stats.totalAnalyses = parseInt(counts.total_analyses, 10);
    stats.phishingDetected = parseInt(counts.phishing_detected, 10);
    stats.activeIndicators = parseInt(counts.active_indicators, 10);
    stats.detectedPatterns = parseInt(counts.detected_patterns, 10);
    stats.analysesLast24h = parseInt(counts.analyses_24h, 10);
    stats.analysesLast7d = parseInt(counts.analyses_7d, 10);

    // Get top threatened domains
    const domainsResult = await this.pool.query(`
      SELECT from_domain as domain, COUNT(*) as count
      FROM email_analyses
      WHERE is_phishing = TRUE
      GROUP BY from_domain
      ORDER BY count DESC
      LIMIT 10
    `);

    stats.topThreatenedDomains = domainsResult.rows.map(row => ({
      domain: row.domain as string,
      count: parseInt(row.count, 10),
    }));

    // Get risk distribution
    const riskResult = await this.pool.query(`
      SELECT risk_level, COUNT(*) as count
      FROM email_analyses
      GROUP BY risk_level
    `);

    for (const row of riskResult.rows) {
      stats.riskDistribution[row.risk_level as string] = parseInt(row.count, 10);
    }

    return stats;
  }

  /**
   * Check if an email has been analyzed (deduplication)
   */
  async hasBeenAnalyzed(messageId: string): Promise<boolean> {
    await this.initialize();

    const result = await this.pool.query(
      'SELECT 1 FROM email_analyses WHERE message_id = $1 LIMIT 1',
      [messageId]
    );

    return result.rows.length > 0;
  }

  /**
   * Track a detection for campaign analysis
   * Returns campaign match info if alert threshold is met
   */
  async trackCampaignDetection(
    senderDomain: string,
    subject: string,
    recipientEmail: string,
    riskLevel: CampaignRecord['riskLevel'],
    indicators: string[]
  ): Promise<CampaignMatch | null> {
    await this.initialize();

    // Generate campaign signature from sender domain + normalized subject
    const normalizedSubject = this.normalizeSubjectForCampaign(subject);
    const signature = createHash('sha256')
      .update(`${senderDomain.toLowerCase()}:${normalizedSubject}`)
      .digest('hex')
      .substring(0, 16);

    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      // Upsert campaign record
      const result = await client.query(
        `INSERT INTO campaigns
         (campaign_signature, sender_domain, subject_pattern, detection_count,
          unique_recipients, risk_level, sample_indicators, first_seen_at, last_seen_at)
         VALUES ($1, $2, $3, 1, ARRAY[$4], $5, $6, NOW(), NOW())
         ON CONFLICT (campaign_signature)
         DO UPDATE SET
           detection_count = campaigns.detection_count + 1,
           unique_recipients = CASE
             WHEN $4 = ANY(campaigns.unique_recipients) THEN campaigns.unique_recipients
             ELSE array_append(campaigns.unique_recipients, $4)
           END,
           risk_level = CASE
             WHEN $5 = 'critical' THEN 'critical'
             WHEN campaigns.risk_level = 'critical' THEN 'critical'
             WHEN $5 = 'high' OR campaigns.risk_level = 'high' THEN 'high'
             ELSE campaigns.risk_level
           END,
           last_seen_at = NOW(),
           is_active = TRUE
         RETURNING id, campaign_signature, detection_count, unique_recipients,
                   first_seen_at, alert_sent_at`,
        [signature, senderDomain.toLowerCase(), normalizedSubject, recipientEmail.toLowerCase(),
         riskLevel, indicators.slice(0, 5)]
      );

      const row = result.rows[0];
      const campaignId = row.id as string;
      const detectionCount = row.detection_count as number;
      const uniqueRecipients = row.unique_recipients as string[];
      const firstSeenAt = row.first_seen_at as Date;
      const alertSentAt = row.alert_sent_at as Date | null;

      await client.query('COMMIT');

      // Calculate hours since first detection
      const hoursActive = (Date.now() - firstSeenAt.getTime()) / (1000 * 60 * 60);

      // Determine if we should alert
      // Criteria: ≥3 detections, ≥2 unique recipients, within 4 hours, not alerted in last 24h
      const shouldAlert =
        detectionCount >= 3 &&
        uniqueRecipients.length >= 2 &&
        hoursActive <= 4 &&
        (riskLevel === 'high' || riskLevel === 'critical') &&
        (!alertSentAt || (Date.now() - alertSentAt.getTime()) > 24 * 60 * 60 * 1000);

      return {
        campaignId,
        signature,
        detectionCount,
        uniqueRecipientCount: uniqueRecipients.length,
        hoursActive,
        shouldAlert,
        alertSentAt: alertSentAt ?? undefined,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to track campaign detection', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Mark a campaign as alerted
   */
  async markCampaignAlerted(campaignId: string): Promise<void> {
    await this.initialize();

    await this.pool.query(
      'UPDATE campaigns SET alert_sent_at = NOW() WHERE id = $1',
      [campaignId]
    );

    logger.info('Marked campaign as alerted', { campaignId });
  }

  /**
   * Get campaign details for alert generation
   */
  async getCampaignDetails(campaignId: string): Promise<CampaignRecord | null> {
    await this.initialize();

    const result = await this.pool.query(
      'SELECT * FROM campaigns WHERE id = $1',
      [campaignId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    return {
      id: row.id as string,
      campaignSignature: row.campaign_signature as string,
      senderDomain: row.sender_domain as string,
      subjectPattern: row.subject_pattern as string,
      detectionCount: row.detection_count as number,
      uniqueRecipients: row.unique_recipients as string[],
      riskLevel: row.risk_level as CampaignRecord['riskLevel'],
      sampleIndicators: row.sample_indicators as string[],
      firstSeenAt: row.first_seen_at as Date,
      lastSeenAt: row.last_seen_at as Date,
      alertSentAt: row.alert_sent_at as Date | undefined,
      isActive: row.is_active as boolean,
    };
  }

  /**
   * Normalize subject line for campaign matching
   * Strips numbers, dates, invoice numbers, etc. to group similar subjects
   */
  private normalizeSubjectForCampaign(subject: string): string {
    return subject
      .toLowerCase()
      .replace(/re:\s*/gi, '')
      .replace(/fw:\s*/gi, '')
      .replace(/fwd:\s*/gi, '')
      .replace(/\d+/g, '#')          // Replace numbers with #
      .replace(/[^\w\s#]/g, '')       // Remove special chars except #
      .replace(/\s+/g, ' ')           // Normalize whitespace
      .trim()
      .substring(0, 100);             // Limit length
  }

  /**
   * Store AI usage record for cost tracking
   */
  async storeAIUsage(record: AIUsageRecord): Promise<string> {
    await this.initialize();

    const result = await this.pool.query(
      `INSERT INTO ai_usage
       (analysis_id, provider, model, input_tokens, output_tokens, total_tokens, estimated_cost_usd)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [
        record.analysisId ?? null,
        record.provider,
        record.model,
        record.inputTokens,
        record.outputTokens,
        record.totalTokens,
        record.estimatedCostUsd ?? null,
      ]
    );

    const id = result.rows[0].id as string;
    logger.debug('Stored AI usage record', {
      id,
      model: record.model,
      totalTokens: record.totalTokens,
    });

    return id;
  }

  /**
   * Get AI usage statistics
   */
  async getAIUsageStats(): Promise<AIUsageStats> {
    await this.initialize();

    // Get aggregate stats
    const statsResult = await this.pool.query(`
      SELECT
        COUNT(*) as total_requests,
        COALESCE(SUM(input_tokens), 0) as total_input_tokens,
        COALESCE(SUM(output_tokens), 0) as total_output_tokens,
        COALESCE(SUM(total_tokens), 0) as total_tokens,
        COALESCE(SUM(estimated_cost_usd), 0) as total_cost,
        COALESCE(AVG(input_tokens), 0) as avg_input_tokens,
        COALESCE(AVG(output_tokens), 0) as avg_output_tokens,
        COALESCE(AVG(estimated_cost_usd), 0) as avg_cost,
        (SELECT COUNT(*) FROM ai_usage WHERE created_at > NOW() - INTERVAL '24 hours') as requests_24h,
        (SELECT COUNT(*) FROM ai_usage WHERE created_at > NOW() - INTERVAL '7 days') as requests_7d,
        (SELECT COALESCE(SUM(estimated_cost_usd), 0) FROM ai_usage WHERE created_at > NOW() - INTERVAL '24 hours') as cost_24h,
        (SELECT COALESCE(SUM(estimated_cost_usd), 0) FROM ai_usage WHERE created_at > NOW() - INTERVAL '7 days') as cost_7d
      FROM ai_usage
    `);

    const row = statsResult.rows[0];

    // Get usage by model
    const modelResult = await this.pool.query(`
      SELECT
        model,
        COUNT(*) as requests,
        SUM(total_tokens) as total_tokens,
        COALESCE(SUM(estimated_cost_usd), 0) as estimated_cost
      FROM ai_usage
      GROUP BY model
      ORDER BY total_tokens DESC
    `);

    return {
      totalRequests: parseInt(row.total_requests, 10),
      totalInputTokens: parseInt(row.total_input_tokens, 10),
      totalOutputTokens: parseInt(row.total_output_tokens, 10),
      totalTokens: parseInt(row.total_tokens, 10),
      estimatedTotalCostUsd: parseFloat(row.total_cost),
      avgInputTokensPerRequest: parseFloat(row.avg_input_tokens),
      avgOutputTokensPerRequest: parseFloat(row.avg_output_tokens),
      avgCostPerRequest: parseFloat(row.avg_cost),
      requestsLast24h: parseInt(row.requests_24h, 10),
      requestsLast7d: parseInt(row.requests_7d, 10),
      costLast24h: parseFloat(row.cost_24h),
      costLast7d: parseFloat(row.cost_7d),
      usageByModel: modelResult.rows.map(r => ({
        model: r.model as string,
        requests: parseInt(r.requests, 10),
        totalTokens: parseInt(r.total_tokens, 10),
        estimatedCostUsd: parseFloat(r.estimated_cost),
      })),
    };
  }

  /**
   * Close the database connection pool
   */
  async close(): Promise<void> {
    await this.pool.end();
    logger.info('Database connection pool closed');
  }

  /**
   * Hash an indicator value for storage
   */
  private hashIndicator(type: IndicatorType, value: string): string {
    return createHash('sha256')
      .update(`${type}:${value.toLowerCase()}`)
      .digest('hex');
  }

  /**
   * Map database row to EmailAnalysisRecord
   */
  private mapRowToAnalysis(row: Record<string, unknown>): EmailAnalysisRecord {
    return {
      id: row.id as string,
      profileId: row.profile_id as string | undefined,
      messageId: row.message_id as string,
      fromEmail: row.from_email as string,
      fromDomain: row.from_domain as string,
      subject: row.subject as string,
      isPhishing: row.is_phishing as boolean,
      confidenceScore: parseFloat(row.confidence_score as string),
      riskLevel: row.risk_level as EmailAnalysisRecord['riskLevel'],
      analysisResult: row.analysis_result as AnalysisResult,
      indicators: row.indicators as string[],
      vipImpersonationDetected: row.vip_impersonation_detected as boolean,
      aiProvider: row.ai_provider as string,
      aiModel: row.ai_model as string,
      processingTimeMs: row.processing_time_ms as number,
      createdAt: row.created_at as Date,
    };
  }

  /**
   * Map database row to ThreatIndicatorRecord
   */
  private mapRowToIndicator(row: Record<string, unknown>): ThreatIndicatorRecord {
    return {
      id: row.id as string,
      indicatorType: row.indicator_type as IndicatorType,
      indicatorValue: row.indicator_value as string,
      indicatorHash: row.indicator_hash as string,
      confidenceScore: parseFloat(row.confidence_score as string),
      severity: row.severity as ThreatIndicatorRecord['severity'],
      timesSeen: row.times_seen as number,
      firstSeenAt: row.first_seen_at as Date,
      lastSeenAt: row.last_seen_at as Date,
      isActive: row.is_active as boolean,
      expiresAt: row.expires_at as Date | undefined,
      metadata: row.metadata as Record<string, unknown> | undefined,
    };
  }
}

-- Migration 001: Initial intelligence database schema
--
-- This is the baseline schema for Phishy's optional threat-intelligence
-- feature (PHISHY_INTELLIGENCE_ENABLED=true). It matches exactly what
-- IntelligenceDatabaseService.initialize() auto-creates on first connection,
-- and every statement is idempotent (IF NOT EXISTS), so it is safe to run
-- against both fresh databases and existing deployments.
--
-- Apply with:  psql "$DATABASE_URL" -f migrations/001_initial_schema.sql
--
-- Requires PostgreSQL 13+ (gen_random_uuid() without the pgcrypto extension).
-- On PostgreSQL 12, run: CREATE EXTENSION IF NOT EXISTS pgcrypto;

BEGIN;

-- One row per analyzed email
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

-- Deduplicated IOCs extracted from analyzed emails
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

-- Recurring patterns spotted across multiple analyses
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

-- Campaign/flood detection: similar emails hitting multiple recipients
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

-- Per-request AI token usage and cost tracking
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

COMMIT;

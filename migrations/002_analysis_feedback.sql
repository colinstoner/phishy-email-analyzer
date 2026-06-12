-- Migration 002: Email commands — verdict feedback and reply linkage
--
-- Supports the email-command channel: the security team replies to Phishy's
-- analysis reports to correct verdicts ("confirmed phishing" / "false
-- positive"), and Phishy acts on them. One feedback row per analysis;
-- resubmitting updates in place so a correction wins.
--
-- Also adds report_message_id to email_analyses so inbound replies can be
-- matched to their analysis via the In-Reply-To header.
--
-- Apply with:  psql "$DATABASE_URL" -f migrations/002_analysis_feedback.sql
--
-- NOTE: unlike the 001 baseline, this migration is NOT auto-applied by the
-- application — run it before enabling PHISHY_EMAIL_COMMANDS_ENABLED=true.

BEGIN;

-- Link outbound reports to analyses for In-Reply-To matching
ALTER TABLE email_analyses ADD COLUMN IF NOT EXISTS report_message_id VARCHAR(500);
CREATE INDEX IF NOT EXISTS idx_email_analyses_report_message_id
  ON email_analyses(report_message_id) WHERE report_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS analysis_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id UUID NOT NULL REFERENCES email_analyses(id) ON DELETE CASCADE,
  verdict VARCHAR(30) NOT NULL,
  source VARCHAR(30) NOT NULL DEFAULT 'email_reply',
  submitted_by VARCHAR(500),
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

  CONSTRAINT valid_feedback_verdict CHECK (verdict IN ('confirmed_phishing', 'false_positive')),
  CONSTRAINT valid_feedback_source CHECK (source IN ('email_reply', 'api')),
  CONSTRAINT unique_feedback_per_analysis UNIQUE (analysis_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_feedback_created_at ON analysis_feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_feedback_verdict ON analysis_feedback(verdict);

COMMIT;

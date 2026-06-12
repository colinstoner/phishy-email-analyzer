-- Migration 004: Structured verdict
--
-- Next-gen risk model. The model now produces a categorical verdict (bec,
-- phishing, malware_delivery, spam, graymail, suspicious, legitimate) and a
-- 0-100 risk score on an axis SEPARATE from confidence — so a
-- confidently-legitimate email is high confidence, low risk. The full
-- assessment already lives inside analysis_result JSONB; these columns surface
-- the two most-queried fields for dashboards and campaign stats.
--
-- Apply with:  psql "$DATABASE_URL" -f migrations/004_structured_verdict.sql
--
-- NOTE: like 002/003, NOT auto-applied. The app degrades gracefully when these
-- columns are absent (stores the analysis without them and logs a warning).

BEGIN;

ALTER TABLE email_analyses ADD COLUMN IF NOT EXISTS verdict VARCHAR(32);
ALTER TABLE email_analyses ADD COLUMN IF NOT EXISTS risk_score SMALLINT;

CREATE INDEX IF NOT EXISTS idx_email_analyses_verdict
  ON email_analyses(verdict, created_at DESC)
  WHERE verdict IS NOT NULL;

COMMIT;

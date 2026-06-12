-- Migration 003: Campaign verdict cache
--
-- Tags each analysis with its campaign signature (the same 16-char
-- sender-domain + normalized-subject hash used by flood detection). When a
-- flood of the same email is reported, the first report pays for a full AI
-- analysis and subsequent reports within the cache window reuse its verdict —
-- consistent answers for every reporter at no extra AI cost.
--
-- Combined with migration 002 (analysis_feedback), one security-team reply
-- resolves the whole campaign: cache lookups prefer an analysis that has a
-- recorded verdict over the most recent raw analysis.
--
-- Apply with:  psql "$DATABASE_URL" -f migrations/003_campaign_verdict_cache.sql
--
-- NOTE: unlike the 001 baseline, this migration is NOT auto-applied by the
-- application — run it before enabling PHISHY_CAMPAIGN_CACHE_ENABLED=true.

BEGIN;

ALTER TABLE email_analyses ADD COLUMN IF NOT EXISTS campaign_signature VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_email_analyses_campaign_signature
  ON email_analyses(campaign_signature, created_at DESC)
  WHERE campaign_signature IS NOT NULL;

COMMIT;

-- Migration 005: Campaign response
--
-- Incidents, response actions and their append-only audit trail, for
-- campaign response (PHISHY_CAMPAIGN_RESPONSE_ENABLED): the security team's
-- incident email, the targeted employee warning, and proposed actions the
-- security team approves through the email command channel.
--
--   campaign_incidents     one row per campaign Phishy is responding to
--   response_actions       what Phishy proposed or did, with its exact scope,
--                          approver, approval window, status and result
--   response_action_audit  every state change; rows can be added, never
--                          updated or deleted (enforced by a trigger)
--
-- Uses campaigns (001) and joins email_analyses.campaign_signature (003) when
-- a "false positive" verdict closes an incident.
--
-- Apply with:  psql "$DATABASE_URL" -f migrations/005_campaign_response.sql
--
-- NOTE: unlike the 001 baseline, this migration is NOT auto-applied by the
-- application. Without it, campaign response logs an instructive warning and
-- the campaign alert behaves exactly as it does with campaign response off.
-- Safe to re-run.

BEGIN;

CREATE TABLE IF NOT EXISTS campaign_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
  campaign_signature VARCHAR(64) NOT NULL UNIQUE,
  -- Unguessable PHY-XXXX-XXXX-XXXX-XXXX reference shown to the security team
  reference VARCHAR(32) NOT NULL UNIQUE,
  trigger_source VARCHAR(20) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  -- Verdict, score, reasons, lure, subject, claimed sender, timeline, reporters
  summary JSONB NOT NULL,
  -- Blast radius merged across lookups: recipients, folder, read and reply
  -- state, and the Graph mailbox and message IDs a removal may name
  reach JSONB NOT NULL,
  report_count INTEGER NOT NULL DEFAULT 0,
  -- SES message ID of the first incident email; updates reply to it
  thread_message_id VARCHAR(200),
  last_update_sent_at TIMESTAMP WITH TIME ZONE,
  notified_report_count INTEGER NOT NULL DEFAULT 0,
  notified_recipient_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

  CONSTRAINT valid_incident_trigger CHECK (trigger_source IN ('reports', 'fanout_scan')),
  CONSTRAINT valid_incident_status CHECK (status IN ('open', 'false_positive', 'closed'))
);

CREATE INDEX IF NOT EXISTS idx_campaign_incidents_status ON campaign_incidents(status);
CREATE INDEX IF NOT EXISTS idx_campaign_incidents_created ON campaign_incidents(created_at DESC);

CREATE TABLE IF NOT EXISTS response_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES campaign_incidents(id) ON DELETE CASCADE,
  -- Unguessable reference quoted in "APPROVE WARNING|REMOVAL <reference>"
  reference VARCHAR(32) NOT NULL UNIQUE,
  action_type VARCHAR(30) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'proposed',
  -- 'approve': needs a security-team approval; 'auto': the operator's setting
  authorization_mode VARCHAR(10) NOT NULL,
  -- Computed by code: recipients for a warning; mailbox IDs and exact Graph
  -- message IDs (never a search) and the caps for a removal
  scope JSONB NOT NULL,
  scope_hash CHAR(64) NOT NULL,
  proposed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  -- The authenticated security-team member, or 'auto'
  approved_by VARCHAR(320),
  approved_at TIMESTAMP WITH TIME ZONE,
  executed_at TIMESTAMP WITH TIME ZONE,
  -- 'ses_warning', 'dry_run_removal' (a future write tier adds its own name)
  executor VARCHAR(40),
  result JSONB,

  CONSTRAINT valid_action_type CHECK (action_type IN ('send_warning', 'remove_messages')),
  CONSTRAINT valid_action_status CHECK (status IN
    ('proposed', 'approved', 'completed', 'dry_run_completed', 'expired', 'cancelled', 'failed')),
  CONSTRAINT valid_authorization_mode CHECK (authorization_mode IN ('approve', 'auto'))
);

CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id, proposed_at);
CREATE INDEX IF NOT EXISTS idx_response_actions_pending
  ON response_actions(expires_at) WHERE status = 'proposed';

CREATE TABLE IF NOT EXISTS response_action_audit (
  id BIGSERIAL PRIMARY KEY,
  incident_id UUID NOT NULL REFERENCES campaign_incidents(id) ON DELETE RESTRICT,
  action_id UUID REFERENCES response_actions(id) ON DELETE RESTRICT,
  event VARCHAR(40) NOT NULL,
  -- 'phishy' for Phishy's own decisions, otherwise the authenticated approver
  actor VARCHAR(320) NOT NULL,
  -- Counts, reasons and hashes; no message content
  detail JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_response_action_audit_incident
  ON response_action_audit(incident_id, created_at);

-- Append-only: an audit row can be added, never changed or removed
CREATE OR REPLACE FUNCTION response_action_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'response_action_audit is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS response_action_audit_no_change ON response_action_audit;
CREATE TRIGGER response_action_audit_no_change
  BEFORE UPDATE OR DELETE ON response_action_audit
  FOR EACH ROW EXECUTE FUNCTION response_action_audit_append_only();

DROP TRIGGER IF EXISTS response_action_audit_no_truncate ON response_action_audit;
CREATE TRIGGER response_action_audit_no_truncate
  BEFORE TRUNCATE ON response_action_audit
  FOR EACH STATEMENT EXECUTE FUNCTION response_action_audit_append_only();

COMMIT;

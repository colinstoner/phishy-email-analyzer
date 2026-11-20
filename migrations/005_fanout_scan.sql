-- Migration 005: state for the scheduled fan-out scan (graph.fanoutScan)
--
-- Apply manually; Phishy auto-creates only the 001 baseline. Without these
-- tables the scan does not run: each scheduled invocation logs that this
-- migration is missing and emits FanoutScans with Outcome=migration_missing.
-- Nothing else in Phishy uses them.
--
-- fanout_scan_state: one row. The scan lock (so a scan never overlaps the
-- previous one, whichever Lambda instance runs it), where the last scan's
-- window ended (the next one starts a little before it), and the trace
-- requests scans spent in the last five minutes (their shared allowance).
--
-- fanout_scan_waves: one row per sender-and-subject wave the security team
-- was alerted about, for dedupe (one alert per wave, an update only when it
-- grows materially) and as the stable reference a reply can name. The sender
-- address and subject come from mail flow and are hostile text: always
-- parameterized, never interpolated into SQL.

CREATE TABLE IF NOT EXISTS fanout_scan_state (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  lock_token UUID,
  lock_until TIMESTAMP WITH TIME ZONE,
  last_window_end TIMESTAMP WITH TIME ZONE,
  last_started_at TIMESTAMP WITH TIME ZONE,
  -- [{"at": "<ISO time>", "requests": <n>}, ...] for the last five minutes
  recent_requests JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fanout_scan_waves (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- sha256 of "<sender address>\n<normalized subject>"
  wave_key CHAR(64) NOT NULL,
  -- Quoted in the alert; what a security-team reply names
  reference VARCHAR(40) NOT NULL UNIQUE,
  sender_address VARCHAR(320) NOT NULL,
  subject VARCHAR(1000),
  first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
  last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
  -- Recipients the last alert (or update) reported
  alerted_recipients INTEGER NOT NULL,
  -- Most recipients any scan has seen for this wave
  max_recipients INTEGER NOT NULL,
  alerts_sent INTEGER NOT NULL DEFAULT 1,
  last_alert_at TIMESTAMP WITH TIME ZONE,
  -- SES message ID of the latest alert, for matching replies (In-Reply-To)
  report_message_id VARCHAR(500),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fanout_scan_waves_key ON fanout_scan_waves (wave_key, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_fanout_scan_waves_report_message_id ON fanout_scan_waves (report_message_id);

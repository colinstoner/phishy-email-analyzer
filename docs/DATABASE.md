# Intelligence Database

Phishy's threat-intelligence layer is **optional** and backed by PostgreSQL. When `PHISHY_INTELLIGENCE_ENABLED=true`, every analysis is recorded, IOCs are extracted and deduplicated, and campaign/flood detection runs across recipients. With it disabled (the default), Phishy is stateless and needs no database.

## Requirements

- PostgreSQL 13+ (uses `gen_random_uuid()`; on PostgreSQL 12 run `CREATE EXTENSION IF NOT EXISTS pgcrypto;` first)
- A connection string, supplied either directly in config or via AWS Secrets Manager (see [CONFIGURATION.md](CONFIGURATION.md))

## Schema Management

Schema lives in versioned SQL files under [migrations/](../migrations/), applied in order:

```bash
psql "$DATABASE_URL" -f migrations/001_initial_schema.sql
```

**Auto-initialization:** for zero-setup convenience, the application also creates the baseline schema (migration 001, exactly) on first connection. This means existing deployments are already at the 001 baseline — running 001 against them is a safe no-op, since every statement is idempotent.

**Policy going forward:** the application only ever auto-creates the *baseline*. Any future schema change ships as a new numbered migration (`002_*.sql`, ...) that operators apply manually before upgrading the Lambda. Each migration must be idempotent or guarded so re-running is safe. The changelog will call out releases that require a migration.

## Tables

### `email_analyses`
One row per analyzed email: sender, subject, verdict (`is_phishing`, `confidence_score`, `risk_level`), the full AI analysis as JSONB, indicators found, VIP-impersonation flag, and which provider/model produced it. `message_id` powers deduplication (`hasBeenAnalyzed`).

### `threat_indicators`
Deduplicated IOCs (domains, IPs, URLs, emails, hashes, file names, subject patterns) extracted from analyses. Keyed by `(indicator_type, indicator_hash)` where the hash is SHA-256 of `type:lowercased-value`; re-sightings refresh `last_seen_at` and escalate `severity`/`confidence_score` (never downgrade). Supports expiry via `expires_at` and soft-deactivation via `is_active`.

Indicators are written only for a model-malicious verdict from a fresh analysis or a security-team confirmation (see [INTELLIGENCE.md](INTELLIGENCE.md#which-indicators-count)). `times_seen` counts **distinct reported emails**: each write carries a report key (the campaign signature), and a key already in `metadata.reportKeys` does not count again, so a repeat report of the same email, a reply in its thread or a copy from the same campaign leaves it unchanged. The `metadata` JSONB carries, besides the source fields (`sourceAnalysisId`, `sourceMessageId`, `extractionContext`, ...):

| Key | Meaning |
|---|---|
| `provenance` | `model_malicious` or `security_confirmed`; absent on rows written before this was recorded |
| `sourceVerdict` | the model verdict (`bec`, `phishing`, `malware_delivery`) or `confirmed_phishing` that caused the write |
| `role`, `roleSource` | `sender` / `payload` / `infrastructure`, and whether the model or the extractor assigned it. A recorded `sender`/`payload` role is never downgraded |
| `reportKeys` | the last 50 report keys counted in `times_seen` |
| `legacyTimesSeen` | a pre-existing row's old count, kept when its first keyed write restarts `times_seen` at 1 |
| `securityConfirmed`, `securityCleared` | set by security-team feedback; a cleared indicator never counts as a strong match |
| `deactivatedBy`, `deactivatedRule`, `deactivatedAt` | set when `npm run indicators:audit -- --apply` deactivated the row; removed by `--restore` |

No migration: all of this lives in the existing `metadata` column, and rows without it are read as legacy (weak) indicators.

### `campaigns`
Flood/campaign detection. Emails are grouped by a 16-char SHA-256 signature of `sender_domain + normalized subject` (numbers and punctuation stripped, so "Invoice #4821" and "Invoice #4822" match). Tracks detection count, unique recipients, and escalating risk level. An employee alert fires when a campaign reaches ≥3 detections across ≥2 recipients within 4 hours at high/critical risk, throttled to once per 24h via `alert_sent_at`. With campaign response on, `alert_sent_at` is set when an incident is opened at that threshold, or, for an incident opened earlier on reach, when a later report reaches it.

### `detected_patterns`
Recurring patterns confirmed across multiple analyses, keyed by `(pattern_type, pattern_name)` with match counting.

### `ai_usage`
Per-request token counts and estimated cost, optionally linked to the analysis row (`ON DELETE SET NULL`). Powers the cost-analytics stats (totals, 24h/7d windows, per-model breakdown).

### `email_analyses.campaign_signature` *(migration 003 — not auto-created)*
Tags each analysis with its flood-detection campaign signature, powering the **campaign verdict cache**: a report matching a recently analyzed campaign (within `PHISHY_CAMPAIGN_CACHE_TTL_HOURS`) reuses that verdict instead of triggering a new AI analysis. Cache lookups prefer an analysis with a security-team verdict (`analysis_feedback`) over the most recent raw analysis, and verdict feedback adjusts indicators sourced from *every* analysis sharing the signature — one reply resolves the whole campaign. Cached reports are stored with `ai_provider = 'cache'` and never serve as cache sources themselves (unless they carry feedback), so a campaign is re-analyzed once the original analysis ages out. Apply `migrations/003_campaign_verdict_cache.sql` before setting `PHISHY_CAMPAIGN_CACHE_ENABLED=true`.

### `analysis_feedback` *(migration 002 — not auto-created)*
Security-team verdicts on analyses, submitted by replying to Phishy's reports (the email command channel). One row per analysis (`UNIQUE(analysis_id)`); resubmission updates in place so a correction wins. Feedback also adjusts `threat_indicators` confidence through IOC provenance (`metadata.sourceAnalysisId`). Migration 002 additionally adds `email_analyses.report_message_id`, which links each outbound report to its analysis so replies can be matched via `In-Reply-To`. Apply `migrations/002_analysis_feedback.sql` before setting `PHISHY_EMAIL_COMMANDS_ENABLED=true`.

### Campaign response *(migration 006 — not auto-created)*
`migrations/006_campaign_response.sql` adds three tables for [campaign response](ARCHITECTURE.md#campaign-response-optional) (`PHISHY_CAMPAIGN_RESPONSE_ENABLED`). Without them, campaign response logs `apply migrations/006_campaign_response.sql` and the campaign alert behaves exactly as with campaign response off (any query that hits a missing table or column, `42P01`/`42703`, degrades this way).

- **`campaign_incidents`** — one row per campaign Phishy is responding to (`UNIQUE(campaign_signature)`, so concurrent reports open one incident). `reference` is the unguessable `PHY-…` code in the incident email. `trigger_source` is `reports` or `fanout_scan` (an incident opened by campaign response's reach trigger, on one report with enough blast radius, is `reports`: `summary.openedOnReach` and the `incident_opened` audit row's `basis: "reach"` say so, so no new value or migration was needed); `status` is `open`, `false_positive` or `closed`. `summary` (JSONB) holds the verdict, risk score, reasons, the model's description of the lure, the subject and claimed sender (hostile strings, shown defanged), the timeline and the reporters' addresses. `reach` (JSONB) is the blast radius merged across the incident's lookups: recipient addresses, folder, read/replied/forwarded, and the mailbox directory IDs and Graph message IDs a removal may name. `thread_message_id` is the first incident email's SES message ID (updates reply to it); `last_update_sent_at`, `notified_report_count` and `notified_recipient_count` drive the update rate limit.
- **`response_actions`** — what Phishy proposed or did: `action_type` (`send_warning`, `remove_messages`), `status` (`proposed`, `approved`, `completed`, `dry_run_completed`, `expired`, `cancelled`, `failed`), `authorization_mode` (`approve` or `auto`), the code-computed `scope` (JSONB: recipients for a warning; mailbox IDs, exact message IDs and caps for a removal) with its SHA-256 `scope_hash`, `expires_at`, the authenticated `approved_by` and `approved_at`, `executor` (`ses_warning`, `dry_run_removal`) and `result` (JSONB: who was emailed, or the dry run's counts). Approval is a conditional `UPDATE … WHERE status = 'proposed' AND expires_at > NOW()`, which is what makes approving twice a no-op.
- **`response_action_audit`** — append-only trail of every state change (`incident_opened`, `incident_updated`, `incident_false_positive`, `action_proposed`, `action_approved`, `approval_rejected`, `action_expired`, `action_cancelled`, `action_executed`, `action_dry_run`, `action_failed`), with the `actor` (`phishy` or the approver's address) and a small JSONB `detail` (counts, reasons, hashes; no message content). A trigger rejects `UPDATE`, `DELETE` and `TRUNCATE`; foreign keys from it are `ON DELETE RESTRICT`, so an incident with audit rows cannot be deleted by accident.

Useful queries:

```sql
-- Who approved what, and what happened
SELECT ci.reference AS incident, ra.reference, ra.action_type, ra.status, ra.approved_by, ra.approved_at, ra.result->'summary'
  FROM response_actions ra JOIN campaign_incidents ci ON ci.id = ra.incident_id
 ORDER BY ra.proposed_at DESC LIMIT 20;

-- The full trail of one incident
SELECT a.created_at, a.event, a.actor, a.detail
  FROM response_action_audit a JOIN campaign_incidents ci ON ci.id = a.incident_id
 WHERE ci.reference = 'PHY-XXXX-XXXX-XXXX-XXXX' ORDER BY a.id;
```
### `fanout_scan_state` and `fanout_scan_waves` *(migration 005 — not auto-created)*
State for the [scheduled fan-out scan](ARCHITECTURE.md#scheduled-fan-out-scan) (`graph.fanoutScan`); nothing else uses them. Apply `migrations/005_fanout_scan.sql` before setting `PHISHY_GRAPH_FANOUT_SCAN_ENABLED=true`. Without them the scan does not run: every scheduled invocation logs that the migration is missing and emits `FanoutScans` with `Outcome=migration_missing` (a missing table or column, `42P01` / `42703`, is caught; email analysis is unaffected).

- `fanout_scan_state` is a single row (`id = 1`): the **scan lock** (`lock_token`, `lock_until`: a scan takes it with one conditional upsert and skips if another scan holds an unexpired lease; the lease is the invocation's remaining time plus 30 s, so a crashed scan's lock expires on its own), **where the last window ended** (`last_window_end`; advanced only when a window was read and every flag in it handled, so a failed scan's window is read again), and the **request log** (`recent_requests`, a JSON array of `{at, requests}` for the last five minutes: the scans' shared message-trace allowance).
- `fanout_scan_waves` has one row per alerted wave: `wave_key` (SHA-256 of the sender address and the normalized subject), the `reference` quoted in the alert (`FANOUT-` and 10 hex digits), the sender address and subject (hostile mail-flow text, always bound as parameters), first and last sighting, the recipient count the last alert reported (`alerted_recipients`) and the most any scan saw (`max_recipients`), how many alerts went out, and the SES message ID of the latest one (`report_message_id`, for matching replies). A row whose `last_seen_at` is within `dedupeHours` is the same wave: a later sighting updates it and alerts again only if the wave at least doubled and grew by at least `fanoutMinRecipients`. A claim whose email could not be sent is undone, so the next scan alerts. No recipient address is stored.

## Privacy & Retention

The database stores sender addresses, subjects, recipient addresses (in `campaigns.unique_recipients`), and AI analysis output — but **not raw email bodies** (those stay in S3 under your bucket's lifecycle rules). There is currently no built-in retention job; operators subject to data-retention policies should schedule their own cleanup, e.g.:

```sql
DELETE FROM email_analyses WHERE created_at < NOW() - INTERVAL '180 days';
DELETE FROM ai_usage       WHERE created_at < NOW() - INTERVAL '180 days';
DELETE FROM fanout_scan_waves WHERE last_seen_at < NOW() - INTERVAL '180 days';
```

With campaign response (migration 006), `campaign_incidents.reach` and `response_actions.scope`/`result` also hold the organization's recipient addresses and Graph mailbox/message IDs. The audit table is append-only by design; retiring old audit history is a deliberate DBA action (drop the trigger, delete, recreate it), not something a cleanup job should do silently.

Safelisted users are never written to the intelligence database (see [INTELLIGENCE.md](INTELLIGENCE.md)).

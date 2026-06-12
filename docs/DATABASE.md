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
Deduplicated IOCs (domains, IPs, URLs, emails, hashes, file names, subject patterns) extracted from analyses. Keyed by `(indicator_type, indicator_hash)` where the hash is SHA-256 of `type:lowercased-value`; re-sightings bump `times_seen`, refresh `last_seen_at`, and escalate `severity`/`confidence_score` (never downgrade). Supports expiry via `expires_at` and soft-deactivation via `is_active`.

### `campaigns`
Flood/campaign detection. Emails are grouped by a 16-char SHA-256 signature of `sender_domain + normalized subject` (numbers and punctuation stripped, so "Invoice #4821" and "Invoice #4822" match). Tracks detection count, unique recipients, and escalating risk level. An employee alert fires when a campaign reaches ≥3 detections across ≥2 recipients within 4 hours at high/critical risk, throttled to once per 24h via `alert_sent_at`.

### `detected_patterns`
Recurring patterns confirmed across multiple analyses, keyed by `(pattern_type, pattern_name)` with match counting.

### `ai_usage`
Per-request token counts and estimated cost, optionally linked to the analysis row (`ON DELETE SET NULL`). Powers the cost-analytics stats (totals, 24h/7d windows, per-model breakdown).

## Privacy & Retention

The database stores sender addresses, subjects, recipient addresses (in `campaigns.unique_recipients`), and AI analysis output — but **not raw email bodies** (those stay in S3 under your bucket's lifecycle rules). There is currently no built-in retention job; operators subject to data-retention policies should schedule their own cleanup, e.g.:

```sql
DELETE FROM email_analyses WHERE created_at < NOW() - INTERVAL '180 days';
DELETE FROM ai_usage       WHERE created_at < NOW() - INTERVAL '180 days';
```

Safelisted users are never written to the intelligence database (see [INTELLIGENCE.md](INTELLIGENCE.md)).

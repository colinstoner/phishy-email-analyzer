# Threat Intelligence Module

## Purpose

The intelligence module is **optional** and provides organizational learning capabilities:

### Internal Benefits

1. **Institutional Memory**: Track what phishing attempts have targeted your organization
2. **Pattern Detection**: Automatically identify coordinated campaigns (same sender across multiple employees)
3. **Deduplication**: Don't re-analyze the same phishing email forwarded by multiple users
4. **Trend Analysis**: See how threats evolve over time (weekly reports, quarterly trends)
5. **VIP Targeting**: Identify when specific executives are being targeted

### Security Team Value

- **Faster Response**: See related emails when investigating an incident
- **IOC Extraction**: Automatically extract domains, IPs, URLs from confirmed phishing
- **Historical Context**: "Have we seen this sender before?"
- **Campaign Tracking**: Link related attacks together

### What It Does NOT Do

- Does not share data externally (stays in your database)
- Does not require external threat feeds
- Does not phone home to any service
- Does not impact the core email analysis functionality

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│  Email Analysis │────▶│ Intelligence DB  │
│    (Lambda)     │     │   (PostgreSQL)   │
└─────────────────┘     └──────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │   REST API       │
                        │  (API Gateway)   │
                        └──────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌─────────┐     ┌───────────┐    ┌───────────┐
        │  SIEM   │     │ Dashboard │    │  Alerts   │
        │ Webhook │     │  (Future) │    │  (Future) │
        └─────────┘     └───────────┘    └───────────┘
```

## Enabling Intelligence

### Minimal Setup

```bash
# Enable the feature
export PHISHY_INTELLIGENCE_ENABLED=true

# PostgreSQL connection (any PostgreSQL 12+ works)
export PHISHY_DB_CONNECTION=postgresql://user:pass@host:5432/phishy
```

### Database Options

1. **AWS RDS PostgreSQL** - Managed, recommended for production
2. **Aurora Serverless v2** - Auto-scaling, cost-effective for variable load
3. **Self-hosted PostgreSQL** - Any PostgreSQL 12+ on EC2, container, etc.
4. **Local development** - Docker: `docker run -p 5432:5432 postgres:15`

### Tables Created Automatically

When intelligence is enabled, these tables are created on first run:

- `email_analyses` - Every analyzed email with results
- `threat_indicators` - Extracted IOCs (domains, IPs, URLs, hashes) with provenance metadata
- `campaigns` - Coordinated attack tracking (same sender pattern across multiple recipients)
- `detected_patterns` - Identified attack patterns (reserved for future use)

### IOC Provenance

Each threat indicator includes metadata linking back to its source:

```json
{
  "sourceAnalysisId": "uuid-of-analysis",
  "sourceMessageId": "email-message-id",
  "sourceFromEmail": "attacker@malicious.com",
  "sourceFromDomain": "malicious.com",
  "sourceSubject": "Urgent: Verify your account",
  "extractionContext": "url_in_content"
}
```

Extraction contexts: `sender_email`, `sender_domain`, `url_domain`, `url_in_content`, `ip_in_content`, `hash_in_content`

Stored indicators also record why they were stored and what part they played (see [DATABASE.md](DATABASE.md#threat_indicators) for every key):

```json
{
  "provenance": "model_malicious",
  "sourceVerdict": "phishing",
  "role": "payload",
  "roleSource": "model",
  "reportKeys": ["3f9c0a1b2c3d4e5f"]
}
```

## Which indicators count

The rules live in `src/services/intelligence/indicator.policy.ts`; risk fusion, the agentic `lookup_indicators` tool and the audit CLI all use them.

### When an email's indicators are stored

| Situation | Stored? |
|---|---|
| Fresh analysis, model verdict `bec`, `phishing` or `malware_delivery` | yes, `provenance: model_malicious` |
| Security team confirmed the campaign (`confirmed_phishing`) | yes, `provenance: security_confirmed` |
| Model verdict `suspicious`, `spam`, `graymail`, `legitimate` | no — even when intelligence raised the score |
| Campaign-cache hit without a ruling | no — the source analysis already stored them |
| Analysis failed, or the security team cleared the campaign | no |

`times_seen` counts distinct reported emails. Each write carries the campaign signature as a report key; repeat reports of the same email, replies in its thread and copies from the same campaign share a key and count once.

### Strong and weak matches

When a new email contains a stored indicator, the match is **strong** only if the stored indicator is:

- active and not past `expires_at`;
- stored from a model-malicious or security-confirmed report (and not cleared by the security team since);
- an exact URL, an exact email address, or a domain; and
- recorded in the role `sender` or `payload`.

Everything else is **weak**: infrastructure (redirectors, click trackers, relays), IPs, hashes, expired rows, and every indicator stored before provenance was recorded.

| | Strong | Weak |
|---|---|---|
| Reason shown in the report | yes | yes ("…not treated as evidence of an attack") |
| Score | floor `min(95, 60 + timesSeen × 8)` | lifts a `suspicious` or unassessed email to at most `WEAK_INDICATOR_RISK_CEILING` (40); never changes a benign verdict |
| Verdict | a benign verdict becomes `suspicious`, with a reason | unchanged (an unassessed email becomes `suspicious` at 40) |
| Can make the email "phishing" | yes | never |

### Score bands

After fusion the score is clamped into the band for the final verdict, so the number never contradicts the label (`VERDICT_SCORE_BANDS` in `risk.fusion.ts`):

| Final verdict | Band | Level shown |
|---|---|---|
| `legitimate` | 0–10 | safe / low |
| `graymail`, `spam` | 10–29 | low |
| `suspicious` | 30–79 | medium / high, never critical |
| `bec`, `phishing`, `malware_delivery` | 55–100 | high / critical |

A raise changes the verdict first, then the band applies. `isPhishing` follows verdict and score together: malicious verdicts always, `suspicious` at 55 or more, benign verdicts never. Security-team rulings are applied first and are not banded (confirmed ≥ 95, cleared 0).

### Confidence

The report's confidence line is the model's own certainty in its verdict (`verdictConfidence`: ≥ 0.9 Very High, ≥ 0.7 High, ≥ 0.5 Medium, ≥ 0.3 Low, else Very Low). When a security-team ruling decided, it reads "Decided by your security team's review"; when a strong indicator or an active campaign changed the outcome, "Based on a known threat from earlier reports". It is omitted when the email could not be analyzed.

### Auditing existing indicators

Indicators stored before these rules have no provenance, so they all count as weak from the first run of this version — nothing needs to change for that. To see how a database's indicators classify, and optionally deactivate some:

```bash
export PHISHY_DB_CONNECTION=postgresql://user:pass@host:5432/phishy   # or --connection
npm run indicators:audit                    # dry run: counts and the most-seen weak indicators
npm run indicators:audit -- --json          # machine-readable
npm run indicators:audit -- --apply         # deactivate rows matching the default rules
npm run indicators:audit -- --apply --rule unproven   # opt-in: every row without provenance
npm run indicators:audit -- --restore       # reactivate everything this tool deactivated
```

| Rule | Matches (active rows only) | Default |
|---|---|---|
| `expired` | `expires_at` in the past | yes |
| `unproven-infrastructure` | no provenance and role `infrastructure` (redirectors, trackers, IPs, hashes; derived from `extractionContext` for legacy rows) | yes |
| `unproven` | no provenance, any role | no (opt-in) |

`--apply` only sets `is_active = FALSE` and marks the row (`metadata.deactivatedBy`), so `--restore` reverses it; nothing is ever deleted. The tool reads in pages, uses parameterized SQL only, does not create tables, prints indicator values with control and bidi characters removed and email local parts masked (unless `--show-values`), and never prints the connection string. A Secrets Manager ARN in `PHISHY_DB_CONNECTION` is not resolved; pass the connection string with `--connection`.

## API Endpoints

When you deploy the API Lambda (optional), these endpoints are available:

```
GET  /api/v1/analyses              List recent analyses
GET  /api/v1/analyses/:id          Get single analysis
POST /api/v1/analyses/search       Search with filters
GET  /api/v1/indicators            List extracted IOCs
GET  /api/v1/indicators/export     Export in STIX format
GET  /api/v1/patterns              Detected patterns
GET  /api/v1/stats                 Aggregate statistics
```

## SIEM/SOAR Integration

Register a webhook to receive real-time alerts:

```bash
curl -X POST https://your-api/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-siem.com/webhook",
    "events": ["threat.detected", "vip.impersonation"],
    "secret": "your-hmac-secret"
  }'
```

### Webhook Events

| Event | Description |
|-------|-------------|
| `threat.detected` | High-confidence phishing detected |
| `vip.impersonation` | Executive impersonation attempt |
| `pattern.detected` | New attack pattern identified |

### Payload Format

```json
{
  "event": "threat.detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "high",
  "data": {
    "analysisId": "uuid",
    "fromEmail": "attacker@fake-domain.com",
    "subject": "Urgent wire transfer",
    "indicators": [
      {"type": "domain", "value": "fake-domain.com"},
      {"type": "url", "value": "https://fake-domain.com/login"}
    ]
  }
}
```

## Campaign Flood Detection

When multiple phishing emails with similar patterns hit your organization, Phishy can alert your security team automatically.

### Enabling Campaign Alerts

```bash
export PHISHY_CAMPAIGN_ALERTS_ENABLED=true
export PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION=security@yourcompany.com
```

### Alert Triggers

An alert is sent when ALL of these conditions are met:

- ≥3 detections with the same sender domain + subject pattern
- ≥2 unique recipients targeted
- Within a 4-hour window
- Risk level is high or critical
- No alert sent for this campaign in the last 24 hours

### How It Works

1. Subject lines are normalized (numbers stripped, prefixes removed) to group similar emails
2. A campaign signature is generated from sender domain + normalized subject
3. Each detection updates the campaign record
4. When thresholds are met, an email alert is sent with campaign details

## Privacy & Compliance

- **Data stays internal**: All data remains in your PostgreSQL instance
- **Retention control**: Configure data retention policies as needed
- **No external dependencies**: Intelligence module has no external API calls
- **Your data, your control**: Export, delete, or migrate freely

## Disabling Intelligence

Simply don't set `PHISHY_INTELLIGENCE_ENABLED=true`. The core email analysis works identically without it - the feature is completely optional.

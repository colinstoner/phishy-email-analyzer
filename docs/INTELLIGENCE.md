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
- `threat_indicators` - Extracted IOCs (domains, IPs, URLs, hashes)
- `detected_patterns` - Identified attack campaigns/patterns

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

## Privacy & Compliance

- **Data stays internal**: All data remains in your PostgreSQL instance
- **Retention control**: Configure data retention policies as needed
- **No external dependencies**: Intelligence module has no external API calls
- **Your data, your control**: Export, delete, or migrate freely

## Disabling Intelligence

Simply don't set `PHISHY_INTELLIGENCE_ENABLED=true`. The core email analysis works identically without it - the feature is completely optional.

# Configuration Guide

Phishy supports multiple configuration methods with a clear priority chain. This guide covers all options from simple environment variables to full enterprise profiles.

## Quick Start (Environment Variables Only)

For simple deployments, you only need these environment variables:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...          # Your Anthropic API key

# Recommended
S3_BUCKET_NAME=my-phishy-emails       # S3 bucket for email storage
SENDER_EMAIL=phishy@yourcompany.com   # Email address for notifications
SECURITY_TEAM_DISTRIBUTION=security@yourcompany.com  # Where to send alerts
```

That's it! Phishy will work with just these settings.

---

## Configuration Priority

When the same setting is defined in multiple places, Phishy uses this priority (highest wins):

1. **Environment Variables** - Runtime overrides, always win
2. **S3 Configuration** - `PHISHY_CONFIG_S3=s3://bucket/config.json`
3. **Local File** - `./config/phishy.config.json`
4. **Defaults** - Built-in sensible defaults

---

## Environment Variables Reference

### AI Provider Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_AI_PROVIDER` | `anthropic` | AI provider: `anthropic` or `bedrock` |
| `ANTHROPIC_API_KEY` | - | Anthropic API key (required for anthropic provider) |
| `CLAUDE_MODEL` | `claude-opus-4-8` | Model for Anthropic provider |
| `PHISHY_BEDROCK_REGION` | `us-east-1` | AWS region for Bedrock |
| `PHISHY_BEDROCK_MODEL` | `global.anthropic.claude-opus-4-8` | Bedrock model ID |

> Max tokens and request timeout are file-config only (`ai.anthropic.maxTokens` / `ai.bedrock.timeout`, etc.) — see the example configuration below.

### Email Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFE_DOMAINS` | - | Comma-separated safe sender domains |
| `SAFE_SENDERS` | - | Comma-separated safe sender emails |
| `DELETE_EMAILS_AFTER_PROCESSING` | `false` | Delete emails from S3 after analysis |

### Notification Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDER_EMAIL` | - | From address for notification emails |
| `SECURITY_TEAM_DISTRIBUTION` | - | Comma-separated CC recipients for enterprise users |
| `SAFE_SENDER_SECURITY` | - | Comma-separated CC recipients for safelist users (optional, separate from enterprise) |
| `SES_CONFIG_SET` | - | Optional SES configuration set |

### Storage Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_BUCKET_NAME` | - | S3 bucket for email storage |
| `S3_PREFIX` | `emails` | Prefix for stored emails |
| `AWS_REGION` | `us-east-1` | AWS region for S3/SES |

### Enterprise Features

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_CONFIG_S3` | - | S3 path to config file |
| `PHISHY_PROFILE` | - | S3 path or JSON of enterprise profile |
| `PHISHY_INTELLIGENCE_ENABLED` | `false` | Enable threat intelligence DB |
| `PHISHY_DB_CONNECTION` | - | PostgreSQL connection string or Secrets Manager ARN |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | `false` | Enable campaign flood detection alerts |
| `PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION` | - | Email to receive campaign alerts |

### Agentic Analysis

By default Phishy analyzes each email in a single AI call. With agentic mode enabled, the analysis runs as a **bounded tool-use loop**: Claude reads the email and may consult Phishy's own data before delivering its verdict.

The tools — deliberately limited to organizational data and pure computation, with no network fetches or open-ended browsing:

| Tool | Backed by | Answers |
|------|-----------|---------|
| `examine_url` | pure computation | "What's structurally suspicious about this link?" (IP hosts, punycode, redirect chains, credential tricks — never fetched) |
| `lookup_indicators` | intelligence DB | "Have we seen this domain/URL/IP/email before, and how bad was it?" |
| `check_campaign` | intelligence DB | "Are other employees reporting this same email right now?" |
| `check_profile` | enterprise profile | "Is this a VIP, a trusted partner, our own domain — or a lookalike of one?" |

Tools are only offered when their backing data exists (no database → no intel tools). The loop is hard-capped at `maxToolRounds`; any failure falls back to the standard single-shot analysis, so agentic mode can never make Phishy less reliable. The verdict summary cites what the intelligence showed (e.g. "this domain was flagged in 4 previous reports"), and the tools used are recorded with the analysis.

Agentic mode also upgrades **Email Commands**: free-text replies the keyword parser can't read ("checked with accounting, that vendor switched banks — all good") are interpreted by the model, constrained to the two known verdicts.

Note: each tool round is an additional model call, so an agentic analysis can cost roughly 2–4× a standard one. The campaign verdict cache offsets this — in a flood, only the first report pays for the deep analysis.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_AGENTIC_ENABLED` | `false` | Run analysis as a bounded tool-use loop |
| `PHISHY_AGENTIC_MAX_TOOL_ROUNDS` | `5` | Maximum tool rounds before a verdict is required (1–10) |

### Campaign Verdict Cache

When a phishing campaign hits many inboxes at once, every recipient may forward the same email. With the cache enabled, the **first** report gets a full AI analysis; reports matching the same campaign within the cache window reuse that verdict — every reporter gets a consistent answer, instantly and at no extra AI cost. Reports served from the cache say so in the summary, and a `CampaignCacheHits` / `EstimatedCostSavedUSD` metric is emitted (see Cost Tracking below).

Campaign matching uses the same signature as flood detection: sender domain plus the subject with numbers normalized out, so "Invoice #4821" and "Invoice #4822" match.

This composes with Email Commands: when the security team replies "confirmed phishing" or "false positive" to **any one** report, that ruling overrides the AI verdict for the whole campaign — subsequent reporters are told their security team has already reviewed it.

Requires the intelligence database and `migrations/003_campaign_verdict_cache.sql`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | `false` | Reuse recent verdicts for same-campaign reports |
| `PHISHY_CAMPAIGN_CACHE_TTL_HOURS` | `24` | How long a verdict may be reused before re-analysis (max 168) |

### Email Commands (Security Team Correspondence)

When enabled, the security team can direct Phishy by replying to its analysis reports. Phishy matches the reply to the analysis (via the email thread or the quoted `Analysis ID:` line), executes the command, and replies with the completed actions.

v1 commands — anywhere in the reply text:

- **"confirmed phishing"** (or "confirm", "malicious", "agreed") — confirms the verdict and strengthens the confidence of every indicator extracted from that email
- **"false positive"** (or "not phishing", "legit", "safe") — overturns the verdict, decays those indicators, and deactivates any that fall below the confidence floor

Replying again with the other verdict corrects a mistake — the latest answer wins.

**Authorization is two-factor:** the sender must be in `SECURITY_TEAM_DISTRIBUTION` *and* the inbound mail must pass SES SPF or DKIM verification, so a spoofed From header cannot issue commands. Regular employees' replies are never treated as commands.

Requires the intelligence database and `migrations/002_analysis_feedback.sql`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_EMAIL_COMMANDS_ENABLED` | `false` | Process security-team replies as commands |

### Microsoft Graph (Optional)

Phishy can authenticate to Microsoft Graph on your own Microsoft 365 tenant. `PHISHY_GRAPH_ENABLED` is a **foundation**: on its own it does not change how emails are analyzed. Each feature that uses Graph has its own flag — today that is the [original-message lookup](#original-message-lookup) — so that features (and later ones, such as checking who else received an email) share one safe, already-reviewed way to reach the tenant. Leave it off unless you are enabling one of them. See [ARCHITECTURE.md](ARCHITECTURE.md#microsoft-graph-optional-foundation) for the trust rules.

To find out which Graph calls work in your tenant — with which permissions and licences — before any feature depends on them, run the read-only probe: [GRAPH_PROBE.md](GRAPH_PROBE.md). It runs locally (`npm run graph:probe`), takes the same tenant ID, client ID and certificate, and does not need `PHISHY_GRAPH_ENABLED`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_ENABLED` | `false` | Enable Microsoft Graph access |
| `PHISHY_GRAPH_TENANT_ID` | - | Directory (tenant) ID (GUID), or a verified domain of the tenant. Required when enabled |
| `PHISHY_GRAPH_READ_CLIENT_ID` | - | Application (client) ID (GUID) of the read-only app registration. Required when enabled |
| `PHISHY_GRAPH_READ_CERTIFICATE` | - | Secrets Manager ARN (recommended) or inline PEM holding the app's private key and certificate. Required when enabled |
| `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` | `false` | Before analysis, read the original message's real headers from the reporter's own mailbox. Has effect only when `PHISHY_GRAPH_ENABLED` is also `true`. See [Original-message lookup](#original-message-lookup) |

File configuration uses the same names: `graph.enabled`, `graph.tenantId`, `graph.read.clientId`, `graph.read.certificate`, `graph.originalFetch.enabled`. With `graph.enabled` set, a missing or malformed value fails configuration at startup; with it unset, the other values are ignored.

Authentication is **certificate-only** — there is no client-secret option. Phishy signs a five-minute JWT assertion with the private key and exchanges it for an access token, which is cached in memory and refreshed before it expires. The certificate thumbprint is derived from the certificate itself; you do not configure it.

#### The certificate

Create a key pair and a self-signed certificate (an internal CA works too). The key must be RSA and must not be passphrase-protected:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout phishy-graph-read.key -out phishy-graph-read.crt \
  -subj "/CN=phishy-graph-read"
```

Upload **only** `phishy-graph-read.crt` (the public certificate) to Entra. Store the private key and certificate together in Secrets Manager, in either form:

```bash
# 1. PEM bundle: private key followed by certificate
cat phishy-graph-read.key phishy-graph-read.crt > bundle.pem
aws secretsmanager create-secret --name phishy/graph-read --secret-string file://bundle.pem

# 2. JSON: {"privateKey": "-----BEGIN PRIVATE KEY-----\n...", "certificate": "-----BEGIN CERTIFICATE-----\n..."}
```

Then set `PHISHY_GRAPH_READ_CERTIFICATE` to the secret's ARN and delete the local key file. The Lambda execution role needs `secretsmanager:GetSecretValue` on that secret. The secret is read on the first Graph call, not at startup, and never logged.

Inline PEM (the bundle itself as the setting's value, with newlines or literal `\n`) is accepted for local development. Do not use it in a deployed environment: Lambda environment variables are visible to anyone who can read the function's configuration.

Phishy refuses an expired certificate and logs a warning when one is within 30 days of expiry. To rotate, upload the new certificate to the app registration, update the secret, then remove the old certificate from Entra.

#### Entra app registration

1. **Register a single-tenant app.** Microsoft Entra admin center → *App registrations* → *New registration*. Choose *Accounts in this organizational directory only*. No redirect URI. Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Upload the certificate.** *Certificates & secrets* → *Certificates* → *Upload certificate* → select the `.crt` file. Do **not** create a client secret.
3. **Grant application permissions, with admin consent.** *API permissions* → *Add a permission* → *Microsoft Graph* → *Application permissions*. Add only what the features you enable require (each feature documents its own; the foundation needs none), then *Grant admin consent*. Use read-only permissions on this registration — anything that writes to the tenant belongs to a separate app registration with its own certificate.
4. **Scope mailbox permissions in Exchange Online, not Entra.** A mailbox permission such as `Mail.Read` granted in Entra applies to **every mailbox in the tenant**. To limit Phishy to the mailboxes it should see, grant the mailbox permission through Exchange Online [RBAC for Applications](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac) instead:

   ```powershell
   # IDs come from Entra > Enterprise applications (not App registrations)
   New-ServicePrincipal -AppId <application-id> -ObjectId <enterprise-app-object-id> -DisplayName "Phishy Graph (read)"
   New-ManagementScope -Name "Phishy reporters" -RecipientRestrictionFilter "<filter selecting the mailboxes>"
   New-ManagementRoleAssignment -App <application-id> -Role "Application Mail.Read" -CustomResourceScope "Phishy reporters"
   Test-ServicePrincipalAuthorization -Identity <application-id> -Resource <a-mailbox>
   ```

   > **An unscoped grant in Entra defeats the scoping.** Effective access is the *union* of the Entra grant and the Exchange RBAC assignment. If `Mail.Read` is also consented tenant-wide in Entra, the app can read every mailbox regardless of the management scope. Grant mailbox permissions in one place only — Exchange RBAC — and remove the same permission from the app's Entra API permissions. `Test-ServicePrincipalAuthorization` does not show Entra grants, so check both. Changes can take 30 minutes to 2 hours to take effect.

#### Network

The Lambda needs outbound HTTPS (TCP 443) to:

- `login.microsoftonline.com` — token requests
- `graph.microsoft.com` — Graph API

If the function runs in a VPC, that means a NAT gateway (or equivalent egress) and security-group/egress-filter rules allowing those hosts; there is no VPC endpoint for them. Phishy only ever contacts these two hosts for Graph: the client's base URL is fixed, it refuses redirects, and it will not follow a paging link to any other origin.

#### Original-message lookup

When an employee forwards a suspicious email, the forward carries none of the original's headers — only the From, Sent and Subject lines the mail client pasted in. With `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED=true` (and Graph enabled), Phishy looks the original up in **the reporter's own mailbox** and gives the analysis its real headers: `Authentication-Results`, the `Received` chain, `Return-Path`, `Reply-To`, `Message-ID`.

- **Permission:** `Mail.Read` (application) on the mailboxes of the people who report to Phishy, on the read-only app registration. Grant it through Exchange RBAC for Applications as described above, scoped to those mailboxes, not tenant-wide in Entra. No other permission is used, and nothing is ever written.
- **What is read:** message metadata to find the message, then that one message's Internet headers. Never a body or an attachment, and never a mailbox other than the reporter's.
- **When it runs:** only for reports that arrive through SES with an SPF or DKIM `PASS` and whose `From` address is the safe-domain reporter; not for safelist senders, not when a campaign verdict is reused.
- **Matching:** the claimed sender, sent time and subject must match **exactly one** message, counting the mailbox and its Recoverable Items (so a message the reporter deleted after forwarding is still found). No match, or more than one, and the analysis proceeds exactly as it does without this feature. So does any Graph error or timeout: the lookup has an 8-second overall budget and never fails a report.
- **Network:** the hosts listed under [Network](#network) must be reachable from the function.

To confirm beforehand that these calls work in your tenant, run the [probe](GRAPH_PROBE.md) (`Sender + time-window filter`, `/messages covers Recoverable Items`, `Internet headers via $select`).

Each lookup emits one CloudWatch EMF line in the `Phishy` namespace:

| Metric | Dimension | Meaning |
|--------|-----------|---------|
| `OriginalFetchCount` | `Outcome` = `found` / `not_found` / `ambiguous` / `error` / `skipped` | One per lookup. `skipped`: no request was made (no usable claimed sender or sent time, or the reporter could not be confirmed). A sustained `error` share means a permission, certificate or network problem — the log line `Original-message lookup failed` carries Graph's status, error code and request id |
| `OriginalFetchDurationMs` | `Outcome` | Time the lookup added to the report |

How the retrieved headers are labelled for the model, and why they are not treated as verified facts, is in [ARCHITECTURE.md](ARCHITECTURE.md#original-message-lookup).

### AWS Secrets Manager Integration

Instead of storing database credentials in environment variables, you can use AWS Secrets Manager:

```bash
# Use Secrets Manager ARN instead of raw connection string
PHISHY_DB_CONNECTION=arn:aws:secretsmanager:us-west-2:123456789:secret:phishy/db-credentials

# The secret can be stored as:
# 1. Raw connection string: "postgresql://user:pass@host:5432/db"
# 2. JSON with connectionString key: {"connectionString": "postgresql://..."}
# 3. JSON with components: {"username": "...", "password": "...", "host": "...", "port": "5432", "database": "phishy"}
```

The Lambda execution role needs `secretsmanager:GetSecretValue` permission for the secret ARN.

The Microsoft Graph certificate (`PHISHY_GRAPH_READ_CERTIFICATE`) follows the same convention — a Secrets Manager ARN or the value itself — see [Microsoft Graph](#microsoft-graph-optional).

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level: debug, info, warn, error |

### Cost Tracking (CloudWatch Metrics)

Every analysis emits token usage and estimated cost to CloudWatch via [Embedded Metric Format](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html) — structured log lines that CloudWatch converts to metrics automatically. No SDK calls, no extra IAM permissions, and it works whether or not the intelligence database is enabled.

Metrics appear in the **`Phishy`** namespace, dimensioned by `Provider` and `Model`:

| Metric | Meaning |
|--------|---------|
| `AnalysisCount` | Analyses performed |
| `InputTokens` / `OutputTokens` / `TotalTokens` | Token consumption |
| `EstimatedCostUSD` | Estimated spend per analysis (per-model pricing, including the 10% Bedrock regional-endpoint premium) |
| `ProcessingTimeMs` | End-to-end analysis latency |
| `PhishingDetected` | 1 if the verdict was phishing, 0 otherwise |
| `CampaignCacheHits` | Reports answered from the campaign verdict cache (no AI call) |
| `EstimatedCostSavedUSD` | Approximate spend avoided by cache hits |

Useful starting points: a dashboard widget on `SUM(EstimatedCostUSD)` per day, and a billing alarm such as "alert when `SUM(EstimatedCostUSD)` over 24h exceeds $X". Set `PHISHY_DISABLE_METRICS=true` to turn emission off.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_DISABLE_METRICS` | `false` | Set `true` to disable CloudWatch EMF metrics |

---

## File-Based Configuration

For more complex setups, use a JSON configuration file.

### Location Options

1. **Local file**: `./config/phishy.config.json`
2. **S3**: Set `PHISHY_CONFIG_S3=s3://bucket/path/config.json`

### Example Configuration

```json
{
  "ai": {
    "provider": "bedrock",
    "bedrock": {
      "region": "us-east-1",
      "modelId": "global.anthropic.claude-opus-4-8",
      "maxTokens": 4096,
      "timeout": 60000
    },
    "fallbackProvider": "anthropic"
  },
  "email": {
    "safeDomains": ["yourcompany.com", "trusted-partner.com"],
    "safeSenders": ["ceo@yourcompany.com"],
    "deleteAfterProcessing": false
  },
  "notification": {
    "senderEmail": "phishy@yourcompany.com",
    "senderName": "Phishy Security",
    "securityTeamDistribution": ["security@yourcompany.com", "soc@yourcompany.com"]
  },
  "storage": {
    "s3Bucket": "phishy-emails",
    "s3Prefix": "emails",
    "region": "us-east-1"
  },
  "logLevel": "info"
}
```

See `config/phishy.config.example.json` for a complete example.

---

## AWS Bedrock vs Anthropic Direct

### When to Use Bedrock

- **Already on AWS**: No additional API keys needed, uses IAM
- **Compliance**: Data stays within your AWS account
- **Cost**: May be more cost-effective at scale with reserved capacity
- **Enterprise**: Better audit trails via CloudTrail

### When to Use Anthropic Direct

- **Simplicity**: Just needs an API key
- **Latest models**: Sometimes available sooner
- **Non-AWS**: Running outside AWS infrastructure

### Switching Providers

```bash
# Use Anthropic (default)
export PHISHY_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Use Bedrock (requires IAM permissions)
export PHISHY_AI_PROVIDER=bedrock
export PHISHY_BEDROCK_REGION=us-east-1
```

### Provider Fallback

Configure automatic fallback if primary provider fails:

```json
{
  "ai": {
    "provider": "bedrock",
    "fallbackProvider": "anthropic",
    "anthropic": {
      "apiKey": "sk-ant-..."
    }
  }
}
```

---

## Enterprise Profiles

Enterprise profiles provide organization-specific context for better phishing detection.

### Quick Setup

1. Copy the example: `cp config/profile.example.json config/profile.json`
2. Customize for your organization
3. Set the path: `export PHISHY_PROFILE=./config/profile.json`

Or store in S3: `export PHISHY_PROFILE=s3://bucket/profiles/mycompany.json`

### What Profiles Enable

- **VIP Protection**: Flag impersonation of executives
- **Domain Awareness**: Know your legitimate domains vs. lookalikes
- **Partner Trust**: Recognize legitimate partner communications
- **Threat Context**: Include recent threats targeting your org
- **Custom Keywords**: High-risk terms specific to your business

See `config/profile.example.json` for the full schema.

---

## Threat Intelligence Database (Optional)

Enable persistent threat tracking with PostgreSQL.

### Setup

```bash
export PHISHY_INTELLIGENCE_ENABLED=true
export PHISHY_DB_CONNECTION=postgresql://user:pass@host:5432/phishy
```

### What It Provides

- **IOC Tracking**: Automatically extract and store indicators
- **Pattern Detection**: Identify related phishing campaigns
- **Historical Analysis**: Query past threats
- **STIX Export**: Share threat intel in standard format

### Database Schema

The database is automatically initialized on first connection. See `src/services/intelligence/database.service.ts` for the schema.

---

## Migration from v1

If you're upgrading from the original Phishy, your existing environment variables continue to work unchanged:

| v1 Variable | Still Works | New Alternative |
|-------------|-------------|-----------------|
| `ANTHROPIC_API_KEY` | ✓ | `ai.anthropic.apiKey` |
| `CLAUDE_MODEL` | ✓ | `ai.anthropic.model` |
| `SAFE_DOMAINS` | ✓ | `email.safeDomains` |
| `SAFE_SENDERS` | ✓ | `email.safeSenders` |
| `S3_BUCKET_NAME` | ✓ | `storage.s3Bucket` |
| `SECURITY_TEAM_DISTRIBUTION` | ✓ | `notification.securityTeamDistribution` |

**Zero changes required** - your v1 deployment will work with v2.

---

## Validation

Phishy validates all configuration at startup using Zod schemas. Invalid configuration will fail fast with clear error messages:

```
Configuration error: ai.anthropic.apiKey must start with 'sk-ant-'
```

Validation runs on every cold start, so a misconfigured deployment fails immediately and loudly in CloudWatch logs rather than silently misbehaving. To catch problems before deploying, compare your config against [config/phishy.config.example.json](../config/phishy.config.example.json) — every key is documented in this file.

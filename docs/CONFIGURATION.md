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
| `CLAUDE_MODEL` | `claude-sonnet-4-5-20250514` | Model for Anthropic provider |
| `BEDROCK_REGION` | `us-east-1` | AWS region for Bedrock |
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-sonnet-4-5-20250514-v1:0` | Bedrock model ID |
| `AI_MAX_TOKENS` | `4096` | Max tokens for AI response |
| `AI_TIMEOUT` | `60000` | AI request timeout (ms) |

### Email Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFE_DOMAINS` | - | Comma-separated safe sender domains |
| `SAFE_SENDERS` | - | Comma-separated safe sender emails |
| `DELETE_AFTER_PROCESSING` | `false` | Delete emails from S3 after analysis |

### Notification Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDER_EMAIL` | - | From address for notification emails |
| `SENDER_NAME` | `Phishy Security` | Display name for notifications |
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

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level: debug, info, warn, error |

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
      "modelId": "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
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
export BEDROCK_REGION=us-east-1
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

To validate your config without running:

```bash
npm run validate-config
```

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Unified handler routing SES and API Gateway events through a single Lambda entry point
- Campaign detection and employee alert system
- Recipient signature analysis for risk-aware phishing detection
- Safelist bypass for enterprise profiles, with separate security CC for safelist users
- Original sender header extraction from forwarded emails, with an "Original Email" section in reports
- IOC provenance tracking with source context metadata
- Intelligence database storage with IOC extraction (optional PostgreSQL backend)
- AWS Secrets Manager support for database credentials
- AI usage tracking and cost analytics for Bedrock
- `WebhookService` (SIEM/SOAR delivery with HMAC signing) exported from the package root
- AWS SAM template (`template.yaml`) for one-command deployment of the Lambda, S3 bucket, SES receipt rules, and IAM permissions
- Versioned database migrations (`migrations/`) and schema documentation (`docs/DATABASE.md`)
- Unit test suites for the email parser and analysis service
- Email command channel (`PHISHY_EMAIL_COMMANDS_ENABLED`): the security team replies to analysis reports to correct verdicts ("confirmed phishing" / "false positive"), and Phishy executes the command and replies with completed actions. Verdicts are stored per analysis (migration 002) and immediately adjust indicator confidence via IOC provenance. Authorization is two-factor: security-team membership plus SES SPF/DKIM verification
- SES SPF/DKIM/DMARC verdicts are now captured from receipt events and available to the pipeline
- Reports include an `Analysis ID` line, and outbound report message IDs are stored for `In-Reply-To` thread matching
- Campaign verdict cache (`PHISHY_CAMPAIGN_CACHE_ENABLED`): when a flood of the same email is reported, the first report gets a full AI analysis and subsequent same-campaign reports reuse its verdict (migration 003) — consistent answers for every reporter, no duplicate AI spend. A security-team reply to any one report ("confirmed phishing" / "false positive") overrides the AI verdict for the whole campaign, and verdict feedback now adjusts indicators campaign-wide. Cache hits emit `CampaignCacheHits` / `EstimatedCostSavedUSD` metrics
- CloudWatch cost/usage metrics via Embedded Metric Format: every analysis emits tokens, estimated USD cost, latency, and verdict to the `Phishy` namespace, with no database or extra IAM required (`PHISHY_DISABLE_METRICS` to opt out)
- Per-model pricing table for cost estimation, replacing hardcoded Sonnet rates; includes the 10% Bedrock regional-endpoint premium
- Token usage capture for the Anthropic API provider (previously Bedrock-only)

### Changed
- **Default model upgraded to Claude Opus 4.8** on both providers (`claude-opus-4-8` / `anthropic.claude-opus-4-8`); model catalogs refreshed with Opus 4.6, Sonnet 4.6, and current Bedrock `global.`/regional ID formats
- Full-prompt logging in the Bedrock provider moved from info to debug level — reported email content no longer lands in CloudWatch logs at default log levels
- **License changed from GPL-3.0 to Apache-2.0**
- Bedrock model defaults and configuration updated for inference profiles and VPC endpoints

### Fixed
- Anthropic provider model catalog contained invalid IDs (wrong date suffixes) that returned 404 from the API; catalog rebuilt with current model aliases
- Cost estimation previously used hardcoded Sonnet 4.5 rates regardless of which model ran
- Security fixes from audit: XSS in reports, ReDoS in extraction regexes, SSRF in webhook URLs, error detail disclosure, prompt injection hardening
- Documentation listed environment variables the code never read: `BEDROCK_REGION` → `PHISHY_BEDROCK_REGION`, `BEDROCK_MODEL_ID` → `PHISHY_BEDROCK_MODEL`, `DELETE_AFTER_PROCESSING` → `DELETE_EMAILS_AFTER_PROCESSING`
- Base64 MIME decoding for forwarded content
- Bedrock VPC endpoint HTTP/2 stream timeout
- Config validation no longer requires an Anthropic API key when using Bedrock
- The built-in default config still pointed Bedrock at the retired Sonnet 4.5 dated model ID, overriding the schema's Opus 4.8 default
- Migration 002's `source` column default (`'report_link'`) violated its own CHECK constraint — leftover from the removed one-click feedback design

## [2.0.0] - 2026-02-14

### Added
- Complete TypeScript rewrite with strict typing and Zod-validated configuration
- AI provider abstraction supporting both the Anthropic API and AWS Bedrock, with fallback
- Enterprise profiles: organization-specific context (VIPs, partners, known threats) for better detection
- Optional threat-intelligence layer: IOC extraction, pattern detection, PostgreSQL storage
- Configuration loading priority chain: environment → S3 → local file → defaults
- Unit and integration test suites with mocked AWS clients

## [1.0.0] - 2025-04-22

### Added
- Initial release: single-file Node.js Lambda (`index.js`)
- SES-triggered analysis of forwarded emails with Claude via the Anthropic API
- HTML security report delivered back to the forwarder

[Unreleased]: https://github.com/colinstoner/phishy-email-analyzer/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/colinstoner/phishy-email-analyzer/releases/tag/v2.0.0
[1.0.0]: https://github.com/colinstoner/phishy-email-analyzer/tree/0641640

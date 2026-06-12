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

### Changed
- **License changed from GPL-3.0 to Apache-2.0**
- Bedrock model defaults and configuration updated for inference profiles and VPC endpoints

### Fixed
- Security fixes from audit: XSS in reports, ReDoS in extraction regexes, SSRF in webhook URLs, error detail disclosure, prompt injection hardening
- Documentation listed environment variables the code never read: `BEDROCK_REGION` → `PHISHY_BEDROCK_REGION`, `BEDROCK_MODEL_ID` → `PHISHY_BEDROCK_MODEL`, `DELETE_AFTER_PROCESSING` → `DELETE_EMAILS_AFTER_PROCESSING`
- Base64 MIME decoding for forwarded content
- Bedrock VPC endpoint HTTP/2 stream timeout
- Config validation no longer requires an Anthropic API key when using Bedrock

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

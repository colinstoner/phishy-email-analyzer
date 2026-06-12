# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-06-12

### Added
- **Structured threat verdicts** (migration 004): the model produces a categorical verdict (`bec`, `phishing`, `malware_delivery`, `spam`, `graymail`, `suspicious`, `legitimate`) and a 0–100 risk score on an axis separate from confidence — a confidently-legitimate email is high confidence, low risk. Queryable `verdict`/`risk_score` columns; the full assessment persists in `analysis_result` JSONB; legacy `isPhishing`/confidence are derived so existing consumers keep working
- **Risk fusion** (`risk.fusion.ts`): deterministically fuses the model verdict with Phishy's own intelligence — known indicators and active campaigns raise the risk floor, a security-team ruling overrides (verdict included), a safe-sender match caps — and returns the explanation trail shown in the report
- **Attributed IOC extraction**: indicators are attributed to the original (forwarded) sender, never the reporter — previously the victim could be recorded as the attacker. The model nominates IOCs structurally (sender/payload/infrastructure roles), merged with regex extraction; open-redirect and tracker chains are unwrapped so the final destination is the high-value indicator; free-mail provider domains are excluded as domain indicators; configured SafeDomains/SafeSenders are honored during extraction
- **Employee-facing report redesign**: thanks the reporter every time, leads with a plain-language verdict gloss and risk score, one clear "What to do" line, "Why we flagged it" fused-intelligence reasons, and a "How to spot this next time" teaching block driven by the identified threat vectors
- **RDS TLS verification**: the official Amazon RDS global CA bundle is pinned for `*.rds.amazonaws.com` hosts with full certificate verification (replacing connection failures / no-verify workarounds)
- SAM template parameters for the enterprise profile and safe-sender lists; `.nvmrc` and CI scoped to the Lambda runtime (Node 22)
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
- **Real MIME parsing**: hand-rolled regex parsing of raw email (manual multipart splitting, base64/quoted-printable decoding, HTML regex extraction) replaced with [mailparser](https://nodemailer.com/extras/mailparser/) — correct handling of nested multiparts, all transfer encodings, charsets, and header folding
- **Forward-as-attachment support** (`message/rfc822`): the original email forwarded as an attachment — the one forwarding mode that preserves its full headers — is now parsed, surfaced as a forwarded block, and its headers (including Reply-To and Authentication-Results) made available to analysis. Previously this format silently yielded nothing
- **Attachment metadata**: attachments are surfaced to analysis as name/type/size/SHA-256 (content is never executed or forwarded); the analysis prompt previously asked the model to assess attachments it never received
- External event payloads (API Gateway path) are validated with a Zod schema that strips trust-bearing fields — callers cannot inject forged `authVerdicts` (which would defeat email-command authorization) or `s3Location`
- `docs/ARCHITECTURE.md` (pipeline, trust boundaries, provenance model) and `CLAUDE.md` (conventions and security invariants for AI coding assistants and contributors)
- **Provenance-labeled analysis prompt**: the briefing Claude receives is now organized by who asserts each fact — VERIFIED (computed by Phishy), OPERATOR (org configuration), REPORTED (the employee's note), and CLAIMED (the suspicious email, fenced with a per-request nonce as hostile data). The agentic loop uses the same vocabulary for tool results
- **Canonicalization of hostile content** (pure computation, no fetching): NFKC normalization, zero-width/bidi control stripping, numeric-entity decoding, and unwrapping of Microsoft SafeLinks / Proofpoint URL Defense (v2+v3) / Google redirect wrappers. Every raw-vs-canonical divergence is reported to the model as a flag — obfuscation is itself an indicator. Anchor-text vs. href domain mismatches are flagged; threat intel now stores true destinations instead of gateway wrappers
- **Adversarial bounding**: body truncation is head+tail (padding can no longer push the payload out of view) and the link budget is filled round-robin across registrable domains (50 benign links can no longer crowd out the payload link). Every elision is disclosed to the model as a labeled fact
- Agentic analysis (`PHISHY_AGENTIC_ENABLED`): analysis runs as a bounded tool-use loop in which Claude may consult Phishy's own data — `lookup_indicators` (threat intel sightings), `check_campaign` (concurrent reports of the same email), `examine_url` (syntactic URL inspection, never fetched), and `check_profile` (VIP/partner/lookalike checks) — before delivering its verdict. Tools are offered only when their backing data exists; the loop is capped at `PHISHY_AGENTIC_MAX_TOOL_ROUNDS` and any failure falls back to the standard single-shot analysis. Tool usage and accumulated token counts are recorded with each analysis
- AI interpretation of free-text email commands: with agentic mode on, security-team replies the keyword parser can't read are classified by the model, strictly constrained to the two known verdicts
- `converse()` on both AI providers: multi-turn, tool-capable conversations in the shared Messages format (Bedrock InvokeModel and the Anthropic API)
- Campaign verdict cache (`PHISHY_CAMPAIGN_CACHE_ENABLED`): when a flood of the same email is reported, the first report gets a full AI analysis and subsequent same-campaign reports reuse its verdict (migration 003) — consistent answers for every reporter, no duplicate AI spend. A security-team reply to any one report ("confirmed phishing" / "false positive") overrides the AI verdict for the whole campaign, and verdict feedback now adjusts indicators campaign-wide. Cache hits emit `CampaignCacheHits` / `EstimatedCostSavedUSD` metrics
- CloudWatch cost/usage metrics via Embedded Metric Format: every analysis emits tokens, estimated USD cost, latency, and verdict to the `Phishy` namespace, with no database or extra IAM required (`PHISHY_DISABLE_METRICS` to opt out)
- Per-model pricing table for cost estimation, replacing hardcoded Sonnet rates; includes the 10% Bedrock regional-endpoint premium
- Token usage capture for the Anthropic API provider (previously Bedrock-only)

### Changed
- **The analysis is no longer armed with attacker-controlled "facts"**: the forwarded sender's identity (parsed from the attacker-controlled body in inline forwards) moved from the VERIFIED block to a CLAIMED cannot-be-authenticated section; "legitimate systems" lists are reframed as the brands attackers impersonate most, not an allowlist; reasoning rules added — a familiar-looking From is not verification, and content that cannot be inspected is never "legitimate"
- **Default model upgraded to Claude Opus 4.8** on both providers (`claude-opus-4-8` / `global.anthropic.claude-opus-4-8`); model catalogs refreshed with Opus 4.6, Sonnet 4.6, and current Bedrock `global.`/regional ID formats
- Full-prompt logging in the Bedrock provider moved from info to debug level — reported email content no longer lands in CloudWatch logs at default log levels
- **License changed from GPL-3.0 to Apache-2.0**
- Bedrock model defaults and configuration updated for inference profiles and VPC endpoints

### Fixed
- **Security**: the pinned RDS CA could be silently bypassed for connection strings in libpq `key=value` form — `pg` gives an embedded `sslmode` precedence over `config.ssl`, and `sslmode=disable`/`no-verify` would fail open (connect with no TLS verification, no error). `sslmode`/`ssl` are now stripped from both the URL and key=value forms before the CA is pinned
- Risk fusion: a security-team ruling now overrides the **verdict** too, so the stored verdict and the employee report banner can't contradict the human ruling (a confirmation no longer leaves a `legitimate` verdict at critical risk; a clearance forces `legitimate`). A confirmed ruling preserves an already-malicious model verdict (e.g. `bec`)
- IOC dedupe lowercased entire URL values, which could merge two distinct malicious URLs (paths/queries are case-sensitive) and drop an indicator; only the scheme+host are now case-folded
- Tests no longer reference a real organization domain (CLAUDE.md requires invented `example.com`-style data only)
- Bedrock default model ID corrected to `global.anthropic.claude-opus-4-8`: on-demand invocation requires an inference-profile ID, and Bedrock rejects the bare `anthropic.claude-opus-4-8` form with a ValidationException (verified against a live account)
- **Security**: `X-Forwarded-For` was trusted verbatim as the report recipient — an attacker-influenceable header (often an IP chain, never validated) could redirect analysis reports. It now requires an extractable address on a safe domain, the same bar as every other source
- Outlook-style forwarded headers never captured the original subject: the marker pattern stopped at the literal `Subject:` before its value
- Messages whose content could not be retrieved from S3 still reported a guessed `s3Reference`/`s3Location`, misleading cleanup and provenance; they now report none
- External event payloads (API Gateway paths) were blind-cast instead of validated; malformed entries are now dropped with a warning
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

[Unreleased]: https://github.com/colinstoner/phishy-email-analyzer/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/colinstoner/phishy-email-analyzer/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/colinstoner/phishy-email-analyzer/releases/tag/v2.0.0
[1.0.0]: https://github.com/colinstoner/phishy-email-analyzer/tree/0641640

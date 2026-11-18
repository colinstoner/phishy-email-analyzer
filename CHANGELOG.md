# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SAM parameter `BedrockModelId` (optional): pins a deployment to a specific Bedrock model ID, such as a geography-specific inference profile, by setting `PHISHY_BEDROCK_MODEL`. Empty keeps Phishy's default.
- **Blast radius for malicious verdicts** (optional, off by default: `PHISHY_GRAPH_BLAST_RADIUS_ENABLED`, effective only with `PHISHY_GRAPH_ENABLED`): after a malicious verdict Phishy looks up who else in the organization received the message and whether they read, replied to or forwarded it, and adds a compact section to the **security team's copy of the report only**. The reporter's report is sent first and never waits on the lookup; the security team then always gets its own email (with the section, or a one-line note if the lookup failed), a reporter who is on the security team gets only that copy, and a failure to send it is logged and counted (`SecurityCopySendFailures`). A malicious Outlook Report-button report stays silent toward the reporter: the lookup runs before the single security-team email, which carries the section. Code-driven and read-only (`src/services/graph/blast-radius.service.ts`; not an agentic tool, never shown to the model, nothing persisted): identifies the message by Message-ID when the parsed email carries one, otherwise by claimed sender + subject + time window, always through `odataFilter`; uses Exchange message trace first — reading each recipient's mailbox by the Message-ID trace recorded for them, leaving out distribution-list expansion rows and listing failed deliveries as not delivered — and falls back to a per-mailbox search of licensed user mailboxes (including Recoverable Items) when trace is unavailable. Folder and replied/forwarded detail is read with each match, and detail that could not be read is counted and stated. Bounded by a hard time budget (`PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS`, default 45000) and a mailbox cap (`PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES`, default 2000); partial coverage is always stated ("checked N of M mailboxes"); any failure leaves the report as it was, with a one-line note to the security team. EMF metrics for route, recipients, coverage, errors and duration. `MessageSummary` now includes `isRead`. See `docs/CONFIGURATION.md` and `docs/ARCHITECTURE.md`
- **Original-message lookup** (optional, off by default; `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` / `graph.originalFetch.enabled`, effective only with `graph.enabled`): before analysis, Phishy finds the original of a forwarded email in the reporter's own mailbox through Microsoft Graph and reads its real Internet headers (`Authentication-Results`, the `Received` chain, `Return-Path`, `Reply-To`, `Message-ID`), which a forward otherwise destroys. Code-driven and GET-only — not an agentic tool. Only the reporter's mailbox is ever read, and only when the report's `From` is the safe-domain forwarder and SES reports an SPF or DKIM `PASS`. The message is matched by claimed sender, sent-time window and exact subject (all escaped as `$filter` literals) across the mailbox and Recoverable Items, and used only when **exactly one** message matches and passes a re-check in code. In the prompt the retrieval itself is a `VERIFIED` fact while every header name and value stays `CLAIMED`, in its own nonce fence, shown in stored order with guidance that only the topmost trace headers come from the receiving system; the header set is bounded adversarially (per-name first+last quotas, head+tail values, a priority-ordered budget) with every cut disclosed. No match, several matches, any Graph error or exceeding the 8-second budget leaves analysis exactly as before. New EMF metrics `OriginalFetchCount` (dimension `Outcome`: `found`/`not_found`/`ambiguous`/`error`/`skipped`) and `OriginalFetchDurationMs`. Needs `Mail.Read` on reporters' mailboxes; see `docs/CONFIGURATION.md` and `docs/ARCHITECTURE.md`
- **Graph read operations and probe CLI** (optional; the probe is not part of the email pipeline): a typed, read-only, bounded operations library on the Graph foundation (`mail.operations.ts`, `trace.operations.ts`, `directory.operations.ts` — find messages by Internet message ID or by sender + time window, search, Internet headers, MIME with a size cap, last-verb, message trace by message ID or sender + subject, users, subscribed-SKU capability flags), and `npm run graph:probe` (`phishy-graph-probe`), which an operator runs locally against their own tenant to learn which of those calls work there, with which permissions and licences, before any feature depends on them. GET-only (enforced by a test); a failed check never stops the run; output is counts, sizes, header names and Graph error codes, with addresses, subjects and message IDs hashed unless `--show-identifiers`; `--json` for machine-readable output. Request-builder extensions, each keeping data as data: `kqlSearch` (`$search` from typed terms), `$expand` of one single-value extended property by type and tag, `odataSeconds` (dates without milliseconds), and a 5000 `$top` cap on message trace only. See `docs/GRAPH_PROBE.md`
- **Microsoft Graph foundation** (`src/services/graph/`, optional, off by default — no feature or pipeline code calls it yet): app-only authentication with a certificate-signed JWT assertion (PS256, `x5t#S256`; no client secret, no new dependencies), an in-memory token cache with a shared in-flight request, and a constrained HTTP client — fixed `https://graph.microsoft.com/v1.0` base URL, `graphPath`/`odataFilter` tagged templates as the only way data enters a path or `$filter`, `@odata.nextLink` followed only on the Graph origin, caller-capped paging, bounded `Retry-After` handling, per-request timeouts, response-size bounds, and typed errors that never carry tokens, key material or response bodies. Configured with `PHISHY_GRAPH_ENABLED`, `PHISHY_GRAPH_TENANT_ID`, `PHISHY_GRAPH_READ_CLIENT_ID`, `PHISHY_GRAPH_READ_CERTIFICATE` (Secrets Manager ARN or inline PEM); Entra app-registration and Exchange "RBAC for Applications" guidance in `docs/CONFIGURATION.md`
- Security invariant 6 in `CLAUDE.md`: Graph access is code-driven, never model-driven; reads and writes use separate certificate-authenticated app registrations; tenant writes require security-team approval
- **Outlook Report-button intake** (`PHISHY_REPORT_BUTTON_ENABLED`, SAM parameter `ReportButtonEnabled`): when Microsoft 365's user-reported settings deliver Report-button submissions to Phishy, they are recognized and handled silently — the reporter is never emailed. Phishing reports are analyzed, stored, and counted toward campaign detection, and the security team is notified only for malicious or suspicious verdicts (or when analysis could not be completed); junk / not-junk reports are counted and skipped. The reported email's own subject replaces the machine-generated wrapper subject so campaigns group with forwards of the same email, and the wrapper's header-dump body is discarded rather than presented to the model as the employee's note. New `UserReports` CloudWatch metric (dimension `ReportedAs`). Off by default; forwards are unaffected
- Example report screenshots in the README (four scenarios across the three tones), rendered from the live report template via `scripts/render-report-samples.js` — invented data only
- `AnalysisFailureCount` CloudWatch metric (EMF, dimensioned by Provider/Model) emitted when the model can't be reached after retries — a provider outage is now alarmable instead of silent
- New `undetermined` threat verdict for analyses that could not be completed, rendered as an amber **"ANALYSIS UNAVAILABLE"** report (risk shown as "not assessed") that explicitly tells the reporter the email was *not* checked
- `ai.effort` setting (`PHISHY_AI_EFFORT`; `low`/`medium`/`high`/`xhigh`/`max`, default `medium`): how much the model thinks, and so the main cost and latency control. Sent as `output_config.effort` on every call path, only to models that accept it (`src/services/ai/model.capabilities.ts`)
- **Refusal handling with a fallback model.** Claude Opus 5.5's safety classifiers can decline security content with `stop_reason: "refusal"`. A declined request is retried once on `ai.refusalFallbackModel` (`PHISHY_AI_REFUSAL_FALLBACK_MODEL`; default Claude Opus 4.8 in the same provider, empty string disables). If that model declines too, the reporter gets the "ANALYSIS UNAVAILABLE" report — a refusal is never a `legitimate` verdict and is never stored or cached. `reasoning_extraction` refusals are not retried; a refusal inside the agentic loop abandons the loop for the single-shot path
- `AnalysisRefusalCount` CloudWatch metric (EMF, dimensioned by Provider/Model, category as the `RefusalCategory` property), emitted once per declined call
- `ThinkingTokens` property on the usage metric line and `thinkingTokens` on a result's token usage, when the API reports the thinking share of output tokens
- Model catalogs and the pricing table cover Claude Opus 5.5 / 5, Sonnet 5.5 / 5, Haiku 5.5 (including its over-100K-token prompt rate), and Fable 5.2 / 5.1 / 5

### Fixed
- **A failed AI analysis no longer reports as "safe."** When the provider was unreachable, the error result (`isPhishing:false`) was fused to a `legitimate` verdict and the reporter received a green "LIKELY LEGITIMATE — safe to proceed" report for an un-analyzed email. Analysis failure now carries an explicit `analysisFailed` flag, routes to the `undetermined` verdict (never capped to "safe" by the safe-sender allowlist, still escalated by known indicators / active campaigns / security-team rulings), and renders the honest caution report above
- Failed analyses are no longer stored as a reusable verdict, and the campaign verdict cache excludes failure placeholders (`ai_provider = 'none'`) — preventing a transient outage from poisoning the cache with a false "legitimate" served to future identical emails
- **A truncated or malformed model reply no longer reads as "not phishing."** A reply cut off at `max_tokens`, text that is not JSON and states no explicit `isPhishing`, and JSON with neither a recognized `verdict` nor a boolean `isPhishing` all defaulted to `isPhishing:false`. Each is now an `analysisFailed` result
- The Anthropic provider read `content[0].text`, which is a thinking block — not the answer — on models that think. Both providers now select text by block type on every path, through one shared module
- A Bedrock refusal was thrown inside the retry loop and retried through the full ~105s backoff before failing; the Anthropic provider did not check for refusals at all. Refusals are now handled once, without backoff, identically on both providers
- The agentic loop dropped thinking blocks when sending an assistant turn back. Turns are now replayed exactly as received
- AI command parsing asked for 50 output tokens and provider health checks for 10, which a model that always thinks spends before writing anything. Both budgets now leave room for thinking
- Anthropic authentication failures and Bedrock `ValidationException`s are no longer retried
- Bedrock error logs no longer include the response body, which can hold model output derived from the reported email

### Changed
- **Default model upgraded to Claude Opus 5.5** on both providers (`claude-opus-5-5` / `global.anthropic.claude-opus-5-5`). Opus 5.5 always thinks, and thinking counts toward `max_tokens`, so the default `maxTokens` rises 4096→16000. No `thinking` field is sent (the model rejects `disabled`). Deployments that pin a model or `maxTokens` in their own configuration keep their values; a pinned `maxTokens` of 4096 should be raised before moving to Opus 5.5
- Removed the unused `temperature` analysis option: current models reject sampling parameters
- The Bedrock refusal-fallback call gets one retry instead of the full analysis retry budget, keeping worst-case backoff (≈120s) inside the Lambda `Timeout` of 180s
- Bedrock analysis retry budget widened to ride out transient `InternalServerException`/throttling windows: 4 attempts backing off ~15s/30s/60s (was 3 × ~1s). Lambda `Timeout` raised 90→180s to accommodate (kept in sync with the `ANALYSIS_*` constants in `bedrock.provider.ts`)
- Bedrock invocation errors now log the SDK exception name, HTTP status, and request id — the bare "Bedrock is unable to process your request." message alone was too generic to triage

## [3.0.0] - 2026-06-12

### Added
- Local try-it CLI (`npm run try <file.eml>` / `npx phishy-try`): parses any `.eml` exactly as the deployed Lambda would — MIME, forwarded headers, link unwrapping, content-integrity flags — with no AWS required; add `ANTHROPIC_API_KEY` for a live Claude verdict. Bundled fictional sample in `examples/sample-phish.eml`
- Community infrastructure: issue templates (bug/feature with data-hygiene guidance), PR template with the security-invariant checklist, Dependabot (npm + actions, AWS SDK grouped), and CodeQL scanning
- README: "Try It in 60 Seconds" quick start
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

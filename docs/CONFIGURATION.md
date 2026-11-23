# Configuration Guide

Phishy is configured with environment variables, optionally on top of a JSON file in S3. This guide lists every setting: the core ones first, then each optional layer.

## Quick Start (Environment Variables Only)

A working deployment needs these:

```bash
# AI provider: either an Anthropic API key ...
ANTHROPIC_API_KEY=sk-ant-...
# ... or AWS Bedrock (IAM, no key)
# PHISHY_AI_PROVIDER=bedrock

S3_BUCKET_NAME=my-phishy-emails              # bucket SES stores raw email in
SENDER_EMAIL=phishy@example.com              # SES-verified From address for reports
SAFE_DOMAINS=example.com                     # your organization's domain(s): who may report
SECURITY_TEAM_DISTRIBUTION=security@example.com  # Cc'd on reports; may issue commands
SECURITY_TEAM_MEMBERS=alice@example.com          # optional: individuals who may also issue commands (never emailed)
```

`SAFE_DOMAINS` matters: Phishy only answers reports from an address on one of these domains (or listed in `SAFE_SENDERS`), and only ever sends a report to such an address. Its built-in default is `example.com`, so without it nothing your employees forward is analyzed.

---

## Configuration Priority

When the same setting is defined in more than one place, the highest wins:

1. **Environment variables** — always win
2. **S3 configuration file** — `PHISHY_CONFIG_S3=s3://bucket/config.json`
3. **Built-in defaults**

There is no local configuration file in the deployed function: `config/phishy.config.json` is only a convenient place to keep a file before uploading it to S3 (it is gitignored). A Secrets Manager ARN in `PHISHY_DB_CONNECTION` is resolved after the sources are merged; one in `PHISHY_GRAPH_READ_CERTIFICATE` on the first Graph call.

Environment variables are converted according to the setting they map to: for an on/off setting `true` / `false` (any case) become booleans; for a numeric setting a plain decimal such as `30` or `2.5` becomes a number (whole-number settings still reject `2.5`); the settings that are lists (`SAFE_DOMAINS`, `SAFE_SENDERS`, `SECURITY_TEAM_DISTRIBUTION`, `SECURITY_TEAM_MEMBERS`, `SAFE_SENDER_SECURITY`) are split on commas. Every other variable, including `PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION`, IDs and model names, is kept as the exact string given.

The SAM template has no parameter for a configuration file. To use one with it, add `PHISHY_CONFIG_S3` to the function's environment in `template.yaml`; an object under `profiles/` in the stack's email bucket is already readable by the function's role.

---

## Feature Flags at a Glance

Everything beyond forward-and-reply is off by default and switched on independently. Each row links to its section.

| Flag (env var) | Default | Needs | Effect |
|---|---|---|---|
| `PHISHY_INTELLIGENCE_ENABLED` + `PHISHY_DB_CONNECTION` | off | PostgreSQL 13+ (migration 001 is created automatically) | [Threat intelligence](#threat-intelligence-database-optional): analyses, indicators and campaigns are stored and feed later verdicts |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | off | intelligence DB; a distribution list | [Campaign alerts](#campaign-alerts): one broadcast warning once several people report the same email |
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | off | intelligence DB + migration 003 | [Verdict cache](#campaign-verdict-cache): repeat reports of one campaign reuse the first verdict |
| `PHISHY_EMAIL_COMMANDS_ENABLED` | off | intelligence DB + migration 002 | [Email commands](#email-commands-security-team-correspondence): the security team confirms or overturns a verdict by replying |
| `PHISHY_CAMPAIGN_RESPONSE_ENABLED` | off | campaign alerts, intelligence DB + migration 006; email commands for approvals; blast radius for targeted warnings | [Campaign response](#campaign-response-optional): incident email, targeted warning, actions approved by reply (removal is a dry run unless the [mailbox write tier](#mailbox-write-tier-optional) is on) |
| `PHISHY_AGENTIC_ENABLED` | off | nothing (database tools appear when the DB is on) | [Agentic analysis](#agentic-analysis): Claude may consult Phishy's own data before its verdict |
| `PHISHY_SCORING_MODE=checklist` | `model` | nothing | [Checklist scoring](#risk-score-mode-experimental) (experimental): the risk score is computed by code from a fixed checklist |
| `PHISHY_ATTACHMENT_ANALYSIS_ENABLED` | off | nothing (in process, no network) | [Attachment analysis](#attachment-analysis-optional): Phishy inspects attachment bytes statically |
| `PHISHY_REPORT_BUTTON_ENABLED` | off | Microsoft 365 user-reported settings delivering to Phishy | [Report-button intake](#outlook-report-button-intake): Outlook Report-button submissions handled silently |
| `PHISHY_GRAPH_ENABLED` | off | Entra app registration with a certificate; a route to Microsoft, or broker mode | [Microsoft Graph](#microsoft-graph-optional) foundation; changes nothing on its own |
| `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` | off | Graph; `Mail.Read` on reporters' mailboxes | [Original-message lookup](#original-message-lookup): the forwarded email's real headers from the reporter's mailbox |
| `PHISHY_GRAPH_SENDER_HISTORY_ENABLED` | off | Graph; `ExchangeMessageTrace.Read.All` | [Sender-relationship check](#sender-relationship-check-optional): message-trace counts about the claimed sender |
| `PHISHY_GRAPH_BLAST_RADIUS_ENABLED` | off | Graph; read permissions listed in that section | [Blast radius](#blast-radius-optional): who else received a malicious email (security team's copy only) |
| `PHISHY_GRAPH_FANOUT_SCAN_ENABLED` | off | Graph; `ExchangeMessageTrace.Read.All`; intelligence DB + migration 005; a schedule | [Scheduled fan-out scan](#scheduled-fan-out-scan-optional): proactive alert when a known external sender suddenly mails many people (no model) |
| `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE=live` | `dry_run` | campaign response; the Graph write broker (its own app registration with `Mail.ReadWrite`, and its own `PHISHY_GRAPH_WRITE_ENABLED`) | [Mailbox write tier](#mailbox-write-tier-optional): an approved removal moves the copies to Deleted Items |

Migrations past 001 are applied by hand (`psql -f migrations/00N_*.sql`); see [DATABASE.md](DATABASE.md). A feature whose migration is missing logs which file to apply and stays off.

---

## Environment Variables Reference

### AI Provider Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_AI_PROVIDER` | `anthropic` | AI provider: `anthropic` or `bedrock` |
| `ANTHROPIC_API_KEY` | - | Anthropic API key (required for anthropic provider) |
| `CLAUDE_MODEL` | `claude-opus-5-5` | Model for Anthropic provider |
| `PHISHY_BEDROCK_REGION` | `us-east-1` | AWS region for Bedrock |
| `PHISHY_BEDROCK_MODEL` | `global.anthropic.claude-opus-5-5` | Bedrock model ID (an inference-profile ID). In the SAM template, set it with the `BedrockModelId` parameter (empty = this default) |
| `PHISHY_AI_EFFORT` | `medium` | How much the model thinks: `low`, `medium`, `high`, `xhigh`, or `max` (`ai.effort`) |
| `PHISHY_AI_REFUSAL_FALLBACK_MODEL` | `claude-opus-4-8` / `global.anthropic.claude-opus-4-8` | Model a declined request is retried on once (`ai.refusalFallbackModel`). On Bedrock the default keeps the primary model's routing prefix (a `us.` primary retries on `us.anthropic.claude-opus-4-8`). Set to an empty string to disable the retry |

> Max tokens and request timeout are file-config only (`ai.anthropic.maxTokens`, `ai.anthropic.timeout`, `ai.bedrock.maxTokens`, `ai.bedrock.timeout`). Both providers default to `maxTokens: 16000` and `timeout: 60000`. So is `ai.fallbackProvider` (see [Provider Fallback](#provider-fallback)).

#### Effort and max tokens

Claude Opus 5.5 always thinks before it answers, and thinking cannot be turned off. Two settings follow from that:

- **`ai.effort`** is the control for how much it thinks, and so for cost and latency per email. `medium` is the model's own default and Phishy's. Lower it to `low` to cut cost and latency; raise it only if you have measured a detection gain. Phishy sends the value as `output_config.effort` to models that accept it and omits it for those that don't (Sonnet 4.5, Haiku 4.5, and any model ID it does not recognize). A level the model lacks is stepped down to the nearest one it has (`xhigh` on Opus 4.6 becomes `high`).
- **`maxTokens`** caps thinking *plus* the answer. A limit sized for the JSON verdict alone cuts the reply off mid-answer, which is why the default is 16000. If you override it, leave room for thinking. A reply that hits the limit is treated as a failed analysis, never parsed as a verdict.

Thinking tokens are billed as output tokens. They are already included in the `OutputTokens` metric; the share spent on thinking is logged as the `ThinkingTokens` property on each usage line (see Cost Tracking).

#### Refusals

Claude Opus 5.5 runs safety classifiers on incoming requests, and security content is one of the things they look for. A phishing email is, by design, full of that content, so the model will occasionally decline to analyze a reported email. This is not an error: the API answers normally with `stop_reason: "refusal"`.

What Phishy does:

1. Retries the same request **once** on `ai.refusalFallbackModel` (Claude Opus 4.8 by default, in the same provider). In agentic mode the tool loop is abandoned first and the retry uses the standard single-shot analysis.
2. If that model declines too, or the retry is disabled, the reporter receives the **"ANALYSIS UNAVAILABLE"** report, which says the email was *not* checked. A refusal is never reported as "legitimate", never stored as a verdict, and never cached.
3. Emits the `AnalysisRefusalCount` metric for every declined call.

Refusals in the `reasoning_extraction` category are not retried: they mean the prompt asked the model to reproduce its reasoning, which a different model does not fix.

`ai.refusalFallbackModel` must be a model ID for your **primary** provider (`claude-…` for Anthropic, an inference-profile ID such as `global.anthropic.claude-…` for Bedrock). The fallback model needs the same access as the primary one: on Bedrock, the Lambda role must be allowed to invoke it.

### Email Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFE_DOMAINS` | `example.com` | Comma-separated domains whose addresses may report emails (subdomains included). Reports are only ever sent to addresses on these domains. Set it |
| `SAFE_SENDERS` | - | Comma-separated individual addresses that may report in addition to `SAFE_DOMAINS`. Their reports skip the enterprise profile, are not written to the intelligence database, and Cc `SAFE_SENDER_SECURITY` instead of the security team |
| `DELETE_EMAILS_AFTER_PROCESSING` | `false` | Delete the raw email from S3 after analysis |

### Notification Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SENDER_EMAIL` | - | From address for everything Phishy sends; must be verified in SES. Required |
| `REPLY_TO_EMAIL` | - | `Reply-To` for everything Phishy sends. Set it to the address Phishy receives mail at when `SENDER_EMAIL` is a different address (a no-reply sender): the command channel works by reply. The SAM template sets it to `RecipientEmail` when `EmailCommandsEnabled` is true |
| `SECURITY_TEAM_DISTRIBUTION` | - | Comma-separated security-team addresses: Cc'd on reports and sent security-only emails (incident emails, fan-out alerts, silent Report-button reports). Replies from these addresses count as commands |
| `SECURITY_TEAM_MEMBERS` | - | Optional. Comma-separated addresses of individual people who may also issue commands and approvals, for when `SECURITY_TEAM_DISTRIBUTION` is a list address. They are never sent anything. Addresses outside `SAFE_DOMAINS` are ignored (a startup warning gives the count). See [who can issue commands](#who-can-issue-commands) |
| `SAFE_SENDER_SECURITY` | - | Comma-separated addresses Cc'd instead of the security team on reports from `SAFE_SENDERS` addresses |
| `SES_CONFIG_SET` | - | Optional SES configuration set for outbound mail |

The display name on outbound mail (`notification.senderName`, default `Phishy`) is file-config only.

### Storage Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_BUCKET_NAME` | - | S3 bucket SES stores raw emails in. Required |
| `PHISHY_AWS_REGION` / `AWS_REGION` | the Lambda's region, else `us-east-1` | Region for S3 and SES (`storage.region`) |
| `S3_PREFIX` | `emails` | Accepted (`storage.s3Prefix`) so existing configurations keep loading, but ignored, with a warning at startup when set: the object key comes from the SES receipt, and the fallback key is always `emails/<message-id>`. Keep SES's prefix `emails/` and leave this unset |

### Profile and Configuration File

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_CONFIG_S3` | - | `s3://bucket/key` of a JSON configuration file (same structure as `config/phishy.config.example.json`). The function's role needs `s3:GetObject` on it |
| `PHISHY_PROFILE` | - | Enterprise profile: an `s3://` URI or the profile JSON itself (`profile` in the file). See [Enterprise Profiles](#enterprise-profiles) |

### Threat Intelligence and Campaign Alerts

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_INTELLIGENCE_ENABLED` | `false` | Enable the threat-intelligence database. See [below](#threat-intelligence-database-optional) |
| `PHISHY_DB_CONNECTION` | - | PostgreSQL connection string or Secrets Manager ARN (`intelligence.connectionString`) |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | `false` | Enable campaign alerts (needs the database) |
| `PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION` | - | The address the campaign broadcast goes to, typically an all-staff list (`campaignAlerts.distributionList`) |

`intelligence.type` accepts `postgres` (the default) and `dynamodb`, but only PostgreSQL is implemented: `dynamodb` is ignored, and so is `intelligence.tableName`. Both are still accepted so existing configuration files keep loading, and each logs a warning at startup when set.

#### Campaign alerts

With the database and `PHISHY_CAMPAIGN_ALERTS_ENABLED` on, every report flagged as phishing (a malicious verdict, or `suspicious` at a risk score of 55 or more) is counted against its campaign; reports from `SAFE_SENDERS` addresses are not. A campaign is the reporting employee's domain (the `From` of the forward, not the attacker's) plus the subject with `re:`/`fw:` prefixes, digits and punctuation normalized away, so "Invoice #4821" and "Invoice #4822" match. When a campaign reaches **3 reports from at least 2 different reporters within 4 hours** and the current report is high or critical risk, Phishy emails one warning to the distribution list, at most once per 24 hours per campaign. With [campaign response](#campaign-response-optional) on, that threshold opens an incident instead.

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

### Risk-Score Mode (Experimental)

How the 0-100 risk score in the report is produced. With `model` (the default) it starts from the model's own free-form score, exactly as before this setting existed. With `checklist` the score is computed by code from a fixed checklist (version 2): Phishy answers every item it can compute itself (link text that does not match its destination, a file share owned by someone other than the sender, a risky attachment, a Reply-To that diverts, hidden characters, ...), the model answers only the items that need judgement (does it ask for credentials or payment? does it impersonate someone? bulk mail with an unsubscribe link? ...), and a request only counts in full when something about the email is actually wrong. The same answers always give the same score and each point can be explained. Items whose facts come from an optional feature (attachment analysis, the original-message lookup, the sender-history check) are answered `unknown` and score nothing while that feature is off. The model still decides the verdict, the score stays inside that verdict's band, and every existing floor and cap still applies. A missing or malformed checklist falls back to the model's score and is counted in the `ChecklistScoring` metric (`Outcome`: `ok` / `missing` / `malformed`). The weights are a first draft that has not been calibrated on real mail; see [ARCHITECTURE.md](ARCHITECTURE.md#checklist-scoring-experimental) for the items, weights and rule, and run the injection eval with `--scoring checklist --repeats N` to compare modes. The checklist adds roughly 800 input tokens and 100-200 output tokens per analysis.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_SCORING_MODE` | `model` | `model` or `checklist` (config file: `scoring.mode`) |

### Campaign Verdict Cache

When a phishing campaign hits many inboxes at once, every recipient may forward the same email. With the cache enabled, the **first** report gets a full AI analysis; reports matching the same campaign within the cache window reuse that verdict — every reporter gets a consistent answer, instantly and at no extra AI cost. Reports served from the cache say so in the summary, and a `CampaignCacheHits` / `EstimatedCostSavedUSD` metric is emitted (see Cost Tracking below).

Campaign matching uses the same signature as [campaign alerts](#campaign-alerts): the reporting employee's domain plus the normalized subject, so "Invoice #4821" and "Invoice #4822" match.

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

**Authorization is two-factor:** the sender must be one of the security team's addresses (below) *and* the inbound mail must pass SES SPF or DKIM verification, so a spoofed From header cannot issue commands. Regular employees' replies are never treated as commands.

#### Who can issue commands

A reply counts as a command or an approval only when its From address exactly matches (ignoring case and surrounding spaces) one of:

- an address in `SECURITY_TEAM_DISTRIBUTION`, or
- an address in `SECURITY_TEAM_MEMBERS` whose domain is one of `SAFE_DOMAINS` (or a subdomain of one); any other member address is ignored, so a typo cannot authorize an outside address.

and the message passes SES SPF or DKIM. Most organizations set `SECURITY_TEAM_DISTRIBUTION` to one list address such as `security@example.com`; a reply from a team member's own mailbox comes from that person's address, not the list's, so it is not a command unless the person is in `SECURITY_TEAM_MEMBERS`. Listing people there changes only who may act: Phishy's security email still goes only to `SECURITY_TEAM_DISTRIBUTION`, and its answer to a command goes to the person who sent it.

Requires the intelligence database and `migrations/002_analysis_feedback.sql`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_EMAIL_COMMANDS_ENABLED` | `false` | Process security-team replies as commands |

With [campaign response](#campaign-response-optional) on, the channel also accepts **approvals** of proposed actions. Those are never interpreted by the model and never matched loosely: only a line of its own reading `APPROVE WARNING <reference>` or `APPROVE REMOVAL <reference>`, in your own new text (not the quoted history), with the reference printed next to that action in the incident email. For the warning only there is a short form, for replying from a phone: a reply to an incident email whose own new text has a line that is exactly `APPROVE WARNING` approves the one warning that exact email proposed. It is matched by the reply's `In-Reply-To`, so a reply to an older email whose proposal has since been replaced approves nothing, and a reply Phishy cannot match to an incident email it sent is refused. Removal always needs its reference. Approving twice does nothing twice.

### Campaign Response (Optional)

What Phishy does once a campaign crosses the [campaign-alert](#campaign-alerts) threshold (at least 3 reports from at least 2 people within 4 hours), or earlier, once one report shows the email reached enough people (below). Off by default; off means the campaign alert behaves as described above: one generic warning to the distribution list.

When on, each campaign becomes an **incident**:

- **The security team** gets one incident email: what the attack is, timeline, blast radius, what Phishy has done, and proposed actions, each with the exact reply line that approves it. Later reports and wider reach arrive as replies in the same thread, at most one per `updateIntervalMinutes`.
- **The people who received it** (found by blast radius) get a plain-language warning, one email each, with your organization's own "if you already clicked" instructions. People who reported it are not emailed. When the [mailbox write tier](#mailbox-write-tier-optional) moves a copy to Deleted Items (only in `live` removal mode), the person whose copy was moved gets a short notice that it was moved. Nobody whose copy was not delivered is warned; every address must be on a safe domain; no link from the attack is ever included.
- **Remove remaining copies** is proposed with a scope of exact message IDs per mailbox, always for approval. By default approving it runs a **dry run**: Phishy replies with what it would remove, and no mailbox is changed. With the [mailbox write tier](#mailbox-write-tier-optional) on (`PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE=live`), approving it moves those copies to Deleted Items.

**Reach trigger.** With [blast radius](#blast-radius-optional) on, the incident opens on the *first* malicious report (verdict phishing, BEC or malware delivery; not merely suspicious) when that report's lookup found at least `reachThreshold` people (default 5) whose copy was delivered to a mailbox, not counting anyone who reported it. Only recipients the lookup actually listed count; failed, quarantined and unread-mailbox rows do not. When the lookup is unavailable or blast radius is off, the report-count threshold still applies. `0` turns the reach trigger off. Because such an incident can rest on one person's report, anything set to `auto` is proposed for approval instead until a second person reports it; it then goes ahead automatically (once), unless the security team approved it first.

`audience` decides who is warned. The default, `distribution`, keeps today's broadcast. Choose `recipients` (or `both`) to warn the people who actually received it; that needs [blast radius](#blast-radius-optional). `employeeWarning` decides whether the targeted warning waits for an approval (`approve`, the default), goes out at once (`auto`) or never (`off`); `distributionWarning` does the same for the broadcast (default `auto`, as before). An approval is good for `approvalTtlHours` and applies to its own campaign only; a late approval is proposed again under a new reference.

**Fan-out trigger.** With the [scheduled fan-out scan](#scheduled-fan-out-scan-optional) on too, a wave the scan flags opens an incident before anyone reports it (zero reports, every action waiting for approval), and that incident email replaces the scan's own alert. Reports of the same email join it later.

Requires campaign alerts (`PHISHY_CAMPAIGN_ALERTS_ENABLED`), the intelligence database, `migrations/006_campaign_response.sql` (applied manually; without it Phishy logs which migration to apply and behaves as with campaign response off), and the email command channel for approvals. Migration 003 is needed for a `false positive` reply to close an incident.

| Variable | Config key | Default | Description |
|----------|-----------|---------|-------------|
| `PHISHY_CAMPAIGN_RESPONSE_ENABLED` | `campaignResponse.enabled` | `false` | Turn campaign response on |
| `PHISHY_CAMPAIGN_RESPONSE_AUDIENCE` | `campaignResponse.audience` | `distribution` | Who is warned: `distribution`, `recipients` or `both` |
| `PHISHY_CAMPAIGN_RESPONSE_EMPLOYEE_WARNING` | `campaignResponse.employeeWarning` | `approve` | Targeted warning: `off`, `approve` (after a security-team approval) or `auto` |
| `PHISHY_CAMPAIGN_RESPONSE_LIST_WARNING` | `campaignResponse.distributionWarning` | `auto` | Distribution-list broadcast: `off`, `approve` or `auto` |
| `PHISHY_CAMPAIGN_RESPONSE_APPROVAL_TTL_HOURS` | `campaignResponse.approvalTtlHours` | `4` | How long a proposed action can be approved (max 72) |
| `PHISHY_CAMPAIGN_RESPONSE_MAX_WARNINGS` | `campaignResponse.maxWarningsPerCampaign` | `100` | Most employees one campaign emails (warnings and removal notices; someone already warned is not counted again) (1–1000) |
| `PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MAILBOXES` | `campaignResponse.maxRemovalMailboxes` | `500` | Most mailboxes one removal may name |
| `PHISHY_CAMPAIGN_RESPONSE_MAX_REMOVAL_MESSAGES` | `campaignResponse.maxRemovalMessages` | `1000` | Most messages one removal may name |
| `PHISHY_CAMPAIGN_RESPONSE_UPDATE_INTERVAL_MINUTES` | `campaignResponse.updateIntervalMinutes` | `30` | Shortest gap between incident updates |
| `PHISHY_CAMPAIGN_RESPONSE_REACH_THRESHOLD` | `campaignResponse.reachThreshold` | `5` | Open the incident on the first malicious report when its blast radius found at least this many delivered recipients besides the reporters; `0` = report count only |
| `PHISHY_CAMPAIGN_RESPONSE_CLICKED_INSTRUCTIONS` | `campaignResponse.alreadyClickedInstructions` | *(see below)* | Plain text shown under "If you already clicked or entered your password" |
| `PHISHY_CAMPAIGN_RESPONSE_TIME_ZONE` | `campaignResponse.timeZone` | `UTC` | IANA time zone for the times in the warning, the incident email and the fan-out alert (e.g. `Europe/London`) |
| `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE` | `campaignResponse.removal.mode` | `dry_run` | `dry_run` or `live` (moves approved copies to Deleted Items through the write broker); see [Mailbox write tier](#mailbox-write-tier-optional) |
| `PHISHY_GRAPH_WRITE_BROKER_FUNCTION` | `campaignResponse.removal.writeBrokerFunctionName` | - | Name or ARN of the Graph write broker function (`live` only) |

Default "already clicked" text: *If you clicked a link in it, opened an attachment, or entered your password, contact your IT or security team straight away and change your password. You will not be in trouble: reporting it quickly is what limits the damage.* Replace it with your organization's own instructions (who to call, how to reach them out of hours).

Sending notes: warnings are sent one per person through SES, so `maxWarningsPerCampaign` emails count against your SES sending rate and quota; in `auto` mode they are sent from the Lambda that crossed the threshold, after the reports, and anything not sent before the function runs short of time is counted and proposed again. The targeted warning reaches at most the 100 recipients a blast-radius lookup lists; a larger campaign's incident email says how many have no known address, and `audience: both` covers them with the broadcast.

**Metrics** (namespace `Phishy`): `CampaignIncidentsOpened` (dimension `Trigger`), `CampaignIncidentUpdates`, `CampaignWarningsSent` (`Audience`), `CampaignWarningsSkipped` (`Reason`), `CampaignWarningSendFailures`, `CampaignRemovalNoticesSent` (only after a live removal), `CampaignMessagesRemoved`, `CampaignRemovalErrors`, `CampaignRemovalRefused` (`Reason`), `CampaignRemovalNotAttempted`, and `ResponseActionsProposed`, `ResponseActionApprovals`, `ResponseActionApprovalsRejected` (`Reason`), `ResponseActionsExpired`, `ResponseActionsDryRun`, dimensioned by `ActionType`.

### Outlook Report Button Intake

Microsoft 365 can deliver a copy of every message an employee reports with Outlook's built-in **Report** button to a mailbox of your choice (Defender portal → Settings → Email & collaboration → User reported settings → *Send reported messages to*). If those reports reach Phishy's address, this flag makes Phishy recognize them and handle them **silently** — the employee clicked a button and is not waiting for an answer, so their experience does not change:

- **Reported as Phishing** — analyzed, stored, and counted toward campaign detection exactly like a forward. The reporter is **not** emailed. The security team (`SECURITY_TEAM_DISTRIBUTION`) receives the report only when the verdict is malicious or suspicious, or when the analysis could not be completed.
- **Reported as Junk / Not junk** — counted and skipped. No analysis, no email.

Forwards to Phishy are unaffected: the person who forwards still gets their answer.

A button report carries the reported email as an attachment with its full original headers, so the analysis sees the real `Authentication-Results`. The wrapper's machine-generated body (a dump of the reported email's headers) is discarded and never presented to the model as the employee's note.

Every report emits a `UserReports` CloudWatch metric (dimension `ReportedAs`). Delivery depends on a Microsoft 365 setting Phishy cannot see, so alarm on that metric going quiet.

With the flag off (the default), a button report that reaches Phishy is treated like any other forward — it is analyzed and the reporter gets a reply.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_REPORT_BUTTON_ENABLED` | `false` | Handle Outlook Report-button submissions silently |

### Attachment Analysis (Optional)

With this on, Phishy inspects attachment bytes itself, in the Lambda, before analysis: it identifies each file's real type, reports what the format can do (forms posting passwords, macros, remote templates, PDF actions and links, executables inside archives, and so on) as facts, and gives the model the text it extracted, fenced as hostile data. Nothing is executed, rendered or fetched, and no network access or new permission is needed. Two findings — an HTML attachment with a password form that posts to a web host, and an executable disguised as a document — raise risk on their own; nothing an inspection finds ever lowers it. Details and the formats covered: [ARCHITECTURE.md](ARCHITECTURE.md#attachment-analysis-optional).

Off by default; with it off attachments are reduced to name, type, size and hash exactly as before. Extracted text adds to the prompt (at the defaults at most about 24,000 characters, roughly 6,000 input tokens, for an email with text-bearing attachments). The step's time comes out of the Lambda's 180 s; its default 10 s budget is small next to the model call.

| Variable | Config key | Default | Description |
|----------|------------|---------|-------------|
| `PHISHY_ATTACHMENT_ANALYSIS_ENABLED` | `attachments.analysis.enabled` | `false` | Turn static attachment analysis on |
| `PHISHY_ATTACHMENT_ANALYSIS_TIME_BUDGET_MS` | `attachments.analysis.timeBudgetMs` | `10000` | Wall-clock budget for all attachments of one email (500–60000); each attachment gets a fair share, at least 500 ms |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_BYTES` | `attachments.analysis.maxAttachmentBytes` | `26214400` (25 MiB) | Larger attachments are identified but not inspected |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_UNCOMPRESSED_BYTES` | `attachments.analysis.maxUncompressedBytes` | `67108864` (64 MiB) | Decompression budget for one email (archive entries, Office parts, PDF streams); the zip-bomb limit together with a 16 MiB per-entry bound |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_ARCHIVE_ENTRIES` | `attachments.analysis.maxArchiveEntries` | `200` | Entries listed and examined per archive |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_DEPTH` | `attachments.analysis.maxDepth` | `3` | How deep archives and attached emails are followed (0–5) |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_PER_ATTACHMENT` | `attachments.analysis.maxTextPerAttachment` | `8000` | Characters of extracted text shown to the model per file (head and tail kept) |
| `PHISHY_ATTACHMENT_ANALYSIS_MAX_TEXT_TOTAL` | `attachments.analysis.maxTextTotal` | `24000` | Characters of extracted text for all attachments of one email, shared equally |

Every limit that stops an inspection is disclosed to the model, and the step logs counts and status words only (`Attachment analysis complete`).

### Microsoft Graph (Optional)

Phishy can authenticate to Microsoft Graph on your own Microsoft 365 tenant. Everything in this section is read-only. `PHISHY_GRAPH_ENABLED` is a **foundation**: on its own it does not change how emails are analyzed. Each feature that uses Graph has its own flag — the [original-message lookup](#original-message-lookup), the [sender-relationship check](#sender-relationship-check-optional), [blast radius](#blast-radius-optional) (checking who else received a malicious email) and the [scheduled fan-out scan](#scheduled-fan-out-scan-optional) — so that features share one safe, already-reviewed way to reach the tenant. Leave it off unless you are enabling one of them. None of these features changes a mailbox; the one thing that can is the separate, optional [mailbox write tier](#mailbox-write-tier-optional), with its own app registration. See [ARCHITECTURE.md](ARCHITECTURE.md#microsoft-graph-optional-foundation) for the trust rules.

To find out which Graph calls work in your tenant — with which permissions and licences — before any feature depends on them, run the read-only probe: [GRAPH_PROBE.md](GRAPH_PROBE.md). It runs locally (`npm run graph:probe`), takes the same tenant ID, client ID and certificate, and does not need `PHISHY_GRAPH_ENABLED`.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_ENABLED` | `false` | Enable Microsoft Graph access |
| `PHISHY_GRAPH_MODE` | `direct` | `direct`: this function calls Graph itself. `broker`: it invokes the Graph broker function instead and holds no Graph credential. See [Graph broker](#graph-broker-optional) |
| `PHISHY_GRAPH_BROKER_FUNCTION` | - | Name or ARN of the Graph broker function. Required when the mode is `broker` |
| `PHISHY_GRAPH_TENANT_ID` | - | Directory (tenant) ID (GUID), or a verified domain of the tenant. Required when enabled (in `broker` mode: on the broker function, not the main function) |
| `PHISHY_GRAPH_READ_CLIENT_ID` | - | Application (client) ID (GUID) of the read-only app registration. Required when enabled (in `broker` mode: on the broker function only) |
| `PHISHY_GRAPH_READ_CERTIFICATE` | - | Secrets Manager ARN (recommended) or inline PEM holding the app's private key and certificate. Required when enabled (in `broker` mode: on the broker function only) |
| `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` | `false` | Before analysis, read the original message's real headers from the reporter's own mailbox. Has effect only when `PHISHY_GRAPH_ENABLED` is also `true`. See [Original-message lookup](#original-message-lookup) |

Blast radius, the sender-relationship check and the fan-out scan have their own variables, listed in their sections below.

File configuration uses the same names: `graph.enabled`, `graph.mode`, `graph.brokerFunctionName`, `graph.tenantId`, `graph.read.clientId`, `graph.read.certificate`, `graph.originalFetch.enabled`. With `graph.enabled` set, a missing or malformed value fails configuration at startup; with it unset, the other values are ignored.

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

Then set `PHISHY_GRAPH_READ_CERTIFICATE` to the secret's ARN and delete the local key file. The execution role of the function that calls Graph (the main function in `direct` mode, the broker in `broker` mode) needs `secretsmanager:GetSecretValue` on that secret. The secret is read on the first Graph call, not at startup, and never logged.

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

The function that calls Graph needs outbound HTTPS (TCP 443) to:

- `login.microsoftonline.com` — token requests
- `graph.microsoft.com` — Graph API

There is no VPC endpoint for those hosts. If the main function runs in a VPC without internet access, there are two ways to give Graph a route, and the second is the recommended one:

1. `direct` mode with a NAT gateway (or equivalent egress) and security-group/egress-filter rules allowing those hosts. This gives the function that parses hostile email a route to the internet.
2. `broker` mode: the main function stays without an internet route and invokes the [Graph broker](#graph-broker-optional), a second function outside the VPC.

Phishy only ever contacts these two hosts for Graph: the client's base URL is fixed, it refuses redirects, and it will not follow a paging link to any other origin.

#### Graph broker (Optional)

With `PHISHY_GRAPH_MODE=broker` the main function makes no Graph request. It invokes a second Lambda function, the Graph broker, which holds the read certificate and runs the lookups. The main function then needs no tenant ID, client ID or certificate (any it is given are dropped when configuration is loaded, and inline certificate material logs a warning), no route to Microsoft, and no access to the certificate secret. The design and its trust rules are in [ARCHITECTURE.md](ARCHITECTURE.md#graph-broker).

The SAM template sets all of the following up when you deploy with `GraphEnabled=true` (the broker function, its role, the main function's settings and permission, and the Lambda VPC endpoint): see [AWS.md](../AWS.md#optional-microsoft-graph-the-graph-broker-function). The rest of this section is the reference for what it configures, and for deployments that do not use the template.

**Main function**

| Variable | Value |
|----------|-------|
| `PHISHY_GRAPH_ENABLED` | `true` |
| `PHISHY_GRAPH_MODE` | `broker` |
| `PHISHY_GRAPH_BROKER_FUNCTION` | the broker's function name or ARN |
| the feature flags and their settings | as in `direct` mode. They decide whether the main function asks at all, and its `PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS` / `PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS` are how long it waits |

Its execution role needs `lambda:InvokeFunction` on the broker function, and only on it. In a VPC without internet access it also needs a way to reach the Lambda API: an interface VPC endpoint for `com.amazonaws.<region>.lambda`.

**Broker function**

Handler `graph-broker.handler` when bundled from `src/graph-broker.ts` (or `dist/handlers/graph.broker.handler.handler` from the `tsc` build). Deploy it **outside** the VPC, with no trigger: no function URL, API Gateway route or event source. It is invoked only by the main function.

| Variable | Value |
|----------|-------|
| `PHISHY_GRAPH_ENABLED` | `true` |
| `PHISHY_GRAPH_TENANT_ID`, `PHISHY_GRAPH_READ_CLIENT_ID`, `PHISHY_GRAPH_READ_CERTIFICATE` | the read app registration, as above |
| the feature flags and their settings | the broker refuses an operation whose feature is off in its **own** configuration, so set each flag on both functions. The broker's lookback, mailbox cap and budgets are the ones that apply to the Graph work; a caller's budget can only shorten them |
| `LOG_LEVEL` | optional |

The broker reads nothing else: it has no AI, email, notification, storage or database settings, and it ignores `PHISHY_GRAPH_MODE`. (`PHISHY_CONFIG_S3` works as it does for the main function if you keep `graph.*` in a file, and then its role needs to read that object.) Its execution role needs CloudWatch Logs and `secretsmanager:GetSecretValue` on the certificate secret, nothing more.

Sizing:

- **Timeout**: at least the blast-radius time budget plus 20 seconds (the lookup keeps 20 s of the function's remaining time in reserve). 180 seconds covers every allowed budget.
- **Memory**: 512 MB is ample.
- **Concurrency**: consider a small reserved concurrency (for example 5). Sender history keeps a per-instance allowance of 60 message-trace requests per 5 minutes against a tenant-wide limit of 100, so the number of broker instances is what bounds Phishy's share of that quota. An invocation that Lambda throttles for this reason fails open like any other broker failure.

**Behaviour.** Nothing changes in what the features do or report. A broker that times out, is throttled, crashes, refuses or returns something malformed or oversized is treated exactly as a Graph failure is: the original-message lookup's `Outcome=error`, sender history's `Outcome=timeout` or `error`, or a blast-radius note to the security team; the analysis and the reports proceed. Each lookup also emits:

| Metric | Dimensions | Meaning |
|--------|-----------|---------|
| `GraphBrokerCalls` | `Operation` = `original_message_lookup` / `sender_history_lookup` / `blast_radius_lookup` / `fanout_scan`; `Outcome` = `ok` / `refused` / `timeout` / `throttled` / `invoke_error` / `function_error` / `oversized` / `malformed` / `invalid_request` | One per invocation of the broker. Anything but `ok` is worth an alarm: `invoke_error` usually means a missing `lambda:InvokeFunction` permission or no route to the Lambda API; `refused` means the broker's own configuration is wrong or a feature flag is off there (the main function's log line `Graph broker call did not produce a result` carries the broker's reason word) |
| `GraphBrokerCallDurationMs` | same | Round-trip time of the invocation |

The features' own metrics (`OriginalFetchCount`, `SenderHistoryLookups`, `BlastRadius*`) are emitted by the main function in both modes, so existing dashboards and alarms keep working. Cached answers (`cache_hit`, `BlastRadiusCacheHits`) now come from the broker's instances, which are shared by every main-function instance.

#### Mailbox write tier (Optional)

The only way Phishy changes a mailbox: after a security-team member approves a campaign removal with the exact `APPROVE REMOVAL <ref>` reply, the approved copies of the phishing email are moved to each mailbox's **Deleted Items** (never deleted for good; each person can restore it), and each person whose copy was moved gets a short notice. It is done by a third Lambda function, the **Graph write broker**, which holds its own app registration and certificate. Off by default at every level; without it, an approved removal is a dry run. Design and threat model: [ARCHITECTURE.md](ARCHITECTURE.md#the-mailbox-write-tier).

Three switches must all be on for anything to move:

1. the write broker is deployed with its own credential;
2. its own kill switch, `PHISHY_GRAPH_WRITE_ENABLED=true`, on the write broker;
3. `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE=live` and `PHISHY_GRAPH_WRITE_BROKER_FUNCTION` on the main function.

`live` without a valid function name logs a warning and runs the dry run. A removal is never automatic, whatever `employeeWarning` says.

**Which incidents get a live removal.** Only one with an **anchor**: the reported email as Phishy's [original-message lookup](#original-message-lookup) found it in the reporter's own mailbox, whose Internet Message-ID the report's own `In-Reply-To` header names (or, without one, the last `References` entry), whose subject matches the forward's own Subject, which a Message-ID search finds exactly once in the reporter's mailbox, and which Exchange marks as forwarded. So a live removal needs `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` and `PHISHY_GRAPH_BLAST_RADIUS_ENABLED` as well, reports forwarded inline from an Exchange client that writes those headers (Outlook does), a malicious verdict and at least one report. Report-button submissions, fan-out-scan incidents and reports without a matching anchor get a dry-run removal, and the proposal says why. A live removal then names only copies with the anchor's own Internet Message-ID, its From address and exactly its subject (after collapsing whitespace and case), arriving within `sameMessageSpreadMinutes` of it. There is no setting that widens this. A wave sent as several separate messages is only partly removable from one report; the warning still reaches everyone the lookup found. Other copies the lookup matched are listed as "not provably the same email: not included" and still get the warning. A legitimate email from the same sender with the same subject and Message-ID in that window would still be included: read the sender and subject in the proposal before approving. See [ARCHITECTURE.md](ARCHITECTURE.md#the-mailbox-write-tier).

**Main function**

| Variable | Config key | Default | Description |
|----------|-----------|---------|-------------|
| `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE` | `campaignResponse.removal.mode` | `dry_run` | `dry_run`: an approved removal is reported, nothing changes. `live`: the write broker moves the approved copies |
| `PHISHY_GRAPH_WRITE_BROKER_FUNCTION` | `campaignResponse.removal.writeBrokerFunctionName` | - | Name or ARN of the write broker function (used only in `live` mode) |
| `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_SAME_MESSAGE_SPREAD_MINUTES` | `campaignResponse.removal.sameMessageSpreadMinutes` | `60` | Live only: a copy (which must carry the reported copy's own Internet Message-ID) must have arrived within this many minutes of it (5-360); the write broker re-checks each copy in that window |

Its execution role needs `lambda:InvokeFunction` on the write broker and nothing else for it: **never** the write client ID, the write certificate or access to the write secret. Any `PHISHY_GRAPH_WRITE_CLIENT_ID` or `PHISHY_GRAPH_WRITE_CERTIFICATE` in its environment (or a `graph.write` key in the configuration file) is ignored, with a warning to remove it. In a VPC without internet access it also needs the Lambda interface endpoint, as for the read broker.

**Write broker function**

Handler `graph-write-broker.handler` when bundled from `src/graph-write-broker.ts` (or `dist/handlers/graph.write.broker.handler.handler` from the `tsc` build). Deploy it **outside** the VPC, with no trigger. It reads **only its own environment**: not `PHISHY_CONFIG_S3`, not the read registration's variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_WRITE_ENABLED` | `false` | The kill switch. Anything but `true` refuses every request (`write_disabled`) |
| `PHISHY_GRAPH_TENANT_ID` | - | Directory (tenant) ID or verified domain. Required when enabled |
| `PHISHY_GRAPH_WRITE_CLIENT_ID` | - | Application (client) ID of the **write** app registration (not the read one). Required when enabled |
| `PHISHY_GRAPH_WRITE_CERTIFICATE` | - | Secrets Manager ARN of the **write** app's private key and certificate (same formats as the read certificate). Required when enabled |
| `PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS` | - | Optional. Comma-separated Entra object IDs (GUIDs) of the only mailboxes it may change; any other is refused (`not_allowed`). An entry that is not a GUID, or a value that lists nothing (`""`, `","`), makes the function refuse everything (`misconfigured`). Use it to limit a staging deployment to one test mailbox |
| `LOG_LEVEL` | `info` | Optional |

Its execution role needs CloudWatch Logs and `secretsmanager:GetSecretValue` on the write secret, and nothing else: not the read secret. If the secret is encrypted with a customer-managed KMS key (not the default `aws/secretsmanager` key), the role also needs `kms:Decrypt` on that key; the SAM template does not add it. The function refuses to start if its environment also carries the read app's client ID or certificate and they equal its own.

**Who may invoke it.** Anything in the AWS account allowed `lambda:InvokeFunction` on the write broker can request moves, within its kill switch and allowlist; the write broker cannot check an approval. The template grants that permission only to the main function, and only in live mode, but an administrator, a broad `lambda:*` policy or a CI role has it too. Restrict it: for example an explicit deny on the function for every principal except the main function's role (a permissions boundary or a service control policy), and alert on its invocations (CloudTrail data events for Lambda).

**Deploy order.** The read broker's protocol is strict: a read broker of this version talking to an older main function answers in a shape that function refuses (`malformed`), so blast radius and the original-message lookup are unavailable until the main function is updated. Deploy both together (one SAM stack does), or the main function first. Timeout: 100 seconds (one call works for at most 80). Memory: 256 MB. A small reserved concurrency (the template uses 2) bounds how many calls can run at once.

**Entra setup (a separate app registration)**

1. **Register a second single-tenant app**, for example *Phishy Graph (write)*, exactly as in [Entra app registration](#entra-app-registration). Never reuse the read app: a read path must not be able to obtain a write token.
2. **Create a new certificate** for it (a new key pair, as in [The certificate](#the-certificate), with its own CN such as `phishy-graph-write`), upload only the `.crt` to this app, and store the key and certificate as a **new** Secrets Manager secret (for example `phishy/graph-write`). Do not create a client secret.
3. **Grant `Mail.ReadWrite` (Application) and grant admin consent.** That is the least-privileged application permission for [moving a message](https://learn.microsoft.com/en-us/graph/api/message-move?view=graph-rest-1.0) and also covers the re-read Phishy does before each move. Grant nothing else to this app.
4. **Optional hardening: scope it to mailboxes.** Granted in Entra, `Mail.ReadWrite` applies to every mailbox in the tenant. Exchange Online application RBAC can limit an app's mailbox permission to a management scope instead; see Microsoft's documentation on [RBAC for Applications](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac), and the warning above that an unscoped Entra grant defeats the scope. `PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS` is Phishy's own, independent limit.
5. Find the mailbox object IDs for the allowlist in Entra (*Users* → the user → *Object ID*).

**Before turning live removal on.**

1. Confirm your mail clients set `In-Reply-To` (or `References`) to the forwarded message's ID on forwards: forward a test email to Phishy from each client your staff use and check the report's headers. Without it no incident gets a live removal (the proposal says "not proposed").
2. Deploy the main function before, or together with, the read broker (the read broker's protocol is strict; see Deploy order above).
3. Deploy the write broker with `PHISHY_GRAPH_WRITE_ENABLED=false`, set the main function to `live`, and approve one removal: the reply should say the write broker refused (`write_disabled`). Nothing moves.
4. Enable it with `PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS` set to one test mailbox and rehearse the whole path on a test campaign that reached it: proposal → `APPROVE REMOVAL` → the copy moves to Deleted Items → the removal notice arrives → approving the same line again does nothing.
5. Brief the approvers: Phishy cannot exclude a legitimate email from the same sender with the same subject and the same Message-ID, so compare what the approval shows (sender, subject, number of copies, arrival times) with the analysis report before approving. Tell them too that a wave sent as several separate messages is only partly covered by one removal.
6. Only then remove the allowlist.

Pre-release configurations that set `campaignResponse.removal.sizeTolerancePercent` or `windowHours` (or `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_SIZE_TOLERANCE_PERCENT` / `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_WINDOW_HOURS`) still load: the keys are ignored, with a startup warning to remove them.

**What the approver is told.** The proposal states what the removal rests on (how many copies, all carrying the same Internet Message-ID as the reported copy; the sender and exact subject; when they arrived) and what it leaves out. The reply to `APPROVE REMOVAL` gives, by count: moved to Deleted Items, already in Deleted Items, not found, refused because the copy was no longer provably the approved email (its Message-ID, sender, subject or arrival time differed), refused by the allowlist, errors, not attempted (with why: time, throttling, a refusal) and, if the write broker did not answer in time, outcome unknown, with which mailboxes those are, that those people were not notified, and how to check. Only people whose copy was actually moved get the removal notice. A removal proposed as a dry run is carried out as a dry run, and one proposed live is carried out as a dry run if the deployment is no longer live; the reply says so.

**Metrics:** `CampaignMessagesRemoved`, `CampaignRemovalErrors`, `CampaignRemovalRefused` (`Reason`: `mismatch` or `not_allowed`), `CampaignRemovalNotAttempted`, `CampaignRemovalNoticesSent`, and `GraphBrokerCalls` with `Operation=remove_messages`. The write broker logs one line per call (`Graph write broker request finished`) with the action ID and the counts, never a mailbox, message or Internet Message-ID.

#### Blast radius (Optional)

When Phishy's verdict on a forwarded email is malicious, it can look up **who else in the organization received the message and what they did with it**, and add the answer to the security team's copy of the report. The reporter's copy never contains it, and the result is never shown to the model. The lookup is read-only: it does not move, delete or change any message. See [ARCHITECTURE.md](ARCHITECTURE.md#blast-radius-optional) for how it works.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_BLAST_RADIUS_ENABLED` | `false` | Run the lookup after a malicious verdict. Has no effect unless `PHISHY_GRAPH_ENABLED` is `true` |
| `PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS` | `45000` | Hard limit on the whole lookup, in milliseconds (1000-150000). The lookup also never starts with less than about 22 seconds of Lambda time left, and shrinks its budget to leave 20 seconds for sending the reports |
| `PHISHY_GRAPH_BLAST_RADIUS_MAX_MAILBOXES` | `2000` | Most mailboxes one lookup will read (1-20000) |

File configuration: `graph.blastRadius.enabled`, `graph.blastRadius.timeBudgetMs`, `graph.blastRadius.maxMailboxes`.

Application permissions on the **read** app registration (admin consent required):

| Permission | Needed for | Without it |
|---|---|---|
| `User.Read.All` | listing the organization's mailboxes | recipients from message trace are listed with delivery status only; the per-mailbox route cannot run |
| `Mail.ReadBasic.All` | finding the message in a mailbox, its folder and its read flag | no mailbox details; without message trace as well, the lookup reports that it could not be completed |
| `Mail.Read` | whether the message was replied to or forwarded (a MAPI extended property) | that column reads "Unknown" |
| `ExchangeMessageTrace.Read.All` | the message-trace route (recipients and delivery status without reading mailboxes) | Phishy falls back to searching mailboxes directly |

Message trace also needs Microsoft's message-trace service principal in the tenant; many tenants do not have it, and the request is then refused (HTTP 403). That is expected and handled: Phishy searches mailboxes instead. Run the [probe](GRAPH_PROBE.md) to see which of these calls work in your tenant before enabling the flag.

Things to know before enabling:

- **It needs to read every mailbox it is to cover.** A mailbox permission scoped with Exchange RBAC for Applications (above) limits the lookup to the mailboxes in that scope; mailboxes outside it count as not checked, and the report says so.
- **Coverage is always stated.** The section reads "checked N of M mailboxes" and is marked `PARTIAL COVERAGE` whenever the time budget, the mailbox cap, throttling or failed requests kept the lookup from covering everything. The per-mailbox route covers licensed, enabled user mailboxes only: shared mailboxes, unlicensed and disabled accounts are not searched.
- **The reporter never waits for it.** For a malicious verdict the reporter's report is sent first, then the lookup runs, then the security team's copy is sent. The security team's copy arrives later by at most the time budget. Reports with any other verdict are unaffected. Keep the budget well under the Lambda timeout minus the time analysis can take.
- **Two emails instead of one.** For a malicious verdict with the lookup enabled, the reporter receives the usual report without the security team in Cc, and the security team receives its own copy carrying the section. The security team's copy is always sent: with the section, or with a one-line note when the lookup failed or ran out of time. A reporter who is on the security-team distribution gets only the security team's copy. Command replies ([email commands](#email-commands-security-team-correspondence)) are matched to the security team's copy. If that copy cannot be sent, Phishy logs an error and emits the `SecurityCopySendFailures` metric; alarm on it, because the reporter has been told and the security team has not.
- **Outlook Report-button reports get one email, not two.** With `PHISHY_REPORT_BUTTON_ENABLED`, a malicious button report is still handled silently: the reporter is never emailed, and the single email to the security team carries the section (or the one-line note). The lookup runs before that email.
- **Not every trace row is a mailbox copy.** Rows that message trace reports as *expanded* are distribution lists (their members are listed individually) and are left out; *failed* rows are listed as "Not delivered" and counted separately.
- **Request volume.** The per-mailbox route makes one or two requests per mailbox. Microsoft limits an app to 10,000 Outlook requests per 10 minutes; a flood of reports of different malicious messages in a large tenant can reach that. Phishy stops a lookup when throttled, reports what it covered, and reuses a result for repeat reports of the same message for 10 minutes (per Lambda instance). Lower the mailbox cap if you see `BlastRadiusPartial` rise.
- **Failure changes nothing else.** If the lookup fails or runs out of time before finding anything, the report is sent as usual with a one-line note to the security team.

CloudWatch metrics (namespace `Phishy`, dimension `BlastRadiusRoute` = `trace`, `mailbox` or `none`): `BlastRadiusLookups`, `BlastRadiusRecipientsFound`, `BlastRadiusMailboxesChecked`, `BlastRadiusMailboxesEligible`, `BlastRadiusCoveragePercent`, `BlastRadiusPartial`, `BlastRadiusFailures`, `BlastRadiusErrors`, `BlastRadiusCacheHits`, `BlastRadiusDurationMs`. Without a dimension: `SecurityCopySendFailures`.

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

#### Sender-relationship check (optional)

When a known external contact's mailbox is taken over, the attacker's mail comes from the real account: SPF, DKIM and DMARC pass and the address is familiar. What gives it away is behaviour — a sender with a history suddenly writes to far more people than usual, most of whom it never dealt with. With this check on, before each analysis Phishy reads your tenant's **Exchange message trace** (delivery records only; no mailbox is opened) for the sender address the forwarded email claims, and computes counts about that relationship. The counts go to the model as facts computed by Phishy, to risk fusion, and into the report. It runs for forwarded emails and for Outlook Report-button phishing submissions alike, never for safelist senders.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_SENDER_HISTORY_ENABLED` | `false` | Enable the check. Only effective when `PHISHY_GRAPH_ENABLED` is `true` |
| `PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS` | `30` | Days of mail-flow records to examine (14-90; message trace keeps 90) |
| `PHISHY_GRAPH_SENDER_HISTORY_BURST_WINDOW_HOURS` | `24` | Hours before the email's time that count as the burst rather than as history (1-72) |
| `PHISHY_GRAPH_SENDER_HISTORY_BUDGET_MS` | `8000` | Overall deadline for one lookup (1000-30000). On expiry the analysis runs without the facts |
| `PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MIN_RECIPIENTS` | `15` | Fewest distinct recipients of one subject in the burst that can count as anomalous fan-out (2-1000) |
| `PHISHY_GRAPH_SENDER_HISTORY_FANOUT_MULTIPLIER` | `3` | Those recipients must be at least this many times the distinct recipients in the history period (1-100) |

File configuration uses `graph.senderHistory.*` with the same names (`enabled`, `lookbackDays`, `burstWindowHours`, `budgetMs`, `fanoutMinRecipients`, `fanoutMultiplier`).

**Permission.** Add the Microsoft Graph application permission `ExchangeMessageTrace.Read.All` to the read app registration and grant admin consent. Message trace also depends on a Microsoft-owned service principal existing in the tenant; `npm run graph:probe` ([GRAPH_PROBE.md](GRAPH_PROBE.md)) tells you whether trace calls work before you turn this on. Message trace can answer 403 *intermittently* — for some hours after that service principal is created, identical requests alternate between 200 and 403 — so a request that gets a 403 is retried up to 3 times (250, 500, 750 ms apart) inside the lookup's deadline and request allowance; `SenderHistoryForbiddenRetries` counts those retries. Only when a lookup ends on a 403 and **no** request in it succeeded does Phishy treat it as a permission or provisioning problem: it emits `Outcome=forbidden` and leaves the API alone for five minutes. A request that still gets 403 after its retries while others succeeded is an ordinary `Outcome=error` with no pause. Either way the email is analyzed exactly as it would be with the check off.

**What is computed.** The lookback is split into a *burst window* and a *history period*. The burst window starts `burstWindowHours` before the email's own date and always ends at lookup time (the email's date is claimed text, so it can only move the start back, by at most 7 days; if it does not parse, "now" is used). Everything in the lookback before that is history.

| Fact | Meaning |
|------|---------|
| History | Messages from the address, distinct internal recipients, and the first date seen, in the history period |
| Two-way contact | Messages your organization sent *to* the address, and from how many distinct internal senders, in the history period (replies sent during the burst are not counted) |
| Burst window | Messages and distinct internal recipients from the address, and how many of those recipients had no mail from it in the history period |
| Widest single message | The largest number of distinct internal recipients that received the **same subject** in the burst window, and how many of them had no mail from the address in the history period. This is the figure fan-out is judged on. Subjects are compared after trimming, case-folding and collapsing whitespace; the subject is only a grouping key in memory and is never logged, stored or shown to the model |
| Sending IPs | How many distinct sending IPs the burst used, and how many of them were seen in the history period. The model and the combined report get the counts only; the addresses themselves appear only in an email sent to the security team alone (see below) |

**Classification** (decided by code, never by the model):

| Class | Rule |
|-------|------|
| `no_history` | No message from the address and none to it in the history period |
| `limited_history` | Some history, but below `established` |
| `established` | At least 3 history messages from the address, **or** at least 1 together with two-way contact |
| `established_with_anomalous_fanout` | `established`, **and** two-way contact (at least one message from your organization to the address in the history period), **and** one subject in the burst reached at least `fanoutMinRecipients` (15) distinct recipients, **and** that is at least `fanoutMultiplier` (3) times the history's distinct recipients, **and** at least half of those recipients had no mail from the address in the history period |

**Why these defaults.** The rule is deliberately narrow, because the common look-alikes are all legitimate. A single email to a project team reaches a dozen or so people, so the minimum is 15. Bulk senders — marketing, webinars, newsletters — have a history but nobody in the organization ever writes to them, so two-way contact is required. Transactional systems send many different messages in a day to many people, so fan-out is measured per subject rather than over everything the sender sent. A sender that fans out without meeting all of these stays `established`, and the counts are still shown.

**Known limit.** A mailbox takeover that reaches fewer recipients than the minimum, or that comes from a contact nobody has written to in the lookback, is not flagged by this rule; catching it rests on the content analysis, which runs regardless. Lowering `fanoutMinRecipients` trades that gap for more false positives on ordinary team-wide emails.

**A relationship never lowers risk.** Trust is exactly what a mailbox takeover borrows, so `established` earns nothing: the model is told not to treat it as evidence of legitimacy, risk fusion ignores it, and the reporter is told nothing about it. Only `established_with_anomalous_fanout` acts (and `established` without it is never reassurance, for the reason just given): it adds one plain-language reason to the report and raises the risk score to at least 35 (medium), turning a `legitimate` verdict into `suspicious` when it does. A security-team ruling still overrides it.

**Bounds and honesty.**

- One trace query covers at most 10 days, so a lookup makes one request per 10-day window per query type (mail from the address, mail to the address): **6 requests** at the defaults, 18 at a 90-day lookback (each may be retried up to 3 times on a 403, counted against the allowance below). They run in parallel, at most 6 at a time, under the single `budgetMs` deadline; requests still in flight at the deadline are cancelled.
- Each window keeps at most 2000 rows (at most two requests). When a sender exceeds that, the affected counts are reported as **"at least N"** to the model and in the report, the number of new recipients is reported as undeterminable, and fan-out is not judged.
- Message trace allows 100 requests per 5 minutes per tenant. Each Lambda instance spends at most 60 of them per 5 minutes on this check, then skips it (`Outcome=rate_limited`). In practice that is about **10 distinct senders per 5 minutes per instance** at the defaults (3 at a 90-day lookback), fewer when requests are retried or a sender needs a second page. Results are reused per sender address for 5 minutes within an instance, so repeated reports of one sender cost nothing more.
- **Only exact address matches are queried, and every row is checked.** Message trace applies `senderAddress eq` and `recipientAddress eq`, but it accepts `endswith(...)` and `contains(...)` on an address with HTTP 200 and silently ignores them, returning rows as if no address filter had been sent. That is why there is no domain-level history. As a defence against the same failure anywhere else, after every query Phishy verifies that each returned row carries the address it asked for; if any row does not, the whole lookup is discarded (`Outcome=error`, `SenderHistoryFilterMismatches`) and the analysis proceeds without it. Counts from rows the filter did not select never reach the model.
- Any failure — timeout, 403, a failed window — means no facts at all rather than partial counts, and the analysis proceeds exactly as it would with the check off.
- The sender address is taken from the forwarded message's `From:` line and must be a single, plain ASCII address on a domain outside `SAFE_DOMAINS`; anything else is not looked up. It is never logged, and it is not repeated in the facts given to the model. Recipient addresses are never shown to the model, logged, stored or put in any report. Nothing is written to the database.

**What each email shows.** How much of this appears depends on who the email goes to:

| Email | Sender-relationship content |
|-------|-----------------------------|
| Combined report (reporter, security team in Cc) — the default | Counts and the classification in the "Original Email for IT Review" part. No IPs |
| Reporter's own copy (sent separately when [blast radius](#blast-radius-optional) is on and the verdict is malicious) | None, beyond the one plain sentence on anomalous fan-out |
| Security team's own copy (the second email in that case, or the single email about a silent [Report-button](#outlook-report-button-intake) report) | Counts and the classification, plus the burst's sending IPs, each marked as seen or not seen in the history period. At most 20 are listed, then "and N more" |

The sending IPs are never given to the model and never logged at info level.

**Metrics** (namespace `Phishy`, dimension `Outcome` = `ok`, `cache_hit`, `skipped`, `timeout`, `forbidden`, `cooldown`, `rate_limited`, `error`): `SenderHistoryLookups`, `SenderHistoryDurationMs`, `SenderHistoryAnomalousFanout`, `SenderHistoryTruncated`, `SenderHistoryForbiddenRetries`, `SenderHistoryFilterMismatches`.

#### Scheduled fan-out scan (optional)

The sender-relationship rule above, run proactively: every few minutes, without waiting for anyone to report, Phishy reads the last few minutes of your tenant's inbound mail flow from message trace and emails the **security team** when an established external contact suddenly sends one subject to many internal people. A real takeover wave typically reaches dozens of mailboxes within a minute or two, minutes before the first employee report; the scan exists to close that gap. Code-driven and read-only; **no AI model is involved**. How it works and what it cannot see: [ARCHITECTURE.md](ARCHITECTURE.md#scheduled-fan-out-scan).

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_GRAPH_FANOUT_SCAN_ENABLED` | `false` | Enable the scan. Only effective with `PHISHY_GRAPH_ENABLED=true`. Set it on the main function and, in broker mode, on the broker too (the broker refuses the operation otherwise) |
| `PHISHY_GRAPH_FANOUT_SCAN_OVERLAP_MINUTES` | `10` | Each window starts this long before the previous scan's window ended (1-30), so mail flow that message trace records late is still seen |
| `PHISHY_GRAPH_FANOUT_SCAN_MAX_WINDOW_MINUTES` | `60` | Widest window one scan reads (5-120). After a longer gap (the schedule was off, scans failed) the oldest part is skipped, logged, and the scan counted as incomplete |
| `PHISHY_GRAPH_FANOUT_SCAN_MAX_PAGES` | `4` | Message trace pages (up to 5000 rows each) one scan reads (1-10). More rows than that makes the scan incomplete, never silently truncated |
| `PHISHY_GRAPH_FANOUT_SCAN_MAX_CANDIDATES` | `3` | Sender-and-subject groups (most recipients first) whose history one scan checks (1-10) |
| `PHISHY_GRAPH_FANOUT_SCAN_REQUEST_ALLOWANCE` | `20` | Message trace requests all scans together may spend in any 5 minutes (5-40), tracked in the database across Lambda instances |
| `PHISHY_GRAPH_FANOUT_SCAN_BUDGET_MS` | `60000` | Hard limit on one scan's Graph work (10000-120000) |
| `PHISHY_GRAPH_FANOUT_SCAN_DEDUPE_HOURS` | `24` | A wave (one sender, one subject) quiet for this long is over; the same sender and subject later is a new wave and alerts again (1-168) |

File configuration uses `graph.fanoutScan.*` (`enabled`, `overlapMinutes`, `maxWindowMinutes`, `maxPages`, `maxCandidates`, `requestAllowancePer5Min`, `budgetMs`, `dedupeHours`). The rule's thresholds and history period are the sender-relationship check's (`PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS`, `_BURST_WINDOW_HOURS`, `_FANOUT_MIN_RECIPIENTS`, `_FANOUT_MULTIPLIER`, or their defaults); in broker mode the broker's values are the ones applied. The scan does not need the on-report check to be enabled.

**Requirements.**

- `ExchangeMessageTrace.Read.All` on the read app registration, as for the sender-relationship check.
- **The intelligence database, with `migrations/005_fanout_scan.sql` applied manually.** The scan keeps its lock, its window, its request log and the alerted waves there ([DATABASE.md](DATABASE.md)). Without the database it does not run: each scheduled invocation logs what to configure and emits `Outcome=no_database`; without the migration, `Outcome=migration_missing` and a log line naming the file.
- `SECURITY_TEAM_DISTRIBUTION`: the only recipients of the alert. With it empty the scan does not run.

**With campaign response on** (`PHISHY_CAMPAIGN_RESPONSE_ENABLED`, see [Campaign Response](#campaign-response-optional)), a flagged wave opens a campaign-response incident and the security team gets the **incident email instead of the alert**: one email per wave, with the scan's findings, the reach and proposed actions (always waiting for approval: nothing goes to employees from a scan on its own). A wave that grows materially becomes an update in that incident's thread, and an employee report of the same email later joins the incident. The plain alert is still sent when no incident email went out (migration 006 not applied, the incident is closed or a false positive, or the send failed). No new setting.
- `SAFE_DOMAINS` decide what "internal" means: a recipient on one of them (or a subdomain) is internal, a sender on none of them is external. In broker mode they are sent to the broker in the scan request.
- A schedule that invokes the **main** function every 5 minutes (or so) with exactly this payload: `{"phishyScheduledTask": "graph_fanout_scan", "version": 1}`. The SAM template can create it ([AWS.md](../AWS.md)). Any other payload carrying `phishyScheduledTask` is refused; an EventBridge rule without this constant input does nothing.

**Request budget.** Message trace allows 100 requests per 5 minutes per tenant, shared by everything that reads it. A scan costs one request per page of the window (one at most tenants' volumes: a 15-minute window is a few hundred rows) plus, for each candidate it checks, the sender-relationship lookup's requests (6 at a 30-day lookback, up to 12 when the sender's history needs a second page per query; each 403 retry is one more), plus about 2 for a blast-radius lookup when an alert is sent and that feature is on. A scan stops at its allowance: every request is counted before it is made, and what the allowance cut short (a history page, a candidate, a window page) makes the scan incomplete and is said in the alert. If it ran out before every page of the window was read, the window is read again by the next scan rather than skipped. All scans together spend at most `PHISHY_GRAPH_FANOUT_SCAN_REQUEST_ALLOWANCE` (20) per 5 minutes on the scan itself (blast-radius lookups are charged to the same record after the scan, as an estimate): the allowance is tracked in the database, so it holds whichever Lambda instance runs a scan, and only one scan runs at a time. It is separate from the on-report sender-relationship check's own allowance (60 per broker instance per 5 minutes), so a scan never takes requests from a report, and 20 + 60 stays under the tenant's 100 with one broker instance. Each broker instance also caps scans at 40 requests per 5 minutes whatever the caller asks.

**Metrics** (namespace `Phishy`, dimension `Outcome` = `ok`, `skipped_running`, `no_database`, `migration_missing`, `rate_limited`, `forbidden`, `timeout`, `error`): `FanoutScans`, `FanoutScanDurationMs`, `FanoutScanRowsScanned`, `FanoutScanCandidates`, `FanoutScanFlags`, `FanoutScanAlertsSent`, `FanoutScanIncomplete`, `FanoutScanTraceRequests`. Alarm on `FanoutScans` with any outcome other than `ok` and `skipped_running` persisting, and on `FanoutScanIncomplete`.

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
| `AnalysisFailureCount` | Reports sent as "analysis unavailable" — the provider was unreachable, the model declined, or its reply was incomplete |
| `AnalysisRefusalCount` | Model calls declined with `stop_reason: "refusal"`, counted against the model that declined. The category (`cyber`, `bio`, …) is the `RefusalCategory` property on the log line |
| `VerdictProseDiscardedCount` | Verdicts accepted after discarding prose the model wrote before or after its one JSON object (for example a trailing "Note: ..."). A count only; the prose is never logged |
| `CampaignCacheHits` | Reports answered from the campaign verdict cache (no AI call) |
| `EstimatedCostSavedUSD` | Approximate spend avoided by cache hits |

`OutputTokens` includes thinking tokens. When the API reports the thinking share, each usage line also carries a `ThinkingTokens` property — a log field you can query with CloudWatch Logs Insights, not a separate metric.

Useful starting points: a dashboard widget on `SUM(EstimatedCostUSD)` per day, a billing alarm such as "alert when `SUM(EstimatedCostUSD)` over 24h exceeds $X", and an alarm on `AnalysisRefusalCount` relative to `AnalysisCount`. Set `PHISHY_DISABLE_METRICS=true` to turn emission off.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHY_DISABLE_METRICS` | `false` | Set `true` to disable CloudWatch EMF metrics |

---

## File-Based Configuration

For more complex setups, use a JSON configuration file. Upload it to S3 and set `PHISHY_CONFIG_S3=s3://bucket/path/config.json`; the function's role needs `s3:GetObject` on that object. Environment variables still override what the file says. Keep your working copy as `config/phishy.config.json`, which is gitignored.

### Example Configuration

```json
{
  "ai": {
    "provider": "bedrock",
    "bedrock": {
      "region": "us-east-1",
      "modelId": "global.anthropic.claude-opus-5-5",
      "maxTokens": 16000,
      "timeout": 60000
    },
    "effort": "medium",
    "refusalFallbackModel": "global.anthropic.claude-opus-4-8",
    "fallbackProvider": "anthropic"
  },
  "email": {
    "safeDomains": ["example.com", "example.org"],
    "safeSenders": ["contractor@partner.example"],
    "deleteAfterProcessing": false
  },
  "notification": {
    "senderEmail": "phishy@example.com",
    "replyToEmail": "phishy@example.com",
    "senderName": "Phishy Security",
    "securityTeamDistribution": ["security@example.com", "soc@example.com"],
    "securityTeamMembers": ["alice@example.com", "bob@example.com"]
  },
  "storage": {
    "s3Bucket": "phishy-emails",
    "region": "us-east-1"
  },
  "logLevel": "info"
}
```

See `config/phishy.config.example.json` for a complete example with every key at its default (optional features off).

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

Provider fallback covers outages and errors. A model *refusal* is handled separately, inside the primary provider, by `ai.refusalFallbackModel` (see [Refusals](#refusals)) — a declined request is not sent to the fallback provider.

---

## Enterprise Profiles

Enterprise profiles provide organization-specific context for better phishing detection.

### Quick Setup

1. Copy the example: `cp config/profile.example.json config/my-org.profile.json` (files named `*.profile.json` are gitignored)
2. Customize for your organization
3. Upload it to S3 and point Phishy at it: `PHISHY_PROFILE=s3://bucket/profiles/my-org.profile.json`. With the SAM template, put it under `profiles/` in the stack's email bucket and pass the URI as `ProfileS3Uri`; the function's role can read that prefix.

`PHISHY_PROFILE` also accepts the profile JSON itself as its value. A local file path is not supported.

Reports from `SAFE_SENDERS` addresses are analyzed without the profile.

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

Requires PostgreSQL 13+. In a SAM deployment, pass the secret's ARN as `IntelligenceDbSecretArn` with `VpcId` and `SubnetIds` ([AWS.md](../AWS.md)).

### What It Provides

- **Analysis history**: every analysis stored (sender, subject, verdict, score, model, cost)
- **Indicators**: IOCs from malicious verdicts, which raise the risk of later emails that reuse them ([INTELLIGENCE.md](INTELLIGENCE.md#which-indicators-count))
- **Campaigns**: repeat reports of one email grouped, for [campaign alerts](#campaign-alerts), the [verdict cache](#campaign-verdict-cache) and [campaign response](#campaign-response-optional)
- **The data the other layers need**: email commands, the fan-out scan and campaign response keep their state here

### Database Schema

Phishy creates the baseline schema (migration 001) on first connection. Everything later ships as a numbered file in `migrations/` that you apply by hand before enabling the feature that needs it (002 email commands, 003 verdict cache, 004 structured verdict columns, 005 fan-out scan, 006 campaign response). See [DATABASE.md](DATABASE.md).

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

These names are unchanged in v3. The v1 runtime itself (the former root `index.js`) has been removed; deploy with the SAM template or `npm run package`.

---

## Validation

Phishy validates all configuration at startup using Zod schemas. Invalid configuration fails fast: the function logs `Configuration validation failed` with the offending paths, for example:

```
{"campaignAlerts":{"distributionList":{"_errors":["Invalid input: expected string, received array"]}}}
```

Validation runs on every cold start, so a misconfigured deployment fails immediately and loudly in CloudWatch logs rather than silently misbehaving. To catch problems before deploying, compare your config against [config/phishy.config.example.json](../config/phishy.config.example.json) — every key in it is documented in this file.

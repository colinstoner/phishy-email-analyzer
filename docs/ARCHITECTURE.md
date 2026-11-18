# Architecture

Phishy is an AWS Lambda that receives employee-forwarded emails via SES, analyzes them with Claude, and replies with a security report. Everything else — threat intelligence, campaign detection, the email command channel, agentic analysis, Microsoft Graph access — layers on top of that loop and is individually optional.

```
                          ┌─────────────────────────────────────────────┐
 employee forwards email  │                  Lambda                     │
        │                 │                                             │
        ▼                 │  EmailParserService                         │
  SES receipt rule ──────▶│   raw MIME → labeled, canonicalized facts   │
   (S3 action first,      │        │                                    │
    then Lambda)          │        ▼                                    │
        │                 │  command? ──yes──▶ EmailCommandService      │
        ▼                 │        │            (security team only)    │
   S3 (raw email)         │        ▼                                    │
                          │  campaign cache? ──hit──▶ reuse verdict     │
                          │        │                                    │
                          │        ▼                                    │
                          │  AnalysisService                            │
                          │   ├─ AgenticAnalyzer (tool loop, optional)  │
                          │   └─ single-shot prompt (default/fallback)  │
                          │        │                                    │
                          │        ▼                                    │
                          │  intelligence DB writes · IOC extraction    │
                          │  campaign tracking · EMF cost metrics       │
                          │        │                                    │
                          │        ▼                                    │
                          │  SESNotifier → report to the reporter       │
                          └─────────────────────────────────────────────┘
```

## The parser is the trust boundary

`EmailParserService` does not just "get text out of MIME" — its output decides **who receives the report** (`originalForwarder`), **what Claude analyzes**, and **what enters the threat-intel DB**. Design rules that follow from this:

- **Real MIME parsing.** Raw email is parsed with [mailparser](https://nodemailer.com/extras/mailparser/), never regexes. `message/rfc822` attachments (forward-as-attachment — the one mode that preserves the original's full headers) are parsed recursively and surfaced as a forwarded block.
- **Provenance labels.** Every fact handed to the model is labeled by who asserts it:
  - `VERIFIED` — computed by Phishy: headers, canonical link destinations, attachment hashes, integrity flags, disclosed elisions.
  - `OPERATOR` — the organization's profile and configuration.
  - `REPORTED` — the forwarding employee's own note.
  - `CLAIMED` — the suspicious email's content: hostile data, fenced with a per-request nonce in the prompt. Nothing inside the fence can change instructions.
- **Canonicalization** (`src/utils/canonicalize.ts`, pure computation): NFKC, zero-width/bidi stripping, entity decoding, unwrapping of known URL wrappers (SafeLinks, Proofpoint, Google redirects). Raw-vs-canonical divergence is reported as a flag — obfuscation is itself an indicator. Threat intel stores canonical destinations, not gateway wrappers.
- **Adversarial bounding.** Body truncation keeps head+tail (padding can't hide the payload); the link budget fills round-robin across registrable domains; every elision is disclosed to the model.
- **Boundary validation.** External (API Gateway) payloads pass a Zod schema that strips trust-bearing fields — `authVerdicts` and `s3Location` only exist when derived from SES receipts.

## Who may tell Phishy what to do

Three principals, three levels of trust:

| Principal | May | Authenticated by |
|---|---|---|
| Any safe-domain employee | report emails for analysis | sender domain ∈ `SAFE_DOMAINS` |
| Security team | correct verdicts by replying to reports (commands) | membership in `SECURITY_TEAM_DISTRIBUTION` **and** SES SPF or DKIM `PASS` on the reply |
| The suspicious email | nothing | it is CLAIMED data, everywhere |

The SES verdicts describe the hop that delivered the reply to Phishy — which is exactly the hop that needs authenticating for commands. They are never presented as authenticating the *suspicious* sender (that email's own Authentication-Results header, when preserved by forward-as-attachment, is surfaced as a CLAIMED/forwarded header instead).

## Services

| Service | File | Role |
|---|---|---|
| `EmailParserService` | `services/email/parser.service.ts` | events → labeled email facts (trust boundary) |
| `AnalysisService` | `services/ai/analysis.service.ts` | provider orchestration: agentic → primary → fallback |
| `AgenticAnalyzer` | `services/ai/agentic/agentic.analyzer.ts` | bounded tool loop (max N rounds, falls back on any failure) |
| `AgenticToolExecutor` | `services/ai/agentic/tool.executor.ts` | the four tools; org data and pure computation only, no network |
| `AnthropicProvider` / `BedrockProvider` | `services/ai/*.provider.ts` | Messages API via raw HTTP / InvokeModel; both implement `converse()` for tool use |
| `EmailCommandService` | `services/commands/email.command.service.ts` | security-team replies → verdict feedback → completed-action replies |
| `IntelligenceDatabaseService` | `services/intelligence/database.service.ts` | PostgreSQL: analyses, IOCs, campaigns, feedback, usage |
| `CampaignAlertService` | `services/intelligence/campaign.service.ts` | flood detection → employee alerts |
| `SESNotifier` | `services/notification/ses.notifier.ts` | outbound reports and replies |

## Data flow decisions worth knowing

- **Campaign signature** (`computeCampaignSignature`) is the shared grouping key: sender domain + subject with numbers normalized out. Flood alerts, the verdict cache, and campaign-wide feedback all use it. One security-team reply resolves a whole campaign.
- **IOC provenance**: indicators carry `metadata.sourceAnalysisId`, which is how verdict feedback adjusts the confidence of exactly the indicators an analysis produced.
- **Verdict cache rows** are stored with `ai_provider='cache'` and never serve as cache sources themselves (unless they carry feedback), so campaigns are re-analyzed when the original analysis ages out.
- **Graceful migration degradation**: the app auto-creates only the 001 baseline schema. Later migrations (002 feedback, 003 campaign signature) are applied manually; every query that needs them catches `42P01`/`42703` and degrades with an instructive log line instead of failing.
- **Cost metrics are EMF**: structured stdout lines CloudWatch converts to metrics. No SDK calls, no IAM, works without the database.

## Microsoft Graph (optional foundation)

`src/services/graph/` lets Phishy call Microsoft Graph on the organization's own Microsoft 365 tenant. It is off by default, and on its own it is a **foundation only**: authentication, credential loading and an HTTP client. Enabling it changes nothing in the email-processing path; features that call it (checking who else received an email — see [Blast radius](#blast-radius-optional)) have their own flags.

| Piece | File | Role |
|---|---|---|
| Authentication | `graph.auth.ts` | app-only client-credentials flow; signs a short-lived JWT assertion with a certificate (no client secret, no MSAL); in-memory token cache, one shared in-flight request |
| Credential loading | `graph.credential.ts` | certificate from Secrets Manager or inline PEM, resolved lazily on the first Graph call; `createGraphReadClient(config.graph)` |
| Request building | `graph.request.ts` | `graphPath` and `odataFilter` tagged templates — the only way data enters a path or a `$filter` |
| HTTP client | `graph.client.ts` | `getJson` / `getBytes` / `getText` / `postJson` / `getPaged` against a fixed base URL |
| Read operations | `mail.operations.ts`, `trace.operations.ts`, `directory.operations.ts` | small typed GET-only functions (find a message by Internet message ID or sender + window, search, headers, MIME, last-verb, message trace, users, licence capabilities); every result is capped and reports truncation; cross-mailbox and trace lookups return metadata only |
| Probe CLI | `src/cli/graph-probe*.ts` | `npm run graph:probe` — an operator's local, read-only check of which of those calls work in their tenant ([GRAPH_PROBE.md](GRAPH_PROBE.md)); not part of the pipeline |

Trust rules (CLAUDE.md invariant 6):

- **Code-driven, never model-driven.** Graph is not an agentic tool. Requests go to fixed endpoints chosen by Phishy's code; the model never authors a URL, a filter or a query. Values that originate in a suspicious email (a message ID, a subject) are hostile and enter a request only through `graphPath` (percent-encoded as a single segment), `odataFilter` (escaped string literal) or `kqlSearch` (reduced to plain lower-case words, since mail `$search` has no documented escape).
- **The client cannot be steered off Graph.** The base URL is fixed to `https://graph.microsoft.com/v1.0` and callers cannot pass a URL. `@odata.nextLink` is followed only on that origin and API version; redirects are refused; paging is capped by the caller and reports truncation; response sizes and time are bounded; throttling (`Retry-After`) is honoured within a bounded wait and attempt count.
- **Mailbox content is hostile data.** Response bodies are never logged. Content read from any mailbox other than the reporter's own is metadata-only toward the model and logs.
- **Reads and writes are separate identities.** A client holds exactly one credential. Configuration has a `read` app registration today; a `write` registration, when one exists, is a different app with its own certificate and its own client, so a read path can never obtain a write token. Any write to the tenant additionally requires security-team approval through the authenticated command channel.
- **Secrets stay secret.** The private key, client assertion and access token never appear in logs or error messages; errors carry only status, Graph error code, request id and a path template with data segments blanked.

### Blast radius (optional)

`blast-radius.service.ts` answers the security team's next question after a malicious verdict: who else received this, and did anyone open or answer it? Off by default (`graph.blastRadius.enabled`, effective only with `graph.enabled`).

- **Where it runs.** In `lambda.handler.ts`, after the fused verdict and after the analysis has been stored, only when that verdict is malicious (`riskDecision.isPhishing`), the analysis did not fail, the reporter is not a safelist user and there is a security team to tell. Its result is passed to the report template and nowhere else: not to the model, not to the database, not to the logs (which get counts only).
- **Identifying the message.** By the original's Internet Message-ID when the parsed email carries one (`forwardedHeaders['Original-Message-ID']`); otherwise by the claimed sender address, the quoted subject and a time window (24 hours either side of the claimed date, or the last 7 days when the forward has no usable date). All of these are hostile strings and reach Graph only through `odataFilter`.
- **Route 1: message trace.** Recipients and delivery status without reading a mailbox. For each recipient that is a user mailbox, Phishy then reads the message's folder, read flag and last verb.
- **Route 2: per-mailbox search.** When trace fails (commonly HTTP 403: the tenant lacks Microsoft's message-trace service principal) or returns no rows, Phishy lists users, keeps licensed, enabled, non-guest accounts up to the mailbox cap, and runs the same `$filter` lookup in each. `/messages` does not cover Recoverable Items, so mailboxes without a match are searched there too, time permitting.
- **Bounds.** A hard time budget (default 45 s, shrunk to leave 20 s of Lambda time for sending), a mailbox cap (default 2000), 12 mailboxes at a time with one search per mailbox at a time, and a client limited to two attempts per request. `Retry-After` is honoured within a bound; a throttled request that cannot be retried stops the lookup. When the budget ends, what was established so far is reported.
- **Honest coverage.** The section always says "checked N of M mailboxes" and is marked partial when anything was left uncovered: cap, budget, throttling, failed requests, a truncated trace or directory listing, or Recoverable Items not searched everywhere. "Replied" and "forwarded" are reported only for the last-verb values the MAPI definition gives (102/103 and 104); any other value is shown as unknown with its code.
- **Delivery.** `sendReports` sends the security team its own copy with the section, and the reporter the usual report without it. The security copy's message ID is the one stored for command replies. If that copy cannot be sent, or there is no result, the single combined email goes out exactly as before. A failed lookup adds one line to the security team's copy and nothing else.
- **Read-only.** GET requests through the operations library only; no message is moved, deleted or changed.

## Feature flags

Everything optional is off by default and independently enableable:

| Flag | Feature | Requires |
|---|---|---|
| `PHISHY_INTELLIGENCE_ENABLED` | threat-intel DB | PostgreSQL |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | flood alerts | intelligence DB |
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | verdict reuse | intelligence DB + migration 003 |
| `PHISHY_EMAIL_COMMANDS_ENABLED` | security-team replies | intelligence DB + migration 002 |
| `PHISHY_AGENTIC_ENABLED` | tool-loop analysis + AI command parsing | nothing (tools appear as their backends do) |
| `PHISHY_GRAPH_ENABLED` | Microsoft Graph access (foundation only — features on it have their own flags) | Entra app registration with a certificate; outbound HTTPS to Microsoft |
| `PHISHY_GRAPH_BLAST_RADIUS_ENABLED` | who else received a malicious email (security-team copy only) | `PHISHY_GRAPH_ENABLED` + read permissions listed in [CONFIGURATION.md](CONFIGURATION.md#blast-radius-optional) |

See [CONFIGURATION.md](CONFIGURATION.md) for the full reference.

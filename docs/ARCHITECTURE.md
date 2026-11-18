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
                          │  original-message lookup (Graph, optional)  │
                          │        │                                    │
                          │        ▼                                    │
                          │  AnalysisService                            │
                          │   ├─ AgenticAnalyzer (tool loop, optional)  │
                          │   └─ single-shot prompt (default/fallback)  │
                          │        └─ refused? retry once on the        │
                          │           refusal-fallback model            │
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

  Headers that Phishy retrieves from the reporter's mailbox (the optional [original-message lookup](#original-message-lookup)) are split across two labels rather than given one: *that* Phishy found and read the stored message is `VERIFIED`; *what the headers say* stays `CLAIMED`.
- **Canonicalization** (`src/utils/canonicalize.ts`, pure computation): NFKC, zero-width/bidi stripping, entity decoding, unwrapping of known URL wrappers (SafeLinks, Proofpoint, Google redirects). Raw-vs-canonical divergence is reported as a flag — obfuscation is itself an indicator. Threat intel stores canonical destinations, not gateway wrappers.
- **Adversarial bounding.** Body truncation keeps head+tail (padding can't hide the payload); the link budget fills round-robin across registrable domains; every elision is disclosed to the model.
- **Boundary validation.** External (API Gateway) payloads pass a Zod schema that strips trust-bearing fields — `authVerdicts` and `s3Location` only exist when derived from SES receipts.

## Two kinds of report

A **forward** is a question: the employee gets a report back. An **Outlook Report-button submission** (opt-in, `PHISHY_REPORT_BUTTON_ENABLED`) is not — the employee clicked a button and moved on — so Phishy never replies to the reporter. Phishing reports run the same pipeline and reach only the security team, and only when the verdict warrants it; junk / not-junk reports are counted and skipped.

Button reports are recognized in the parser (`services/email/user.report.ts`) from the wrapper's machine-generated subject, on SES-delivered mail only — the external payload schema strips the marker. The marker is not authentication and grants nothing: recognizing a report only ever reduces what Phishy does, so forging one gains an attacker nothing. The wrapper body (a dump of the reported email's headers) is discarded rather than labeled `REPORTED`; the attached original is parsed like any forward-as-attachment. Notifications go to operator-configured security addresses, never to anything derived from the message.

## Who may tell Phishy what to do

Three principals, three levels of trust:

| Principal | May | Authenticated by |
|---|---|---|
| Any safe-domain employee | report emails for analysis | sender domain ∈ `SAFE_DOMAINS` |
| Security team | correct verdicts by replying to reports (commands) | membership in `SECURITY_TEAM_DISTRIBUTION` **and** SES SPF or DKIM `PASS` on the reply |
| The suspicious email | nothing | it is CLAIMED data, everywhere |

The SES verdicts describe the hop that delivered the reply to Phishy — which is exactly the hop that needs authenticating for commands. They are never presented as authenticating the *suspicious* sender (that email's own Authentication-Results header, when preserved by forward-as-attachment, is surfaced as a CLAIMED/forwarded header instead; so are headers retrieved by the original-message lookup).

## Services

| Service | File | Role |
|---|---|---|
| `EmailParserService` | `services/email/parser.service.ts` | events → labeled email facts (trust boundary) |
| `AnalysisService` | `services/ai/analysis.service.ts` | provider orchestration: agentic → primary → fallback |
| `AgenticAnalyzer` | `services/ai/agentic/agentic.analyzer.ts` | bounded tool loop (max N rounds, falls back on any failure) |
| `AgenticToolExecutor` | `services/ai/agentic/tool.executor.ts` | the four tools; org data and pure computation only, no network |
| `AnthropicProvider` / `BedrockProvider` | `services/ai/*.provider.ts` | Messages API via raw HTTP / InvokeModel; both implement `converse()` for tool use |
| response handling | `services/ai/model.response.ts` | shared by both providers: reads replies by block type, handles refusals (one retry on the refusal-fallback model) and truncation, fail closed |
| model capabilities | `services/ai/model.capabilities.ts` | pure table: which models accept `output_config.effort`, and at which levels |
| `EmailCommandService` | `services/commands/email.command.service.ts` | security-team replies → verdict feedback → completed-action replies |
| `IntelligenceDatabaseService` | `services/intelligence/database.service.ts` | PostgreSQL: analyses, IOCs, campaigns, feedback, usage |
| `CampaignAlertService` | `services/intelligence/campaign.service.ts` | flood detection → employee alerts |
| `SESNotifier` | `services/notification/ses.notifier.ts` | outbound reports and replies |

## When the model does not produce a verdict

The default model (Claude Opus 5.5) always thinks before answering, and its safety classifiers can decline a request. Both change what a reply can look like, so every call path — single-shot analysis, the agentic loop, and command parsing — reads replies through `model.response.ts`:

- **Blocks are selected by type.** A reply starts with `thinking` blocks; the verdict is in the `text` blocks. Nothing indexes `content[0]`.
- **A refusal** (`stop_reason: "refusal"`, an HTTP 200) is retried once, as the same single-shot request, on `ai.refusalFallbackModel` in the same provider. `reasoning_extraction` refusals are not retried. A refusal inside the agentic loop abandons the loop and falls through to the single-shot path, which builds a fresh request from the prompt — the loop's thinking blocks are never replayed to another model.
- **A truncated reply** (`stop_reason: "max_tokens"`) is never parsed. Thinking counts toward `max_tokens`, so the cut can land anywhere, including after a `"verdict"` field.
- **A reply with no recognizable verdict** — not JSON, or JSON with neither a known `verdict` nor a boolean `isPhishing` — is not a ruling.

All of these end the same way: an `analysisFailed` result, which risk fusion routes to the `undetermined` verdict and the report renders as "analysis unavailable". It is never stored, never cached, and never shown as `legitimate`.

The agentic conversation is **append-only**: the system prompt and tool list are fixed for the loop, earlier messages are never edited, and each assistant turn is sent back exactly as received. Thinking blocks are signed against the conversation prefix that produced them, so editing history would invalidate them.

## Data flow decisions worth knowing

- **Campaign signature** (`computeCampaignSignature`) is the shared grouping key: sender domain + subject with numbers normalized out. Flood alerts, the verdict cache, and campaign-wide feedback all use it. One security-team reply resolves a whole campaign.
- **IOC provenance**: indicators carry `metadata.sourceAnalysisId`, which is how verdict feedback adjusts the confidence of exactly the indicators an analysis produced.
- **Verdict cache rows** are stored with `ai_provider='cache'` and never serve as cache sources themselves (unless they carry feedback), so campaigns are re-analyzed when the original analysis ages out.
- **Graceful migration degradation**: the app auto-creates only the 001 baseline schema. Later migrations (002 feedback, 003 campaign signature) are applied manually; every query that needs them catches `42P01`/`42703` and degrades with an instructive log line instead of failing.
- **Cost metrics are EMF**: structured stdout lines CloudWatch converts to metrics. No SDK calls, no IAM, works without the database.

## Microsoft Graph (optional foundation)

`src/services/graph/` lets Phishy call Microsoft Graph on the organization's own Microsoft 365 tenant. It is off by default. The foundation is authentication, credential loading, an HTTP client and a library of read operations; enabling it alone changes nothing. One pipeline feature is built on it, behind its own flag: the [original-message lookup](#original-message-lookup). Further features (checking who else received an email) build on it separately.

| Piece | File | Role |
|---|---|---|
| Authentication | `graph.auth.ts` | app-only client-credentials flow; signs a short-lived JWT assertion with a certificate (no client secret, no MSAL); in-memory token cache, one shared in-flight request |
| Credential loading | `graph.credential.ts` | certificate from Secrets Manager or inline PEM, resolved lazily on the first Graph call; `createGraphReadClient(config.graph)` |
| Request building | `graph.request.ts` | `graphPath` and `odataFilter` tagged templates — the only way data enters a path or a `$filter` |
| HTTP client | `graph.client.ts` | `getJson` / `getBytes` / `getText` / `postJson` / `getPaged` against a fixed base URL |
| Read operations | `mail.operations.ts`, `trace.operations.ts`, `directory.operations.ts` | small typed GET-only functions (find a message by Internet message ID or sender + window, search, headers, MIME, last-verb, message trace, users, licence capabilities); every result is capped and reports truncation; cross-mailbox and trace lookups return metadata only |
| Original-message lookup | `original.fetch.ts` | the pipeline step described [below](#original-message-lookup): reporter-mailbox check, claimed-time parsing, the unique-match rule, time budget |
| Probe CLI | `src/cli/graph-probe*.ts` | `npm run graph:probe` — an operator's local, read-only check of which of those calls work in their tenant ([GRAPH_PROBE.md](GRAPH_PROBE.md)); not part of the pipeline |

Trust rules (CLAUDE.md invariant 6):

- **Code-driven, never model-driven.** Graph is not an agentic tool. Requests go to fixed endpoints chosen by Phishy's code; the model never authors a URL, a filter or a query. Values that originate in a suspicious email (a message ID, a subject) are hostile and enter a request only through `graphPath` (percent-encoded as a single segment), `odataFilter` (escaped string literal) or `kqlSearch` (reduced to plain lower-case words, since mail `$search` has no documented escape).
- **The client cannot be steered off Graph.** The base URL is fixed to `https://graph.microsoft.com/v1.0` and callers cannot pass a URL. `@odata.nextLink` is followed only on that origin and API version; redirects are refused; paging is capped by the caller and reports truncation; response sizes and time are bounded; throttling (`Retry-After`) is honoured within a bounded wait and attempt count.
- **Mailbox content is hostile data.** Response bodies are never logged. Content read from any mailbox other than the reporter's own is metadata-only toward the model and logs.
- **Reads and writes are separate identities.** A client holds exactly one credential. Configuration has a `read` app registration today; a `write` registration, when one exists, is a different app with its own certificate and its own client, so a read path can never obtain a write token. Any write to the tenant additionally requires security-team approval through the authenticated command channel.
- **Secrets stay secret.** The private key, client assertion and access token never appear in logs or error messages; errors carry only status, Graph error code, request id and a path template with data segments blanked.

### Original-message lookup

A forward destroys the original's headers. Phishy sees only what the mail client pasted into the forwarded block (a claimed From, Sent and Subject) — not `Authentication-Results`, the `Received` chain, `Return-Path`, `Reply-To` or the real `Message-ID`. With `graph.originalFetch.enabled` (and `graph.enabled`), Phishy looks for the original in the reporter's own mailbox before analysis and reads its real headers. It runs only when an analysis is about to run (not on a campaign-cache hit, not for safelist senders), is entirely code-driven, and issues GET requests only.

**Whose mailbox.** Only the reporter's, and only when the report demonstrably came from them (`confirmedReporterMailbox`): `originalForwarder` must be an address on a safe domain, must equal the address in the report's own `From` header — so the weaker sources `originalForwarder` can fall back to (`X-Forwarded-For`, the To line) never select a mailbox — and the report must carry an SES SPF or DKIM `PASS`, the same bar as the command channel. Payloads without SES verdicts (API Gateway) therefore never cause a mailbox read. No address taken from email content is ever used as a mailbox.

**Which message.** The claimed sender address, sent time and subject from the forwarded block — all hostile strings, which enter the request only as escaped `odataFilter` literals:

```
receivedDateTime ge {from} and receivedDateTime lt {to}
  and from/emailAddress/address eq '{claimed sender}' [and subject eq '{claimed subject}']
```

Mail clients print the sent time in the reporter's local time with no UTC offset, so the window is the claimed wall-clock time widened to cover every offset (UTC−12 to UTC+14) plus three hours of delivery slack either side; when the text does carry an offset (forward-as-attachment), it is just the slack. Dates must spell the month in English or be ISO 8601 — an all-numeric date is ambiguous between day-first and month-first and is not guessed at. The same filter is sent twice, in parallel: to `/users/{reporter}/messages` (every ordinary folder, Junk Email and Deleted Items included) and to `/mailFolders/recoverableitemsdeletions/messages` (Recoverable Items, where the message is if the reporter deleted it for good after forwarding).

**The matching rule.** Enrich only on **exactly one** message across both locations. Each query asks for at most two results; more than one distinct message in total, or a result Graph says continues, is *ambiguous*; none is *not found*. The single candidate is then re-checked in code (sender equal ignoring case, received time inside the window, subject equal ignoring case and whitespace) rather than trusting the filter to have been honoured. Phishy never picks "the most likely" of several: a wide window can only produce more ambiguous outcomes, never a wrong match. If either query fails, the whole lookup fails — uniqueness cannot be claimed without seeing both locations.

**How the result is labelled.** Two different things are true of retrieved headers, and the prompt keeps them apart:

| What | Label | Why |
|---|---|---|
| A lookup happened, found exactly one message, where (mailbox or Recoverable Items), when the mailbox received it, how many headers the stored copy has | `VERIFIED` | Phishy did or computed these itself, or the mailbox system stamped them (the timestamp is re-serialized before use) |
| Every header name and value | `CLAIMED`, in its own nonce fence (`original-headers-{nonce}`) | They were written by the sender and by each server the message crossed. Retrieval proves they are the delivered message's headers and not the forwarder's paste; it does not prove who wrote them |

Labelling the headers `VERIFIED` wholesale would be wrong: a sender can pre-insert a look-alike `Authentication-Results` or `Received` line. The only headers that can be trusted are those the organization's own mail system stamped on delivery, and position is the evidence for that — servers add trace headers at the top. So headers are shown in stored order with their position, and the prompt tells the model that the lowest-numbered `Received` / `Authentication-Results` entries are normally the receiving system's, that anything further down can be forged, and that an authentication *pass* is never by itself evidence of legitimacy. Phishy does not itself decide which headers are trustworthy.

**Bounding** (`services/ai/retrieved.headers.ts`). A header block can be padded like a body can. Only a fixed list of security-relevant names is shown; each name has its own quota that keeps the first and last occurrences (so 300 fake `Received` lines cannot displace the real top or the origin); each value keeps its head and tail; an overall budget is spent in priority order (authentication results, then identity headers, then the route). Every cut is counted and disclosed under ELISIONS. Each header is reduced to one line before it reaches the prompt.

**Failure.** Nothing in the lookup throws. No usable claimed sender or time, an unconfirmed reporter, no match, several matches, any Graph or authentication error, an empty header list, or exceeding the 8-second overall budget all leave the email facts — and so the prompt — exactly as they are without the feature. The Graph client used here has short per-attempt timeouts and at most one retry so three requests fit that budget. Each lookup emits one EMF line: `OriginalFetchCount` dimensioned by `Outcome` (`found`, `not_found`, `ambiguous`, `error`, `skipped`) and `OriginalFetchDurationMs`. Logs carry the outcome, a fixed reason word, counts and Graph's status/code/request id — never an address, subject or header value.

## Feature flags

Everything optional is off by default and independently enableable:

| Flag | Feature | Requires |
|---|---|---|
| `PHISHY_INTELLIGENCE_ENABLED` | threat-intel DB | PostgreSQL |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | flood alerts | intelligence DB |
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | verdict reuse | intelligence DB + migration 003 |
| `PHISHY_EMAIL_COMMANDS_ENABLED` | security-team replies | intelligence DB + migration 002 |
| `PHISHY_AGENTIC_ENABLED` | tool-loop analysis + AI command parsing | nothing (tools appear as their backends do) |
| `PHISHY_GRAPH_ENABLED` | Microsoft Graph access (foundation — changes nothing on its own) | Entra app registration with a certificate; outbound HTTPS to Microsoft |
| `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` | read the original message's real headers from the reporter's mailbox | `PHISHY_GRAPH_ENABLED`; `Mail.Read` on reporters' mailboxes |
| `PHISHY_REPORT_BUTTON_ENABLED` | silent handling of Outlook Report-button submissions | Microsoft 365 user-reported settings delivering to Phishy |

See [CONFIGURATION.md](CONFIGURATION.md) for the full reference.

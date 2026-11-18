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

`src/services/graph/` lets Phishy call Microsoft Graph on the organization's own Microsoft 365 tenant. It is off by default. The foundation is authentication, credential loading, an HTTP client and a library of read operations; enabling it alone changes nothing. Three pipeline features are built on it, each behind its own flag: the [original-message lookup](#original-message-lookup) and the [sender-relationship check](#sender-relationship-check) (both before analysis), and [blast radius](#blast-radius-optional) (after a malicious verdict).

| Piece | File | Role |
|---|---|---|
| Authentication | `graph.auth.ts` | app-only client-credentials flow; signs a short-lived JWT assertion with a certificate (no client secret, no MSAL); in-memory token cache, one shared in-flight request |
| Credential loading | `graph.credential.ts` | certificate from Secrets Manager or inline PEM, resolved lazily on the first Graph call; `createGraphReadClient(config.graph)` |
| Request building | `graph.request.ts` | `graphPath` and `odataFilter` tagged templates — the only way data enters a path or a `$filter` |
| HTTP client | `graph.client.ts` | `getJson` / `getBytes` / `getText` / `postJson` / `getPaged` against a fixed base URL |
| Read operations | `mail.operations.ts`, `trace.operations.ts`, `directory.operations.ts` | small typed GET-only functions (find a message by Internet message ID or sender + window, search, headers, MIME, last-verb, message trace, users, licence capabilities); every result is capped and reports truncation; cross-mailbox and trace lookups return metadata only |
| Original-message lookup | `original.fetch.ts` | the pipeline step described [below](#original-message-lookup): reporter-mailbox check, claimed-time parsing, the unique-match rule, time budget |
| Blast radius | `blast-radius.service.ts` | the post-verdict step described [below](#blast-radius-optional): message trace, per-mailbox fallback, time budget, coverage |
| Sender-relationship check | `sender.history.ts` | before analysis, message-trace counts about the claimed external sender (see below) |
| Probe CLI | `src/cli/graph-probe*.ts` | `npm run graph:probe` — an operator's local, read-only check of which of those calls work in their tenant ([GRAPH_PROBE.md](GRAPH_PROBE.md)); not part of the pipeline |

Trust rules (CLAUDE.md invariant 6):

- **Code-driven, never model-driven.** Graph is not an agentic tool. Requests go to fixed endpoints chosen by Phishy's code; the model never authors a URL, a filter or a query. Values that originate in a suspicious email (a message ID, a subject) are hostile and enter a request only through `graphPath` (percent-encoded as a single segment), `odataFilter` (escaped string literal) or `kqlSearch` (reduced to plain lower-case words, since mail `$search` has no documented escape).
- **The client cannot be steered off Graph.** The base URL is fixed to `https://graph.microsoft.com/v1.0` and callers cannot pass a URL. `@odata.nextLink` is followed only on that origin and API version; redirects are refused; paging is capped by the caller and reports truncation; response sizes and time are bounded; throttling (`Retry-After`) is honoured within a bounded wait and attempt count.
- **Mailbox content is hostile data.** Response bodies are never logged. Content read from any mailbox other than the reporter's own is metadata-only toward the model and logs.
- **Reads and writes are separate identities.** A client holds exactly one credential. Configuration has a `read` app registration today; a `write` registration, when one exists, is a different app with its own certificate and its own client, so a read path can never obtain a write token. Any write to the tenant additionally requires security-team approval through the authenticated command channel.
- **Secrets stay secret.** The private key, client assertion and access token never appear in logs or error messages; errors carry only status, Graph error code, request id and a path template with data segments blanked.

### Blast radius (optional)

`blast-radius.service.ts` answers the security team's next question after a malicious verdict: who else received this, and did anyone open or answer it? Off by default (`graph.blastRadius.enabled`, effective only with `graph.enabled`).

- **Where it runs.** In `lambda.handler.ts` (`sendReports`), after the fused verdict, after the analysis has been stored and after the reporter's copy of the report has been sent, only when that verdict is malicious (`riskDecision.isPhishing`), the analysis did not fail, the reporter is not a safelist user and there is a security team to tell. Its result is passed to the report template and nowhere else: not to the model, not to the database, not to the logs (which get counts only).
- **Identifying the message.** By the original's Internet Message-ID when the parsed email carries one (`forwardedHeaders['Original-Message-ID']`); otherwise by the claimed sender address, the quoted subject and a time window (24 hours either side of the claimed date, or the last 7 days when the forward has no usable date). All of these are hostile strings and reach Graph only through `odataFilter`.
- **Route 1: message trace.** Recipients and delivery status without reading a mailbox. Each trace row also names the Message-ID that recipient received, so however the trace was keyed, each recipient's mailbox is then read by `internetMessageId eq` (an exact, cheap lookup; at most 3 distinct IDs per mailbox, disclosed when capped) for the folder, read flag and last verb. Rows with status *expanded* (a distribution list, whose members have their own rows) are left out; *failed* rows are listed as not delivered and their mailboxes are not read.
- **Route 2: per-mailbox search.** When trace fails (commonly HTTP 403: the tenant lacks Microsoft's message-trace service principal, or it is still propagating) or returns no rows, Phishy lists users, keeps licensed, enabled, non-guest accounts up to the mailbox cap, and searches each: by Message-ID when the key has one, otherwise by sender + window (+ subject). The sender search is a filtered, ordered scan and is much slower per mailbox than a Message-ID lookup; it is used only here, where no Message-ID is known. `/messages` does not cover Recoverable Items, so mailboxes without a match are searched there too, time permitting.
- **Detail is read with the match.** Folder and last verb are read as soon as a mailbox matches, not in a later pass, so a lookup that runs out of time has full detail for every mailbox it reached. Detail that could not be read (a failed request, or the budget ending mid-read) is counted, makes the result partial and is stated in the section.
- **Bounds.** A hard time budget (default 45 s, shrunk to leave 20 s of Lambda time for sending), a mailbox cap (default 2000), 12 mailboxes at a time with one search per mailbox at a time, and a client limited to two attempts and 5 s per request. `Retry-After` is honoured within a bound; a throttled request that cannot be retried stops the lookup. When the budget ends, what was established so far is reported.
- **Honest coverage.** The section always says "checked N of M mailboxes" and is marked partial when anything was left uncovered: cap, budget, throttling, failed requests, a truncated trace or directory listing, or Recoverable Items not searched everywhere. "Replied" and "forwarded" are reported only for the last-verb values the MAPI definition gives (102/103 and 104); any other value is shown as unknown with its code.
- **Delivery.** `sendReports` sends the reporter the usual report first (no Cc, no section), then runs the lookup, then sends the security team its own copy with the section — always, with a one-line note in place of the section when the lookup failed or ran out of time. A reporter who is on the security team gets only that copy. The security copy's message ID is the one stored for command replies; command recognition itself depends only on the sender, the subject, the quoted reference and reply headers, none of which needed the Cc. If the security copy cannot be sent, an error is logged and `SecurityCopySendFailures` is emitted; nothing is re-sent to the reporter. When the feature is off or the verdict is not malicious, the single combined email goes out exactly as before.
- **Report-button submissions.** A malicious Outlook Report-button report is handled silently: the reporter is never emailed, and the security team gets one email. With blast radius on, the lookup runs before that single email (same budget rules) and the email carries the section, or the one-line note when the lookup produced nothing. There is no second email on that path.
- **Read-only.** GET requests through the operations library only; no message is moved, deleted or changed.

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

### Sender-relationship check

Off by default (`graph.senderHistory.enabled`). It targets one case the rest of the pipeline cannot see: a known external contact's mailbox is taken over, so the mail authenticates and the sender is familiar, but it suddenly reaches far more people than that sender ever wrote to.

```
processEmailEvent
  campaign cache miss
    └─ SenderHistoryService.lookupForEmail(emailData)        code only, GET only
         claimed From → validated address → external?        (else: skipped)
         per-instance cache (sha256 of the address, 5 min)
         message trace, 10-day windows × {from address, to address}; every row checked against the address
           in parallel, page-capped, one deadline (default 8 s)
         computeSenderHistoryFacts → counts + classification
    └─ emailData.senderHistory ──▶ prompt (VERIFIED block) ──▶ fuseRisk ──▶ report (by audience)
```

- **A relationship never lowers risk.** Trust is what the attacker borrows. The prompt block says so; `fuseRisk` reads only `established_with_anomalous_fanout`, and only to add a reason and raise the score to a floor (after the allowlist cap, so the cap cannot undo it). No classification can reduce a score or turn a verdict benign, and a test asserts that across every verdict and class. The reporter is never told a sender is "known".
- **Provenance.** The counts are Phishy's own computation from the organization's records, so they are a VERIFIED block. They are *about* the address the email claims, which is hostile text: that address is not repeated in the block and stays in the CLAIMED section. The block holds numbers, dates and an enum — no recipient address, no IP (the IPs kept for the security team's copy are not rendered into it).
- **Hostile input.** The claimed address must be a single plain-ASCII address before anything is queried, enters the filter only through `odataFilter`, and is never logged. The email's claimed date only widens the burst window, by a bounded amount.
- **A narrow anomaly rule.** `established_with_anomalous_fanout` needs two-way contact and one *subject* reaching many people (15 by default), far beyond the sender's usual reach, most of them new to it. Measuring per subject and requiring two-way contact keeps single team-wide emails, bulk senders nobody replies to and transactional systems out; the cost is that a small takeover is not flagged by this rule and rests on content analysis. The subject is a grouping key in memory only.
- **Rows are verified, not assumed.** Message trace can accept an address predicate and silently not apply it (it does so for `endswith` and `contains`), returning unrelated mail flow with HTTP 200. Only `eq` is used, and the trace operations reject any result in which a row names a different address (`filter_not_applied`); the check additionally rejects rows with no address. A mismatch discards the lookup, so counts about the wrong mail never become facts. There is no domain-level history for this reason.
- **Bounded and disclosed.** Fixed windows, a row and page cap per window, a concurrency cap, a per-instance request allowance and one deadline. A count cut short by a cap is "at least N" everywhere it appears, and fan-out is not judged against a truncated history.
- **Fails open to today's behaviour.** Timeout, 403 or any failed window yields no facts (never partial counts), a metric, and an unchanged analysis. Message trace answers 403 intermittently while its service principal propagates, so a 403 is retried per request (bounded, inside the deadline and allowance); the lookup is `forbidden`, with a pause, only when nothing in it succeeded.
- **Who it runs for.** Forwards and Outlook Report-button phishing submissions alike (both fill the same forwarded-header fields), on a campaign-cache miss, never for safelist users.
- **What each copy of the report shows.** The detail follows who reads the email (`ReportOptions.audience`). The *reporter's own copy* (sent first when blast radius splits a malicious report in two) shows none of it — at most the one plain sentence on anomalous fan-out, and never that a sender is "known". The *combined email* (reporter with the security team in Cc) puts counts and the classification in the "Original Email for IT Review" part, with no IPs, because the reporter reads it too. An email *addressed to the security team alone* — the separate security copy of a malicious report, or the single email about a silent Report-button report — carries the same block plus the burst's sending IPs, each marked as seen or not seen in the history period (capped at 20, "and N more", shape-checked and escaped). The IPs travel in the facts for that copy only: they are never in the prompt block or an info-level log. No copy shows a recipient address. Nothing is persisted.

Thresholds and request counts are in [CONFIGURATION.md](CONFIGURATION.md#sender-relationship-check-optional).

## Feature flags

Everything optional is off by default and independently enableable:

| Flag | Feature | Requires |
|---|---|---|
| `PHISHY_INTELLIGENCE_ENABLED` | threat-intel DB | PostgreSQL |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | flood alerts | intelligence DB |
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | verdict reuse | intelligence DB + migration 003 |
| `PHISHY_EMAIL_COMMANDS_ENABLED` | security-team replies | intelligence DB + migration 002 |
| `PHISHY_AGENTIC_ENABLED` | tool-loop analysis + AI command parsing | nothing (tools appear as their backends do) |
| `PHISHY_GRAPH_ENABLED` | Microsoft Graph access (foundation — changes nothing on its own; the three features below have their own flags) | Entra app registration with a certificate; outbound HTTPS to Microsoft |
| `PHISHY_GRAPH_ORIGINAL_FETCH_ENABLED` | read the original message's real headers from the reporter's mailbox | `PHISHY_GRAPH_ENABLED`; `Mail.Read` on reporters' mailboxes |
| `PHISHY_GRAPH_BLAST_RADIUS_ENABLED` | who else received a malicious email (security-team copy only) | `PHISHY_GRAPH_ENABLED` + read permissions listed in [CONFIGURATION.md](CONFIGURATION.md#blast-radius-optional) |
| `PHISHY_GRAPH_SENDER_HISTORY_ENABLED` | sender-relationship check: message-trace counts about the claimed sender, before analysis | `PHISHY_GRAPH_ENABLED`; `ExchangeMessageTrace.Read.All` |
| `PHISHY_REPORT_BUTTON_ENABLED` | silent handling of Outlook Report-button submissions | Microsoft 365 user-reported settings delivering to Phishy |

See [CONFIGURATION.md](CONFIGURATION.md) for the full reference.

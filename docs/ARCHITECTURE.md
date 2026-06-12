# Architecture

Phishy is an AWS Lambda that receives employee-forwarded emails via SES, analyzes them with Claude, and replies with a security report. Everything else — threat intelligence, campaign detection, the email command channel, agentic analysis — layers on top of that loop and is individually optional.

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

## Feature flags

Everything optional is off by default and independently enableable:

| Flag | Feature | Requires |
|---|---|---|
| `PHISHY_INTELLIGENCE_ENABLED` | threat-intel DB | PostgreSQL |
| `PHISHY_CAMPAIGN_ALERTS_ENABLED` | flood alerts | intelligence DB |
| `PHISHY_CAMPAIGN_CACHE_ENABLED` | verdict reuse | intelligence DB + migration 003 |
| `PHISHY_EMAIL_COMMANDS_ENABLED` | security-team replies | intelligence DB + migration 002 |
| `PHISHY_AGENTIC_ENABLED` | tool-loop analysis + AI command parsing | nothing (tools appear as their backends do) |

See [CONFIGURATION.md](CONFIGURATION.md) for the full reference.

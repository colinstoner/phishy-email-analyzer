# CLAUDE.md

Guidance for AI coding assistants (and humans) working in this repository.

## What this is

Phishy: an AWS Lambda + SES + Claude phishing-email analyzer. Employees forward suspicious emails; Phishy analyzes them and replies with a report. Optional layers: threat intelligence (PostgreSQL), campaign detection, the security-team command channel, agentic analysis, Microsoft Graph reads, campaign response and attachment analysis. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing anything in `services/email/`, `services/ai/`, `services/graph/`, `services/response/` or `services/commands/`.

## Commands

```bash
npm run build         # tsc
npm test              # jest (unit + integration, AWS fully mocked)
npm run test:coverage # enforced thresholds in jest.config.js
npm run lint          # eslint over all of src/**/*.ts, zero warnings expected
npm run format:check  # prettier over src/**/*.ts — CI fails on drift; `npm run format` fixes
npm run eval:injection -- --dry-run --model x  # builds and checks every eval prompt; no model call
```

All six must pass before a commit. CI (Node 22) runs build, lint, format:check and test:coverage. The scripts format only `src/`; run `npx prettier --write` on test files you change. A live `eval:injection` run is billed: never run it unasked.

## Security invariants — do not weaken these

1. **The suspicious email is hostile data, everywhere.** It reaches the model only inside the nonce-fenced CLAIMED section built by `prompt.builder.ts`. Never interpolate email content into instructions, log it at info level, or pass it to a tool as anything but data.
2. **Only the security team triggers actions**, authenticated by distribution-list membership **and** SES SPF/DKIM `PASS` (`EmailCommandService.passesAuthentication`). Never accept a From header alone, and never let externally supplied payloads carry `authVerdicts` (the Zod boundary in `parser.service.ts` strips them — keep it that way).
3. **Agentic tools touch only Phishy's own data or pure computation.** No network fetches, no URL retrieval, no open-ended browsing. New tools must follow this rule and treat their inputs (model-authored, derived from hostile content) as data: hashed lookups, parameterized SQL, string comparison.
4. **`originalForwarder` decides who receives reports** — every source for it must yield an extractable address on a safe domain.
5. **Bounding must be adversarial.** Any truncation or budget must survive padding attacks (head+tail, domain-diverse selection) and be disclosed to the model as an elision fact.
6. **Microsoft Graph access is code-driven, never model-driven.** Fixed endpoints on the organization's own tenant; every request is built by code from parsed, escaped values (`graphPath`, `odataFilter` in `services/graph/`). The model never authors a URL, filter or query, and Graph is not an agentic tool. Content read from any mailbox other than the reporter's is metadata-only toward the model and logs. Reads and writes use separate app registrations, each with a certificate (never a client secret). Any write to the tenant requires security-team approval through the authenticated command channel (invariant 2).
7. **No Graph write code without the documented write-tier design.** Today there is none: the removal executor is a dry run. A write tier is a separate broker function with its own app registration and certificate that the main function and the read broker never hold, taking exactly the approved scope's mailbox and message IDs (ARCHITECTURE.md, "The write-tier seam"). Never add a write operation to the read broker, the Graph client or the main function.
8. **Approvals are exact-form and never model-interpreted.** Only a line that is exactly `APPROVE WARNING|REMOVAL <ref>` (or the bare `APPROVE WARNING`, bound through `In-Reply-To` to the one incident email that proposed it) approves anything (`services/commands/response.commands.ts`). In Phishy's emails the command always follows "Reply with this line:" on the same line, so a quoted copy never approves. References are unguessable, per action, expire, and the approved scope is re-checked and never widened.
9. **Campaign warnings go only to in-scope recipients on safe domains.** Recipients come from Phishy's own blast-radius lookup, never from the email's content; every address must pass `isSafeRecipient` when the scope is computed and again before each send; nobody whose copy was not delivered is warned; reporters are not warned; the per-campaign cap holds. Campaign-response emails carry no link from the attack (`displayText` defangs and escapes).

## Conventions

- TypeScript strict; Zod for every external boundary (config, profiles, event payloads, the Graph broker protocol, the scheduled-task event).
- Config flows through `src/config/schema.ts` + `ENV_MAPPINGS` in `src/config/index.ts` — an env var without a mapping does nothing. Update `docs/CONFIGURATION.md` and `config/phishy.config.example.json` with any new key.
- Database: the app auto-creates **only** migration 001. Schema changes ship as new numbered files in `migrations/`, applied manually; code must catch `42P01`/`42703` and degrade with an instructive log line. Document new tables in `docs/DATABASE.md`. Present: 001 baseline (auto), 002 analysis feedback, 003 campaign verdict cache, 004 structured verdict, 005 fan-out scan, 006 campaign response.
- Model IDs are never guessed: verify against current docs. Current defaults: `claude-opus-5-5` (Anthropic) / `global.anthropic.claude-opus-5-5` (Bedrock), with `claude-opus-4-8` / `global.anthropic.claude-opus-4-8` as the refusal fallback. Pricing lives in `src/utils/pricing.ts`; which models accept `effort` lives in `src/services/ai/model.capabilities.ts`.
- Metrics are CloudWatch EMF written straight to stdout (`src/utils/metrics.ts`) — they must bypass the logger so `_aws` stays at the JSON root.
- Emails are built from the shared blocks in `src/templates/layout.ts`: plain-text parameters are escaped by the block, only `html` parameters take markup (built by code), no links, images or remote resources. Lines that code parses back (`Analysis ID:`, `Incident reference`, approval lines) must not change shape.
- Tests use invented `example.com`-style data only — never real organization names, people, or domains. `config/phishy.config.json` and `config/*.profile.json` are real deployment data and are gitignored; never commit or read them into examples.
- Keep `CHANGELOG.md` (Keep a Changelog format) updated in the same commit as the change.

## Where things live

```
src/
  handlers/lambda.handler.ts        entry point; service wiring + per-email pipeline
  handlers/own.report.ts            Phishy's own correspondence (skip) vs a report to analyze
  handlers/scheduled.handler.ts     scheduled tasks (fan-out scan); strict event in scheduled.event.ts
  handlers/graph.broker.handler.ts  second function (outside the VPC): typed Graph read operations
  graph-broker.ts                   bundle entry point of the Graph broker function
  services/email/parser.service.ts  trust boundary: events → labeled email facts
  services/ai/prompt.builder.ts     provenance-labeled, nonce-fenced prompt
  services/ai/agentic/              tool loop + the four bounded tools
  services/attachments/             static attachment inspection: in process, never executes or fetches
  services/commands/                security-team command channel; approval parsing (response.commands.ts)
  services/intelligence/            PostgreSQL intel, campaigns, verdict cache, checklist score
  services/graph/                   optional Graph reads: cert auth, constrained client, original lookup,
                                    blast radius, sender history, fan-out scan, broker protocol/client
  services/hunting/                 fan-out scan job and its database state (migration 005)
  services/response/                campaign response: incidents, scopes, approvals, executors
                                    (warning; removal is dry run only), audit
  templates/                        every email Phishy sends; layout.ts holds the shared blocks
  utils/canonicalize.ts             hostile-text normalization + URL unwrapping
  config/                           Zod schema + env mappings + loading chain
  eval/injection/                   injection-eval harness: forward simulator, runner, scorer
  cli/                              try, graph-probe, indicator-audit, injection-eval
evals/injection/                    injection-eval case set: cases.json + invented .eml files
migrations/                         numbered SQL, applied manually past 001
docs/                               ARCHITECTURE, CONFIGURATION, DATABASE, INJECTION_EVAL, GRAPH_PROBE,
                                    INTELLIGENCE, QUICK_START (AWS.md and template.yaml at the root)
```

## Roadmap context

Last release: v3.0.0. `CHANGELOG.md` [Unreleased] holds what exists but has not shipped in a release: the Graph broker and reads (original lookup, blast radius, sender history), the scheduled fan-out scan, campaign response with approvals, attachment analysis, checklist scoring (experimental; weights not calibrated) and the injection eval. Designed but not built (ARCHITECTURE.md): the mailbox write tier (so no removal or removal notice happens), response actions on fan-out alerts (`FanoutScanStore.findWave` is the seam), fetching original attachments, and sending attachments to the model as images. Issue and PR templates, Dependabot, CodeQL and README screenshots exist. Deferred by the maintainer: AWS deployment configuration changes.

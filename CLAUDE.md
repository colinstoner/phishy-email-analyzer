# CLAUDE.md

Guidance for AI coding assistants (and humans) working in this repository.

## What this is

Phishy: an AWS Lambda + SES + Claude phishing-email analyzer. Employees forward suspicious emails; Phishy analyzes them and replies with a report. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing anything in `services/email/` or `services/ai/`.

## Commands

```bash
npm run build         # tsc
npm test              # jest (unit + integration, AWS fully mocked)
npm run test:coverage # enforced thresholds in jest.config.js
npm run lint          # eslint, zero warnings expected
npm run format:check  # prettier — CI fails on drift; run `npm run format` to fix
```

All five must pass before a commit. CI runs them on Node 18/20/22.

## Security invariants — do not weaken these

1. **The suspicious email is hostile data, everywhere.** It reaches the model only inside the nonce-fenced CLAIMED section built by `prompt.builder.ts`. Never interpolate email content into instructions, log it at info level, or pass it to a tool as anything but data.
2. **Only the security team triggers actions**, authenticated by distribution-list membership **and** SES SPF/DKIM `PASS` (`EmailCommandService.passesAuthentication`). Never accept a From header alone, and never let externally supplied payloads carry `authVerdicts` (the Zod boundary in `parser.service.ts` strips them — keep it that way).
3. **Agentic tools touch only Phishy's own data or pure computation.** No network fetches, no URL retrieval, no open-ended browsing. New tools must follow this rule and treat their inputs (model-authored, derived from hostile content) as data: hashed lookups, parameterized SQL, string comparison.
4. **`originalForwarder` decides who receives reports** — every source for it must yield an extractable address on a safe domain.
5. **Bounding must be adversarial.** Any truncation or budget must survive padding attacks (head+tail, domain-diverse selection) and be disclosed to the model as an elision fact.

## Conventions

- TypeScript strict; Zod for every external boundary (config, profiles, event payloads).
- Config flows through `src/config/schema.ts` + `ENV_MAPPINGS` in `src/config/index.ts` — an env var without a mapping does nothing. Update `docs/CONFIGURATION.md` and `config/phishy.config.example.json` with any new key.
- Database: the app auto-creates **only** migration 001. Schema changes ship as new numbered files in `migrations/`, applied manually; code must catch `42P01`/`42703` and degrade with an instructive log line. Document new tables in `docs/DATABASE.md`.
- Model IDs are never guessed: verify against current docs. Current defaults: `claude-opus-4-8` (Anthropic) / `anthropic.claude-opus-4-8` (Bedrock). Pricing lives in `src/utils/pricing.ts`.
- Metrics are CloudWatch EMF written straight to stdout (`src/utils/metrics.ts`) — they must bypass the logger so `_aws` stays at the JSON root.
- Tests use invented `example.com`-style data only — never real organization names, people, or domains. `config/phishy.config.json` and `config/*.profile.json` are real deployment data and are gitignored; never commit or read them into examples.
- Keep `CHANGELOG.md` (Keep a Changelog format) updated in the same commit as the change.

## Where things live

```
src/
  handlers/lambda.handler.ts        entry point; service wiring + per-email pipeline
  services/email/parser.service.ts  trust boundary: events → labeled email facts
  services/ai/prompt.builder.ts     provenance-labeled, nonce-fenced prompt
  services/ai/agentic/              tool loop + the four bounded tools
  services/commands/                security-team email command channel
  services/intelligence/            PostgreSQL intel, campaigns, verdict cache
  utils/canonicalize.ts             hostile-text normalization + URL unwrapping
  config/                           Zod schema + env mappings + loading chain
migrations/                         numbered SQL, applied manually past 001
docs/                               ARCHITECTURE, CONFIGURATION, DATABASE, AWS
```

## Roadmap context

Held intentionally: Phase 3 community work (issue templates, releases, Dependabot/CodeQL, README screenshots). Deferred by the maintainer: AWS deployment configuration changes. Check `CHANGELOG.md` [Unreleased] for what exists but hasn't shipped in a release yet.

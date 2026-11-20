## What & why

<!-- What does this change, and what problem does it solve? -->

## Checklist

- [ ] `npm run build && npm run lint && npm run format:check && npm test` all pass, and `npm run eval:injection -- --dry-run --model x` if prompts, parsing or eval cases changed
- [ ] Tests use invented `example.com`-style data only — no real organizations, people, or domains
- [ ] No real phishing content, credentials, or internal configuration in the diff
- [ ] Security invariants 1–9 in [CLAUDE.md](../blob/main/CLAUDE.md) respected (hostile-data handling, command authorization, no network access from agentic tools, code-driven read-only Graph, exact-form approvals, safe-domain recipients)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] New config keys added to `ENV_MAPPINGS` and documented in `docs/CONFIGURATION.md` + `config/phishy.config.example.json`
- [ ] Schema changes ship as a new numbered migration with graceful degradation (see `docs/DATABASE.md`)

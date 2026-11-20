# Contributing to Phishy

Thanks for your interest in improving Phishy! Contributions of all kinds are welcome — bug reports, documentation fixes, new features, and test coverage.

## Development Setup

Prerequisites:

- Node.js 22 (the Lambda runtime; `.nvmrc` pins it and `package.json` requires it)
- npm

```bash
git clone https://github.com/colinstoner/phishy-email-analyzer.git
cd phishy-email-analyzer
npm install
npm run build
npm test
```

You do **not** need an AWS account or an Anthropic API key to build the project or run the test suite — all AWS and AI calls are mocked in tests.

## Project Layout

```
src/
  handlers/       Lambda entry points: unified router, SES pipeline, scheduled tasks,
                  the Graph broker function, the API handler, own-report recognition
  services/
    ai/           Claude providers (Anthropic API, AWS Bedrock), prompt builder, agentic tool loop
    attachments/  Static attachment inspection (in process; never executes or fetches)
    commands/     Security-team command channel and approval parsing
    email/        MIME/email parsing: the trust boundary
    graph/        Optional Microsoft Graph reads and the broker client
    hunting/      Scheduled fan-out scan job and state
    intelligence/ Optional threat-intel layer (IOCs, campaigns, verdict cache, risk fusion, PostgreSQL)
    notification/ SES delivery
    response/     Campaign response: incidents, scopes, approvals, executors
    storage/      S3 raw-email retrieval
  config/         Zod-validated configuration loading (env → S3 file → defaults)
  models/         Enterprise profile model
  templates/      Every email Phishy sends, on the shared blocks in layout.ts
  utils/          Logging, metrics, canonicalization, validation
  eval/, cli/     Injection-eval harness; try, graph-probe, indicators:audit and eval CLIs
evals/injection/  Injection-eval case set (invented emails only)
migrations/       Numbered SQL; only 001 is applied automatically
tests/
  unit/           Unit tests
  integration/    Handler-level tests with mocked AWS clients
  mocks/          Shared fakes (Graph tenant, fan-out database)
```

Read [CLAUDE.md](CLAUDE.md) (the security invariants) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing parsing, prompts, Graph access, campaign response or the command channel.

## Local Configuration

`config/phishy.config.json` and `config/*.profile.json` are **intentionally gitignored** — they hold deployment-specific settings (and in real deployments, organization data). Copy the examples to get started:

```bash
cp config/phishy.config.example.json config/phishy.config.json
cp config/profile.example.json config/my-org.profile.json
```

Never commit real configuration, profiles, email addresses, or credentials. PRs containing them will be closed and the data treated as compromised.

## Before Submitting a PR

Run the same checks CI runs:

```bash
npm run build          # TypeScript compile
npm run lint           # ESLint over src/
npm run format:check   # Prettier over src/
npm test               # Jest (CI runs npm run test:coverage, with enforced thresholds)
npm run eval:injection -- --dry-run --model x   # builds and checks every eval prompt; no model call
```

The format scripts cover `src/` only; run `npx prettier --write` on test files you change. A live `eval:injection` run calls a model and is billed: never needed for a PR.

A few guidelines:

- **Add tests** for new behavior. Handler changes belong in `tests/integration/`, everything else in `tests/unit/`.
- **Keep AWS optional in tests.** Use the mocks in `tests/integration/mocks/` and `tests/mocks/` rather than hitting real services.
- **Follow the provider pattern.** New AI backends implement `AIProvider` (`src/services/ai/provider.interface.ts`); don't special-case providers in handlers.
- **No real-world data in fixtures.** Test emails must use invented domains (`example.com`, `example.org`, `*.example`, `*.test`) and people.
- **New config keys** go in `src/config/schema.ts`, `ENV_MAPPINGS` in `src/config/index.ts`, `docs/CONFIGURATION.md` and `config/phishy.config.example.json`.
- **Schema changes** ship as a new numbered file in `migrations/`, with code that degrades when it is missing ([docs/DATABASE.md](docs/DATABASE.md)).
- **Update `CHANGELOG.md`** under `[Unreleased]` in the same PR.
- **Match existing style.** Prettier and ESLint configs are authoritative; don't hand-format.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests.
3. Update documentation (`README.md`, `docs/`) if behavior or configuration changed.
4. Open a PR describing **what** changed and **why**. Link any related issue.
5. CI must pass before review.

Small, focused PRs get reviewed faster than large ones. If you're planning a big change, open an issue first to discuss the approach.

## Reporting Bugs

Open a [GitHub issue](https://github.com/colinstoner/phishy-email-analyzer/issues) with:

- What you did, what you expected, what happened
- Relevant log output (with any email addresses, domains, or org details redacted)
- Your deployment style (Anthropic API vs. Bedrock, which optional layers are on)

**Do not open public issues for security vulnerabilities** — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).

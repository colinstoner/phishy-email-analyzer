# Contributing to Phishy

Thanks for your interest in improving Phishy! Contributions of all kinds are welcome — bug reports, documentation fixes, new features, and test coverage.

## Development Setup

Prerequisites:

- Node.js 18 or later
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
  handlers/       Lambda entry points (SES, API Gateway, unified router) + webhook delivery
  services/
    ai/           Claude providers (Anthropic API, AWS Bedrock) behind a common interface
    email/        MIME/email parsing
    intelligence/ Optional threat-intel layer (IOC extraction, campaigns, PostgreSQL)
    notification/ SES report delivery
    storage/      S3 raw-email retrieval
  config/         Zod-validated configuration loading (env → S3 → local file → defaults)
  models/         Enterprise profile model
  templates/      HTML report template
  utils/          Logging, retry, validation, signature analysis
tests/
  unit/           Unit tests
  integration/    Handler-level tests with mocked AWS clients
```

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
npm run build        # TypeScript compile
npm run lint         # ESLint
npm run format:check # Prettier
npm test             # Jest
```

A few guidelines:

- **Add tests** for new behavior. Handler changes belong in `tests/integration/`, everything else in `tests/unit/`.
- **Keep AWS optional in tests.** Use the mocks in `tests/integration/mocks/` rather than hitting real services.
- **Follow the provider pattern.** New AI backends implement `AIProvider` (`src/services/ai/provider.interface.ts`); don't special-case providers in handlers.
- **No real-world data in fixtures.** Test emails must use invented domains (`example.com`, `example.org`) and people.
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
- Your deployment style (Anthropic API vs. Bedrock, intelligence DB on/off)

**Do not open public issues for security vulnerabilities** — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).

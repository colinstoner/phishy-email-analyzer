# Security Policy

Phishy is a security tool — it processes untrusted, often actively malicious email content by design. We take vulnerabilities in it seriously.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.x     | ✅        |
| 1.x (legacy `index.js`) | ❌ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of these private channels:

1. **GitHub private vulnerability reporting** (preferred): [Report a vulnerability](https://github.com/colinstoner/phishy-email-analyzer/security/advisories/new)
2. **Email**: colinstoner@gmail.com with `[PHISHY SECURITY]` in the subject line

Include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce (a crafted `.eml` file is ideal for parser/injection issues)
- Affected component (email parser, AI prompt construction, webhook delivery, report template, etc.)
- Any suggested fix

You can expect an acknowledgment within a few days. Please allow time for a fix to be released before public disclosure — we'll coordinate timing with you and credit you in the advisory unless you prefer otherwise.

## Scope

Especially interested in:

- **Prompt injection** — malicious email content that manipulates the AI analysis or report
- **XSS in reports** — email content escaping into the HTML report sent to users
- **SSRF** — via webhook URLs, embedded links, or S3/config loading
- **ReDoS** — pathological inputs against IOC extraction or parsing regexes
- **Information disclosure** — analysis reports, logs, or errors leaking data across tenants/users
- **Authentication bypass** — in the API Gateway handler or webhook signature verification

Out of scope: vulnerabilities in AWS services themselves, social engineering, and issues requiring a compromised AWS account.

## Hardening Your Deployment

Operators should also review [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — in particular restricting safe domains/senders, using AWS Secrets Manager for database credentials, and scoping the Lambda IAM role to the minimum required actions.

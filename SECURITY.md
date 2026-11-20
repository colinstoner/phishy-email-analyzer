# Security Policy

Phishy is a security tool — it processes untrusted, often actively malicious email content by design. We take vulnerabilities in it seriously.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 3.x (and unreleased `main`) | ✅ |
| 2.x and earlier | ❌ |
| 1.x (the former root `index.js`, removed) | ❌ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of these private channels:

1. **GitHub private vulnerability reporting** (preferred): [Report a vulnerability](https://github.com/colinstoner/phishy-email-analyzer/security/advisories/new)
2. **Email**: colinstoner@gmail.com with `[PHISHY SECURITY]` in the subject line

Include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce (a crafted `.eml` file is ideal for parser/injection issues)
- Affected component (email parser, AI prompt construction, attachment inspection, command channel or approvals, Graph broker, email templates, etc.)
- Any suggested fix

You can expect an acknowledgment within a few days. Please allow time for a fix to be released before public disclosure — we'll coordinate timing with you and credit you in the advisory unless you prefer otherwise.

## Scope

Especially interested in:

- **Prompt injection** — malicious email content that manipulates the AI analysis or report, or escapes the nonce fence
- **HTML injection in emails** — email content escaping into any email Phishy sends (reports, incident emails, warnings, alerts)
- **Command or approval forgery** — anything that makes Phishy act on a command or `APPROVE` line not sent by an authenticated security-team member, or widens an approved scope
- **Recipient steering** — getting Phishy to send a report or warning to an address outside the safe domains or the computed scope
- **Graph misuse** — steering a Graph request (path, filter, mailbox) from email content, or reaching the broker's credential from the main function
- **Resource exhaustion** — pathological attachments (archive bombs, malformed PDFs or Office files) or regex inputs (ReDoS) against parsing and IOC extraction
- **SSRF** — via embedded links, attachment references, or S3/config loading
- **Information disclosure** — analysis reports, logs, or errors leaking email content or data across users

Out of scope: vulnerabilities in AWS services themselves, social engineering, and issues requiring a compromised AWS account.

## Hardening Your Deployment

Operators should also review [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — in particular restricting safe domains/senders, using AWS Secrets Manager for database credentials and the Graph certificate, deploying Graph in broker mode, scoping mailbox permissions with Exchange RBAC for Applications, and scoping the Lambda IAM role to the minimum required actions. The optional intelligence API (`/api/v1/...`) has no authentication of its own: never expose it without an authorizer.

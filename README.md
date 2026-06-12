# Phishy Email Analyzer

[![CI](https://github.com/colinstoner/phishy-email-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/colinstoner/phishy-email-analyzer/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](package.json)

AI-powered phishing email analysis tool that uses Claude to evaluate suspicious emails and provide detailed security reports.

## Overview

Phishy is a serverless application that:

1. Receives emails via AWS SES
2. Analyzes them for phishing indicators using Claude (via Anthropic API or AWS Bedrock)
3. Delivers a detailed security report back to the sender

Perfect for security teams, IT departments, or anyone who needs to verify suspicious emails.

## Features

- 🛡️ **Robust Analysis**: Uses Claude AI (Sonnet 4.5/Haiku 4.5) to evaluate email senders, content, links, and attachments
- ⚡ **Serverless Architecture**: Runs on AWS Lambda for zero-maintenance operation
- 🔄 **Easy Workflow**: Just forward suspicious emails to your designated address
- 📊 **Detailed Reports**: Get comprehensive security analysis with recommendations
- 🔒 **Secure Processing**: Only processes emails from trusted domains
- 🔧 **Customizable**: Configure trusted domains, senders, and security team distribution
- 🏢 **Enterprise Profiles**: Organization-specific context for better detection (VIPs, partners, known threats)
- ☁️ **Flexible AI Backend**: Use Anthropic API or AWS Bedrock (no external API key needed)
- 📈 **Threat Intelligence** (optional): Track patterns, extract IOCs, integrate with SIEM

## How It Works

1. User forwards a suspicious email to `phishy@yourdomain.com`
2. AWS SES receives the email and:
   - Stores the complete raw email in S3 (preserving all content)
   - Triggers the Lambda function with email metadata and S3 reference
3. Lambda retrieves the full email content from S3, including forwarded content
4. Claude AI analyzes the content for phishing indicators with access to the complete email
5. Lambda sends a detailed security report back to the original forwarder and security team

## Architecture

```
User → SES → S3 (stores raw email)
            ↓
            Lambda + Claude API (analyzes email)
            ↓
            SES → Original Sender (delivers analysis)
```

## Setup

**Quick Start**: See [docs/QUICK_START.md](docs/QUICK_START.md) for a 15-minute setup guide.

**Full Setup**: See [AWS.md](AWS.md) for detailed AWS configuration instructions.

### Quick Start

1. Clone this repository
2. Install dependencies: `npm install`
3. Build: `npm run build`
4. Follow the AWS setup guide to configure SES and Lambda
5. Deploy to AWS Lambda

### Minimum Environment Variables

```bash
# Option 1: Anthropic API
ANTHROPIC_API_KEY=sk-ant-...

# Option 2: AWS Bedrock (no API key needed)
PHISHY_AI_PROVIDER=bedrock

# Required for both
S3_BUCKET_NAME=my-phishy-emails
SENDER_EMAIL=phishy@yourdomain.com
SECURITY_TEAM_DISTRIBUTION=security@yourdomain.com
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all configuration options.

> **Note**: This application requires an S3 bucket configured with SES for storing raw emails. See [AWS.md](AWS.md) for detailed setup instructions.

## Example Report

The analysis report includes:

- Summary of findings
- Phishing confidence assessment
- Suspicious indicators found
- Recommended actions
- Original email details

## Documentation

| Document | Description |
|----------|-------------|
| [docs/QUICK_START.md](docs/QUICK_START.md) | 15-minute setup guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All configuration options |
| [docs/INTELLIGENCE.md](docs/INTELLIGENCE.md) | Threat intelligence features |
| [AWS.md](AWS.md) | Detailed AWS setup |

## Development

### Prerequisites

- Node.js 18+
- AWS account with SES access
- Anthropic API key OR AWS Bedrock access

### Local Testing

```bash
npm install
npm run build
npm test
```

### Deployment

```bash
npm run build
zip -r phishy.zip dist/ node_modules/ package.json
# Upload to Lambda
```

## License

[Apache-2.0](LICENSE)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

Found a security vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).
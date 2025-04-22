# Phishy Email Analyzer

AI-powered phishing email analysis tool that uses Claude to evaluate suspicious emails and provide detailed security reports.

## Overview

Phishy is a serverless application that:

1. Receives emails via AWS SES
2. Analyzes them for phishing indicators using Anthropic's Claude
3. Delivers a detailed security report back to the sender

Perfect for security teams, IT departments, or anyone who needs to verify suspicious emails.

## Features

- 🛡️ **Robust Analysis**: Uses Claude AI to evaluate email senders, content, links, and attachments
- ⚡ **Serverless Architecture**: Runs on AWS Lambda for zero-maintenance operation
- 🔄 **Easy Workflow**: Just forward suspicious emails to your designated address
- 📊 **Detailed Reports**: Get comprehensive security analysis with recommendations
- 🔒 **Secure Processing**: Only processes emails from trusted domains
- 🔧 **Customizable**: Configure trusted domains, senders, and security team distribution

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

See the [AWS.md](AWS.md) file for detailed setup instructions.

### Quick Start

1. Clone this repository
2. Install dependencies: `npm install`
3. Follow the AWS setup guide to configure SES and Lambda
4. Deploy to AWS Lambda

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Your Claude API key | (Required) |
| `SAFE_DOMAINS` | Comma-separated list of trusted domains | `example.com` |
| `SAFE_SENDERS` | Comma-separated list of trusted email addresses | `trusted-sender@example.com` |
| `SENDER_EMAIL` | Email address used to send analysis reports | `noreply@yourdomain.com` |
| `SECURITY_TEAM_DISTRIBUTION` | Comma-separated list of security team emails | (Empty) |
| `PHISHY_AWS_REGION` | AWS region for AWS services | Lambda's region |
| `S3_BUCKET_NAME` | Override S3 bucket for email storage (optional) | Uses SES rule bucket |

> **Note**: This application requires an S3 bucket configured with SES for storing raw emails. See [AWS.md](AWS.md) for detailed setup instructions.

## Example Report

The analysis report includes:

- Summary of findings
- Phishing confidence assessment
- Suspicious indicators found
- Recommended actions
- Original email details

## Development

### Prerequisites

- Node.js 18+
- AWS account with SES access
- Anthropic API key

### Local Testing

Create a `.env` file with the required environment variables, then run:

```bash
npm install
node test/local.js
```

### Deployment

```bash
npm run deploy
```

## License

GPLv3

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
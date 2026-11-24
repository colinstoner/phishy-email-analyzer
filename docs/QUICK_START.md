# Phishy Quick Start Guide

Get the core of Phishy running: employees forward a suspicious email, Phishy replies with a report. Every optional layer stays off; turn them on later from [CONFIGURATION.md](CONFIGURATION.md).

To see what Phishy does before deploying anything, run it locally on the bundled sample: `npm install && npm run try examples/sample-phish.eml` (no AWS needed).

## What You Need

1. An AWS account, in a region where SES can receive email (for example us-east-1, us-west-2 or eu-west-1)
2. A domain whose MX record you can point at SES
3. An AI provider: AWS Bedrock access to the Claude model (no key; the default) **or** an Anthropic API key
4. The [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html), an authenticated AWS CLI and Node.js 22

## Minimal AWS Resources

| Service | Purpose |
|---------|---------|
| Lambda | Runs the analysis (Node.js 22, 1024 MB, 180 s timeout) |
| S3 | Holds incoming raw emails (deleted after 90 days by a lifecycle rule) |
| SES | Receives the forwards and sends the reports |
| Bedrock or the Anthropic API | The model |

**No database required.** The intelligence database and everything built on it are optional.

---

## Step 1: Deploy with SAM

```bash
git clone https://github.com/colinstoner/phishy-email-analyzer.git
cd phishy-email-analyzer
sam build
sam deploy --guided
```

`--guided` asks for each parameter. For the core you need only these; leave the rest at their defaults:

| Parameter | Example | |
|---|---|---|
| `RecipientEmail` | `phishy@example.com` | The address employees forward to |
| `SenderEmail` | `phishy@example.com` | The address reports come from (must be verified in SES) |
| `SecurityTeamDistribution` | `security@example.com` | Cc'd on reports |
| `SafeDomains` | `example.com` | Your organization's domain(s). Phishy answers only reports from these domains |
| `AIProvider` | `bedrock` | Or `anthropic`, with `AnthropicApiKey` |

The stack creates the function, the email bucket (with the policy that lets SES write to it), the receipt rule set (S3 action first, then the function) and the IAM permissions. See [AWS.md](../AWS.md) for every parameter.

## Step 2: Two manual steps in SES

CloudFormation cannot do these:

1. **Verify your domain** in SES (Verified identities → Create identity → Domain, with DKIM) and add the DNS records it gives you. Point the domain's MX record at SES receiving, for example `10 inbound-smtp.us-east-1.amazonaws.com`.
2. **Activate the rule set.** SES allows one active receipt rule set per account, so the template does not switch it for you: Email receiving → Rule sets → `<stack name>-rules` → Set as active. The stack's `ReceiptRuleSetName` output gives the exact name.

While your SES account is in the sandbox, it can only send to verified addresses: verify the addresses you will test from, or request production access (SES → Account dashboard).

## Step 3: Test it

Forward any email to your `RecipientEmail` from an address on one of your `SafeDomains`. You should receive a report within a minute or two. The function's logs are in CloudWatch under `/aws/lambda/<function name>`.

---

## Without SAM (manual function)

If you deploy the function yourself, build it the way the SAM template does, as an esbuild bundle (same settings as `template.yaml`):

```bash
npm ci
npm run package        # writes dist/lambda/phishy.zip (index.js)
```

Create a Node.js 22 function with handler `index.handler`, 1024 MB and a **180-second** timeout (the Bedrock retry budget needs it), upload `dist/lambda/phishy.zip` (later updates: `npm run deploy -- <function-name>`), and set at least:

```bash
SAFE_DOMAINS=example.com
S3_BUCKET_NAME=my-phishy-emails
SENDER_EMAIL=phishy@example.com
SECURITY_TEAM_DISTRIBUTION=security@example.com
PHISHY_AI_PROVIDER=bedrock          # or: ANTHROPIC_API_KEY=sk-ant-...
```

The execution role needs `s3:GetObject` (and `s3:DeleteObject` if you set `DELETE_EMAILS_AFTER_PROCESSING=true`) on `arn:aws:s3:::my-phishy-emails/emails/*`, `ses:SendEmail` and `ses:SendRawEmail`, and for Bedrock `bedrock:InvokeModel` on both `arn:aws:bedrock:*::foundation-model/anthropic.claude-*` and `arn:aws:bedrock:*:<account-id>:inference-profile/*` (the default model is a global inference profile). Then create an SES receipt rule with an S3 action (prefix `emails/`) **first** and a Lambda action second. [AWS.md](../AWS.md#option-b-manual-console-setup) walks through it, including the permissions SES itself needs.

---

## Optional: Enterprise Profile

Organization context (VIPs, partners, your domains, recent threats) for better detection:

```bash
cp config/profile.example.json config/my-org.profile.json   # *.profile.json is gitignored
# edit it, then upload it under profiles/ in the stack's email bucket
aws s3 cp config/my-org.profile.json s3://<email-bucket>/profiles/my-org.profile.json
```

Redeploy with `ProfileS3Uri=s3://<email-bucket>/profiles/my-org.profile.json`.

## Optional: Threat Intelligence and the layers built on it

Set `IntelligenceDbSecretArn` (a Secrets Manager secret holding a PostgreSQL 13+ connection string) with `VpcId` and `SubnetIds`, and Phishy records analyses and indicators. Campaign alerts, the verdict cache, email commands, campaign response and the fan-out scan build on it; each needs a migration applied by hand. See [AWS.md](../AWS.md#optional-the-intelligence-database) and [DATABASE.md](DATABASE.md).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No reply at all | Is the rule set active and the MX record pointing at SES? Is the sender's domain in `SafeDomains`? |
| "Email body empty" or only headers analyzed | The S3 action must come before the Lambda action, and `S3_BUCKET_NAME` must be that bucket |
| "Access Denied" in the logs | Check the function role's S3, SES and Bedrock permissions |
| Report says "ANALYSIS UNAVAILABLE" | The model could not be reached or declined; see `AnalysisFailureCount` / `AnalysisRefusalCount` and the logs |
| Function fails at start with `Configuration validation failed` | The log line names the setting; see [CONFIGURATION.md](CONFIGURATION.md#validation) |
| Reports reach only some people | SES sandbox: verify recipients or request production access |

---

## Next Steps

- [Full AWS Setup Guide](../AWS.md) - every SAM parameter, manual setup, optional layers
- [Microsoft 365 setup](./MICROSOFT_365.md) - forwarding, Graph, the Report button and removal, in order
- [Configuration Reference](./CONFIGURATION.md) - all options and feature flags
- [Architecture](./ARCHITECTURE.md) - how a report is analyzed and what is trusted
- [Intelligence Module](./INTELLIGENCE.md) - threat tracking

# AWS Setup for Phishy

This document provides step-by-step instructions for deploying Phishy on AWS.

## Prerequisites

- AWS account with administrator access
- Domain name you control (for receiving emails)
- **Either**:
  - Anthropic API key for Claude (direct API), OR
  - AWS Bedrock access (no external API key needed)
- Node.js and npm installed (for package preparation)

> **Quick Start**: See [docs/QUICK_START.md](docs/QUICK_START.md) for a 15-minute setup guide.

## Option A: Deploy with AWS SAM (recommended)

The [template.yaml](template.yaml) in the repo root provisions everything except DNS: the Lambda function (Node.js 22, 1024 MB, 180 s, built from TypeScript via esbuild), the S3 email bucket with SES write access and a 90-day lifecycle rule on `emails/`, the SES receipt rule set (S3 action first, then Lambda), IAM permissions, and — when you pick the `bedrock` provider — the Bedrock invoke policy. Optional layers add their own resources only when enabled.

```bash
# Prerequisites: AWS SAM CLI, authenticated AWS CLI, Node.js 22
sam build
sam deploy --guided   # prompts for every parameter below
```

Two manual steps remain, because CloudFormation cannot do them:

1. **Verify your domain in SES** (Section 1 below) and point your domain's MX record at SES — e.g. `10 inbound-smtp.us-east-1.amazonaws.com`.
2. **Activate the rule set**: SES allows only one active receipt rule set per account, so the template won't force a switch. In the SES console: Email receiving → Rule sets → `<stack name>-rules` (the `ReceiptRuleSetName` output) → Set as active.

> SES email receiving is only available in certain regions (including us-east-1, us-west-2, and eu-west-1) — deploy the stack in one of them.

If you deploy with SAM, you can skip to Section 9 (production access) and Section 10 (testing). Option B below documents the same setup done manually via the console.

### Core parameters

| Parameter | Default | |
|---|---|---|
| `RecipientEmail` | - | The address employees forward to. Its domain must be verified in SES with MX records pointing to SES |
| `SenderEmail` | - | The SES-verified address reports are sent from |
| `ReplyToEmail` | empty | `Reply-To` on Phishy's emails. Empty: `RecipientEmail` when `EmailCommandsEnabled` is true, none otherwise |
| `SecurityTeamDistribution` | - | Security-team address(es), comma-separated: Cc'd on reports and sent incident emails and alerts. Replies from these addresses count as commands |
| `SecurityTeamMembers` | empty | Individual people, comma-separated, whose replies also count as commands and approvals (for when `SecurityTeamDistribution` is a list address). Never sent anything; addresses outside `SafeDomains` are ignored |
| `SafeDomains` | - | Your domain(s), comma-separated. Phishy answers only reports from these domains |
| `SafeSenders` | empty | Individual addresses that may also report (outside `SafeDomains`) |
| `SafeSenderSecurity` | empty | Cc'd instead of the security team on reports from `SafeSenders` |
| `AIProvider` | `bedrock` | `bedrock` (IAM, no key) or `anthropic` |
| `AnthropicApiKey` | empty | Required with `AIProvider=anthropic` |
| `BedrockModelId` | empty | Pin a Bedrock inference profile (for example a `us.` geography profile); empty uses Phishy's default |
| `DeleteEmailsAfterProcessing` | `false` | Delete the raw email from S3 once processed |
| `ProfileS3Uri` | empty | `s3://` URI of an enterprise profile; store it under `profiles/` in the stack's email bucket |
| `ReportButtonEnabled` | `false` | Handle Outlook Report-button submissions silently ([CONFIGURATION.md](docs/CONFIGURATION.md#outlook-report-button-intake)) |

### Optional: the intelligence database

| Parameter | Default | |
|---|---|---|
| `IntelligenceDbSecretArn` | empty | Secrets Manager secret holding the PostgreSQL 13+ connection string (raw, JSON with `connectionString`/`url`, or `username`/`password`/`host` fields). Empty: no database and nothing that needs one |
| `VpcId`, `SubnetIds` | empty | Required with the database: the function is attached to this VPC to reach it privately |
| `DatabaseSecurityGroupId` | empty | When set, an ingress rule for port 5432 from the function's security group is added to it |
| `CreateVpcEndpoints` | `true` | Interface endpoints for bedrock-runtime (with Bedrock), SES and Secrets Manager, plus Lambda with Graph, so the VPC-attached function needs no NAT. Set `false` if the VPC already has them or a NAT gateway. The VPC must also have an S3 gateway endpoint or NAT route |
| `CampaignAlertsEnabled` | `false` | Broadcast warning once several people report one email |
| `CampaignAlertDistribution` | empty | Where that broadcast goes (a single address, typically an all-staff list) |

With `AIProvider=anthropic`, a VPC-attached function also needs NAT egress to reach `api.anthropic.com`: interface endpoints only cover AWS services.

Phishy creates the baseline schema (migration 001) on first connection. **Apply later migrations by hand** before enabling what needs them: `migrations/002_analysis_feedback.sql` (email commands), `003_campaign_verdict_cache.sql` (verdict cache), `004_structured_verdict.sql` (queryable verdict columns), `005_fanout_scan.sql` (fan-out scan), `006_campaign_response.sql` (campaign response). See [docs/DATABASE.md](docs/DATABASE.md). The verdict cache and agentic analysis have no template parameter; set them through a configuration file or by adding their variables to the function's environment.

### Optional: campaign response, the command channel and attachment analysis

All off by default; each is one parameter.

| Parameter | Default | |
|---|---|---|
| `EmailCommandsEnabled` | `false` | Security-team replies record verdicts and approve response actions. Needs the intelligence database and `migrations/002_analysis_feedback.sql` |
| `CampaignResponseEnabled` | `false` | Incident email, targeted warning and approved actions. Needs `CampaignAlertsEnabled`, the intelligence database and `migrations/006_campaign_response.sql`; approvals need `EmailCommandsEnabled` |
| `CampaignResponseAudience` | `distribution` | `distribution`, `recipients` (needs `GraphBlastRadiusEnabled`) or `both` |
| `CampaignResponseEmployeeWarning` | `approve` | `approve`, `auto` or `off` |
| `CampaignResponseReachThreshold` | `5` | Open the incident on the first malicious report when its blast radius found at least this many delivered recipients besides the reporters (needs `GraphBlastRadiusEnabled`); `0` waits for the report count. Automatic warnings still wait for a second reporter |
| `CampaignResponseUpdateIntervalMinutes` | `30` | Shortest gap, in minutes, between incident update emails for one campaign |
| `AttachmentAnalysisEnabled` | `false` | Static inspection of attachments |

With `CampaignResponseEnabled`, `CampaignAlertDistribution` may be left empty: no broadcast is sent, so choose `CampaignResponseAudience=recipients` (or `both`) and enable blast radius, or nobody is warned. The other campaign-response and attachment settings keep their defaults unless set in a config file (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)). Campaign response needs `CampaignAlertsEnabled=true` and `IntelligenceDbSecretArn`; a deploy without them is rejected.

### Optional: Microsoft Graph (the Graph broker function)

Phishy's optional Microsoft Graph features (original-message lookup, sender-relationship check, blast radius, and the scheduled fan-out scan) are off by default, and with `GraphEnabled=false` the template creates exactly what it creates without them. Setting `GraphEnabled=true` deploys them in **broker mode**: Graph requests are made by a second function, the Graph broker, and never by the function that parses email. Why, and what crosses between the two, is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#graph-broker).

Before deploying, create the read-only Entra app registration and store its certificate in Secrets Manager as described in [docs/CONFIGURATION.md](docs/CONFIGURATION.md#microsoft-graph-optional).

| Parameter | Default | |
|---|---|---|
| `GraphEnabled` | `false` | Adds the Graph broker and points the main function at it. Changes nothing on its own |
| `GraphTenantId` | - | Directory (tenant) ID, or a verified domain of the tenant. Required with `GraphEnabled` |
| `GraphReadClientId` | - | Application (client) ID of the read-only app registration. Required with `GraphEnabled` |
| `GraphCertificateSecretArn` | - | ARN of the Secrets Manager secret holding the app's private key and certificate. Required with `GraphEnabled` |
| `GraphOriginalFetchEnabled` | `false` | Original-message lookup |
| `GraphBlastRadiusEnabled` | `false` | Blast radius |
| `GraphSenderHistoryEnabled` | `false` | Sender-relationship check |
| `GraphFanoutScanEnabled` | `false` | Scheduled fan-out scan (see below). Needs `GraphEnabled` and `IntelligenceDbSecretArn` |
| `GraphFanoutScanIntervalMinutes` | `5` | Minutes between scans (2-60) |
| `GraphBrokerReservedConcurrency` | `5` | Most broker instances that can run at once; `0` reserves nothing |

A deploy with `GraphEnabled=true` and one of the three required values missing is rejected before anything is created.

What the stack adds when Graph is enabled:

- **`GraphBrokerFunction`** — built from `src/graph-broker.ts` (handler `graph-broker.handler`), Node.js 22, 512 MB, 180-second timeout. It is **not attached to the VPC**, because it needs the route to Microsoft that the main function should not have. It has no trigger of any kind: no function URL, no API, no event source.
- **`GraphBrokerRole`** — the broker's own role, written out in full rather than generated: `logs:CreateLogStream` and `logs:PutLogEvents` on its own log group, and `secretsmanager:GetSecretValue` on the certificate secret. Nothing else: no S3, SES, Bedrock, database secret or VPC permissions.
- **`GraphBrokerLogGroup`** — the broker's log group (90-day retention), so the role can be scoped to it.
- **On the main function** — `PHISHY_GRAPH_ENABLED=true`, `PHISHY_GRAPH_MODE=broker`, `PHISHY_GRAPH_BROKER_FUNCTION` (the broker's name) and the enabled feature flags, plus one new permission: `lambda:InvokeFunction` on the broker, and only on it. The main function is given no tenant ID, client ID or certificate, and its role cannot read the certificate secret.
- **`LambdaEndpoint`** — only when the main function is in a VPC (`IntelligenceDbSecretArn` set) and `CreateVpcEndpoints=true`: an interface VPC endpoint for the Lambda API (`com.amazonaws.<region>.lambda`), alongside the existing bedrock-runtime, SES and Secrets Manager endpoints and using the same security group. This is how a function with no internet route invokes the broker. If you set `CreateVpcEndpoints=false` because the VPC already has its endpoints, it must have one for Lambda too (or NAT), or every broker call fails with `Outcome=invoke_error` and the features quietly do nothing.

The feature flags are set on both functions from the same parameters. Other Graph settings (`PHISHY_GRAPH_BLAST_RADIUS_TIME_BUDGET_MS`, `PHISHY_GRAPH_SENDER_HISTORY_LOOKBACK_DAYS` and the rest in [docs/CONFIGURATION.md](docs/CONFIGURATION.md)) keep their defaults; to change one, add it to the environment of both functions in the template.

**Why a reserved concurrency.** Sender history allows each broker *instance* 60 message-trace requests per 5 minutes, against a Microsoft limit of 100 per 5 minutes for the whole tenant, shared with everything else that uses message trace. Without a cap, a flood of reports could start as many broker instances as there are concurrent emails, each with its own allowance. `GraphBrokerReservedConcurrency` bounds that: at the default of 5 the worst case is 300 requests per 5 minutes (a typical lookup is 6 and results are cached per sender for 5 minutes), and Microsoft's own throttling takes over beyond the tenant limit; set it to `1` for a hard ceiling below the tenant limit at the cost of more skipped lookups during a flood. An invocation Lambda throttles because of this limit is counted (`GraphBrokerCalls`, `Outcome=throttled`) and the email is analyzed without that lookup, exactly as when Graph is unavailable. Reserving concurrency takes it out of the account's shared pool, and AWS refuses the deploy if that would leave the account with less unreserved concurrency than its minimum; in an account with a small concurrency quota, set the parameter to `0`.

**What it costs to run** (us-east-1 list prices at the time of writing; check current pricing for your region):

- The **Lambda interface endpoint** is the only fixed cost: about USD 0.01 per hour per Availability Zone, so roughly **USD 7.30 a month for each subnet** in `SubnetIds` (about USD 14.60 with two), plus USD 0.01 per GB of data, which is negligible here because requests and responses are a few kilobytes.
- The **broker function** is billed per use like any Lambda: 512 MB for the seconds a lookup runs. A report with all three features on uses a few seconds, up to the blast-radius budget (45 seconds by default) for a malicious verdict. A thousand malicious reports a month at the full budget is about 22,500 GB-seconds, well under a dollar and inside the Lambda free tier if you have it. Reserved concurrency itself is free.
- The **log group** stores a few short lines per lookup.
- The certificate **secret** (about USD 0.40 a month) is needed in either mode.

After deploying, alarm on `GraphBrokerCalls` with any `Outcome` other than `ok`, and see [docs/CONFIGURATION.md](docs/CONFIGURATION.md#graph-broker-optional) for what each outcome means.

#### Optional: the scheduled fan-out scan

`GraphFanoutScanEnabled=true` makes Phishy look at recent inbound mail flow every few minutes, without waiting for a report, and email the security team (`SecurityTeamDistribution`, nobody else) when an established external contact suddenly sends one subject to many internal people. With `CampaignResponseEnabled` too, that email is a campaign-response incident email (every action waiting for approval) instead of the plain alert. It is read-only and involves no AI model. How it works and what it cannot see: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#scheduled-fan-out-scan).

It needs `GraphEnabled=true` and the intelligence database (`IntelligenceDbSecretArn`): the scan keeps its lock, its window and the alerts it has sent there. A deploy that asks for the scan without either is rejected before anything is created. **Apply `migrations/005_fanout_scan.sql` to the database before enabling it**; until then every scan logs that the migration is missing and does nothing else. The read app registration needs `ExchangeMessageTrace.Read.All`, as for the sender-relationship check.

What the stack adds when the scan is enabled (and nothing at all when it is not):

- **`FanoutScanSchedule`** — an EventBridge rule, `rate(<GraphFanoutScanIntervalMinutes> minutes)`, targeting the **main** function with the constant input `{"phishyScheduledTask":"graph_fanout_scan","version":1}`. No retries: a scan that did not run is covered by the next one's overlapping window.
- **`FanoutScanInvokePermission`** — lets that rule, and only that rule (`SourceArn`), invoke the main function.
- **`PHISHY_GRAPH_FANOUT_SCAN_ENABLED=true`** on both the main function and the broker (the broker refuses the operation without it).

No other permission is needed: the main function already invokes the broker, reads the database and sends email, and the broker already reads message trace. Each scan is one more broker invocation of a few seconds; all scans together spend at most 20 message-trace requests per 5 minutes (counted in the database, separately from the on-report sender-relationship check), so a shorter interval means smaller scans, not more requests. To change the scan's other settings (`PHISHY_GRAPH_FANOUT_SCAN_*` in [docs/CONFIGURATION.md](docs/CONFIGURATION.md#scheduled-fan-out-scan-optional)), add them to the main function's environment. After deploying, watch `FanoutScans` by `Outcome` (`migration_missing` or `no_database` mean the scan is not running) and `FanoutScanIncomplete`.

### Optional: the mailbox write tier (live campaign removal)

By default an approved campaign removal is a dry run and nothing in the stack can change a mailbox. The write tier is a third function, the **Graph write broker**, that moves approved copies to Deleted Items. A stack that supplies none of the parameters below is exactly what it was without them: no new resources and no changed ones. Design and threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#the-mailbox-write-tier).

Before deploying, create a **second** Entra app registration with `Mail.ReadWrite` (application, admin consent) and its own certificate, and store that certificate as a **new** Secrets Manager secret, as described in [docs/CONFIGURATION.md](docs/CONFIGURATION.md#mailbox-write-tier-optional).

| Parameter | Default | |
|---|---|---|
| `GraphWriteClientId` | - | Application (client) ID of the write app registration. With `GraphWriteCertificateSecretArn`, deploys the write broker |
| `GraphWriteCertificateSecretArn` | - | ARN of the write app's certificate secret (a different secret from `GraphCertificateSecretArn`) |
| `GraphWriteEnabled` | `false` | The write broker's own kill switch. While `false` it refuses every request |
| `GraphWriteAllowedMailboxIds` | - | Optional comma-separated Entra object IDs: the only mailboxes it may change |
| `GraphWriteBrokerReservedConcurrency` | `2` | Most write broker instances at once; `0` reserves nothing |
| `CampaignRemovalMode` | `dry_run` | `live` points the main function at the write broker. Needs `CampaignResponseEnabled` and the write broker |

The deploy is rejected if only one of the two write parameters is given, if `GraphTenantId` is missing, if the write client ID equals `GraphReadClientId`, if the write secret equals `GraphCertificateSecretArn`, or if `CampaignRemovalMode=live` lacks campaign response or the write broker. The client-ID and secret comparisons are plain text comparisons (a different spelling of the same value, such as an ARN with a different suffix form, is not caught), and the write broker itself cannot repeat them because it is never given the read registration; it only refuses to start if a manual deployment puts the same values in its environment. A live removal also needs `GraphOriginalFetchEnabled` and `GraphBlastRadiusEnabled`: without them no incident has the anchor a live removal requires, and every removal stays a dry run.

Three more things the template cannot do for you:

- **Restrict who may invoke the write broker.** Any principal in the account allowed `lambda:InvokeFunction` on it (administrators, broad `lambda:*` policies, CI roles) can request moves within its kill switch and allowlist. Add an explicit deny for every principal but the main function's role, and alert on its invocations.
- **A customer-managed KMS key on the write secret** needs `kms:Decrypt` on that key added to `GraphWriteBrokerRole`.
- **Deploy order.** The read broker's protocol is strict: a new read broker with an old main function makes blast radius and the original-message lookup unavailable (`malformed`). The stack updates both together; with `npm run deploy`, update the main function first.

What the stack adds:

- **`GraphWriteBrokerFunction`** (with the two write parameters) — built from `src/graph-write-broker.ts` (handler `graph-write-broker.handler`), Node.js 22, 256 MB, 100-second timeout, outside the VPC, no trigger of any kind. Its environment holds the kill switch, the tenant ID, the write client ID, the write secret's ARN and the allowlist, and nothing else.
- **`GraphWriteBrokerRole`** — its own role, in full: logs to its own log group and `secretsmanager:GetSecretValue` on the **write** secret only. It cannot read the read secret, the database secret, S3 or SES.
- **`GraphWriteBrokerLogGroup`** — 365-day retention: each call's line (action ID and counts) is the write tier's own record of what it changed.
- **On the main function**, only with `CampaignRemovalMode=live` and campaign response on: `PHISHY_CAMPAIGN_RESPONSE_REMOVAL_MODE=live`, `PHISHY_GRAPH_WRITE_BROKER_FUNCTION`, and `lambda:InvokeFunction` on the write broker. It is never given the write client ID or the write secret, and its role cannot read that secret. The read broker's role is unchanged.
- The **Lambda interface endpoint** is created for live removal as for Graph (it is normally already there).

Roll it out in steps: deploy with `GraphWriteEnabled=false` and `CampaignRemovalMode=live` (an approval then replies that the write broker refused, proving the path); then `GraphWriteEnabled=true` with `GraphWriteAllowedMailboxIds` set to one test mailbox; then clear the allowlist. `npm run deploy -- <function> --write-broker <write-broker-function>` updates its code outside SAM. Cost: only what it runs (a few seconds of 256 MB per approved removal) and the second secret (about USD 0.40 a month). Alarm on `CampaignRemovalErrors` and on `GraphBrokerCalls` with `Operation=remove_messages` and an `Outcome` other than `ok`.

## Option B: Manual Console Setup

### 1. Domain Verification in SES

1. Go to [AWS SES Console](https://console.aws.amazon.com/ses/)
2. Navigate to "Verified identities" → "Create identity"
3. Select "Domain" and enter your domain name
4. Enable DKIM (recommended) and create the identity
5. Add the provided DNS records to your domain
6. Wait for verification (can take 24-48 hours)

### 2. Create the S3 Bucket

Create a bucket for raw emails (for example `my-phishy-emails`), with public access blocked. SES needs permission to write to it; the console adds a bucket policy when you create the bucket from the receipt-rule wizard, otherwise add one like this (the same policy the SAM template creates):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSESPuts",
            "Effect": "Allow",
            "Principal": { "Service": "ses.amazonaws.com" },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-phishy-emails/emails/*",
            "Condition": { "StringEquals": { "aws:SourceAccount": "YOUR-ACCOUNT-ID" } }
        }
    ]
}
```

A lifecycle rule expiring `emails/` after 90 days (as the template does) keeps the bucket from growing.

### 3. Create Lambda Function

1. Go to [Lambda Console](https://console.aws.amazon.com/lambda/)
2. Create function:
   - Author from scratch
   - Name: `phishy`
   - Runtime: Node.js 22.x
   - Architecture: x86_64
   - Create a new role with basic Lambda permissions

### 4. Configure Inbound Email Handling in SES

1. In SES Console, go to "Email receiving" under the left sidebar
2. Create a rule set if none exists
3. Create a new rule:
   - Recipients: `phishy@example.com` (your address)
   - Add two actions in this order:
     1. First action: "S3" action
        - S3 bucket: the bucket from step 2
        - Object key prefix: `emails/`
     2. Second action: "Lambda function"
        - Select your `phishy` function
        - Invocation type: Event
        - When the console offers to add the permission SES needs to invoke the function, accept. Without the console, add it yourself: `aws lambda add-permission --function-name phishy --statement-id ses-invoke --action lambda:InvokeFunction --principal ses.amazonaws.com --source-account YOUR-ACCOUNT-ID`
4. Save the rule set and set it as active

> **CRITICAL**: The S3 action MUST be the FIRST action in your rule. This ensures the full email content is stored in S3 before the Lambda is invoked. Without this exact configuration, the Lambda will only receive email headers and metadata, not the actual email body content. Make sure you set the `S3_BUCKET_NAME` environment variable to match the bucket you configure here.

### 5. Prepare Lambda Code

Build the function the way the SAM template does, as one esbuild bundle (same entry point, target, externals and `.pem` loader as `template.yaml`):

```bash
git clone https://github.com/colinstoner/phishy-email-analyzer.git
cd phishy-email-analyzer
npm ci
npm run package
```

This writes `dist/lambda/phishy.zip` (one file, `index.js`). Upload it to the function and set the handler to `index.handler`; or, once the function exists, let the script upload it: `npm run deploy -- phishy` (the function name is the argument, or `PHISHY_DEPLOY_FUNCTION`; it runs `aws lambda update-function-code`). The AWS SDK is left out of the bundle because the Node.js 22 runtime provides it. The same command also writes `dist/lambda/graph-broker.zip` (handler `graph-broker.handler`) for a hand-built Graph broker; `npm run deploy -- phishy --broker <broker-function-name>` updates both. Do not upload the `npm run build` output: it is the compiled library without its dependencies.

### 6. Configure Lambda Function

1. Set environment variables:
   - `SAFE_DOMAINS`: Your domain(s), comma-separated (e.g., `example.com`). Phishy answers only reports from these domains
   - `SAFE_SENDERS`: Any individual addresses that may also report (comma-separated, optional)
   - `SENDER_EMAIL`: Email address for analysis reports (must be verified)
   - `SECURITY_TEAM_DISTRIBUTION`: Email address(es) for security team, comma-separated (Cc'd on reports)
   - `SECURITY_TEAM_MEMBERS`: Individual security-team members who may also issue commands and approvals, comma-separated (optional; never emailed; must be on `SAFE_DOMAINS`)
   - `S3_BUCKET_NAME`: The name of the S3 bucket where SES stores emails (must match the bucket configured in SES rules)
   - `PHISHY_AI_PROVIDER`: `bedrock` (default in the SAM template) or `anthropic`; with `anthropic`, also `ANTHROPIC_API_KEY`
   - `PHISHY_AWS_REGION`: Your AWS region (optional; defaults to the function's region)
   - `DELETE_EMAILS_AFTER_PROCESSING`: Set to "true" to automatically delete emails from S3 after they've been processed

   Every other setting is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

2. Adjust function settings:
   - Memory: 1024 MB (what the SAM template uses)
   - Timeout: 180 seconds. The Bedrock retry budget (four attempts backing off about 15, 30 and 60 seconds) needs it; a shorter timeout turns a transient provider error into a lost report

### 7. Set Lambda Permissions

1. Go to the "Configuration" tab → "Permissions"
2. Click the execution role name to open IAM
3. Add permissions → Create inline policy
4. JSON editor:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "ses:SendEmail",
                   "ses:SendRawEmail"
               ],
               "Resource": "*"
           },
           {
               "Effect": "Allow",
               "Action": [
                   "s3:GetObject",
                   "s3:DeleteObject"
               ],
               "Resource": "arn:aws:s3:::YOUR-EMAIL-BUCKET-NAME/emails/*"
           }
       ]
   }
   ```
   - Replace `YOUR-EMAIL-BUCKET-NAME` with the bucket name you created in step 2
   - Add `s3:GetObject` on wherever you keep an enterprise profile or configuration file, and `secretsmanager:GetSecretValue` on the database secret if you use one
5. Name the policy "PhishyPermissions" and create

### 7b. AWS Bedrock (default) or the Anthropic API

With `PHISHY_AI_PROVIDER=bedrock`, add this permission. The default model is a global inference profile, so both resources are needed:

```json
{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel"],
    "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
        "arn:aws:bedrock:*:YOUR-ACCOUNT-ID:inference-profile/*"
    ]
}
```

Set `PHISHY_BEDROCK_REGION` to your region if it differs from the function's. The refusal-fallback model (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md#refusals)) needs the same access.

With `PHISHY_AI_PROVIDER=anthropic`, set `ANTHROPIC_API_KEY` instead; the function then needs outbound internet access to `api.anthropic.com`.

**Benefits of Bedrock**:
- No external API key to manage
- Uses IAM for authentication
- Audit trails via CloudTrail

### 8. Understanding Email Content Handling

SES delivers mail to Phishy in two steps:

1. **SES Email Flow**:
   - SES stores the raw email in S3 (first action)
   - Then SES invokes the Lambda function (second action) with the email's metadata and the S3 location, not its content
   - The function reads the raw email from S3 and parses it (MIME, forwarded headers, attachments)

2. **Content Extraction Process**:
   - Uses content carried in the event itself, when there is any (SES receipt events normally carry none)
   - Otherwise reads the bucket and key named in the SES receipt's S3 action
   - Otherwise tries `emails/<message-id>` in `S3_BUCKET_NAME`
   - If all of these fail, analyzes a minimal representation built from the headers, which gives a much weaker analysis

3. **Important Configuration Points**:
   - The `S3_BUCKET_NAME` environment variable must match your actual S3 bucket name
   - The S3 action must be the first action in your SES rule, with the prefix `emails/`
   - Set `DELETE_EMAILS_AFTER_PROCESSING` to "true" to clean up processed emails (the role then needs `s3:DeleteObject`)

> **Note**: Without proper S3 configuration, the Lambda will only have access to email headers, not the actual email body, resulting in limited analysis capabilities.

### 9. Additional SES Configuration for Production

> **Note**: If you specified a `SENDER_EMAIL` that's not from your verified domain (Step 1), you'll need to verify that specific email address separately in SES.

For production environments:
- Request production access if needed:
  - SES Console → "Account dashboard"
  - "Request production access" under "Sending statistics"
  - Fill out the form explaining your email use case
- In sandbox mode, SES only allows sending to verified email addresses

### 10. Test the Setup

1. Forward a test email to `phishy@example.com` (your address) from an address on one of your safe domains
2. Check CloudWatch Logs:
   - Go to CloudWatch Console
   - "Log groups" → `/aws/lambda/phishy`
   - Check the latest log stream
3. Verify you receive the analysis report

## Troubleshooting

### No Emails Being Processed

- Check SES is receiving emails (verify MX records)
- Check Lambda CloudWatch logs for errors
- Verify SES rule is configured correctly
- Verify the S3 action is listed FIRST in your SES rule, before the Lambda action
- Check that your Lambda has proper S3 permissions to access the email bucket

### Lambda Execution Errors

- Verify all environment variables are set correctly
- Check IAM permissions
- Keep the timeout at 180 seconds (the Bedrock retry budget needs it)
- A `Cannot find module` error means the function was not packaged with `npm run package` (step 5), which bundles every dependency into one `index.js`
- Check that the `S3_BUCKET_NAME` environment variable matches your actual S3 bucket name

### No Analysis Emails Sent

- Check that the reporter's address is on one of `SAFE_DOMAINS` (or in `SAFE_SENDERS`): other senders are not answered
- Look for `Configuration validation failed` in the logs: an invalid setting stops every invocation
- Verify your sender email is verified in SES
- Check if SES is still in sandbox mode
- Confirm Lambda has permissions to send via SES

### Email Content Not Being Retrieved

- Check S3 logs to confirm emails are being stored in the S3 bucket
- Verify the S3 path structure in your bucket matches the expected format (`emails/[message-id]`)
- Check that your Lambda IAM role has s3:GetObject permissions for the correct bucket
- Verify your SES rule has the S3 action first, then the Lambda action

## Production Recommendations

For production-ready deployment:

1. Use infrastructure as code (AWS SAM, CloudFormation, Terraform)
2. Set up CloudWatch Alarms for Lambda errors and for Phishy's own metrics (namespace `Phishy`), at least `AnalysisFailureCount` and, with the optional layers, those their sections name
3. Configure separate development/production environments
4. Set up a Dead Letter Queue for failed executions
5. Consider SES configuration sets for email tracking

## Security Best Practices

1. Use IAM least privilege principle
2. Encrypt sensitive data and environment variables
3. Regularly update dependencies
4. Monitor for unusual patterns
5. Do not expose the function through API Gateway without an authorizer: its intelligence API (`/api/v1/...`) has no authentication of its own
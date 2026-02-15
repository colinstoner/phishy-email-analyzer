# Phishy Quick Start Guide

Get Phishy running in 15 minutes with minimal AWS configuration.

## What You Need

1. An AWS account
2. A domain where you can receive email (or just use SES sandbox for testing)
3. An Anthropic API key

## Minimal AWS Resources

Phishy requires only these AWS services:

| Service | Purpose | Cost |
|---------|---------|------|
| Lambda | Runs the analysis | Free tier: 1M requests/month |
| S3 | Stores incoming emails temporarily | Free tier: 5GB |
| SES | Receives and sends email | Free tier: 1000 emails/month |

**No database required** for basic usage. The intelligence database is optional.

---

## Step 1: Create S3 Bucket (2 minutes)

```bash
# Create bucket for email storage
aws s3 mb s3://my-phishy-emails --region us-east-1
```

---

## Step 2: Deploy Lambda (5 minutes)

### Option A: AWS Console (Easiest)

1. Go to [Lambda Console](https://console.aws.amazon.com/lambda/)
2. Create function → Author from scratch
   - Name: `phishy`
   - Runtime: Node.js 22.x
3. Upload code:
   ```bash
   npm install && npm run build
   zip -r phishy.zip dist/ node_modules/ package.json
   ```
4. Upload `phishy.zip` to your Lambda function

### Option B: AWS CLI

```bash
# Build and package
npm install && npm run build
zip -r phishy.zip dist/ node_modules/ package.json

# Create Lambda function
aws lambda create-function \
  --function-name phishy \
  --runtime nodejs22.x \
  --handler dist/index.handler \
  --role arn:aws:iam::YOUR_ACCOUNT:role/phishy-lambda-role \
  --zip-file fileb://phishy.zip \
  --timeout 60 \
  --memory-size 512
```

---

## Step 3: Set Environment Variables (2 minutes)

In the Lambda console, add these environment variables:

```bash
ANTHROPIC_API_KEY=sk-ant-your-key-here
S3_BUCKET_NAME=my-phishy-emails
SENDER_EMAIL=phishy@yourdomain.com
SECURITY_TEAM_DISTRIBUTION=security@yourdomain.com
```

---

## Step 4: Set Lambda Permissions (3 minutes)

Add this inline policy to your Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::my-phishy-emails/*"
    },
    {
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": "*"
    }
  ]
}
```

---

## Step 5: Configure SES Email Receiving (3 minutes)

1. Verify your domain in SES (or use sandbox mode)
2. Create an SES Rule Set with these actions **in order**:
   1. **S3 action** (first): Store to `my-phishy-emails` bucket, prefix `emails/`
   2. **Lambda action** (second): Invoke your `phishy` function

**Important**: S3 must be first! Lambda only gets headers; full email comes from S3.

---

## Done! Test It

Forward any email to `phishy@yourdomain.com`. You'll receive an analysis report.

---

## Using AWS Bedrock Instead (No API Key Needed)

If you're already on AWS, Bedrock is simpler - no external API key required.

1. Add Bedrock permissions to your Lambda role:
   ```json
   {
     "Effect": "Allow",
     "Action": ["bedrock:InvokeModel"],
     "Resource": ["arn:aws:bedrock:*::foundation-model/anthropic.claude-*"]
   }
   ```

2. Change environment variables:
   ```bash
   PHISHY_AI_PROVIDER=bedrock
   BEDROCK_REGION=us-east-1
   # Remove ANTHROPIC_API_KEY - not needed with Bedrock
   ```

---

## Optional: Add Enterprise Profile

Create a profile for organization-specific detection:

```bash
# Copy and customize the example
cp config/profile.example.json config/profile.json
# Edit with your organization details

# Upload to S3
aws s3 cp config/profile.json s3://my-phishy-emails/config/profile.json

# Add environment variable
PHISHY_PROFILE=s3://my-phishy-emails/config/profile.json
```

---

## Optional: Enable Threat Intelligence

Add PostgreSQL for historical tracking (requires a database):

```bash
# Using RDS PostgreSQL or any PostgreSQL 12+
PHISHY_INTELLIGENCE_ENABLED=true
PHISHY_DB_CONNECTION=postgresql://user:pass@host:5432/phishy
```

See [INTELLIGENCE.md](./INTELLIGENCE.md) for details.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No emails processed | Check SES rule, ensure S3 action is FIRST |
| "Access Denied" errors | Check Lambda IAM permissions |
| "Email body empty" | S3 bucket name must match exactly |
| Claude timeout | Increase Lambda timeout to 90s |
| SES sandbox limits | Request production access in SES console |

---

## Next Steps

- [Full AWS Setup Guide](../AWS.md) - Detailed instructions
- [Configuration Reference](./CONFIGURATION.md) - All options explained
- [Enterprise Profiles](./CONFIGURATION.md#enterprise-profiles) - Organization context
- [Intelligence Module](./INTELLIGENCE.md) - Threat tracking

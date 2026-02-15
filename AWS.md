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

## AWS Service Setup

### 1. Domain Verification in SES

1. Go to [AWS SES Console](https://console.aws.amazon.com/ses/)
2. Navigate to "Verified identities" → "Create identity"
3. Select "Domain" and enter your domain name
4. Enable DKIM (recommended) and create the identity
5. Add the provided DNS records to your domain
6. Wait for verification (can take 24-48 hours)

### 2. Create IAM Role for SES Mail Manager

1. When prompted to select an IAM role during rule creation, click "Create new role"
2. Name the role something descriptive like `SESMailManagerPhishyRole`
3. The console will automatically include the necessary trust relationship for SES
4. Add permissions to invoke Lambda:
   - Click on "View Role"
   - Select "Create inline policy" from the "Add Permissions" dropdown
   - Use the JSON editor and enter:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": "lambda:InvokeFunction",
               "Resource": "arn:aws:lambda:YOUR-REGION:YOUR-ACCOUNT-ID:function:phishy"
           }
       ]
   }
   ```
   - Replace `YOUR-REGION` and `YOUR-ACCOUNT-ID` with your AWS region and account ID
   - Name the policy "SESInvokeLambdaPolicy" and create it
5. Select the newly created role for your SES rule
6. Save Rule Set

### 3. Create Lambda Function

1. Go to [Lambda Console](https://console.aws.amazon.com/lambda/)
2. Create function:
   - Author from scratch
   - Name: `phishyAWS`
   - Runtime: Node.js 22.x
   - Architecture: x86_64
   - Create a new role with basic Lambda permissions

### 4. Configure Inbound Email Handling in SES

1. In SES Console, go to "Email receiving" under the left sidebar
2. Create a rule set if none exists
3. Create a new rule:
   - Recipients: `phishy@yourdomain.com`
   - Add two actions in this order:
     1. First action: "S3" action
        - S3 bucket: Create a new bucket or select an existing one
        - Object key prefix: `emails/`
        - Enable SNS notifications: Optional but helpful
     2. Second action: "Lambda function"
        - Select your Lambda function
        - Select "Include original message" option
        - Use the IAM role created in step 2
4. Save the rule set and set it as active

> **CRITICAL**: The S3 action MUST be the FIRST action in your rule. This ensures the full email content is stored in S3 before the Lambda is invoked. Without this exact configuration, the Lambda will only receive email headers and metadata, not the actual email body content. Make sure you set the `S3_BUCKET_NAME` environment variable to match the bucket you configure here.

### 5. Prepare Lambda Code

1. Clone the Phishy repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a deployment package:
   ```bash
   zip -r function.zip index.js node_modules package.json
   ```
4. Upload the zip file to your Lambda function

### 6. Configure Lambda Function

1. Set environment variables:
   - `ANTHROPIC_API_KEY`: Your Claude API key
   - `SAFE_DOMAINS`: Your domain(s), comma-separated (e.g., `yourdomain.com`)
   - `SAFE_SENDERS`: Any trusted email addresses (comma-separated)
   - `SENDER_EMAIL`: Email address for analysis reports (must be verified)
   - `SECURITY_TEAM_DISTRIBUTION`: Email address(es) for security team, comma-separated (will be CC'd on all analyses)
   - `PHISHY_AWS_REGION`: Your AWS region
   - `S3_BUCKET_NAME`: The name of the S3 bucket where SES stores emails (must match the bucket configured in SES rules)
   - `DELETE_EMAILS_AFTER_PROCESSING`: Set to "true" to automatically delete emails from S3 after they've been processed

2. Adjust function settings:
   - Memory: 512 MB (minimum recommended, 1024 MB preferred for better performance)
   - Timeout: 60 seconds (Claude API can take up to 30+ seconds to respond)
   - Execution role: Will be configured in next step

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
   - Replace `YOUR-EMAIL-BUCKET-NAME` with the bucket name you created in step 4
5. Name the policy "PhishyPermissions" and create

### 7b. (Optional) Use AWS Bedrock Instead of Anthropic API

If you prefer to use AWS Bedrock instead of the Anthropic API, add this permission:

```json
{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel"],
    "Resource": ["arn:aws:bedrock:*::foundation-model/anthropic.claude-*"]
}
```

Then set these environment variables instead:
- `PHISHY_AI_PROVIDER`: Set to `bedrock`
- `BEDROCK_REGION`: Your AWS region (e.g., `us-east-1`)
- Remove `ANTHROPIC_API_KEY` - not needed with Bedrock

**Benefits of Bedrock**:
- No external API key to manage
- Data stays within your AWS account
- Uses IAM for authentication
- Better audit trails via CloudTrail

### 8. Understanding Email Content Handling

The application uses a multi-step approach to extract email content from AWS SES:

1. **SES Email Flow**:
   - When an email is received by SES, it stores the raw email in S3 (first action)
   - Then SES invokes the Lambda function (second action)
   - The Lambda function receives only email metadata, not the full content
   - The Lambda must retrieve the full content from S3

2. **Content Extraction Process**:
   - First checks direct SES event fields for content
   - Then retrieves the email from S3 using the path information in the SES receipt
   - Falls back to a standard path pattern using the message ID if path info isn't available
   - For multipart MIME emails, extracts the text or HTML parts
   - If all else fails, creates a minimal representation from available headers

3. **Important Configuration Points**:
   - The `S3_BUCKET_NAME` environment variable must match your actual S3 bucket name
   - The Lambda IAM role needs s3:GetObject permissions for the bucket
   - The S3 action must be the first action in your SES rule
   - The standard path format is `emails/[message-id]`
   - Set `DELETE_EMAILS_AFTER_PROCESSING` to "true" to automatically clean up processed emails from S3
   - If cleanup is enabled, the Lambda role will need s3:DeleteObject permissions

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

1. Send a test email to `phishy@yourdomain.com`
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
- Increase timeout if processing large emails
- Check that the `S3_BUCKET_NAME` environment variable matches your actual S3 bucket name

### No Analysis Emails Sent

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
2. Set up CloudWatch Alarms for Lambda errors
3. Configure separate development/production environments
4. Set up a Dead Letter Queue for failed executions
5. Consider SES configuration sets for email tracking

## Security Best Practices

1. Use IAM least privilege principle
2. Encrypt sensitive data and environment variables
3. Regularly update dependencies
4. Monitor for unusual patterns
5. Use AWS WAF if exposing any public endpoints
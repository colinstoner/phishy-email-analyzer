/**
 * AWS Service Mocks for Integration Testing
 */

import { mockClient } from 'aws-sdk-client-mock';
import { S3Client, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { SESEvent } from 'aws-lambda';
import { Readable } from 'stream';
import { sdkStreamMixin } from '@smithy/util-stream';

// Create mock clients
export const s3Mock = mockClient(S3Client);
export const sesMock = mockClient(SESClient);
export const bedrockMock = mockClient(BedrockRuntimeClient);

/**
 * Reset all AWS mocks
 */
export function resetAwsMocks(): void {
  s3Mock.reset();
  sesMock.reset();
  bedrockMock.reset();
}

/**
 * Setup S3 mock to return email content
 */
export function mockS3GetObject(content: string): void {
  const stream = new Readable();
  stream.push(content);
  stream.push(null);
  const sdkStream = sdkStreamMixin(stream);

  s3Mock.on(GetObjectCommand).resolves({
    Body: sdkStream,
    ContentType: 'message/rfc822',
  });
}

/**
 * Setup S3 mock to return specific content for specific keys
 */
export function mockS3GetObjectForKey(bucket: string, key: string, content: string): void {
  const stream = new Readable();
  stream.push(content);
  stream.push(null);
  const sdkStream = sdkStreamMixin(stream);

  s3Mock.on(GetObjectCommand, { Bucket: bucket, Key: key }).resolves({
    Body: sdkStream,
    ContentType: 'message/rfc822',
  });
}

/**
 * Setup S3 delete mock
 */
export function mockS3DeleteObject(): void {
  s3Mock.on(DeleteObjectCommand).resolves({});
}

/**
 * Setup SES send email mock
 */
export function mockSESSendEmail(messageId: string = 'test-message-id'): void {
  sesMock.on(SendEmailCommand).resolves({
    MessageId: messageId,
  });
}

/**
 * Setup Bedrock mock to return analysis result
 */
export function mockBedrockInvoke(response: {
  isPhishing: boolean;
  confidence: string;
  summary: string;
  indicators?: string[];
  recommendations?: string[];
}): void {
  const responseBody = {
    content: [
      {
        text: JSON.stringify(response),
      },
    ],
  };

  // Create a Uint8Array that includes the required methods
  const encoded = new TextEncoder().encode(JSON.stringify(responseBody));
  const body = Object.assign(encoded, {
    transformToString: () => JSON.stringify(responseBody),
    transformToByteArray: () => encoded,
    transformToWebStream: () => new ReadableStream(),
  });

  bedrockMock.on(InvokeModelCommand).resolves({
    body,
  });
}

/**
 * Create a mock SES event for testing
 */
export function createMockSESEvent(options: {
  from?: string;
  to?: string;
  subject?: string;
  messageId?: string;
  s3Bucket?: string;
  s3Key?: string;
}): SESEvent {
  const {
    from = 'user@trusted.com',
    to = 'phishy@example.com',
    subject = 'Fw: Suspicious Email',
    messageId = 'test-message-123',
    s3Bucket = 'test-bucket',
    s3Key = 'emails/test-message-123',
  } = options;

  return {
    Records: [
      {
        eventSource: 'aws:ses',
        eventVersion: '1.0',
        ses: {
          mail: {
            messageId,
            source: from,
            destination: [to],
            timestamp: new Date().toISOString(),
            commonHeaders: {
              from: [from],
              to: [to],
              subject,
              returnPath: from,
              messageId: `<${messageId}>`,
              date: new Date().toISOString(),
            },
            headersTruncated: false,
            headers: [
              { name: 'From', value: from },
              { name: 'To', value: to },
              { name: 'Subject', value: subject },
            ],
          },
          receipt: {
            timestamp: new Date().toISOString(),
            processingTimeMillis: 100,
            recipients: [to],
            spamVerdict: { status: 'PASS' },
            virusVerdict: { status: 'PASS' },
            spfVerdict: { status: 'PASS' },
            dkimVerdict: { status: 'PASS' },
            dmarcVerdict: { status: 'PASS' },
            action: {
              type: 'S3',
              bucketName: s3Bucket,
              objectKey: s3Key,
              topicArn: 'arn:aws:sns:us-east-1:123456789:topic',
            },
          },
        },
      },
    ],
  };
}

/**
 * Create a mock Lambda context
 */
export function createMockContext(): {
  functionName: string;
  functionVersion: string;
  invokedFunctionArn: string;
  memoryLimitInMB: string;
  awsRequestId: string;
  logGroupName: string;
  logStreamName: string;
  getRemainingTimeInMillis: () => number;
  done: () => void;
  fail: () => void;
  succeed: () => void;
  callbackWaitsForEmptyEventLoop: boolean;
} {
  return {
    functionName: 'phishy-test',
    functionVersion: '1',
    invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789:function:phishy-test',
    memoryLimitInMB: '512',
    awsRequestId: 'test-request-id',
    logGroupName: '/aws/lambda/phishy-test',
    logStreamName: '2024/01/01/[$LATEST]test',
    getRemainingTimeInMillis: () => 30000,
    done: () => {},
    fail: () => {},
    succeed: () => {},
    callbackWaitsForEmptyEventLoop: false,
  };
}

/**
 * Sample raw email content for testing
 */
export const SAMPLE_EMAIL_CONTENT = `From: attacker@phishing-site.com
To: victim@company.com
Subject: Urgent: Verify Your Account
Date: Mon, 15 Jan 2024 10:00:00 -0500
Message-ID: <suspicious-123@phishing-site.com>
Content-Type: text/plain; charset="UTF-8"

Dear Customer,

Your account has been compromised. Click here immediately to verify:
http://192.168.1.100/login?user=victim

If you don't act within 24 hours, your account will be suspended.

Regards,
Security Team
`;

/**
 * Sample forwarded email for testing
 */
export const SAMPLE_FORWARDED_EMAIL = `From: user@trusted.com
To: phishy@example.com
Subject: Fw: Urgent: Verify Your Account
Date: Mon, 15 Jan 2024 11:00:00 -0500
Message-ID: <forward-456@trusted.com>
Content-Type: text/plain; charset="UTF-8"

---------- Forwarded message ---------
From: attacker@phishing-site.com
Date: Mon, 15 Jan 2024 10:00:00 -0500
Subject: Urgent: Verify Your Account
To: victim@company.com

Dear Customer,

Your account has been compromised. Click here immediately to verify:
http://192.168.1.100/login?user=victim

If you don't act within 24 hours, your account will be suspended.

Regards,
Security Team
`;

/**
 * Sample legitimate email for testing
 */
export const SAMPLE_LEGITIMATE_EMAIL = `From: newsletter@company.com
To: user@trusted.com
Subject: Monthly Newsletter - January 2024
Date: Mon, 15 Jan 2024 09:00:00 -0500
Message-ID: <newsletter-789@company.com>
Content-Type: text/plain; charset="UTF-8"

Hello,

Here's your monthly update from Company Inc.

Best regards,
The Company Team
`;

/**
 * Lambda Handler Integration Tests
 *
 * Note: Full integration tests for the Lambda handler require complex AWS SDK mocking.
 * These tests verify the handler's behavior with mocked dependencies.
 */

// Mock the config module before importing handler
jest.mock('../../../src/config', () => ({
  loadConfig: jest.fn().mockResolvedValue({
    ai: {
      provider: 'bedrock',
      bedrock: {
        region: 'us-east-1',
        modelId: 'us.anthropic.claude-sonnet-4-5-20250514-v1:0',
        maxTokens: 4096,
        timeout: 60000,
      },
    },
    email: {
      safeDomains: ['trusted.com', 'example.com'],
      safeSenders: ['admin@trusted.com'],
      deleteAfterProcessing: false,
    },
    notification: {
      senderEmail: 'phishy@example.com',
      senderName: 'Phishy Security',
      securityTeamDistribution: ['security@example.com'],
    },
    storage: {
      s3Bucket: 'test-bucket',
      s3Prefix: 'emails',
      region: 'us-east-1',
    },
    logLevel: 'error',
  }),
}));

// Import handler after mocking
import { handler } from '../../../src/handlers/lambda.handler';
import { Context, SESEvent } from 'aws-lambda';

describe('Lambda Handler Integration', () => {
  const mockContext: Context = {
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

  describe('Empty Event Handling', () => {
    it('should handle empty Records array', async () => {
      const event: SESEvent = { Records: [] };
      const result = await handler(event, mockContext);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.success).toBe(true);
      expect(body.message).toContain('No email events');
    });
  });

  describe('Response Format', () => {
    it('should return proper CORS headers', async () => {
      const event: SESEvent = { Records: [] };
      const result = await handler(event, mockContext);

      expect(result.headers).toBeDefined();
      expect(result.headers?.['Access-Control-Allow-Origin']).toBe('*');
      expect(result.headers?.['Content-Type']).toBe('application/json');
    });

    it('should return valid JSON body', async () => {
      const event: SESEvent = { Records: [] };
      const result = await handler(event, mockContext);

      expect(() => JSON.parse(result.body)).not.toThrow();
    });

    it('should always return 200 status code', async () => {
      // Lambda should return 200 even for processing errors
      // to prevent SES from retrying
      const event: SESEvent = { Records: [] };
      const result = await handler(event, mockContext);

      expect(result.statusCode).toBe(200);
    });
  });

  // Note: Configuration loading is cached, so checking call count
  // across tests is not reliable
});

/**
 * Jest test setup file
 * Configures global test environment
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce log noise during tests

// Mock environment variables commonly needed
process.env.PHISHY_AWS_REGION = 'us-east-1';
process.env.S3_BUCKET_NAME = 'test-phishy-bucket';
process.env.SAFE_DOMAINS = 'example.com,test.org';
process.env.SAFE_SENDERS = 'trusted@example.com';

// Global test timeout
jest.setTimeout(30000);

// Clean up after all tests
afterAll(() => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
});

// Reset mocks between tests
afterEach(() => {
  jest.clearAllMocks();
});

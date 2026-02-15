/**
 * Database Mocks for Integration Testing
 */

import { Pool, PoolClient, QueryResult } from 'pg';

/**
 * Mock query results storage
 */
const mockQueryResults: Map<string, QueryResult> = new Map();
const mockQueryHistory: Array<{ query: string; params: unknown[] }> = [];

/**
 * Create a mock Pool
 */
export function createMockPool(): jest.Mocked<Pool> {
  const mockClient: Partial<jest.Mocked<PoolClient>> = {
    query: jest.fn().mockImplementation(async (query: string, params?: unknown[]) => {
      mockQueryHistory.push({ query, params: params ?? [] });

      // Check for specific mocked results
      for (const [pattern, result] of mockQueryResults.entries()) {
        if (query.includes(pattern)) {
          return result;
        }
      }

      // Default empty result
      return { rows: [], rowCount: 0 };
    }),
    release: jest.fn(),
  };

  const mockPool: Partial<jest.Mocked<Pool>> = {
    connect: jest.fn().mockResolvedValue(mockClient as PoolClient),
    query: jest.fn().mockImplementation(async (query: string, params?: unknown[]) => {
      mockQueryHistory.push({ query, params: params ?? [] });

      // Check for specific mocked results
      for (const [pattern, result] of mockQueryResults.entries()) {
        if (query.includes(pattern)) {
          return result;
        }
      }

      // Default empty result
      return { rows: [], rowCount: 0 };
    }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn().mockReturnThis(),
  };

  return mockPool as jest.Mocked<Pool>;
}

/**
 * Set mock query result for a pattern
 */
export function mockQueryResult(queryPattern: string, rows: unknown[]): void {
  mockQueryResults.set(queryPattern, {
    rows,
    rowCount: rows.length,
    command: 'SELECT',
    oid: 0,
    fields: [],
  });
}

/**
 * Mock insert returning ID
 */
export function mockInsertReturning(queryPattern: string, id: string): void {
  mockQueryResults.set(queryPattern, {
    rows: [{ id }],
    rowCount: 1,
    command: 'INSERT',
    oid: 0,
    fields: [],
  });
}

/**
 * Get query history for assertions
 */
export function getQueryHistory(): Array<{ query: string; params: unknown[] }> {
  return [...mockQueryHistory];
}

/**
 * Clear all mocks
 */
export function clearDatabaseMocks(): void {
  mockQueryResults.clear();
  mockQueryHistory.length = 0;
}

/**
 * Sample analysis record for testing
 */
export const SAMPLE_ANALYSIS_RECORD = {
  id: 'test-analysis-123',
  profile_id: null,
  message_id: 'test-message-123',
  from_email: 'attacker@phishing-site.com',
  from_domain: 'phishing-site.com',
  subject: 'Urgent: Verify Your Account',
  is_phishing: true,
  confidence_score: 0.95,
  risk_level: 'critical',
  analysis_result: {
    summary: 'High confidence phishing attempt',
    isPhishing: true,
    confidence: 'Very High',
    indicators: ['Suspicious URL', 'Urgency language'],
    recommendations: ['Do not click any links'],
  },
  indicators: ['url:http://192.168.1.100/login', 'domain:phishing-site.com'],
  vip_impersonation_detected: false,
  ai_provider: 'bedrock',
  ai_model: 'claude-sonnet-4-5',
  processing_time_ms: 1500,
  created_at: new Date('2024-01-15T10:00:00Z'),
};

/**
 * Sample threat indicator for testing
 */
export const SAMPLE_THREAT_INDICATOR = {
  id: 'indicator-456',
  indicator_type: 'domain',
  indicator_value: 'phishing-site.com',
  indicator_hash: 'abc123',
  confidence_score: 0.95,
  severity: 'critical',
  times_seen: 5,
  first_seen_at: new Date('2024-01-10T00:00:00Z'),
  last_seen_at: new Date('2024-01-15T10:00:00Z'),
  is_active: true,
  expires_at: null,
  metadata: {},
};

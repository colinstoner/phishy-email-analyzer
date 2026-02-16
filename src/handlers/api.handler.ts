/**
 * Intelligence API Handler
 * REST API endpoints for threat intelligence data
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { loadConfig, PhishyConfig } from '../config';
import {
  IntelligenceDatabaseService,
  AnalysisSearchFilters,
} from '../services/intelligence/database.service';
import { createLogger } from '../utils/logger';

const logger = createLogger('api-handler');

/**
 * Cached database service
 */
let cachedDb: IntelligenceDatabaseService | null = null;
let cachedConfig: PhishyConfig | null = null;

/**
 * Initialize database connection
 */
async function initializeDb(): Promise<IntelligenceDatabaseService> {
  if (cachedDb) return cachedDb;

  cachedConfig ??= await loadConfig();

  if (!cachedConfig.intelligence?.enabled || !cachedConfig.intelligence?.connectionString) {
    throw new Error('Intelligence database is not configured');
  }

  cachedDb = new IntelligenceDatabaseService(cachedConfig.intelligence.connectionString);
  await cachedDb.initialize();

  return cachedDb;
}

/**
 * Main API handler
 */
export async function handler(
  event: APIGatewayProxyEvent,
  _context: Context
): Promise<APIGatewayProxyResult> {
  logger.info('API request received', {
    method: event.httpMethod,
    path: event.path,
  });

  try {
    const method = event.httpMethod;
    const path = event.path;

    // Route requests
    if (path.startsWith('/api/v1/analyses')) {
      return handleAnalysesRoute(event, method, path);
    }

    if (path.startsWith('/api/v1/indicators')) {
      return handleIndicatorsRoute(event, method, path);
    }

    if (path.startsWith('/api/v1/patterns')) {
      return handlePatternsRoute(event, method);
    }

    if (path.startsWith('/api/v1/stats')) {
      return handleStatsRoute();
    }

    if (path.startsWith('/api/v1/health')) {
      return handleHealthRoute();
    }

    return createResponse(404, { error: 'Not found' });
  } catch (error) {
    // Log detailed error server-side for debugging
    logger.error('API error', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    // Return generic error to client - don't expose internal details
    return createResponse(500, {
      error: 'Internal server error',
      requestId: _context.awsRequestId,
    });
  }
}

/**
 * Handle /api/v1/analyses routes
 */
async function handleAnalysesRoute(
  event: APIGatewayProxyEvent,
  method: string,
  path: string
): Promise<APIGatewayProxyResult> {
  const db = await initializeDb();

  // GET /api/v1/analyses - List analyses
  if (method === 'GET' && path === '/api/v1/analyses') {
    const params = event.queryStringParameters ?? {};
    const filters: AnalysisSearchFilters = {
      limit: params.limit ? parseInt(params.limit, 10) : 100,
      offset: params.offset ? parseInt(params.offset, 10) : 0,
    };

    if (params.fromDate) {
      filters.fromDate = new Date(params.fromDate);
    }

    if (params.toDate) {
      filters.toDate = new Date(params.toDate);
    }

    if (params.isPhishing !== undefined) {
      filters.isPhishing = params.isPhishing === 'true';
    }

    if (params.riskLevel) {
      filters.riskLevel = params.riskLevel;
    }

    if (params.fromDomain) {
      filters.fromDomain = params.fromDomain;
    }

    const analyses = await db.searchAnalyses(filters);
    return createResponse(200, { analyses, count: analyses.length });
  }

  // GET /api/v1/analyses/:id - Get single analysis
  const idMatch = path.match(/\/api\/v1\/analyses\/([a-f0-9-]+)$/);
  if (method === 'GET' && idMatch) {
    const analysis = await db.getAnalysis(idMatch[1]);

    if (!analysis) {
      return createResponse(404, { error: 'Analysis not found' });
    }

    return createResponse(200, analysis);
  }

  // POST /api/v1/analyses/search - Advanced search
  if (method === 'POST' && path === '/api/v1/analyses/search') {
    const body = JSON.parse(event.body ?? '{}') as AnalysisSearchFilters;
    const analyses = await db.searchAnalyses(body);
    return createResponse(200, { analyses, count: analyses.length });
  }

  // GET /api/v1/analyses/stats - Aggregate statistics
  if (method === 'GET' && path === '/api/v1/analyses/stats') {
    const stats = await db.getStats();
    return createResponse(200, stats);
  }

  return createResponse(405, { error: 'Method not allowed' });
}

/**
 * Handle /api/v1/indicators routes
 */
async function handleIndicatorsRoute(
  event: APIGatewayProxyEvent,
  method: string,
  path: string
): Promise<APIGatewayProxyResult> {
  const db = await initializeDb();

  // GET /api/v1/indicators - List active indicators
  if (method === 'GET' && path === '/api/v1/indicators') {
    const params = event.queryStringParameters ?? {};
    const type = params.type;
    const limit = params.limit ? parseInt(params.limit, 10) : 100;

    const indicators = await db.getActiveIndicators(
      type as 'domain' | 'ip' | 'url' | 'email' | 'hash' | undefined,
      limit
    );

    return createResponse(200, { indicators, count: indicators.length });
  }

  // POST /api/v1/indicators/lookup - Bulk lookup
  if (method === 'POST' && path === '/api/v1/indicators/lookup') {
    const body = JSON.parse(event.body ?? '{}') as {
      type: 'domain' | 'ip' | 'url' | 'email' | 'hash';
      values: string[];
    };

    if (!body.type || !Array.isArray(body.values)) {
      return createResponse(400, { error: 'Invalid request body' });
    }

    const indicators = await db.lookupIndicators(body.type, body.values);
    return createResponse(200, {
      indicators,
      matched: indicators.length,
      total: body.values.length,
    });
  }

  // GET /api/v1/indicators/export - Export in STIX format
  if (method === 'GET' && path === '/api/v1/indicators/export') {
    const params = event.queryStringParameters ?? {};
    const format = params.format ?? 'stix';
    const limit = params.limit ? parseInt(params.limit, 10) : 1000;

    const indicators = await db.getActiveIndicators(undefined, limit);

    if (format === 'stix') {
      const stixBundle = convertToSTIX(indicators);
      return createResponse(200, stixBundle, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="indicators.json"',
      });
    }

    if (format === 'csv') {
      const csv = convertToCSV(indicators);
      return createResponse(200, csv, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="indicators.csv"',
      });
    }

    return createResponse(200, { indicators });
  }

  return createResponse(405, { error: 'Method not allowed' });
}

/**
 * Handle /api/v1/patterns routes
 */
async function handlePatternsRoute(
  _event: APIGatewayProxyEvent,
  method: string
): Promise<APIGatewayProxyResult> {
  const db = await initializeDb();

  // GET /api/v1/patterns - List detected patterns
  if (method === 'GET') {
    // Note: This would require adding a getPatterns method to the database service
    // For now, return a placeholder
    const stats = await db.getStats();

    return createResponse(200, {
      message: 'Patterns endpoint',
      detectedPatterns: stats.detectedPatterns,
    });
  }

  return createResponse(405, { error: 'Method not allowed' });
}

/**
 * Handle /api/v1/stats routes
 */
async function handleStatsRoute(): Promise<APIGatewayProxyResult> {
  const db = await initializeDb();
  const stats = await db.getStats();
  return createResponse(200, stats);
}

/**
 * Handle /api/v1/health routes
 */
async function handleHealthRoute(): Promise<APIGatewayProxyResult> {
  try {
    const db = await initializeDb();
    const stats = await db.getStats();

    return createResponse(200, {
      status: 'healthy',
      database: 'connected',
      totalAnalyses: stats.totalAnalyses,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    return createResponse(503, {
      status: 'unhealthy',
      database: 'disconnected',
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Convert indicators to STIX 2.1 format
 */
function convertToSTIX(
  indicators: Array<{
    indicatorType: string;
    indicatorValue: string;
    confidenceScore: number;
    severity: string;
    firstSeenAt: Date;
    lastSeenAt: Date;
  }>
): Record<string, unknown> {
  const stixObjects = indicators.map((ind, index) => ({
    type: 'indicator',
    spec_version: '2.1',
    id: `indicator--${crypto.randomUUID?.() ?? `ind-${index}`}`,
    created: ind.firstSeenAt,
    modified: ind.lastSeenAt,
    name: `${ind.indicatorType}: ${ind.indicatorValue}`,
    description: `Phishing indicator - ${ind.indicatorType}`,
    indicator_types: ['malicious-activity', 'phishing'],
    pattern: buildSTIXPattern(ind.indicatorType, ind.indicatorValue),
    pattern_type: 'stix',
    valid_from: ind.firstSeenAt,
    confidence: Math.round(ind.confidenceScore * 100),
    labels: [ind.severity, 'phishing'],
  }));

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID?.() ?? 'export'}`,
    objects: stixObjects,
  };
}

/**
 * Build STIX pattern for indicator
 */
function buildSTIXPattern(type: string, value: string): string {
  switch (type) {
    case 'domain':
      return `[domain-name:value = '${value}']`;
    case 'ip':
      return `[ipv4-addr:value = '${value}']`;
    case 'url':
      return `[url:value = '${value}']`;
    case 'email':
      return `[email-addr:value = '${value}']`;
    case 'hash': {
      const [hashType, hashValue] = value.split(':');
      return `[file:hashes.'${hashType?.toUpperCase() ?? 'SHA-256'}' = '${hashValue ?? value}']`;
    }
    default:
      return `[x-phishy-indicator:value = '${value}']`;
  }
}

/**
 * Convert indicators to CSV format
 */
function convertToCSV(
  indicators: Array<{
    indicatorType: string;
    indicatorValue: string;
    confidenceScore: number;
    severity: string;
    timesSeen: number;
    firstSeenAt: Date;
    lastSeenAt: Date;
  }>
): string {
  const headers = [
    'type',
    'value',
    'confidence',
    'severity',
    'times_seen',
    'first_seen',
    'last_seen',
  ];

  const rows = indicators.map(ind => [
    ind.indicatorType,
    `"${ind.indicatorValue.replace(/"/g, '""')}"`,
    ind.confidenceScore.toFixed(4),
    ind.severity,
    ind.timesSeen,
    ind.firstSeenAt.toISOString(),
    ind.lastSeenAt.toISOString(),
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

/**
 * Create API response
 */
function createResponse(
  statusCode: number,
  body: unknown,
  additionalHeaders?: Record<string, string>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      ...additionalHeaders,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

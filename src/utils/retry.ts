/**
 * Retry utility with exponential backoff
 */

import { createLogger } from './logger';

const logger = createLogger('retry');

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  shouldRetry?: (error: Error) => boolean;
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
};

/**
 * Calculate exponential backoff delay with jitter
 */
function calculateDelay(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt - 1);
  const jitter = Math.random() * 0.1 * exponentialDelay;
  return Math.min(exponentialDelay + jitter, maxDelayMs);
}

/**
 * Sleep for a specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute a function with retry logic and exponential backoff
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      logger.warn(`Attempt ${attempt} of ${opts.maxRetries} failed`, {
        error: lastError.message,
        attempt,
        maxRetries: opts.maxRetries,
      });

      // Check if we should retry this error
      if (opts.shouldRetry && !opts.shouldRetry(lastError)) {
        logger.info('Error is not retryable, throwing immediately');
        throw lastError;
      }

      // Don't wait after the last attempt
      if (attempt < opts.maxRetries) {
        const delay = calculateDelay(attempt, opts.baseDelayMs, opts.maxDelayMs);
        logger.debug(`Waiting ${delay}ms before retry`);
        await sleep(delay);
      }
    }
  }

  throw lastError ?? new Error('All retry attempts failed');
}

/**
 * Default retry predicate for HTTP errors
 * Returns true for errors that should be retried (5xx, timeout, network errors)
 */
export function isRetryableHttpError(error: Error): boolean {
  const message = error.message.toLowerCase();

  // Network errors
  if (message.includes('econnrefused') ||
      message.includes('econnreset') ||
      message.includes('etimedout') ||
      message.includes('socket hang up') ||
      message.includes('network')) {
    return true;
  }

  // Check for status codes in error message or response
  const statusMatch = message.match(/status[:\s]*(\d{3})/i);
  if (statusMatch) {
    const status = parseInt(statusMatch[1], 10);
    // Retry on 5xx errors and 429 (rate limit)
    if (status >= 500 || status === 429 || status === 529) {
      return true;
    }
    // Don't retry on 4xx errors (except 429)
    if (status >= 400 && status < 500) {
      return false;
    }
  }

  // If error mentions "overloaded" or "capacity", retry
  if (message.includes('overload') || message.includes('capacity')) {
    return true;
  }

  return true; // Default to retry for unknown errors
}

/**
 * Create a retry wrapper with predefined options
 */
export function createRetryWrapper(options: Partial<RetryOptions> = {}): <T>(fn: () => Promise<T>) => Promise<T> {
  return <T>(fn: () => Promise<T>) => withRetry(fn, options);
}

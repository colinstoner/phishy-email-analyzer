/**
 * Shared pieces of the Graph read operations: result bounding and response
 * validation.
 *
 * Every operation is read-only (GET), code-driven (CLAUDE.md invariant 6)
 * and bounded: collections always carry an item cap and a page cap, and
 * report `truncated` when a cap cut the result short so the caller can
 * disclose it (invariant 5).
 */

import { z } from 'zod';
import { GraphClient } from './graph.client';
import { GraphError } from './graph.errors';
import { GraphPath } from './graph.request';

/** A bounded collection result */
export interface BoundedResult<T> {
  items: T[];
  /** True when a cap stopped collection while Graph still had more */
  truncated: boolean;
}

/** Resolve a caller's item cap against an operation's default and ceiling */
export function resolveMaxItems(
  requested: number | undefined,
  fallback: number,
  ceiling: number
): number {
  const value = requested ?? fallback;
  if (!Number.isInteger(value) || value < 1 || value > ceiling) {
    throw new Error(`maxItems must be an integer between 1 and ${ceiling}`);
  }
  return value;
}

/**
 * Validate response items against a schema. A response that does not match
 * is an `invalid_response` error; the offending content is never echoed.
 */
export function parseItems<T>(
  client: GraphClient,
  path: GraphPath,
  schema: z.ZodType<T>,
  items: unknown[]
): T[] {
  return items.map(item => parseItem(client, path, schema, item));
}

export function parseItem<T>(
  client: GraphClient,
  path: GraphPath,
  schema: z.ZodType<T>,
  item: unknown
): T {
  const parsed = schema.safeParse(item);
  if (!parsed.success) {
    throw new GraphError(
      `Graph ${client.label} GET ${path.template} failed: response did not have the expected shape`,
      { kind: 'invalid_response', label: client.label, method: 'GET', pathTemplate: path.template }
    );
  }
  return parsed.data;
}

/** Require a `from <= to` pair of valid dates */
export function assertWindow(from: Date, to: Date): void {
  if (
    !(from instanceof Date) ||
    !(to instanceof Date) ||
    Number.isNaN(from.getTime()) ||
    Number.isNaN(to.getTime())
  ) {
    throw new Error('time window bounds must be valid dates');
  }
  if (from.getTime() > to.getTime()) {
    throw new Error('time window start must not be after its end');
  }
}

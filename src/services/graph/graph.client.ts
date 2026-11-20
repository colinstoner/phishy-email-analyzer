/**
 * Microsoft Graph HTTP client
 *
 * A deliberately small client over `fetch`. Its job is less to be convenient
 * than to make unsafe requests unrepresentable:
 *
 * - The base URL is fixed (`https://graph.microsoft.com/v1.0`). Callers pass
 *   a `GraphPath` and typed query options — never a URL.
 * - `@odata.nextLink` is followed only on the Graph origin, and paging is
 *   capped by the caller, so a response cannot redirect or loop the client.
 * - Redirects are refused; response sizes are bounded; every request has a
 *   timeout; retries are bounded and honour `Retry-After`.
 * - One client holds one credential (one app registration), identified by a
 *   label. Read and write access are separate clients by construction.
 * - Response bodies are never logged: mailbox content is hostile data. The
 *   access token never appears in errors or logs.
 *
 * Graph is called by Phishy's code only. It is not an agentic tool and the
 * model never authors a path, filter or query (CLAUDE.md invariant 6).
 */

import { randomUUID } from 'crypto';
import { createLogger } from '../../utils/logger';
import { GraphAccessTokenProvider } from './graph.auth';
import { GraphError, GraphFailureKind } from './graph.errors';
import { GraphPath, GraphQuery, buildRequestUrl, parseNextLink } from './graph.request';

const logger = createLogger('graph-client');

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_MAX_RETRY_AFTER_MS = 20000;
const DEFAULT_BASE_DELAY_MS = 500;
const MAX_BACKOFF_MS = 8000;
const DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_RAW_BYTES = 40 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES = 64 * 1024;
const MAX_ERROR_DETAIL_CHARS = 500;

export interface GraphClientOptions {
  /** Supplies access tokens for this client's single credential */
  tokenProvider: GraphAccessTokenProvider;
  /** Injected for tests; defaults to the global `fetch` */
  fetchImpl?: typeof fetch;
  /** Injected for tests; defaults to a timer-based sleep */
  sleep?: (ms: number) => Promise<void>;
  /** Per-attempt timeout covering headers and body (default 15s) */
  timeoutMs?: number;
  /** Total attempts per request, including the first (default 3) */
  maxAttempts?: number;
  /** Longest `Retry-After` the client will wait out (default 20s) */
  maxRetryAfterMs?: number;
  /** First backoff delay for retries without `Retry-After` (default 500ms) */
  baseDelayMs?: number;
}

export interface GraphRequestOptions {
  query?: GraphQuery;
  /** Sends `ConsistencyLevel: eventual` (needed for `$count` and advanced filters) */
  consistencyLevel?: 'eventual';
  /** Sends `Prefer: IdType="ImmutableId"` so message IDs survive folder moves */
  immutableIds?: boolean;
  /** Overrides the client's per-attempt timeout */
  timeoutMs?: number;
  /** Largest response body accepted, in bytes */
  maxBytes?: number;
  /**
   * Caller's deadline. Once aborted, the request in flight is cancelled and
   * no further attempt or page is sent; the failure is reported as a timeout.
   */
  signal?: AbortSignal;
}

export interface GraphPostOptions extends GraphRequestOptions {
  /**
   * Set only when repeating the POST is harmless (a query-style POST). When
   * false (the default) a POST is retried on 429 — which Graph answers
   * before doing any work — but never after a timeout or a 5xx, where the
   * request may already have taken effect.
   */
  idempotent?: boolean;
}

export interface GraphPagingOptions extends GraphRequestOptions {
  /** Most pages to request. Required: the caller owns the bound. */
  maxPages: number;
  /** Most items to return across all pages */
  maxItems?: number;
}

/**
 * Where the next page of a collection is, as handed out by `getPage`. Opaque:
 * the URL it stands for is held privately by this module, was validated as a
 * Graph next link when it was received, and cannot be set by a caller.
 */
export interface GraphPageCursor {
  readonly __graphPageCursor: true;
}

const pageCursors = new WeakMap<GraphPageCursor, { url: URL; pathTemplate: string }>();

/** One page of a collection and, when Graph has more, where the next one is */
export interface GraphPage<T> {
  items: T[];
  next?: GraphPageCursor;
}

export interface GraphPagedResult<T> {
  items: T[];
  /** Pages actually requested */
  pages: number;
  /**
   * True when a cap stopped collection while Graph still had more. Callers
   * must treat the result as partial (and disclose that wherever it is used).
   */
  truncated: boolean;
}

interface ExecuteRequest {
  method: 'GET' | 'POST';
  url: URL;
  pathTemplate: string;
  accept: string;
  body?: string;
  retryTransient: boolean;
  maxBytes: number;
  options: GraphRequestOptions;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** The `request-id` response header, kept only when it looks like an identifier */
function readRequestId(response: Response): string | undefined {
  const value = response.headers.get('request-id');
  return value && /^[A-Za-z0-9-]{1,64}$/.test(value) ? value : undefined;
}

/**
 * Parse a `Retry-After` header (delta-seconds or an HTTP date) into
 * milliseconds from now
 */
export function parseRetryAfter(
  header: string | null,
  nowMs: number = Date.now()
): number | undefined {
  if (!header) {
    return undefined;
  }
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10) * 1000;
  }
  // Date.parse is lenient ("-5" is a year); accept only the HTTP-date shape
  const dateMs = /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} /.test(trimmed) ? Date.parse(trimmed) : NaN;
  if (Number.isNaN(dateMs)) {
    return undefined;
  }
  return Math.max(0, dateMs - nowMs);
}

export class GraphClient {
  /** Label of the credential this client acts as (e.g. `read`) */
  readonly label: string;

  private readonly tokenProvider: GraphAccessTokenProvider;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly maxRetryAfterMs: number;
  private readonly baseDelayMs: number;

  constructor(options: GraphClientOptions) {
    this.tokenProvider = options.tokenProvider;
    this.label = options.tokenProvider.label;
    this.fetchImpl = options.fetchImpl ?? ((input, init): Promise<Response> => fetch(input, init));
    this.sleep = options.sleep ?? defaultSleep;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxAttempts = Math.max(1, options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? DEFAULT_MAX_RETRY_AFTER_MS;
    this.baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  }

  /**
   * GET a JSON resource
   */
  async getJson<T = unknown>(path: GraphPath, options: GraphRequestOptions = {}): Promise<T> {
    const url = this.buildUrl('GET', path, options.query);
    return this.getJsonFromUrl<T>(url, path.template, options);
  }

  /**
   * GET a resource as raw bytes (e.g. `/messages/{id}/$value` MIME content).
   * The bytes are hostile data: parse them, never log them.
   */
  async getBytes(path: GraphPath, options: GraphRequestOptions = {}): Promise<Buffer> {
    const url = this.buildUrl('GET', path, options.query);
    return this.execute({
      method: 'GET',
      url,
      pathTemplate: path.template,
      accept: '*/*',
      retryTransient: true,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_RAW_BYTES,
      options,
    });
  }

  /**
   * GET a resource as UTF-8 text. Same handling rules as `getBytes`.
   */
  async getText(path: GraphPath, options: GraphRequestOptions = {}): Promise<string> {
    return (await this.getBytes(path, options)).toString('utf8');
  }

  /**
   * POST a JSON body and parse the JSON response (undefined when the
   * response has no content)
   */
  async postJson<T = unknown>(
    path: GraphPath,
    body: unknown,
    options: GraphPostOptions = {}
  ): Promise<T | undefined> {
    const url = this.buildUrl('POST', path, options.query);
    const payload = await this.execute({
      method: 'POST',
      url,
      pathTemplate: path.template,
      accept: 'application/json',
      body: JSON.stringify(body),
      retryTransient: options.idempotent === true,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_JSON_BYTES,
      options,
    });
    if (payload.length === 0) {
      return undefined;
    }
    return this.parseJson<T>(payload, 'POST', path.template);
  }

  /**
   * GET a collection, following `@odata.nextLink` until it runs out or a
   * caller-supplied cap is reached. A next link that leaves the Graph origin
   * is an error, not a page.
   */
  async getPaged<T = unknown>(
    path: GraphPath,
    options: GraphPagingOptions
  ): Promise<GraphPagedResult<T>> {
    const { maxPages, maxItems } = options;
    if (!Number.isInteger(maxPages) || maxPages < 1) {
      throw this.requestError('GET', path.template, 'maxPages must be a positive integer');
    }
    if (maxItems !== undefined && (!Number.isInteger(maxItems) || maxItems < 1)) {
      throw this.requestError('GET', path.template, 'maxItems must be a positive integer');
    }

    const items: T[] = [];
    let url: URL | undefined = this.buildUrl('GET', path, options.query);
    let pages = 0;

    while (url && pages < maxPages) {
      const page: Record<string, unknown> = await this.getJsonFromUrl<Record<string, unknown>>(
        url,
        path.template,
        options
      );
      pages++;

      const values = page?.value;
      if (!Array.isArray(values)) {
        throw new GraphError(
          `Graph ${this.label} GET ${path.template} failed: collection response has no value array`,
          {
            kind: 'invalid_response',
            label: this.label,
            method: 'GET',
            pathTemplate: path.template,
          }
        );
      }

      const rawNext = page['@odata.nextLink'];
      const hasNext = rawNext !== undefined && rawNext !== null;

      const room = maxItems === undefined ? values.length : maxItems - items.length;
      items.push(...(values.slice(0, room) as T[]));
      if (maxItems !== undefined && items.length >= maxItems) {
        return { items, pages, truncated: values.length > room || hasNext };
      }

      if (!hasNext) {
        return { items, pages, truncated: false };
      }

      url = parseNextLink(rawNext);
      if (!url) {
        throw new GraphError(
          `Graph ${this.label} GET ${path.template} failed: next link is not on the Graph origin; paging stopped`,
          {
            kind: 'unsafe_next_link',
            label: this.label,
            method: 'GET',
            pathTemplate: path.template,
          }
        );
      }
    }

    // The page cap was reached with a next link still outstanding
    return { items, pages, truncated: true };
  }

  /**
   * GET one page of a collection: the first (no `cursor`) or the one a
   * previous call's `next` points to. For callers that must treat each page
   * as its own request (to retry one page, or to count pages against a
   * budget). The cursor must come from a page of the same `path`; the next
   * link it stands for was checked against the Graph origin when received.
   */
  async getPage<T = unknown>(
    path: GraphPath,
    options: GraphRequestOptions & { cursor?: GraphPageCursor } = {}
  ): Promise<GraphPage<T>> {
    let url: URL;
    if (options.cursor) {
      const held = pageCursors.get(options.cursor);
      if (!held || held.pathTemplate !== path.template) {
        throw this.requestError('GET', path.template, 'page cursor does not belong to this path');
      }
      url = held.url;
    } else {
      url = this.buildUrl('GET', path, options.query);
    }

    const page = await this.getJsonFromUrl<Record<string, unknown>>(url, path.template, options);
    const values = page?.value;
    if (!Array.isArray(values)) {
      throw new GraphError(
        `Graph ${this.label} GET ${path.template} failed: collection response has no value array`,
        { kind: 'invalid_response', label: this.label, method: 'GET', pathTemplate: path.template }
      );
    }
    const rawNext = page['@odata.nextLink'];
    if (rawNext === undefined || rawNext === null) {
      return { items: values as T[] };
    }
    const nextUrl = parseNextLink(rawNext);
    if (!nextUrl) {
      throw new GraphError(
        `Graph ${this.label} GET ${path.template} failed: next link is not on the Graph origin; paging stopped`,
        {
          kind: 'unsafe_next_link',
          label: this.label,
          method: 'GET',
          pathTemplate: path.template,
        }
      );
    }
    const next = Object.freeze({}) as GraphPageCursor;
    pageCursors.set(next, { url: nextUrl, pathTemplate: path.template });
    return { items: values as T[], next };
  }

  private buildUrl(method: string, path: GraphPath, query?: GraphQuery): URL {
    try {
      return buildRequestUrl(path, query);
    } catch (error) {
      throw this.requestError(
        method,
        path instanceof GraphPath ? path.template : undefined,
        error instanceof Error ? error.message : 'invalid request'
      );
    }
  }

  private requestError(
    method: string,
    pathTemplate: string | undefined,
    reason: string
  ): GraphError {
    return new GraphError(
      `Graph ${this.label} ${method} ${pathTemplate ?? '(invalid path)'} not sent: ${reason}`,
      { kind: 'invalid_request', label: this.label, method, pathTemplate }
    );
  }

  private async getJsonFromUrl<T>(
    url: URL,
    pathTemplate: string,
    options: GraphRequestOptions
  ): Promise<T> {
    const payload = await this.execute({
      method: 'GET',
      url,
      pathTemplate,
      accept: 'application/json',
      retryTransient: true,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_JSON_BYTES,
      options,
    });
    return this.parseJson<T>(payload, 'GET', pathTemplate);
  }

  private parseJson<T>(payload: Buffer, method: string, pathTemplate: string): T {
    try {
      return JSON.parse(payload.toString('utf8')) as T;
    } catch {
      throw new GraphError(
        `Graph ${this.label} ${method} ${pathTemplate} failed: response was not valid JSON`,
        { kind: 'invalid_response', label: this.label, method, pathTemplate }
      );
    }
  }

  private backoffMs(attempt: number): number {
    const exponential = this.baseDelayMs * Math.pow(2, attempt - 1);
    return Math.min(exponential + Math.random() * 0.1 * exponential, MAX_BACKOFF_MS);
  }

  /**
   * Send one logical request, with bounded retries
   */
  private async execute(request: ExecuteRequest): Promise<Buffer> {
    const { method, url, pathTemplate, options } = request;
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    const clientRequestId = randomUUID();
    const context = { kind: 'http' as GraphFailureKind, label: this.label, method, pathTemplate };
    let reauthenticated = false;

    for (let attempt = 1; ; attempt++) {
      if (options.signal?.aborted) {
        throw new GraphError(
          `Graph ${this.label} ${method} ${pathTemplate} failed: cancelled by the caller's deadline`,
          { ...context, kind: 'timeout', clientRequestId }
        );
      }
      const token = await this.tokenProvider.getToken();
      const lastAttempt = attempt >= this.maxAttempts;

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: request.accept,
        'client-request-id': clientRequestId,
      };
      if (request.body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }
      if (options.consistencyLevel) {
        headers.ConsistencyLevel = options.consistencyLevel;
      }
      if (options.immutableIds) {
        headers.Prefer = 'IdType="ImmutableId"';
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const onCallerAbort = (): void => controller.abort();
      options.signal?.addEventListener('abort', onCallerAbort, { once: true });

      let response: Response;
      let payload: Buffer;
      try {
        response = await this.fetchImpl(url, {
          method,
          headers,
          body: request.body,
          redirect: 'error',
          signal: controller.signal,
        });
        payload = await this.readBody(
          response,
          response.ok ? request.maxBytes : MAX_ERROR_BODY_BYTES,
          response.ok,
          { ...context, status: response.status, clientRequestId }
        );
      } catch (error) {
        if (error instanceof GraphError) {
          throw error;
        }
        // The underlying error is dropped on purpose: only its class matters,
        // and nothing about the request (headers included) may leak through it
        const timedOut = controller.signal.aborted;
        const failure = new GraphError(
          timedOut
            ? `Graph ${this.label} ${method} ${pathTemplate} failed: timed out after ${timeoutMs}ms`
            : `Graph ${this.label} ${method} ${pathTemplate} failed: network error`,
          { ...context, kind: timedOut ? 'timeout' : 'network', clientRequestId }
        );
        if (!request.retryTransient || lastAttempt || options.signal?.aborted) {
          throw failure;
        }
        const waitMs = this.backoffMs(attempt);
        logger.warn('Graph request failed before a response; retrying', {
          label: this.label,
          method,
          path: pathTemplate,
          kind: failure.kind,
          attempt,
          waitMs,
        });
        await this.sleep(waitMs);
        continue;
      } finally {
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', onCallerAbort);
      }

      const requestId = readRequestId(response);

      if (response.ok) {
        logger.debug('Graph request completed', {
          label: this.label,
          method,
          path: pathTemplate,
          status: response.status,
          bytes: payload.length,
          attempt,
          requestId,
        });
        return payload;
      }

      const status = response.status;
      const retryAfterMs = parseRetryAfter(response.headers.get('retry-after'));
      const { code, detail } = this.parseErrorBody(payload);
      const failure = new GraphError(
        `Graph ${this.label} ${method} ${pathTemplate} failed: status ${status}${
          code ? ` ${code}` : ''
        }${requestId ? ` (request-id ${requestId})` : ''}`,
        { ...context, status, code, requestId, clientRequestId, retryAfterMs, detail }
      );

      // A token rejected by Graph may have been revoked or rotated early:
      // get a fresh one, once
      if (status === 401 && !reauthenticated && !lastAttempt) {
        reauthenticated = true;
        this.tokenProvider.invalidate();
        continue;
      }

      const throttled = status === 429;
      const serverError = status >= 500 && status <= 599;
      const retryable = throttled || (serverError && request.retryTransient);
      if (!retryable || lastAttempt) {
        throw failure;
      }

      // Honour the server's wait, but only up to a bound: a longer wait than
      // the caller can afford is a failure now, not a retry sooner than asked
      if (retryAfterMs !== undefined && retryAfterMs > this.maxRetryAfterMs) {
        throw failure;
      }
      const waitMs = retryAfterMs ?? this.backoffMs(attempt);

      logger.warn('Graph request will be retried', {
        label: this.label,
        method,
        path: pathTemplate,
        status,
        code,
        requestId,
        attempt,
        waitMs,
      });
      await this.sleep(waitMs);
    }
  }

  /**
   * Read a response body without letting it grow past a bound. Oversized
   * success bodies are an error; oversized error bodies are simply ignored.
   */
  private async readBody(
    response: Response,
    maxBytes: number,
    strict: boolean,
    context: {
      kind: GraphFailureKind;
      label: string;
      method: string;
      pathTemplate: string;
      status: number;
      clientRequestId: string;
    }
  ): Promise<Buffer> {
    const tooLarge = (): GraphError =>
      new GraphError(
        `Graph ${this.label} ${context.method} ${context.pathTemplate} failed: response exceeds ${maxBytes} bytes`,
        {
          ...context,
          kind: 'response_too_large',
          requestId: readRequestId(response),
        }
      );

    if (!response.body) {
      return Buffer.alloc(0);
    }

    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      await response.body.cancel().catch(() => undefined);
      if (strict) {
        throw tooLarge();
      }
      return Buffer.alloc(0);
    }

    const reader = response.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        if (strict) {
          throw tooLarge();
        }
        return Buffer.alloc(0);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  }

  private parseErrorBody(payload: Buffer): { code?: string; detail?: string } {
    if (payload.length === 0) {
      return {};
    }
    try {
      const parsed = JSON.parse(payload.toString('utf8')) as {
        error?: { code?: unknown; message?: unknown };
      };
      const code = typeof parsed.error?.code === 'string' ? parsed.error.code : undefined;
      const message = typeof parsed.error?.message === 'string' ? parsed.error.message : undefined;
      return {
        // The code is an identifier chosen by Microsoft; anything else is not one
        code: code && /^[A-Za-z0-9_.]{1,100}$/.test(code) ? code : undefined,
        detail: message?.slice(0, MAX_ERROR_DETAIL_CHARS),
      };
    } catch {
      return {};
    }
  }
}

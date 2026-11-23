/**
 * The mailbox write tier's HTTP client: three requests and nothing else.
 *
 * This is deliberately not `GraphClient`. `GraphClient` is the read path and
 * stays a general (GET-and-query) client that never changes a mailbox. This
 * client has no general method at all: its public surface is exactly the
 * three requests the `remove_messages` operation needs, each on a fixed
 * endpoint built by code with `graphPath` from IDs the protocol has already
 * shape-checked:
 *
 *   GET  /users/{mailboxId}/messages/{messageId}?$select=internetMessageId,parentFolderId
 *   GET  /users/{mailboxId}/mailFolders/deleteditems?$select=id
 *   POST /users/{mailboxId}/messages/{messageId}/move   {"destinationId":"deleteditems"}
 *
 * Verified against Microsoft's documentation:
 * - message move: https://learn.microsoft.com/en-us/graph/api/message-move?view=graph-rest-1.0
 *   (`POST /users/{id}/messages/{id}/move`, body `destinationId`: "The
 *   destination folder ID, or a well-known folder name"; `201 Created` with
 *   the moved message; application permission `Mail.ReadWrite`)
 * - well-known folder names: https://learn.microsoft.com/en-us/graph/api/resources/mailfolder?view=graph-rest-1.0
 *   (`deleteditems`: "The folder items are moved to when they're deleted";
 *   usable in place of a folder ID, e.g. `GET /me/mailFolders/drafts`)
 * - get message: https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0
 *
 * There is no delete, no permanent delete, no send, no folder creation, no
 * rule change and no read of any message content: the message `$select`
 * names only `internetMessageId` and `parentFolderId`, and the move's
 * response body (the whole moved message) is discarded unread.
 *
 * Other rules, as for the read client: the base URL is fixed; redirects are
 * refused; every attempt has a timeout and the caller's deadline bounds all
 * retries; `Retry-After` is honoured only when it fits that deadline; the
 * access token and response bodies are never logged or placed in an error.
 * A move is retried only after `429` (Graph throttles before doing any
 * work); after a timeout, a network failure or a `5xx` its effect is
 * unknown, so it is reported as unconfirmed and never repeated.
 */

import { randomUUID } from 'crypto';
import { z } from 'zod';
import { createLogger } from '../../utils/logger';
import { GraphAccessTokenProvider } from '../graph/graph.auth';
import { parseRetryAfter } from '../graph/graph.client';
import { GraphPath, buildRequestUrl, graphPath } from '../graph/graph.request';

const logger = createLogger('graph-write-client');

/** The one destination this tier ever moves a message to (a well-known folder name) */
export const DELETED_ITEMS = 'deleteditems';

const MESSAGE_SELECT = ['internetMessageId', 'parentFolderId'];
const FOLDER_SELECT = ['id'];

const DEFAULT_ATTEMPT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_MAX_RETRY_AFTER_MS = 10_000;
const DEFAULT_BASE_DELAY_MS = 500;
/** The two small JSON objects this client reads */
const MAX_JSON_BYTES = 64 * 1024;
/** Graph IDs and Internet Message-IDs are short; anything longer is not one */
const MAX_ID_LENGTH = 1024;

/** Why a request did not produce an answer. Fixed words; no Graph text. */
export type WriteFailureKind =
  | 'throttled' // 429/503 that could not be waited out within the deadline or attempts
  | 'auth_failed' // no token, or 401 after a fresh token
  | 'forbidden' // 403: permission or application RBAC scope
  | 'timeout' // the attempt or the caller's deadline ran out
  | 'network'
  | 'http' // any other unexpected status
  | 'invalid_response' // a 2xx whose body is not the expected shape
  | 'unconfirmed'; // a move whose effect is unknown (timeout, network or 5xx)

export class GraphWriteRequestError extends Error {
  constructor(
    readonly kind: WriteFailureKind,
    readonly status?: number,
    readonly requestId?: string
  ) {
    super(`Graph write request failed: ${kind}${status ? ` (status ${status})` : ''}`);
    this.name = 'GraphWriteRequestError';
  }
}

export interface GraphWriteClientOptions {
  /** Supplies access tokens for the write credential (and only that one) */
  tokenProvider: GraphAccessTokenProvider;
  /** Injected for tests; defaults to the global `fetch` */
  fetchImpl?: typeof fetch;
  /** Injected for tests */
  sleep?: (ms: number) => Promise<void>;
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
  attemptTimeoutMs?: number;
  maxAttempts?: number;
  maxRetryAfterMs?: number;
  baseDelayMs?: number;
}

export type MessageState =
  { kind: 'found'; internetMessageId?: string; parentFolderId?: string } | { kind: 'not_found' };

const MessageStateSchema = z.object({
  internetMessageId: z.string().max(MAX_ID_LENGTH).nullish(),
  parentFolderId: z.string().max(MAX_ID_LENGTH).nullish(),
});

const FolderSchema = z.object({ id: z.string().min(1).max(MAX_ID_LENGTH) });

/** The only three request shapes this client can make */
type WriteRequest =
  | { shape: 'get_message'; path: GraphPath }
  | { shape: 'get_deleted_items'; path: GraphPath }
  | { shape: 'move_message'; path: GraphPath };

interface Answer {
  status: number;
  body?: Buffer;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function readRequestId(response: Response): string | undefined {
  const value = response.headers.get('request-id');
  return value && /^[A-Za-z0-9-]{1,64}$/.test(value) ? value : undefined;
}

export class GraphWriteClient {
  readonly label: string;

  private readonly tokenProvider: GraphAccessTokenProvider;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly attemptTimeoutMs: number;
  private readonly maxAttempts: number;
  private readonly maxRetryAfterMs: number;
  private readonly baseDelayMs: number;

  constructor(options: GraphWriteClientOptions) {
    this.tokenProvider = options.tokenProvider;
    this.label = options.tokenProvider.label;
    this.fetchImpl = options.fetchImpl ?? ((input, init): Promise<Response> => fetch(input, init));
    this.sleep = options.sleep ?? defaultSleep;
    this.now = options.now ?? ((): number => Date.now());
    this.attemptTimeoutMs = options.attemptTimeoutMs ?? DEFAULT_ATTEMPT_TIMEOUT_MS;
    this.maxAttempts = Math.max(1, options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? DEFAULT_MAX_RETRY_AFTER_MS;
    this.baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  }

  /**
   * Re-read one message's identity and folder. Nothing else about it is
   * requested.
   */
  async getMessageState(
    mailboxId: string,
    messageId: string,
    deadline: number
  ): Promise<MessageState> {
    const answer = await this.send(
      { shape: 'get_message', path: graphPath`/users/${mailboxId}/messages/${messageId}` },
      deadline
    );
    if (answer.status === 404) {
      return { kind: 'not_found' };
    }
    const parsed = MessageStateSchema.safeParse(this.json(answer));
    if (!parsed.success) {
      throw new GraphWriteRequestError('invalid_response', answer.status);
    }
    return {
      kind: 'found',
      ...(parsed.data.internetMessageId
        ? { internetMessageId: parsed.data.internetMessageId }
        : {}),
      ...(parsed.data.parentFolderId ? { parentFolderId: parsed.data.parentFolderId } : {}),
    };
  }

  /**
   * The ID of the mailbox's Deleted Items folder, or `mailbox_not_found`
   * when Graph does not know the mailbox.
   */
  async getDeletedItemsFolderId(
    mailboxId: string,
    deadline: number
  ): Promise<{ kind: 'found'; id: string } | { kind: 'mailbox_not_found' }> {
    const answer = await this.send(
      {
        shape: 'get_deleted_items',
        path: graphPath`/users/${mailboxId}/mailFolders/deleteditems`,
      },
      deadline
    );
    if (answer.status === 404) {
      return { kind: 'mailbox_not_found' };
    }
    const parsed = FolderSchema.safeParse(this.json(answer));
    if (!parsed.success) {
      throw new GraphWriteRequestError('invalid_response', answer.status);
    }
    return { kind: 'found', id: parsed.data.id };
  }

  /**
   * Move one message to Deleted Items. `moved` on `201`; `not_found` on
   * `404` (nothing changed). Throws `unconfirmed` when the effect is unknown.
   */
  async moveToDeletedItems(
    mailboxId: string,
    messageId: string,
    deadline: number
  ): Promise<'moved' | 'not_found'> {
    const answer = await this.send(
      { shape: 'move_message', path: graphPath`/users/${mailboxId}/messages/${messageId}/move` },
      deadline
    );
    return answer.status === 404 ? 'not_found' : 'moved';
  }

  private json(answer: Answer): unknown {
    try {
      return JSON.parse((answer.body ?? Buffer.alloc(0)).toString('utf8'));
    } catch {
      throw new GraphWriteRequestError('invalid_response', answer.status);
    }
  }

  private backoffMs(attempt: number): number {
    return this.baseDelayMs * Math.pow(2, attempt - 1);
  }

  /** One logical request with bounded retries, all inside `deadline` */
  private async send(request: WriteRequest, deadline: number): Promise<Answer> {
    const isMove = request.shape === 'move_message';
    const url = buildRequestUrl(
      request.path,
      request.shape === 'get_message'
        ? { select: MESSAGE_SELECT }
        : request.shape === 'get_deleted_items'
          ? { select: FOLDER_SELECT }
          : undefined
    );
    const method = isMove ? 'POST' : 'GET';
    const clientRequestId = randomUUID();
    let reauthenticated = false;

    for (let attempt = 1; ; attempt++) {
      const remaining = deadline - this.now();
      if (remaining <= 0) {
        throw new GraphWriteRequestError('timeout');
      }

      let token: string;
      try {
        token = await this.tokenProvider.getToken();
      } catch {
        // The token provider's message is free of secrets, but it is not
        // needed here: the fixed word is what the caller acts on
        throw new GraphWriteRequestError('auth_failed');
      }

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'client-request-id': clientRequestId,
      };
      if (isMove) {
        headers['Content-Type'] = 'application/json';
      }

      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(),
        Math.max(1, Math.min(this.attemptTimeoutMs, remaining))
      );
      let response: Response;
      let body: Buffer | undefined;
      try {
        response = await this.fetchImpl(url, {
          method,
          headers,
          ...(isMove ? { body: JSON.stringify({ destinationId: DELETED_ITEMS }) } : {}),
          redirect: 'error',
          signal: controller.signal,
        });
        if (isMove || !response.ok) {
          // The move answers with the whole moved message, content included:
          // never read. Error bodies are not needed (the status decides).
          await response.body?.cancel().catch(() => undefined);
        } else {
          body = await this.readBody(response, controller);
        }
      } catch (error) {
        if (error instanceof GraphWriteRequestError) {
          throw error;
        }
        const timedOut = controller.signal.aborted;
        if (isMove) {
          // The move may have happened: never repeated
          throw new GraphWriteRequestError('unconfirmed');
        }
        if (attempt >= this.maxAttempts || this.now() + this.backoffMs(attempt) >= deadline) {
          throw new GraphWriteRequestError(timedOut ? 'timeout' : 'network');
        }
        await this.sleep(this.backoffMs(attempt));
        continue;
      } finally {
        clearTimeout(timer);
      }

      const status = response.status;
      const requestId = readRequestId(response);
      if ((status >= 200 && status < 300) || status === 404) {
        logger.debug('Graph write request completed', {
          label: this.label,
          request: request.shape,
          path: request.path.template,
          status,
          attempt,
          requestId,
        });
        return { status, body };
      }

      if (status === 401 && !reauthenticated) {
        reauthenticated = true;
        this.tokenProvider.invalidate();
        continue;
      }
      if (status === 401) {
        throw new GraphWriteRequestError('auth_failed', status, requestId);
      }
      if (status === 403) {
        throw new GraphWriteRequestError('forbidden', status, requestId);
      }

      const throttled = status === 429 || status === 503;
      if (isMove && status !== 429) {
        // A 5xx (503 included) on a move: it may have taken effect
        throw new GraphWriteRequestError(status >= 500 ? 'unconfirmed' : 'http', status, requestId);
      }
      if (!throttled && !(status >= 500 && status <= 599)) {
        throw new GraphWriteRequestError('http', status, requestId);
      }

      const retryAfterMs = parseRetryAfter(response.headers.get('retry-after'), this.now());
      const waitMs = retryAfterMs ?? this.backoffMs(attempt);
      const fits =
        attempt < this.maxAttempts &&
        waitMs <= this.maxRetryAfterMs &&
        this.now() + waitMs < deadline;
      if (!fits) {
        throw new GraphWriteRequestError(throttled ? 'throttled' : 'http', status, requestId);
      }
      logger.warn('Graph write request will be retried', {
        label: this.label,
        request: request.shape,
        path: request.path.template,
        status,
        attempt,
        waitMs,
        requestId,
      });
      await this.sleep(waitMs);
    }
  }

  private async readBody(response: Response, controller: AbortController): Promise<Buffer> {
    if (!response.body) {
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
      if (total > MAX_JSON_BYTES) {
        await reader.cancel().catch(() => undefined);
        controller.abort();
        throw new GraphWriteRequestError('invalid_response', response.status);
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  }
}

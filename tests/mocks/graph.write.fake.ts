/**
 * A fake Microsoft Graph tenant for the mailbox write tier: just enough of
 * the three endpoints the write client may call, held in memory, recording
 * every request it receives. Any other request is recorded as unexpected and
 * answered 400, so a test can assert the client never made one.
 *
 * Invented data only: random-looking GUIDs and `example.com` Message-IDs.
 */

import type { GraphAccessTokenProvider } from '../../src/services/graph/graph.auth';
import { subjectKeyHash } from '../../src/services/graph/subject.key';
import type { RemoveMessage } from '../../src/services/graph-write/write.protocol';

/** The defaults every fake message has unless a test says otherwise */
export const SENDER = 'billing@examp1e-billing.test';
export const SUBJECT = 'Invoice 2291 overdue';
export const RECEIVED = '2026-11-17T09:14:00Z';

export interface FakeMessage {
  internetMessageId?: string;
  folderId: string;
  /** null: the stored message has none */
  sender?: string | null;
  subject?: string | null;
  received?: string | null;
}

/** What the write broker is told to expect for one copy (defaults match the fake's) */
export function expectation(
  messageId: string,
  internetMessageId: string,
  extra: Partial<RemoveMessage> = {}
): RemoveMessage {
  return {
    messageId,
    expectedInternetMessageId: internetMessageId,
    expectedSenderAddress: SENDER,
    expectedSubjectSha256: subjectKeyHash(SUBJECT),
    receivedFrom: '2026-11-17T03:14:00.000Z',
    receivedTo: '2026-11-17T15:14:00.000Z',
    ...extra,
  };
}

export interface FakeMailbox {
  deletedItemsId: string;
  messages: Map<string, FakeMessage>;
}

export interface RecordedWriteRequest {
  method: string;
  /** Path under /v1.0, decoded, with the query string */
  path: string;
  /** The path with each data segment replaced by `{}` */
  shape: string;
  query: string;
  body?: unknown;
  authorization?: string;
}

/** A queued answer that replaces the normal one for the next matching request */
export interface Override {
  match: (request: RecordedWriteRequest) => boolean;
  respond: () => Response | Promise<Response>;
}

export const ALLOWED_SHAPES = [
  'GET /users/{}/messages/{}?$select=internetMessageId,parentFolderId,from,subject,receivedDateTime',
  'GET /users/{}/mailFolders/deleteditems?$select=id',
  'POST /users/{}/messages/{}/move',
];

export function json(
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export class FakeWriteTenant {
  readonly mailboxes = new Map<string, FakeMailbox>();
  readonly requests: RecordedWriteRequest[] = [];
  readonly unexpected: RecordedWriteRequest[] = [];
  readonly overrides: Override[] = [];
  private moves = 0;

  addMailbox(mailboxId: string, messages: Record<string, FakeMessage> = {}): FakeMailbox {
    const mailbox: FakeMailbox = {
      deletedItemsId: `deleted-folder-${mailboxId.slice(0, 8)}`,
      messages: new Map(Object.entries(messages)),
    };
    this.mailboxes.set(mailboxId.toLowerCase(), mailbox);
    return mailbox;
  }

  /** The next request matching `match` gets `respond()` instead of the normal answer */
  once(match: (request: RecordedWriteRequest) => boolean, respond: () => Response): void {
    this.overrides.push({ match, respond });
  }

  /** Every recorded request as `METHOD shape` (data segments blanked) */
  shapes(): string[] {
    return this.requests.map(r => `${r.method} ${r.shape}${r.query ? `?${r.query}` : ''}`);
  }

  readonly fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    const raw = url.pathname.replace(/^\/v1\.0/, '');
    const segments = raw.split('/').map(decodeURIComponent);
    const query = decodeURIComponent(url.search.replace(/^\?/, ''));
    const shape = shapeOf(segments);
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const request: RecordedWriteRequest = {
      method,
      path: segments.join('/'),
      shape,
      query,
      ...(typeof init?.body === 'string' ? { body: JSON.parse(init.body) } : {}),
      authorization: headers.Authorization,
    };
    this.requests.push(request);

    if (url.origin !== 'https://graph.microsoft.com' || init?.redirect !== 'error') {
      this.unexpected.push(request);
      return json(400, { error: { code: 'BadRequest' } });
    }
    const index = this.overrides.findIndex(o => o.match(request));
    if (index >= 0) {
      const [override] = this.overrides.splice(index, 1);
      return override.respond();
    }
    const signature = `${method} ${shape}${query ? `?${query}` : ''}`;
    if (!ALLOWED_SHAPES.includes(signature)) {
      this.unexpected.push(request);
      return json(400, { error: { code: 'BadRequest' } });
    }

    const mailbox = this.mailboxes.get(segments[2].toLowerCase());
    if (!mailbox) {
      return json(404, { error: { code: 'ErrorInvalidUser', message: 'secret mailbox text' } });
    }
    if (segments[3] === 'mailFolders') {
      return json(200, { id: mailbox.deletedItemsId });
    }
    const message = mailbox.messages.get(segments[4]);
    if (!message) {
      return json(404, { error: { code: 'ErrorItemNotFound', message: 'secret item text' } });
    }
    if (method === 'GET') {
      const sender = message.sender === undefined ? SENDER : message.sender;
      return json(200, {
        internetMessageId: message.internetMessageId ?? null,
        parentFolderId: message.folderId,
        from: sender === null ? null : { emailAddress: { name: 'Accounts', address: sender } },
        subject: message.subject === undefined ? SUBJECT : message.subject,
        receivedDateTime: message.received === undefined ? RECEIVED : message.received,
      });
    }
    if ((request.body as { destinationId?: string })?.destinationId !== 'deleteditems') {
      this.unexpected.push(request);
      return json(400, { error: { code: 'BadRequest' } });
    }
    // A move gives the message a new ID in Deleted Items, as Exchange does
    mailbox.messages.delete(segments[4]);
    this.moves += 1;
    mailbox.messages.set(`moved-${this.moves}`, { ...message, folderId: mailbox.deletedItemsId });
    return json(201, {
      id: `moved-${this.moves}`,
      subject: 'BODY-CONTENT-MARKER should never be read',
      body: { content: 'BODY-CONTENT-MARKER' },
    });
  };
}

function shapeOf(segments: string[]): string {
  // ['', 'users', id, 'messages', id, 'move'?] or ['', 'users', id, 'mailFolders', 'deleteditems']
  const parts = segments.slice(1).map((segment, index) => {
    if (index === 1) {
      return '{}';
    }
    if (segments[3] === 'messages' && index === 3) {
      return '{}';
    }
    return segment;
  });
  return `/${parts.join('/')}`;
}

export function fakeTokenProvider(): GraphAccessTokenProvider & {
  invalidate: jest.Mock;
  getToken: jest.Mock;
} {
  let n = 0;
  return {
    label: 'write',
    getToken: jest.fn(async () => {
      n += 1;
      return `write-token-${n}`;
    }),
    invalidate: jest.fn(),
  };
}

/** Deterministic GUIDs for tests */
export const MAILBOX_ID = (n: number): string =>
  `${String(n).padStart(8, '0')}-2222-4333-8444-555555555555`;
export const ACTION_ID = '0f0e0d0c-0b0a-4908-8706-050403020100';
export const IMID = (n: number): string => `<campaign-${n}@mail.example.com>`;

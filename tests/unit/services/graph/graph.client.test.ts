/**
 * Graph client tests: fixed base URL, paging safety, throttling, timeouts,
 * typed errors. fetch is mocked; no network.
 */

import {
  GraphAccessTokenProvider,
  GraphClient,
  GraphClientOptions,
  GraphError,
  GraphPath,
  graphPath,
  odataFilter,
  parseRetryAfter,
} from '../../../../src/services/graph';

const ACCESS_TOKEN = 'test-access-token-5b21e8';
const BASE = 'https://graph.microsoft.com/v1.0';
const REQUEST_ID = '0a1b2c3d-1111-4222-8333-444455556666';

type FetchCall = [URL, RequestInit];
type FetchMock = jest.Mock<Promise<Response>, FetchCall>;
type Responder = (url: URL, init: RequestInit) => Response | Promise<Response>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'request-id': REQUEST_ID, ...headers },
  });
}

function graphFailure(status: number, code: string, message: string, headers = {}): Response {
  return json({ error: { code, message } }, status, headers);
}

function fetchSequence(...responders: Responder[]): FetchMock {
  const mock = jest.fn<Promise<Response>, FetchCall>();
  responders.forEach(responder =>
    mock.mockImplementationOnce((url, init) => Promise.resolve(responder(url, init)))
  );
  mock.mockImplementation(() => Promise.reject(new Error('unexpected fetch call')));
  return mock;
}

interface Harness {
  client: GraphClient;
  fetchMock: FetchMock;
  sleeps: number[];
  tokens: { getToken: jest.Mock<Promise<string>, []>; invalidate: jest.Mock<void, []> };
}

function harness(fetchMock: FetchMock, options: Partial<GraphClientOptions> = {}): Harness {
  const sleeps: number[] = [];
  const tokens = {
    getToken: jest.fn(() => Promise.resolve(ACCESS_TOKEN)),
    invalidate: jest.fn(),
  };
  const tokenProvider: GraphAccessTokenProvider = { label: 'read', ...tokens };
  const client = new GraphClient({
    tokenProvider,
    fetchImpl: fetchMock as unknown as typeof fetch,
    sleep: ms => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    ...options,
  });
  return { client, fetchMock, sleeps, tokens };
}

function headersOf(call: FetchCall): Record<string, string> {
  return call[1].headers as Record<string, string>;
}

async function failure(promise: Promise<unknown>): Promise<GraphError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(GraphError);
  return error as GraphError;
}

const messagesPath = graphPath`/users/${'reporter@example.com'}/messages`;

describe('GraphClient requests', () => {
  it('GETs JSON from the fixed base URL with a bearer token', async () => {
    const { client, fetchMock } = harness(fetchSequence(() => json({ id: 'abc' })));

    const result = await client.getJson<{ id: string }>(
      graphPath`/users/${'reporter@example.com'}/messages/${'AAMk/AD+x='}`,
      { query: { select: ['id', 'subject'] } }
    );

    expect(result).toEqual({ id: 'abc' });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.href).toBe(
      `${BASE}/users/reporter%40example.com/messages/AAMk%2FAD%2Bx%3D?$select=id%2Csubject`
    );
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('error');
    expect(init.body).toBeUndefined();
    expect(headersOf(fetchMock.mock.calls[0])).toMatchObject({
      Authorization: `Bearer ${ACCESS_TOKEN}`,
      Accept: 'application/json',
    });
    expect(headersOf(fetchMock.mock.calls[0])['client-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('sends a filter built from hostile input as one encoded parameter', async () => {
    const { client, fetchMock } = harness(fetchSequence(() => json({ value: [] })));
    const hostile = "x' or 1 eq 1&$select=body#";

    await client.getJson(messagesPath, { query: { filter: odataFilter`subject eq ${hostile}` } });

    const url = fetchMock.mock.calls[0][0];
    expect(url.origin).toBe('https://graph.microsoft.com');
    expect(url.pathname).toBe('/v1.0/users/reporter%40example.com/messages');
    expect(url.hash).toBe('');
    expect([...url.searchParams.keys()]).toEqual(['$filter']);
    expect(url.searchParams.get('$filter')).toBe("subject eq 'x'' or 1 eq 1&$select=body#'");
  });

  it('refuses anything that is not a GraphPath, before any request', async () => {
    const { client, fetchMock, tokens } = harness(fetchSequence());

    const error = await failure(
      client.getJson('https://evil.example.com/v1.0/me' as unknown as GraphPath)
    );

    expect(error.kind).toBe('invalid_request');
    expect(error.message).toContain('never a URL');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(tokens.getToken).not.toHaveBeenCalled();
  });

  it('rejects an invalid query before any request', async () => {
    const { client, fetchMock } = harness(fetchSequence());
    const error = await failure(client.getJson(messagesPath, { query: { top: 5000 } }));
    expect(error.kind).toBe('invalid_request');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('adds the optional headers only when asked', async () => {
    const { client, fetchMock } = harness(
      fetchSequence(
        () => json({}),
        () => json({})
      )
    );
    await client.getJson(messagesPath);
    await client.getJson(messagesPath, { consistencyLevel: 'eventual', immutableIds: true });

    expect(headersOf(fetchMock.mock.calls[0]).ConsistencyLevel).toBeUndefined();
    expect(headersOf(fetchMock.mock.calls[0]).Prefer).toBeUndefined();
    expect(headersOf(fetchMock.mock.calls[1]).ConsistencyLevel).toBe('eventual');
    expect(headersOf(fetchMock.mock.calls[1]).Prefer).toBe('IdType="ImmutableId"');
  });

  it('GETs raw bytes and text (MIME content)', async () => {
    const mime = 'From: sender@example.com\r\nSubject: Café\r\n\r\nbody';
    const { client, fetchMock } = harness(
      fetchSequence(
        () => new Response(Buffer.from(mime, 'utf8'), { status: 200 }),
        () => new Response(Buffer.from(mime, 'utf8'), { status: 200 })
      )
    );
    const path = graphPath`/users/${'reporter@example.com'}/messages/${'id-1'}/$value`;

    const bytes = await client.getBytes(path);
    expect(Buffer.isBuffer(bytes)).toBe(true);
    expect(bytes.equals(Buffer.from(mime, 'utf8'))).toBe(true);
    expect(await client.getText(path)).toBe(mime);

    expect(fetchMock.mock.calls[0][0].href).toBe(
      `${BASE}/users/reporter%40example.com/messages/id-1/$value`
    );
    expect(headersOf(fetchMock.mock.calls[0]).Accept).toBe('*/*');
  });

  it('POSTs a JSON body', async () => {
    const { client, fetchMock } = harness(fetchSequence(() => json({ value: [1] })));
    const body = { requests: [{ entityTypes: ['message'] }] };

    const result = await client.postJson(graphPath`/search/query`, body);

    expect(result).toEqual({ value: [1] });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url.href).toBe(`${BASE}/search/query`);
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify(body));
    expect(headersOf(fetchMock.mock.calls[0])['Content-Type']).toBe('application/json');
  });

  it('returns undefined for a POST with no response content', async () => {
    const { client } = harness(fetchSequence(() => new Response(null, { status: 204 })));
    await expect(client.postJson(graphPath`/things`, {})).resolves.toBeUndefined();
  });

  it('reports a success body that is not JSON', async () => {
    const { client } = harness(fetchSequence(() => new Response('<html>', { status: 200 })));
    const error = await failure(client.getJson(messagesPath));
    expect(error.kind).toBe('invalid_response');
  });

  it('exposes the credential label', () => {
    expect(harness(fetchSequence()).client.label).toBe('read');
  });
});

describe('GraphClient paging', () => {
  const page = (ids: number[], next?: string): Responder => {
    return () =>
      json({ value: ids.map(id => ({ id })), ...(next ? { '@odata.nextLink': next } : {}) });
  };
  const NEXT_1 = `${BASE}/users/reporter%40example.com/messages?$skiptoken=page2`;
  const NEXT_2 = `${BASE}/users/reporter%40example.com/messages?$skiptoken=page3`;

  it('follows next links on the Graph origin until they run out', async () => {
    const { client, fetchMock } = harness(
      fetchSequence(page([1, 2], NEXT_1), page([3, 4], NEXT_2), page([5]))
    );

    const result = await client.getPaged<{ id: number }>(messagesPath, {
      query: { top: 2 },
      maxPages: 10,
    });

    expect(result.items.map(item => item.id)).toEqual([1, 2, 3, 4, 5]);
    expect(result).toMatchObject({ pages: 3, truncated: false });
    expect(fetchMock.mock.calls.map(call => call[0].href)).toEqual([
      `${BASE}/users/reporter%40example.com/messages?$top=2`,
      NEXT_1,
      NEXT_2,
    ]);
    // The token goes only to the Graph origin
    for (const call of fetchMock.mock.calls) {
      expect(call[0].origin).toBe('https://graph.microsoft.com');
    }
  });

  it.each([
    ['another host', 'https://evil.example.com/v1.0/users/x/messages?$skiptoken=a'],
    ['a lookalike host', 'https://graph.microsoft.com.evil.example.com/v1.0/x'],
    ['userinfo hiding the host', 'https://graph.microsoft.com@evil.example.com/v1.0/x'],
    ['plain http', 'http://graph.microsoft.com/v1.0/x'],
    ['another API version', 'https://graph.microsoft.com/beta/x'],
    ['a non-string', 42 as unknown as string],
  ])('stops with an error when the next link is %s', async (_name, nextLink) => {
    const { client, fetchMock } = harness(fetchSequence(page([1], nextLink)));

    const error = await failure(client.getPaged(messagesPath, { maxPages: 5 }));

    expect(error.kind).toBe('unsafe_next_link');
    expect(error.message).not.toContain('evil.example.com');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('stops at the page cap even if every page has a next link', async () => {
    const endless = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.resolve(page([1], NEXT_1)(new URL(BASE), {}))
    );
    const { client } = harness(endless);

    const result = await client.getPaged(messagesPath, { maxPages: 3 });

    expect(endless).toHaveBeenCalledTimes(3);
    expect(result).toMatchObject({ pages: 3, truncated: true });
    expect(result.items).toHaveLength(3);
  });

  it('asks before each further page and stops, truncated, when refused', async () => {
    const { client, fetchMock } = harness(
      fetchSequence(page([1, 2], NEXT_1), page([3, 4], NEXT_2), page([5]))
    );
    let allowed = 1;
    const beforeNextPage = jest.fn(() => allowed-- > 0);

    const result = await client.getPaged<{ id: number }>(messagesPath, {
      maxPages: 10,
      beforeNextPage,
    });

    // Asked before page 2 (allowed) and page 3 (refused); never before page 1
    expect(beforeNextPage).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.items.map(item => item.id)).toEqual([1, 2, 3, 4]);
    expect(result).toMatchObject({ pages: 2, truncated: true });
  });

  it('stops at the item cap and reports truncation', async () => {
    const { client, fetchMock } = harness(fetchSequence(page([1, 2, 3], NEXT_1), page([4, 5, 6])));

    const result = await client.getPaged<{ id: number }>(messagesPath, {
      maxPages: 10,
      maxItems: 4,
    });

    expect(result.items.map(item => item.id)).toEqual([1, 2, 3, 4]);
    expect(result.truncated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not report truncation when the cap is met exactly at the end', async () => {
    const { client } = harness(fetchSequence(page([1, 2])));
    const result = await client.getPaged(messagesPath, { maxPages: 1, maxItems: 2 });
    expect(result).toMatchObject({ pages: 1, truncated: false });
  });

  it('requires sane caps', async () => {
    const { client, fetchMock } = harness(fetchSequence());
    for (const options of [
      { maxPages: 0 },
      { maxPages: 1.5 },
      { maxPages: Infinity },
      { maxPages: 2, maxItems: 0 },
    ]) {
      expect((await failure(client.getPaged(messagesPath, options))).kind).toBe('invalid_request');
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a collection response without a value array', async () => {
    const { client } = harness(fetchSequence(() => json({ value: 'nope' })));
    expect((await failure(client.getPaged(messagesPath, { maxPages: 2 }))).kind).toBe(
      'invalid_response'
    );
  });
});

describe('GraphClient throttling and retries', () => {
  it('waits out Retry-After on 429 and then succeeds', async () => {
    const { client, fetchMock, sleeps } = harness(
      fetchSequence(
        () => graphFailure(429, 'TooManyRequests', 'slow down', { 'Retry-After': '7' }),
        () => json({ ok: true })
      )
    );

    await expect(client.getJson(messagesPath)).resolves.toEqual({ ok: true });
    expect(sleeps).toEqual([7000]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // Same logical request: the client-request-id is stable across attempts
    expect(headersOf(fetchMock.mock.calls[0])['client-request-id']).toBe(
      headersOf(fetchMock.mock.calls[1])['client-request-id']
    );
  });

  it('honours Retry-After on 503', async () => {
    const { client, sleeps } = harness(
      fetchSequence(
        () => graphFailure(503, 'serviceNotAvailable', 'busy', { 'Retry-After': '2' }),
        () => json({ ok: true })
      )
    );
    await client.getJson(messagesPath);
    expect(sleeps).toEqual([2000]);
  });

  it('fails immediately when Retry-After exceeds the maximum wait', async () => {
    const { client, fetchMock, sleeps } = harness(
      fetchSequence(() =>
        graphFailure(429, 'TooManyRequests', 'slow down', { 'Retry-After': '600' })
      ),
      { maxRetryAfterMs: 20000 }
    );

    const error = await failure(client.getJson(messagesPath));

    expect(error.status).toBe(429);
    expect(error.retryAfterMs).toBe(600000);
    expect(sleeps).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('gives up after a bounded number of attempts', async () => {
    const always429 = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.resolve(graphFailure(429, 'TooManyRequests', 'slow down', { 'Retry-After': '1' }))
    );
    const { client, sleeps } = harness(always429, { maxAttempts: 4 });

    const error = await failure(client.getJson(messagesPath));

    expect(error.status).toBe(429);
    expect(always429).toHaveBeenCalledTimes(4);
    expect(sleeps).toEqual([1000, 1000, 1000]);
  });

  it('backs off exponentially on 5xx without Retry-After', async () => {
    const { client, fetchMock, sleeps } = harness(
      fetchSequence(
        () => graphFailure(500, 'generalException', 'oops'),
        () => graphFailure(502, 'BadGateway', 'oops'),
        () => json({ ok: true })
      ),
      { baseDelayMs: 100 }
    );

    await expect(client.getJson(messagesPath)).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(sleeps).toHaveLength(2);
    expect(sleeps[0]).toBeGreaterThanOrEqual(100);
    expect(sleeps[0]).toBeLessThanOrEqual(110);
    expect(sleeps[1]).toBeGreaterThanOrEqual(200);
    expect(sleeps[1]).toBeLessThanOrEqual(220);
  });

  it('does not retry client errors', async () => {
    const { client, fetchMock, sleeps } = harness(
      fetchSequence(() => graphFailure(404, 'ErrorItemNotFound', 'not found'))
    );
    const error = await failure(client.getJson(messagesPath));
    expect(error.status).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sleeps).toEqual([]);
  });

  it('refreshes the token once on 401', async () => {
    const { client, fetchMock, tokens } = harness(
      fetchSequence(
        () => graphFailure(401, 'InvalidAuthenticationToken', 'expired'),
        () => json({ ok: true })
      )
    );
    await expect(client.getJson(messagesPath)).resolves.toEqual({ ok: true });
    expect(tokens.invalidate).toHaveBeenCalledTimes(1);
    expect(tokens.getToken).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not loop on repeated 401s', async () => {
    const always401 = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.resolve(graphFailure(401, 'InvalidAuthenticationToken', 'no'))
    );
    const { client, tokens } = harness(always401, { maxAttempts: 5 });
    const error = await failure(client.getJson(messagesPath));
    expect(error.status).toBe(401);
    expect(always401).toHaveBeenCalledTimes(2);
    expect(tokens.invalidate).toHaveBeenCalledTimes(1);
  });

  it('retries a POST on 429 but not on 5xx unless marked idempotent', async () => {
    const throttled = harness(
      fetchSequence(
        () => graphFailure(429, 'TooManyRequests', 'slow', { 'Retry-After': '1' }),
        () => json({ ok: true })
      )
    );
    await expect(throttled.client.postJson(graphPath`/things`, {})).resolves.toEqual({ ok: true });

    const unsafe = harness(fetchSequence(() => graphFailure(503, 'serviceNotAvailable', 'busy')));
    expect((await failure(unsafe.client.postJson(graphPath`/things`, {}))).status).toBe(503);
    expect(unsafe.fetchMock).toHaveBeenCalledTimes(1);

    const safe = harness(
      fetchSequence(
        () => graphFailure(503, 'serviceNotAvailable', 'busy'),
        () => json({ ok: true })
      )
    );
    await expect(
      safe.client.postJson(graphPath`/search/query`, {}, { idempotent: true })
    ).resolves.toEqual({ ok: true });
  });

  it('retries a network failure for GET', async () => {
    const { client, fetchMock } = harness(
      fetchSequence(
        () => Promise.reject(new Error('socket hang up')),
        () => json({ ok: true })
      )
    );
    await expect(client.getJson(messagesPath)).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('reports a persistent network failure as a typed error', async () => {
    const down = jest.fn<Promise<Response>, FetchCall>(() =>
      Promise.reject(new Error(`ECONNRESET while sending Bearer ${ACCESS_TOKEN}`))
    );
    const { client } = harness(down, { maxAttempts: 2 });
    const error = await failure(client.getJson(messagesPath));
    expect(error.kind).toBe('network');
    expect(error.status).toBeUndefined();
    expect(error.message).toBe('Graph read GET /users/{}/messages failed: network error');
    expect(down).toHaveBeenCalledTimes(2);
  });
});

describe('parseRetryAfter', () => {
  it('parses delta-seconds', () => {
    expect(parseRetryAfter('0')).toBe(0);
    expect(parseRetryAfter(' 12 ')).toBe(12000);
  });

  it('parses an HTTP date relative to now', () => {
    const now = Date.parse('2026-03-01T00:00:00Z');
    expect(parseRetryAfter('Sun, 01 Mar 2026 00:00:30 GMT', now)).toBe(30000);
    expect(parseRetryAfter('Sun, 01 Mar 2026 00:00:00 GMT', now + 5000)).toBe(0);
  });

  it('ignores missing or unparseable values', () => {
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('')).toBeUndefined();
    expect(parseRetryAfter('soon')).toBeUndefined();
    expect(parseRetryAfter('-5')).toBeUndefined();
  });
});

describe('GraphClient timeouts and size bounds', () => {
  const hang: Responder = (_url, init) =>
    new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener('abort', () => reject(new Error('This operation was aborted')));
    });

  it('aborts a request that exceeds the timeout', async () => {
    const hung = jest.fn<Promise<Response>, FetchCall>((url, init) =>
      Promise.resolve(hang(url, init))
    );
    const { client } = harness(hung, { timeoutMs: 15, maxAttempts: 1 });

    const error = await failure(client.getJson(messagesPath));

    expect(error.kind).toBe('timeout');
    expect(error.message).toBe('Graph read GET /users/{}/messages failed: timed out after 15ms');
    expect(hung.mock.calls[0][1].signal!.aborted).toBe(true);
  });

  it('applies the timeout to a stalled body, not just the headers', async () => {
    const stalled = jest.fn<Promise<Response>, FetchCall>((_url, init) => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(Buffer.from('{"value":'));
          init.signal!.addEventListener('abort', () => controller.error(new Error('aborted')));
        },
      });
      return Promise.resolve(new Response(body, { status: 200 }));
    });
    const { client } = harness(stalled, { timeoutMs: 15, maxAttempts: 1 });
    expect((await failure(client.getJson(messagesPath))).kind).toBe('timeout');
  });

  it('retries a timed-out GET but never a timed-out POST', async () => {
    const getHarness = harness(
      fetchSequence(hang, () => json({ ok: true })),
      { timeoutMs: 15 }
    );
    await expect(getHarness.client.getJson(messagesPath)).resolves.toEqual({ ok: true });

    const postMock = jest.fn<Promise<Response>, FetchCall>((url, init) =>
      Promise.resolve(hang(url, init))
    );
    const postHarness = harness(postMock, { timeoutMs: 15 });
    expect((await failure(postHarness.client.postJson(graphPath`/things`, {}))).kind).toBe(
      'timeout'
    );
    expect(postMock).toHaveBeenCalledTimes(1);
  });

  it('lets a request override the timeout', async () => {
    const hung = jest.fn<Promise<Response>, FetchCall>((url, init) =>
      Promise.resolve(hang(url, init))
    );
    const { client } = harness(hung, { timeoutMs: 60000, maxAttempts: 1 });
    const error = await failure(client.getJson(messagesPath, { timeoutMs: 10 }));
    expect(error.message).toContain('timed out after 10ms');
  });

  it('rejects a body larger than the bound, by declared length', async () => {
    const { client, fetchMock } = harness(
      fetchSequence(
        () => new Response('x'.repeat(200), { status: 200, headers: { 'Content-Length': '200' } })
      )
    );
    const error = await failure(
      client.getBytes(graphPath`/users/${'a@example.com'}/messages/${'id'}/$value`, {
        maxBytes: 100,
      })
    );
    expect(error.kind).toBe('response_too_large');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('rejects a body larger than the bound when the length is not declared', async () => {
    const { client } = harness(
      fetchSequence(() => {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(Buffer.alloc(80, 0x61));
            controller.enqueue(Buffer.alloc(80, 0x61));
            controller.close();
          },
        });
        return new Response(body, { status: 200 });
      })
    );
    const error = await failure(client.getJson(messagesPath, { maxBytes: 100 }));
    expect(error.kind).toBe('response_too_large');
  });
});

describe('GraphClient errors', () => {
  it('carries status, Graph error code and request id', async () => {
    const { client } = harness(
      fetchSequence(() => graphFailure(403, 'ErrorAccessDenied', 'Access is denied.'))
    );

    const error = await failure(
      client.getJson(graphPath`/users/${'someone@example.com'}/messages/${'secret-message-id'}`)
    );

    expect(error.name).toBe('GraphError');
    expect(error.kind).toBe('http');
    expect(error.status).toBe(403);
    expect(error.code).toBe('ErrorAccessDenied');
    expect(error.requestId).toBe(REQUEST_ID);
    expect(error.clientRequestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(error.label).toBe('read');
    expect(error.method).toBe('GET');
    expect(error.pathTemplate).toBe('/users/{}/messages/{}');
    expect(error.message).toBe(
      `Graph read GET /users/{}/messages/{} failed: status 403 ErrorAccessDenied (request-id ${REQUEST_ID})`
    );
  });

  it('keeps data segments out of the message', async () => {
    const { client } = harness(fetchSequence(() => graphFailure(404, 'ErrorItemNotFound', 'x')));
    const error = await failure(
      client.getJson(graphPath`/users/${'someone@example.com'}/messages/${'secret-message-id'}`)
    );
    expect(error.message).not.toContain('someone@example.com');
    expect(error.message).not.toContain('secret-message-id');
  });

  it('keeps Graph’s free-text message off the error message and out of serialization', async () => {
    const echoed = "Invalid filter clause: subject eq 'URGENT wire transfer <hostile text>'";
    const { client } = harness(fetchSequence(() => graphFailure(400, 'BadRequest', echoed)));

    const error = await failure(client.getJson(messagesPath));

    expect(error.detail).toBe(echoed);
    expect(error.message).not.toContain('hostile text');
    expect(JSON.stringify(error)).not.toContain('hostile text');
    expect(JSON.stringify({ ...error })).not.toContain('hostile text');
    expect(Object.keys(error)).not.toContain('detail');
  });

  it('truncates the detail and ignores codes that are not identifiers', async () => {
    const { client } = harness(
      fetchSequence(() => graphFailure(400, 'Bad Request <script>', 'y'.repeat(5000)))
    );
    const error = await failure(client.getJson(messagesPath));
    expect(error.code).toBeUndefined();
    expect(error.detail).toHaveLength(500);
    expect(error.message).toBe(
      `Graph read GET /users/{}/messages failed: status 400 (request-id ${REQUEST_ID})`
    );
  });

  it('tolerates error responses with no body, a non-JSON body or an oversized body', async () => {
    const { client } = harness(
      fetchSequence(
        () => new Response(null, { status: 404 }),
        () => new Response('<html>gateway</html>', { status: 400 }),
        () => new Response('z'.repeat(70 * 1024), { status: 400 })
      )
    );
    for (const status of [404, 400, 400]) {
      const error = await failure(client.getJson(messagesPath));
      expect(error.status).toBe(status);
      expect(error.code).toBeUndefined();
      expect(error.requestId).toBeUndefined();
    }
  });

  it('drops a request-id header that is not an identifier', async () => {
    const { client } = harness(
      fetchSequence(() => json({ error: { code: 'X' } }, 400, { 'request-id': 'bad id; drop' }))
    );
    expect((await failure(client.getJson(messagesPath))).requestId).toBeUndefined();
  });

  it('never puts the access token in an error', async () => {
    const responders: Responder[] = [
      () => graphFailure(403, 'ErrorAccessDenied', `token was Bearer ${ACCESS_TOKEN}`),
      () => Promise.reject(new Error(`failed with header Bearer ${ACCESS_TOKEN}`)),
      () => new Response('<html>', { status: 200 }),
    ];
    for (const responder of responders) {
      const { client } = harness(fetchSequence(responder), { maxAttempts: 1 });
      const error = await failure(client.getJson(messagesPath));
      const visible = `${error.message}\n${error.stack}\n${JSON.stringify(error)}`;
      expect(visible).not.toContain(ACCESS_TOKEN);
      expect(visible).not.toContain('Bearer');
    }
  });

  it('propagates a token failure unchanged', async () => {
    const { client, tokens, fetchMock } = harness(fetchSequence());
    const authFailure = new Error('Graph read token request rejected: status 401 invalid_client');
    tokens.getToken.mockRejectedValueOnce(authFailure);
    await expect(client.getJson(messagesPath)).rejects.toBe(authFailure);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

/**
 * A fake Microsoft Graph for tests: a real `GraphClient` over a mocked
 * `fetch` that records every request and answers from a route table.
 * No network. Invented data only.
 */

import { GraphAccessTokenProvider, GraphClient } from '../../src/services/graph';

export const FAKE_BASE = 'https://graph.microsoft.com/v1.0';

export interface RecordedRequest {
  method: string;
  url: URL;
  /** Path below /v1.0, still percent-encoded */
  path: string;
  /** Query parameters, decoded */
  query: Record<string, string>;
  headers: Record<string, string>;
}

export type FakeResponder = (request: RecordedRequest) => Response | undefined;

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function graphErrorResponse(status: number, code: string, message = 'denied'): Response {
  return jsonResponse({ error: { code, message } }, status);
}

export function collection(items: unknown[], nextLink?: string): Response {
  return jsonResponse(nextLink ? { value: items, '@odata.nextLink': nextLink } : { value: items });
}

/** An unsigned JWT-shaped token carrying the given roles */
export function fakeToken(roles: string[] | undefined): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ roles, tid: 'tenant-claim-not-for-output' })}.c2ln`;
}

export interface FakeGraph {
  client: GraphClient;
  requests: RecordedRequest[];
  fetchMock: jest.Mock<Promise<Response>, [URL | string, RequestInit | undefined]>;
  token: string;
}

/**
 * Build a client whose requests are answered by the first responder that
 * returns a response. Unmatched requests get a 404 `UnmatchedInFake`.
 */
export function fakeGraph(responders: FakeResponder[], roles: string[] = []): FakeGraph {
  const requests: RecordedRequest[] = [];
  const token = fakeToken(roles);

  const fetchMock = jest.fn<Promise<Response>, [URL | string, RequestInit | undefined]>(
    (input, init) => {
      const url = new URL(String(input));
      const request: RecordedRequest = {
        method: init?.method ?? 'GET',
        url,
        path: url.pathname.replace(/^\/v1\.0/, ''),
        query: Object.fromEntries(
          url.search
            .slice(1)
            .split('&')
            .filter(part => part !== '')
            .map(part => {
              const at = part.indexOf('=');
              return [part.slice(0, at), decodeURIComponent(part.slice(at + 1))];
            })
        ),
        headers: (init?.headers ?? {}) as Record<string, string>,
      };
      requests.push(request);
      for (const responder of responders) {
        const response = responder(request);
        if (response) {
          return Promise.resolve(response);
        }
      }
      return Promise.resolve(graphErrorResponse(404, 'UnmatchedInFake'));
    }
  );

  const tokenProvider: GraphAccessTokenProvider = {
    label: 'read',
    getToken: () => Promise.resolve(token),
    invalidate: () => undefined,
  };
  const client = new GraphClient({
    tokenProvider,
    fetchImpl: fetchMock as unknown as typeof fetch,
    sleep: () => Promise.resolve(),
    maxAttempts: 1,
  });
  return { client, requests, fetchMock, token };
}

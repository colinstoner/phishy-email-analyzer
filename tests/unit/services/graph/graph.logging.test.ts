/**
 * Graph logging hygiene: with logging at its most verbose, nothing secret
 * (private key, certificate, client assertion, access token) and no response
 * body content may reach the log output.
 *
 * Loggers capture their level at module load, so the Graph modules are
 * loaded fresh here with LOG_LEVEL=debug.
 */

import { TestCertificate, generateTestCertificate } from '../../../mocks/graph.testcert';

type GraphModule = typeof import('../../../../src/services/graph');

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:000000000000:secret:phishy/graph-read-AbCdEf';
const ACCESS_TOKEN = 'test-access-token-c0ffee1234';
const BODY_MARKER = 'HOSTILE-MAIL-BODY-MARKER';

describe('Graph log output', () => {
  const originalLevel = process.env.LOG_LEVEL;
  let graph: GraphModule;
  let testCert: TestCertificate;

  beforeAll(async () => {
    process.env.LOG_LEVEL = 'debug';
    jest.resetModules();
    graph = await import('../../../../src/services/graph');
    testCert = generateTestCertificate({
      // Close to expiry, so the rotation warning is exercised too
      notAfter: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
    });
  });

  afterAll(() => {
    process.env.LOG_LEVEL = originalLevel;
    jest.resetModules();
  });

  it('never contains secrets or response bodies, even at debug level', async () => {
    const lines: string[] = [];
    const capture = (...args: unknown[]): void => {
      lines.push(args.map(String).join(' '));
    };
    jest.spyOn(console, 'log').mockImplementation(capture);
    jest.spyOn(console, 'warn').mockImplementation(capture);
    jest.spyOn(console, 'error').mockImplementation(capture);

    const assertions: string[] = [];
    const graphResponses: Array<() => Response> = [
      (): Response =>
        new Response(JSON.stringify({ value: [{ subject: BODY_MARKER }] }), {
          status: 200,
          headers: { 'request-id': 'req-1' },
        }),
      (): Response =>
        new Response(JSON.stringify({ error: { code: 'TooManyRequests', message: BODY_MARKER } }), {
          status: 429,
          headers: { 'Retry-After': '1', 'request-id': 'req-2' },
        }),
      (): Response =>
        new Response(`Subject: ${BODY_MARKER}\r\n\r\n${BODY_MARKER}`, { status: 200 }),
      (): Response =>
        new Response(
          JSON.stringify({ error: { code: 'ErrorAccessDenied', message: BODY_MARKER } }),
          {
            status: 403,
            headers: { 'request-id': 'req-4' },
          }
        ),
    ];
    let tokenCalls = 0;

    const fetchMock = jest.fn((url: URL | string, init: RequestInit) => {
      if (String(url).startsWith('https://login.microsoftonline.com/')) {
        assertions.push(new URLSearchParams(init.body as string).get('client_assertion') ?? '');
        tokenCalls++;
        // First token request fails, to exercise the auth retry log line
        return Promise.resolve(
          tokenCalls === 1
            ? new Response(JSON.stringify({ error: 'temporarily_unavailable' }), { status: 503 })
            : new Response(JSON.stringify({ expires_in: 3600, access_token: ACCESS_TOKEN }))
        );
      }
      const next = graphResponses.shift();
      return next ? Promise.resolve(next()) : Promise.reject(new Error('unexpected fetch call'));
    });

    const client = graph.createGraphClient(
      { label: 'read', tenantId: TENANT_ID, clientId: CLIENT_ID, certificate: SECRET_ARN },
      {
        fetchSecret: () => Promise.resolve(testCert.bundlePem),
        tokenOptions: { fetchImpl: fetchMock as unknown as typeof fetch, baseDelayMs: 1 },
        clientOptions: {
          fetchImpl: fetchMock as unknown as typeof fetch,
          sleep: () => Promise.resolve(),
        },
      }
    );

    const messages = graph.graphPath`/users/${'reporter@example.com'}/messages`;
    const errors: Error[] = [];

    await client.getPaged(messages, { maxPages: 1 });
    await client.getText(graph.graphPath`/users/${'reporter@example.com'}/messages/${'id'}/$value`);
    await client.getJson(messages).catch((error: Error) => errors.push(error));

    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(graph.GraphError);
    expect(graphResponses).toHaveLength(0);
    expect(assertions).toHaveLength(2);

    const output = [
      ...lines,
      ...errors.map(error => `${error.message}\n${error.stack}\n${JSON.stringify(error)}`),
    ].join('\n');

    // The scenario really did log: token acquisition, a retry, completions
    expect(output).toContain('Graph access token acquired');
    expect(output).toContain('Graph request will be retried');
    expect(output).toContain('Graph request completed');
    expect(output).toContain('Graph certificate expires soon');

    // Full-width base64 lines only: a short final line could match by chance
    const pemLines = (pem: string): string[] => pem.split('\n').filter(line => line.length === 64);
    const keyBody = pemLines(testCert.privateKeyPem);
    const certBody = pemLines(testCert.certificatePem);
    expect(keyBody.length).toBeGreaterThan(10);
    expect(certBody.length).toBeGreaterThan(5);
    const forbidden = [
      ACCESS_TOKEN,
      'Bearer',
      BODY_MARKER,
      'PRIVATE KEY',
      'BEGIN CERTIFICATE',
      ...keyBody,
      ...certBody,
      ...assertions,
      ...assertions.map(assertion => assertion.split('.')[2]),
      'reporter@example.com',
    ];
    for (const secret of forbidden) {
      expect(secret.length).toBeGreaterThan(0);
      expect(output).not.toContain(secret);
    }
  });
});

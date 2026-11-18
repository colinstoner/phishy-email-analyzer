/**
 * Graph probe CLI: argument parsing, credential handling, output and exit
 * codes. fetch and the file system are injected; no network.
 */

import {
  EXIT_CREDENTIAL,
  EXIT_OK,
  EXIT_USAGE,
  ProbeIo,
  USAGE,
  UsageError,
  parseProbeArgs,
  renderJson,
  renderText,
  runCli,
} from '../../../src/cli/graph-probe.main';
import { ProbeReport } from '../../../src/cli/graph-probe.checks';
import { FakeResponder, RecordedRequest, fakeToken, jsonResponse } from '../../mocks/graph.fake';
import { TestCertificate, generateTestCertificate } from '../../mocks/graph.testcert';
import { IDENTIFIERS, MARKERS, TENANT, workingTenant } from '../../mocks/graph.tenant';

const TENANT_ID = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb';
const CLIENT_ID = 'cccccccc-4444-4555-8666-dddddddddddd';
const CREDS = ['--tenant-id', TENANT_ID, '--client-id', CLIENT_ID, '--certificate', 'bundle.pem'];

describe('parseProbeArgs', () => {
  it('parses every option', () => {
    expect(
      parseProbeArgs([
        ...CREDS,
        '--mailbox',
        ' reporter@example.com ',
        '--message-id',
        '<a@example.net>',
        '--show-identifiers',
        '--json',
      ])
    ).toEqual({
      help: false,
      tenantId: TENANT_ID,
      clientId: CLIENT_ID,
      certificatePath: 'bundle.pem',
      certificateSetting: undefined,
      mailbox: 'reporter@example.com',
      messageId: '<a@example.net>',
      showIdentifiers: true,
      json: true,
    });
  });

  it('falls back to the environment variables, flags winning', () => {
    const env = {
      PHISHY_GRAPH_TENANT_ID: 'example.com',
      PHISHY_GRAPH_READ_CLIENT_ID: CLIENT_ID,
      PHISHY_GRAPH_READ_CERTIFICATE: 'inline-pem-setting',
    };
    expect(parseProbeArgs([], env)).toMatchObject({
      tenantId: 'example.com',
      clientId: CLIENT_ID,
      certificatePath: undefined,
      certificateSetting: 'inline-pem-setting',
      showIdentifiers: false,
      json: false,
    });
    expect(parseProbeArgs(['--tenant-id', TENANT_ID], env).tenantId).toBe(TENANT_ID);
  });

  it('accepts --help without anything else', () => {
    expect(parseProbeArgs(['--help']).help).toBe(true);
    expect(parseProbeArgs(['-h']).help).toBe(true);
  });

  it.each<[string, string[], string]>([
    ['missing tenant', ['--client-id', CLIENT_ID, '--certificate', 'x.pem'], '--tenant-id'],
    ['bad tenant', ['--tenant-id', 'not a tenant', '--client-id', CLIENT_ID], 'GUID or a domain'],
    ['missing client', ['--tenant-id', TENANT_ID, '--certificate', 'x.pem'], '--client-id'],
    ['bad client', ['--tenant-id', TENANT_ID, '--client-id', 'nope'], 'client) GUID'],
    ['missing certificate', ['--tenant-id', TENANT_ID, '--client-id', CLIENT_ID], '--certificate'],
    ['mailbox with spaces', [...CREDS, '--mailbox', 'a b@example.com'], '--mailbox'],
    ['message id without mailbox', [...CREDS, '--message-id', '<a@example.net>'], 'needs --mailbox'],
    [
      'oversized message id',
      [...CREDS, '--mailbox', 'a@example.com', '--message-id', 'x'.repeat(999)],
      'too long',
    ],
    ['unknown option', [...CREDS, '--delete-everything'], 'unknown option'],
    ['positional argument', [...CREDS, 'stray'], 'unexpected argument'],
    ['option without value', ['--tenant-id'], 'missing its value'],
  ])('rejects %s', (_name, argv, message) => {
    expect(() => parseProbeArgs(argv, {})).toThrow(UsageError);
    expect(() => parseProbeArgs(argv, {})).toThrow(message);
  });

  it('never echoes a value in a usage error', () => {
    try {
      parseProbeArgs(['--tenant-id', 'SECRET VALUE', '--client-id', CLIENT_ID], {});
      throw new Error('expected a usage error');
    } catch (error) {
      expect((error as Error).message).not.toContain('SECRET');
    }
  });
});

describe('rendering', () => {
  const report: ProbeReport = {
    generatedAt: '2026-11-17T12:00:00.000Z',
    identifiersShown: false,
    tokenAcquired: true,
    summary: { pass: 1, fail: 1, skipped: 1 },
    checks: [
      { id: 'a', name: 'Alpha', question: 'Does alpha work?', permissions: [], status: 'PASS', detail: 'yes' },
      {
        id: 'b',
        name: 'Beta',
        question: 'Does beta work?',
        permissions: ['Mail.Read'],
        status: 'FAIL',
        detail: 'permission missing or not consented: needs Mail.Read (HTTP 403 ErrorAccessDenied)',
        httpStatus: 403,
        errorCode: 'ErrorAccessDenied',
      },
      {
        id: 'c',
        name: 'Gamma',
        question: 'Does gamma work?',
        permissions: ['User.Read.All', 'Directory.Read.All'],
        status: 'SKIPPED',
        detail: 'no --mailbox given',
      },
    ],
  };

  it('prints a table of result, check, question and detail', () => {
    expect(renderText(report)).toBe(
      [
        'RESULT   CHECK',
        '         question / detail',
        '-'.repeat(72),
        'PASS     Alpha',
        '         Q: Does alpha work?',
        '         -> yes',
        'FAIL     Beta',
        '         Q: Does beta work?',
        '         -> permission missing or not consented: needs Mail.Read (HTTP 403 ErrorAccessDenied)',
        '         needs: Mail.Read',
        'SKIPPED  Gamma',
        '         Q: Does gamma work?',
        '         -> no --mailbox given',
        '         needs: User.Read.All or Directory.Read.All',
        '-'.repeat(72),
        '1 passed, 1 failed, 1 skipped',
        'Addresses, subjects and message IDs are shown as per-run hashes.',
      ].join('\n')
    );
  });

  it('colours only when asked', () => {
    expect(renderText(report)).not.toContain('\x1b[');
    expect(renderText(report, true)).toContain('\x1b[31mFAIL');
  });

  it('prints the same report as JSON', () => {
    const parsed = JSON.parse(renderJson(report)) as ProbeReport & { probeVersion: number };
    expect(parsed.probeVersion).toBe(1);
    expect(parsed.summary).toEqual(report.summary);
    expect(parsed.checks[1]).toEqual(report.checks[1]);
  });
});

describe('runCli', () => {
  let testCert: TestCertificate;
  const accessToken = fakeToken(['Mail.Read', 'User.Read.All']);

  beforeAll(() => {
    testCert = generateTestCertificate();
  });

  interface Harness {
    io: ProbeIo;
    out: string[];
    err: string[];
    calls: { method: string; url: string; body?: string }[];
  }

  function harness(options: { tokenStatus?: number; file?: string | Error } = {}): Harness {
    const out: string[] = [];
    const err: string[] = [];
    const calls: Harness['calls'] = [];
    const graph: FakeResponder = workingTenant;

    const fetchImpl = jest.fn((input: URL | string, init?: RequestInit) => {
      const url = new URL(String(input));
      calls.push({ method: init?.method ?? 'GET', url: url.href, body: init?.body as string });
      if (url.origin === 'https://login.microsoftonline.com') {
        return Promise.resolve(
          options.tokenStatus
            ? jsonResponse({ error: 'invalid_client', error_codes: [700027] }, options.tokenStatus)
            : jsonResponse({ access_token: accessToken, expires_in: 3600 })
        );
      }
      const request: RecordedRequest = {
        method: init?.method ?? 'GET',
        url,
        path: url.pathname.replace(/^\/v1\.0/, ''),
        query: Object.fromEntries(
          [...url.searchParams.entries()].map(([key, value]) => [key, value])
        ),
        headers: (init?.headers ?? {}) as Record<string, string>,
      };
      return Promise.resolve(graph(request) ?? jsonResponse({ error: { code: 'NotFound' } }, 404));
    });

    const file = options.file ?? testCert.bundlePem;
    return {
      out,
      err,
      calls,
      io: {
        stdout: text => out.push(text),
        stderr: text => err.push(text),
        env: {},
        readTextFile: () => (file instanceof Error ? Promise.reject(file) : Promise.resolve(file)),
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    };
  }

  it('prints usage for --help', async () => {
    const h = harness();
    expect(await runCli(['--help'], h.io)).toBe(EXIT_OK);
    expect(h.out).toEqual([USAGE]);
    expect(h.calls).toHaveLength(0);
  });

  it('exits 2 on a usage error, before any request', async () => {
    const h = harness();
    expect(await runCli(['--mailbox', 'reporter@example.com'], h.io)).toBe(EXIT_USAGE);
    expect(h.err[0]).toContain('Error: --tenant-id');
    expect(h.err[0]).toContain('Usage: npm run graph:probe');
    expect(h.out).toHaveLength(0);
    expect(h.calls).toHaveLength(0);
  });

  it.each<[string, string | Error, string]>([
    ['an unreadable file', new Error('ENOENT: /secret/path/key.pem'), 'could not be read'],
    ['a file that is not PEM', 'arn:aws:secretsmanager:us-east-1:000000000000:secret:x', 'does not contain PEM'],
    ['a certificate without its key', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', 'PRIVATE KEY'],
  ])('exits 1 for %s, before any request', async (_name, file, message) => {
    const h = harness({ file });
    expect(await runCli([...CREDS, '--json'], h.io)).toBe(EXIT_CREDENTIAL);
    expect(h.err[0]).toContain('Credential error:');
    expect(h.err[0]).toContain(message);
    expect(h.err.join('')).not.toContain('/secret/path');
    expect(h.out).toHaveLength(0);
    expect(h.calls).toHaveLength(0);
  });

  it('exits 1 when the token is refused, after printing the report', async () => {
    const h = harness({ tokenStatus: 401 });
    expect(await runCli([...CREDS, '--json'], h.io)).toBe(EXIT_CREDENTIAL);
    const report = JSON.parse(h.out[0]) as ProbeReport;
    expect(report.tokenAcquired).toBe(false);
    expect(report.checks[0]).toMatchObject({ id: 'token', status: 'FAIL', errorCode: 'invalid_client' });
    expect(report.summary.skipped).toBe(report.checks.length - 1);
    expect(h.err[0]).toContain('no access token');
    expect(h.calls.every(call => call.url.startsWith('https://login.microsoftonline.com/'))).toBe(true);
  });

  it('runs end to end: one token POST, then GETs only, exit 0', async () => {
    const h = harness();
    const code = await runCli([...CREDS, '--mailbox', TENANT.mailbox, '--json'], h.io);
    expect(code).toBe(EXIT_OK);
    expect(h.err).toHaveLength(0);

    const report = JSON.parse(h.out[0]) as ProbeReport;
    expect(report.summary).toEqual({ pass: 17, fail: 1, skipped: 0 });
    expect(report.checks[0].detail).toBe(
      'token acquired; application roles: Mail.Read, User.Read.All'
    );

    const posts = h.calls.filter(call => call.method !== 'GET');
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`);
    const graphCalls = h.calls.filter(call => call.url.startsWith('https://graph.microsoft.com/v1.0/'));
    expect(graphCalls.length).toBe(h.calls.length - 1);
    expect(graphCalls.every(call => call.method === 'GET')).toBe(true);
  });

  it('never prints the token, the assertion, the key or mailbox content', async () => {
    const h = harness();
    await runCli([...CREDS, '--mailbox', TENANT.mailbox], h.io);
    await runCli([...CREDS, '--mailbox', TENANT.mailbox, '--json'], h.io);
    const output = [...h.out, ...h.err].join('\n');

    const assertion = new URLSearchParams(h.calls[0].body).get('client_assertion') as string;
    expect(assertion.split('.')).toHaveLength(3);
    const keyBody = testCert.privateKeyPem.split('\n')[1];
    for (const secret of [accessToken, assertion, keyBody, ...Object.values(MARKERS), ...IDENTIFIERS]) {
      expect(output).not.toContain(secret);
    }
    expect(output).toContain('RESULT   CHECK');
    expect(output).toContain('per-run hashes');
  });

  it('exits 0 even when checks fail', async () => {
    const h = harness();
    // No such mailbox in the invented tenant: mail checks fail, the run completes
    const code = await runCli([...CREDS, '--mailbox', 'nobody@example.com', '--json'], h.io);
    expect(code).toBe(EXIT_OK);
    const report = JSON.parse(h.out[0]) as ProbeReport;
    expect(report.summary.fail).toBeGreaterThan(0);
  });

  it('shows identifiers when asked', async () => {
    const h = harness();
    await runCli([...CREDS, '--mailbox', TENANT.mailbox, '--show-identifiers'], h.io);
    expect(h.out[0]).toContain(TENANT.sender);
    expect(h.out[0]).toContain('do not post this output publicly');
  });
});

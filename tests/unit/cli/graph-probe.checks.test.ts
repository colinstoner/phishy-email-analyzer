/**
 * Graph probe checks: PASS / FAIL / SKIPPED mapping for every check, the
 * read-only guarantee, and redaction. A real GraphClient over a mocked
 * fetch answers as an invented tenant; no network.
 */

import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import {
  CheckResult,
  PROBE_CHECKS,
  ProbeCheckId,
  ProbeOptions,
  ProbeReport,
  Redactor,
  decodeTokenRoles,
  describeFailure,
  mimeHeaderNames,
  printableHeaderNames,
  runProbe,
} from '../../../src/cli/graph-probe.checks';
import { renderJson, renderText } from '../../../src/cli/graph-probe.main';
import { GraphAuthError, GraphClient, GraphError } from '../../../src/services/graph';
import { FakeGraph, FakeResponder, collection, fakeGraph, fakeToken, jsonResponse } from '../../mocks/graph.fake';
import {
  IDENTIFIERS,
  MARKERS,
  TENANT,
  TEST_MESSAGE,
  TRACE_PATH,
  denied,
  isMessageItem,
  mailboxPath,
  workingTenant,
} from '../../mocks/graph.tenant';

const ALL_ROLES = [
  'ExchangeMessageTrace.Read.All',
  'LicenseAssignment.Read.All',
  'Mail.Read',
  'User.Read.All',
];

interface Run {
  report: ProbeReport;
  graph: FakeGraph;
  check: (id: ProbeCheckId) => CheckResult;
}

async function probe(
  overrides: FakeResponder[] = [],
  options: ProbeOptions = { mailbox: TENANT.mailbox },
  roles: string[] = ALL_ROLES
): Promise<Run> {
  const graph = fakeGraph([...overrides, workingTenant], roles);
  const report = await runProbe(
    { client: graph.client, getToken: () => Promise.resolve(graph.token) },
    { now: () => TENANT.now, salt: 'fixed-test-salt', ...options }
  );
  return {
    report,
    graph,
    check: id => report.checks.find(check => check.id === id) as CheckResult,
  };
}

function statuses(report: ProbeReport): Record<string, string> {
  return Object.fromEntries(report.checks.map(check => [check.id, check.status]));
}

describe('runProbe on a tenant where everything works', () => {
  let run: Run;
  beforeAll(async () => {
    run = await probe();
  });

  it('reports every check, in the fixed order', () => {
    expect(run.report.checks.map(check => check.id)).toEqual(PROBE_CHECKS.map(check => check.id));
    expect(statuses(run.report)).toEqual({
      token: 'PASS',
      licences: 'PASS',
      users: 'PASS',
      'mailbox-read': 'PASS',
      'find-by-message-id': 'PASS',
      'covers-junkemail': 'PASS',
      'covers-recoverableitemsdeletions': 'PASS',
      'sender-window': 'PASS',
      search: 'PASS',
      'search-with-filter': 'PASS',
      headers: 'PASS',
      mime: 'PASS',
      'last-verb': 'PASS',
      'immutable-id': 'PASS',
      'trace-reachable': 'PASS',
      'trace-message-id-brackets': 'PASS',
      // The invented tenant matches message IDs only with their brackets
      'trace-message-id-bare': 'FAIL',
      'trace-sender-subject': 'PASS',
    });
    expect(run.report.summary).toEqual({ pass: 17, fail: 1, skipped: 0 });
    expect(run.report.tokenAcquired).toBe(true);
    expect(run.report.generatedAt).toBe(TENANT.now.toISOString());
  });

  it('gives each check a question and the permissions it needs', () => {
    for (const check of run.report.checks) {
      expect(check.name.length).toBeGreaterThan(3);
      expect(check.question.endsWith('?')).toBe(true);
      expect(check.detail).not.toContain('\n');
      if (check.id !== 'token') {
        expect(check.permissions.length).toBeGreaterThan(0);
      }
    }
  });

  it('lists the application roles decoded from the token', () => {
    expect(run.check('token').detail).toBe(
      `token acquired; application roles: ${ALL_ROLES.join(', ')}`
    );
  });

  it('reports licence capabilities and user counts', () => {
    expect(run.check('licences').detail).toContain(
      'Defender for Office 365 P1: yes, P2: yes; Entra ID P1: yes, P2: no'
    );
    expect(run.check('users').detail).toBe(
      '3 user(s); userType: Member 2, Guest 1; with mail: 2; with enabled Exchange plan: 1; disabled accounts: 1'
    );
  });

  it('reports sizes, counts, header names and values Microsoft defines', () => {
    expect(run.check('find-by-message-id').detail).toMatch(
      /^filter accepted; 1 message\(s\) matched message-id#[0-9a-f]{8}$/
    );
    expect(run.check('covers-junkemail').detail).toBe(
      'covered: junkemail holds 3 item(s) and /messages returns items from it'
    );
    expect(run.check('headers').detail).toBe(
      '4 header(s); names: Received, Authentication-Results (+1 more not shown)'
    );
    expect(run.check('mime').detail).toMatch(
      /^\d+ bytes; header names: Received, From, Subject, Message-ID, Content-Type$/
    );
    expect(run.check('last-verb').detail).toBe('property readable; value 104 (forwarded)');
    expect(run.check('immutable-id').detail).toBe(
      'header accepted; immutable ID differs from the default ID: yes; message fetched by its immutable ID: yes'
    );
    expect(run.check('search').detail).toBe(
      'accepted without ConsistencyLevel; from: search returned 1 result(s), test message among them: yes; grouped subject: search returned 1 result(s), test message among them: yes'
    );
    expect(
      run.graph.requests.filter(request => request.query.$search).map(request => request.query.$search)
    ).toEqual([
      '"from:billing-alerts@example.org"',
      '"subject:(invoice 7731 overdue)"',
      '"from:billing-alerts@example.org"',
    ]);
    expect(run.check('trace-reachable').detail).toBe(
      'works; 2 row(s) in the default 48-hour window; status: Delivered 2'
    );
    expect(run.check('trace-sender-subject').detail).toContain('2 row(s), 2 distinct recipient(s)');
  });

  it('issues only GET requests and never calls postJson', async () => {
    expect(run.graph.requests.length).toBeGreaterThan(15);
    expect(run.graph.requests.map(request => request.method)).toEqual(
      run.graph.requests.map(() => 'GET')
    );

    const graph = fakeGraph([workingTenant], ALL_ROLES);
    const post = jest
      .spyOn(GraphClient.prototype, 'postJson')
      .mockRejectedValue(new Error('the probe must never POST'));
    await runProbe(
      { client: graph.client, getToken: () => Promise.resolve(graph.token) },
      { mailbox: TENANT.mailbox, messageId: TENANT.internetMessageId, now: () => TENANT.now }
    );
    expect(post).not.toHaveBeenCalled();
  });

  it('stays on fixed endpoints', () => {
    const user = `/users/${encodeURIComponent(TENANT.mailbox)}`;
    const allowed = [
      /^\/subscribedSkus$/,
      /^\/users$/,
      new RegExp(`^${user}/messages(/[^/]+(/\\$value)?)?$`),
      new RegExp(`^${user}/mailFolders/(inbox|junkemail|recoverableitemsdeletions)(/messages)?$`),
      /^\/admin\/exchange\/tracing\/messageTraces$/,
    ];
    for (const request of run.graph.requests) {
      expect(allowed.some(pattern => pattern.test(request.path))).toBe(true);
    }
  });

  it('never selects a body, and never asks for attachments', () => {
    for (const request of run.graph.requests) {
      const selected = (request.query.$select ?? '').split(',');
      for (const property of ['body', 'bodyPreview', 'uniqueBody', 'attachments']) {
        expect(selected).not.toContain(property);
      }
      expect(request.path).not.toContain('attachments');
    }
  });
});

describe('source-level read-only guarantee', () => {
  it('has no POST, PATCH or DELETE in the probe or the operations library', () => {
    const root = join(__dirname, '../../../src');
    const files = [
      ...readdirSync(join(root, 'cli'))
        .filter(name => name.startsWith('graph-probe'))
        .map(name => join(root, 'cli', name)),
      ...readdirSync(join(root, 'services/graph'))
        .filter(name => name.includes('operations'))
        .map(name => join(root, 'services/graph', name)),
    ];
    expect(files.length).toBeGreaterThanOrEqual(7);
    for (const file of files) {
      const code = readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '');
      expect(code).not.toMatch(/postJson|['"`](POST|PATCH|PUT|DELETE)['"`]/);
    }
  });
});

describe('redaction', () => {
  const forbiddenAlways = [...Object.values(MARKERS), 'tenant-claim-not-for-output'];

  it('prints no identifier, body, header value or token by default', async () => {
    const run = await probe([], { mailbox: TENANT.mailbox, messageId: TENANT.internetMessageId });
    for (const output of [renderText(run.report), renderText(run.report, true), renderJson(run.report)]) {
      for (const secret of [...IDENTIFIERS, TENANT.mailbox, ...forbiddenAlways, run.graph.token]) {
        expect(output).not.toContain(secret);
      }
      expect(output).not.toContain(TENANT.graphId);
      expect(output).not.toContain('192.0.2.25');
      expect(output).toMatch(/message-id#[0-9a-f]{8}/);
      expect(output).toMatch(/address#[0-9a-f]{8}/);
      expect(output).toMatch(/subject#[0-9a-f]{8}/);
    }
    expect(run.report.identifiersShown).toBe(false);
  });

  it('prints no Graph error message, even when every call fails', async () => {
    const run = await probe([() => denied()], {
      mailbox: TENANT.mailbox,
      messageId: TENANT.internetMessageId,
    });
    const output = renderText(run.report) + renderJson(run.report);
    for (const secret of [...IDENTIFIERS, ...forbiddenAlways]) {
      expect(output).not.toContain(secret);
    }
    expect(output).toContain('ErrorAccessDenied');
  });

  it('shows identifiers only with showIdentifiers, and still no content', async () => {
    const run = await probe([], {
      mailbox: TENANT.mailbox,
      messageId: TENANT.internetMessageId,
      showIdentifiers: true,
    });
    const output = renderText(run.report) + renderJson(run.report);
    expect(output).toContain(TENANT.sender);
    expect(output).toContain(TENANT.subject);
    expect(output).toContain(TENANT.internetMessageId);
    expect(output).toContain('do not post this output publicly');
    for (const secret of [...forbiddenAlways, run.graph.token]) {
      expect(output).not.toContain(secret);
    }
    expect(run.report.identifiersShown).toBe(true);
  });

  it('hashes consistently within a run and differently across runs', () => {
    const first = new Redactor(false);
    const second = new Redactor(false);
    expect(first.id('address', 'A@Example.com ')).toBe(first.id('address', 'a@example.com'));
    expect(first.id('address', 'a@example.com')).toMatch(/^address#[0-9a-f]{8}$/);
    expect(first.id('address', 'a@example.com')).not.toBe(first.id('subject', 'a@example.com'));
    expect(first.id('address', 'a@example.com')).not.toBe(second.id('address', 'a@example.com'));
    expect(first.id('subject', undefined)).toBe('subject:(none)');
    expect(first.id('subject', '')).toBe('subject:(none)');
  });

  it('keeps a shown identifier on one line', () => {
    const shown = new Redactor(true).id('subject', `line one\r\nline two\u0000‮${'x'.repeat(500)}`);
    expect(shown).not.toMatch(/[\r\n\u0000‮]/);
    expect(shown.length).toBeLessThanOrEqual(200);
  });
});

describe('check outcomes', () => {
  it('stops at a credential failure: token FAIL, everything else SKIPPED', async () => {
    const graph = fakeGraph([workingTenant]);
    const report = await runProbe(
      {
        client: graph.client,
        getToken: () =>
          Promise.reject(
            new GraphAuthError('Graph read token request rejected: status 401 invalid_client AADSTS700027', {
              label: 'read',
              status: 401,
              code: 'invalid_client',
            })
          ),
      },
      { mailbox: TENANT.mailbox }
    );
    expect(report.tokenAcquired).toBe(false);
    expect(report.checks[0]).toMatchObject({
      id: 'token',
      status: 'FAIL',
      httpStatus: 401,
      errorCode: 'invalid_client',
    });
    expect(report.checks[0].detail).toContain('AADSTS700027');
    expect(report.checks.slice(1).every(check => check.status === 'SKIPPED')).toBe(true);
    expect(report.checks[1].detail).toBe('no access token');
    expect(graph.requests).toHaveLength(0);
  });

  it('skips the mail checks without a mailbox and traces a recent row instead', async () => {
    const run = await probe([], {});
    expect(statuses(run.report)).toMatchObject({
      licences: 'PASS',
      users: 'PASS',
      'mailbox-read': 'SKIPPED',
      'find-by-message-id': 'SKIPPED',
      'covers-junkemail': 'SKIPPED',
      mime: 'SKIPPED',
      'immutable-id': 'SKIPPED',
      'trace-reachable': 'PASS',
      'trace-message-id-brackets': 'PASS',
      'trace-message-id-bare': 'FAIL',
      'trace-sender-subject': 'PASS',
    });
    expect(run.check('mime').detail).toBe('no --mailbox given');
    expect(run.check('trace-message-id-brackets').detail).toContain('a recent trace row');
    expect(run.graph.requests.every(request => !request.path.includes('/messages'))).toBe(true);
  });

  it('maps 401/403 to the permission each check needs and keeps going', async () => {
    const run = await probe([() => denied()], {
      mailbox: TENANT.mailbox,
      messageId: TENANT.internetMessageId,
    });
    expect(statuses(run.report)).toEqual({
      token: 'PASS',
      licences: 'FAIL',
      users: 'FAIL',
      'mailbox-read': 'FAIL',
      'find-by-message-id': 'FAIL',
      'covers-junkemail': 'FAIL',
      'covers-recoverableitemsdeletions': 'FAIL',
      'sender-window': 'SKIPPED',
      search: 'SKIPPED',
      'search-with-filter': 'SKIPPED',
      headers: 'SKIPPED',
      mime: 'SKIPPED',
      'last-verb': 'SKIPPED',
      'immutable-id': 'SKIPPED',
      'trace-reachable': 'FAIL',
      'trace-message-id-brackets': 'SKIPPED',
      'trace-message-id-bare': 'SKIPPED',
      'trace-sender-subject': 'SKIPPED',
    });
    expect(run.check('licences')).toMatchObject({
      httpStatus: 403,
      errorCode: 'ErrorAccessDenied',
      detail:
        'permission missing or not consented: needs LicenseAssignment.Read.All or Organization.Read.All (HTTP 403 ErrorAccessDenied)',
    });
    expect(run.check('users').detail).toContain('needs User.Read.All');
    expect(run.check('mailbox-read').detail).toContain('needs Mail.ReadBasic.All or Mail.Read');
    expect(run.check('trace-reachable').detail).toContain('needs ExchangeMessageTrace.Read.All');
    expect(run.check('trace-sender-subject').detail).toContain('message trace is not reachable');
    expect(run.check('mime').detail).toContain('no test message');
  });

  it('notes when the needed role is not in the token', async () => {
    const run = await probe([() => denied(401, 'InvalidAuthenticationToken')], { mailbox: TENANT.mailbox }, [
      'User.Read.All',
    ]);
    expect(run.check('users').detail).toBe(
      'permission missing or not consented: needs User.Read.All (HTTP 401 InvalidAuthenticationToken)'
    );
    expect(run.check('licences').detail).toMatch(/; not in the token roles$/);
    expect(run.check('mailbox-read').detail).toContain('Exchange RBAC');
  });

  it.each<[string, ProbeCheckId, FakeResponder, string, string]>([
    [
      'MIME denied with ReadBasic',
      'mime',
      request => (request.path.endsWith('/$value') ? denied() : undefined),
      'FAIL',
      'needs Mail.Read (HTTP 403 ErrorAccessDenied)',
    ],
    [
      'last-verb denied',
      'last-verb',
      request => (request.query.$expand ? denied() : undefined),
      'FAIL',
      'needs Mail.Read',
    ],
    [
      'last-verb property not set',
      'last-verb',
      request => (request.query.$expand ? jsonResponse({ id: 'x' }) : undefined),
      'SKIPPED',
      'could not determine',
    ],
    [
      'extended property id rejected',
      'last-verb',
      request => (request.query.$expand ? denied(400, 'ErrorInvalidProperty') : undefined),
      'FAIL',
      'Graph rejected the request (HTTP 400 ErrorInvalidProperty)',
    ],
    [
      'no headers returned',
      'headers',
      request =>
        request.query.$select === 'internetMessageHeaders' ? jsonResponse({ id: 'x' }) : undefined,
      'FAIL',
      'no headers were returned',
    ],
    [
      '$search needs ConsistencyLevel',
      'search',
      request =>
        request.query.$search && !request.query.$filter && !request.headers.ConsistencyLevel
          ? denied(400, 'BadRequest')
          : undefined,
      'PASS',
      'rejected without ConsistencyLevel (HTTP 400 BadRequest), accepted with ConsistencyLevel: eventual',
    ],
    [
      'grouped subject search rejected (reported, not failed)',
      'search',
      request =>
        request.query.$search?.includes('subject:(') ? denied(400, 'BadRequest') : undefined,
      'PASS',
      'grouped subject: search failed: Graph rejected the request (HTTP 400 BadRequest)',
    ],
    [
      '$search rejected either way',
      'search',
      request => (request.query.$search && !request.query.$filter ? denied(400, 'BadRequest') : undefined),
      'FAIL',
      'Graph rejected the request (HTTP 400 BadRequest)',
    ],
    [
      '$search with $filter rejected',
      'search-with-filter',
      request =>
        request.query.$search && request.query.$filter ? denied(400, 'SearchWithFilter') : undefined,
      'FAIL',
      'not supported: Graph rejected $search with $filter (HTTP 400 SearchWithFilter)',
    ],
    [
      '$search with $filter denied',
      'search-with-filter',
      request => (request.query.$search && request.query.$filter ? denied() : undefined),
      'FAIL',
      'permission missing or not consented',
    ],
    [
      'sender filter misses the test message',
      'sender-window',
      request =>
        mailboxPath(request, '/messages') && request.query.$filter?.startsWith('receivedDateTime')
          ? collection([])
          : undefined,
      'FAIL',
      '0 matched, test message among them: no',
    ],
    [
      'sender filter rejected (InefficientFilter)',
      'sender-window',
      request =>
        mailboxPath(request, '/messages') && request.query.$orderby
          ? denied(400, 'InefficientFilter')
          : undefined,
      'FAIL',
      'HTTP 400 InefficientFilter',
    ],
    [
      'immutable ID header rejected',
      'immutable-id',
      request => (isMessageItem(request) && request.headers.Prefer ? denied(400, 'BadRequest') : undefined),
      'FAIL',
      'Graph rejected the request (HTTP 400 BadRequest)',
    ],
    [
      'junk folder empty',
      'covers-junkemail',
      request =>
        mailboxPath(request, '/mailFolders/junkemail')
          ? jsonResponse({ id: 'j', totalItemCount: 0 })
          : undefined,
      'SKIPPED',
      'could not determine: junkemail is empty',
    ],
    [
      'per-folder form returns nothing',
      'covers-junkemail',
      request =>
        mailboxPath(request, '/mailFolders/junkemail/messages') ? collection([]) : undefined,
      'SKIPPED',
      'could not determine: the per-folder form returned no messages',
    ],
    [
      '/messages does not cover Recoverable Items',
      'covers-recoverableitemsdeletions',
      request =>
        request.query.$filter === `parentFolderId eq '${TENANT.recoverableFolderId}'`
          ? collection([])
          : undefined,
      'FAIL',
      'not covered: recoverableitemsdeletions holds 2 item(s)',
    ],
    [
      'folder not found',
      'covers-recoverableitemsdeletions',
      request =>
        mailboxPath(request, '/mailFolders/recoverableitemsdeletions')
          ? denied(404, 'ErrorItemNotFound')
          : undefined,
      'FAIL',
      'HTTP 404 ErrorItemNotFound',
    ],
    [
      'trace service principal missing',
      'trace-reachable',
      request =>
        request.path === TRACE_PATH
          ? denied(
              401,
              'UnknownError',
              'The service principal for resource 8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found in the tenant'
            )
          : undefined,
      'FAIL',
      'service principal not provisioned',
    ],
    [
      'trace permission missing',
      'trace-reachable',
      request => (request.path === TRACE_PATH ? denied(403, 'Forbidden') : undefined),
      'FAIL',
      'permission missing or not consented: needs ExchangeMessageTrace.Read.All (HTTP 403 Forbidden)',
    ],
    [
      'trace throttled',
      'trace-reachable',
      request => (request.path === TRACE_PATH ? denied(429, 'TooManyRequests') : undefined),
      'FAIL',
      'throttled by Graph',
    ],
    [
      'trace finds nothing by bracketed ID',
      'trace-message-id-brackets',
      request => (request.query.$filter?.includes('messageId eq') ? collection([]) : undefined),
      'FAIL',
      'filter accepted but matched nothing: 0 row(s)',
    ],
    [
      'trace by sender finds nothing',
      'trace-sender-subject',
      request => (request.query.$filter?.includes('senderAddress eq') ? collection([]) : undefined),
      'FAIL',
      'filter accepted but matched nothing',
    ],
    [
      'trace subject filter rejected',
      'trace-sender-subject',
      request =>
        request.query.$filter?.includes('contains(subject') ? denied(400, 'BadRequest') : undefined,
      'FAIL',
      'HTTP 400 BadRequest',
    ],
    [
      'licence list unreadable',
      'licences',
      request => (request.path === '/subscribedSkus' ? jsonResponse({ unexpected: true }) : undefined),
      'FAIL',
      'request did not complete (invalid_response)',
    ],
  ])('%s', async (_name, id, override, status, detail) => {
    const run = await probe([override]);
    expect(run.check(id).status).toBe(status);
    expect(run.check(id).detail).toContain(detail);
    // One failure never stops the run: the last check still got an answer
    expect(run.check('trace-sender-subject').detail).not.toBe('not run');
    expect(run.report.checks).toHaveLength(PROBE_CHECKS.length);
  });

  it('classifies a missing trace service principal without printing the message', async () => {
    const message = 'service principal was not found; hostile-echo-marker';
    const run = await probe([
      request => (request.path === TRACE_PATH ? denied(403, 'Forbidden', message) : undefined),
    ]);
    expect(run.check('trace-reachable')).toMatchObject({
      status: 'FAIL',
      httpStatus: 403,
      errorCode: 'Forbidden',
    });
    expect(run.check('trace-reachable').detail).toContain('8bd644d1-64a1-4d4b-ae52-2e0cbf64e373');
    expect(renderJson(run.report)).not.toContain('hostile-echo-marker');
    expect(run.check('trace-message-id-bare').status).toBe('SKIPPED');
  });

  it('uses --message-id as the test message', async () => {
    const run = await probe([], { mailbox: TENANT.mailbox, messageId: TENANT.internetMessageId });
    const find = run.graph.requests.find(request => request.query.$filter?.startsWith('internetMessageId'));
    expect(find?.query.$filter).toBe(`internetMessageId eq '${TENANT.internetMessageId}'`);
    expect(run.check('find-by-message-id').status).toBe('PASS');
    expect(run.check('mailbox-read').detail).toBe('metadata readable');
    expect(run.check('mime').status).toBe('PASS');
  });

  it('fails the find check when a given message ID matches nothing', async () => {
    const run = await probe(
      [
        request =>
          request.query.$filter?.startsWith('internetMessageId') ? collection([]) : undefined,
      ],
      { mailbox: TENANT.mailbox, messageId: '<missing@example.net>' }
    );
    expect(run.check('find-by-message-id').status).toBe('FAIL');
    expect(run.check('find-by-message-id').detail).toContain('matched 0 messages for message-id#');
    expect(run.check('headers').status).toBe('SKIPPED');
    // Trace falls back to a recent trace row
    expect(run.check('trace-message-id-brackets').status).toBe('PASS');
  });

  it('fails the find check when the filter misses a message known to exist', async () => {
    const run = await probe([
      request =>
        request.query.$filter?.startsWith('internetMessageId') ? collection([]) : undefined,
    ]);
    expect(run.check('find-by-message-id')).toMatchObject({ status: 'FAIL' });
    expect(run.check('find-by-message-id').detail).toContain('the filter is not effective here');
    // The inbox message is still the test subject
    expect(run.check('headers').status).toBe('PASS');
  });

  it('handles an empty inbox', async () => {
    const run = await probe([
      request => (mailboxPath(request, '/mailFolders/inbox/messages') ? collection([]) : undefined),
    ]);
    expect(run.check('mailbox-read')).toMatchObject({ status: 'PASS' });
    expect(run.check('mailbox-read').detail).toContain('inbox is empty');
    expect(run.check('find-by-message-id').status).toBe('SKIPPED');
    expect(run.check('mime').status).toBe('SKIPPED');
    expect(run.check('covers-junkemail').status).toBe('PASS');
  });

  it('skips sender checks when the test message has no sender or time', async () => {
    const bare = { id: TENANT.graphId, internetMessageId: TENANT.internetMessageId };
    const run = await probe([
      request =>
        mailboxPath(request, '/mailFolders/inbox/messages') || mailboxPath(request, '/messages')
          ? collection([bare])
          : undefined,
    ]);
    expect(run.check('sender-window').status).toBe('SKIPPED');
    expect(run.check('search').status).toBe('SKIPPED');
    expect(run.check('search-with-filter').status).toBe('SKIPPED');
    expect(run.check('trace-message-id-brackets').status).toBe('SKIPPED');
    expect(run.check('trace-sender-subject').status).toBe('SKIPPED');
  });

  it('skips trace lookups for a message older than trace reaches', async () => {
    const old = { ...TEST_MESSAGE, receivedDateTime: '2026-06-01T08:00:00Z' };
    const run = await probe([
      request =>
        mailboxPath(request, '/mailFolders/inbox/messages') || mailboxPath(request, '/messages')
          ? collection([old])
          : undefined,
    ]);
    expect(run.check('trace-reachable').status).toBe('PASS');
    expect(run.check('trace-message-id-brackets')).toMatchObject({ status: 'SKIPPED' });
    expect(run.check('trace-message-id-brackets').detail).toContain('90 days');
    expect(run.graph.requests.filter(request => request.path === TRACE_PATH)).toHaveLength(1);
  });

  it('sends trace filters with both ID forms and a bounded window', async () => {
    const run = await probe();
    const filters = run.graph.requests
      .filter(request => request.path === TRACE_PATH)
      .map(request => request.query.$filter);
    const window = 'receivedDateTime ge 2026-11-15T08:00:00Z and receivedDateTime le 2026-11-17T08:00:00Z';
    expect(filters).toEqual([
      undefined,
      `${window} and messageId eq '${TENANT.internetMessageId}'`,
      `${window} and messageId eq '${TENANT.bareMessageId}'`,
      `${window} and senderAddress eq '${TENANT.sender}' and contains(subject, '${TENANT.subject}')`,
    ]);
  });

  it('reports a network failure without stopping', async () => {
    const graph = fakeGraph([workingTenant], ALL_ROLES);
    graph.fetchMock.mockImplementation(input =>
      String(input).includes('/subscribedSkus')
        ? Promise.reject(new Error('socket hang up with secret detail'))
        : Promise.resolve(collection([]))
    );
    const report = await runProbe(
      { client: graph.client, getToken: () => Promise.resolve(graph.token) },
      {}
    );
    expect(report.checks[1]).toMatchObject({
      status: 'FAIL',
      detail: 'request did not complete (network)',
    });
    expect(report.checks[2].status).toBe('PASS');
    expect(JSON.stringify(report)).not.toContain('socket hang up');
  });
});

describe('helpers', () => {
  it('decodes roles and nothing else from a token', () => {
    expect(decodeTokenRoles(fakeToken(['Mail.Read', 'User.Read.All']))).toEqual([
      'Mail.Read',
      'User.Read.All',
    ]);
    expect(decodeTokenRoles(fakeToken(undefined))).toEqual([]);
    expect(decodeTokenRoles(fakeToken(['ok.Role', 'bad role\n', 7 as unknown as string]))).toEqual([
      'ok.Role',
    ]);
    expect(decodeTokenRoles('not-a-jwt')).toBeUndefined();
    expect(decodeTokenRoles('a.%%%.c')).toBeUndefined();
  });

  it('prints only plausible header names, de-duplicated and capped', () => {
    expect(printableHeaderNames(['From', 'To', 'From', 'X bad', 'Evil\r\nInjected'])).toBe(
      'From, To (+2 more not shown)'
    );
    expect(printableHeaderNames([])).toBe('(none)');
    const many = Array.from({ length: 60 }, (_, i) => `X-Header-${i}`);
    expect(printableHeaderNames(many)).toContain('(+20 more not shown)');
  });

  it('reads header names from the top MIME header block only', () => {
    const mime = Buffer.from(
      'From: a@example.com\r\nSubject: s\r\n folded: continuation\r\nX-Two: 2\r\n\r\nBody-Line: nope\r\n'
    );
    expect(mimeHeaderNames(mime)).toEqual(['From', 'Subject', 'X-Two']);
    expect(mimeHeaderNames(Buffer.from('From: a@example.com\nTo: b@example.com'))).toEqual([
      'From',
      'To',
    ]);
  });

  it('describes failures from status, code and kind only', () => {
    const graphError = (status?: number, code?: string) =>
      new GraphError('summary', {
        kind: status === undefined ? 'timeout' : 'http',
        label: 'read',
        status,
        code,
        detail: 'DETAIL-MUST-NOT-PRINT',
      });
    expect(describeFailure(graphError(403, 'Authorization_RequestDenied'), [])).toEqual({
      status: 'FAIL',
      httpStatus: 403,
      errorCode: 'Authorization_RequestDenied',
      detail:
        'permission missing or not consented: needs an application permission (HTTP 403 Authorization_RequestDenied)',
    });
    expect(describeFailure(graphError(500), ['X']).detail).toBe(
      'Graph rejected the request (HTTP 500)'
    );
    expect(describeFailure(graphError(), ['X']).detail).toBe('request did not complete (timeout)');
    expect(describeFailure(new TypeError('value: SECRET'), ['X']).detail).toBe(
      'unexpected TypeError inside the probe'
    );
    expect(describeFailure('thrown string', ['X']).detail).toBe('unexpected error inside the probe');
    expect(JSON.stringify(describeFailure(graphError(403), ['Mail.Read'], ['Mail.Read']))).not.toMatch(
      /DETAIL-MUST-NOT-PRINT|token roles/
    );
  });
});

/**
 * Read operations: request shape (path, filter text, headers, caps) and
 * result shaping. A real GraphClient over a mocked fetch; no network.
 */

import {
  GraphError,
  MESSAGE_TRACE_SERVICE_APP_ID,
  addAngleBrackets,
  assertTraceWindow,
  findMessagesByInternetMessageId,
  findMessagesByParentFolder,
  findMessagesBySender,
  getLastVerb,
  getMailFolder,
  getMessageHeaders,
  getMessageMime,
  getMessageMimeText,
  getMessageSummary,
  listMessageTracesByMessageId,
  listMessageTracesBySender,
  listRecentMessageTraces,
  listRecentMessages,
  listSubscribedSkus,
  listUsers,
  resolveMaxItems,
  searchMessages,
  stripAngleBrackets,
  summarizeCapabilities,
  WellKnownMailFolder,
} from '../../../../src/services/graph';
import { FAKE_BASE, collection, fakeGraph, jsonResponse } from '../../../mocks/graph.fake';

const MAILBOX = 'reporter@example.com';
const MESSAGE_ID = '<abc.123@mail.example.net>';
const GRAPH_ID = 'AAMkAGraphId-0001=';
const SUMMARY_SELECT = 'id,internetMessageId,subject,from,receivedDateTime,parentFolderId,hasAttachments';

const rawMessage = {
  id: GRAPH_ID,
  internetMessageId: MESSAGE_ID,
  subject: 'Invoice overdue',
  from: { emailAddress: { name: 'Sender', address: 'sender@example.org' } },
  receivedDateTime: '2026-11-10T08:00:00Z',
  parentFolderId: 'folder-1',
  hasAttachments: true,
  body: { content: 'BODY-MUST-NOT-SURFACE' },
};

describe('mail operations', () => {
  it('finds by internetMessageId across the mailbox, metadata only', async () => {
    const graph = fakeGraph([() => collection([rawMessage])]);
    const result = await findMessagesByInternetMessageId(graph.client, {
      mailbox: MAILBOX,
      internetMessageId: MESSAGE_ID,
    });

    expect(graph.requests).toHaveLength(1);
    const [request] = graph.requests;
    expect(request.method).toBe('GET');
    expect(request.path).toBe('/users/reporter%40example.com/messages');
    expect(request.query).toEqual({
      $select: SUMMARY_SELECT,
      $filter: `internetMessageId eq '${MESSAGE_ID}'`,
      $top: '25',
    });
    expect(request.headers.Prefer).toBeUndefined();
    expect(result).toEqual({
      truncated: false,
      items: [
        {
          id: GRAPH_ID,
          internetMessageId: MESSAGE_ID,
          subject: 'Invoice overdue',
          fromAddress: 'sender@example.org',
          receivedDateTime: '2026-11-10T08:00:00Z',
          parentFolderId: 'folder-1',
          hasAttachments: true,
        },
      ],
    });
    expect(JSON.stringify(result)).not.toContain('BODY-MUST-NOT-SURFACE');
  });

  it('restricts to a well-known folder and can ask for immutable IDs', async () => {
    const graph = fakeGraph([() => collection([])]);
    await findMessagesByInternetMessageId(graph.client, {
      mailbox: MAILBOX,
      internetMessageId: MESSAGE_ID,
      folder: 'junkemail',
      immutableIds: true,
      maxItems: 3,
    });
    expect(graph.requests[0].path).toBe('/users/reporter%40example.com/mailFolders/junkemail/messages');
    expect(graph.requests[0].query.$top).toBe('3');
    expect(graph.requests[0].headers.Prefer).toBe('IdType="ImmutableId"');
  });

  it('refuses a folder that is not a well-known name', async () => {
    const graph = fakeGraph([]);
    await expect(
      findMessagesByInternetMessageId(graph.client, {
        mailbox: MAILBOX,
        internetMessageId: MESSAGE_ID,
        folder: 'inbox/../../users' as WellKnownMailFolder,
      })
    ).rejects.toThrow('well-known');
    await expect(
      getMailFolder(graph.client, { mailbox: MAILBOX, folder: 'x' as WellKnownMailFolder })
    ).rejects.toThrow('well-known');
    expect(graph.requests).toHaveLength(0);
  });

  it('keeps a hostile message ID and mailbox as data', async () => {
    const graph = fakeGraph([() => collection([])]);
    await findMessagesByInternetMessageId(graph.client, {
      mailbox: 'x/../../admin?$select=body',
      internetMessageId: "<a'b@example.net>' or subject ne '&$select=body",
    });
    const [request] = graph.requests;
    expect(request.url.origin + request.url.pathname).toBe(
      `${FAKE_BASE}/users/x%2F..%2F..%2Fadmin%3F%24select%3Dbody/messages`
    );
    expect(Object.keys(request.query).sort()).toEqual(['$filter', '$select', '$top']);
    expect(request.query.$filter).toBe(
      "internetMessageId eq '<a''b@example.net>'' or subject ne ''&$select=body'"
    );
  });

  it('caps results and reports truncation', async () => {
    const page = Array.from({ length: 5 }, (_, i) => ({ id: `id-${i}` }));
    const graph = fakeGraph([() => collection(page, `${FAKE_BASE}/users/x/messages?$skip=5`)]);
    const result = await listRecentMessages(graph.client, { mailbox: MAILBOX, maxItems: 5 });
    expect(result.items).toHaveLength(5);
    expect(result.truncated).toBe(true);
    expect(graph.requests).toHaveLength(1);
    expect(graph.requests[0].query).toEqual({
      $select: SUMMARY_SELECT,
      $orderby: 'receivedDateTime desc',
      $top: '5',
    });
  });

  it('pages in hundreds up to the cap and refuses caps out of range', async () => {
    const graph = fakeGraph([
      request =>
        collection(
          Array.from({ length: 100 }, (_, i) => ({ id: `id-${request.url.search.length}-${i}` })),
          `${FAKE_BASE}/users/x/messages?$skip=100`
        ),
    ]);
    const result = await listRecentMessages(graph.client, { mailbox: MAILBOX, maxItems: 250 });
    expect(graph.requests[0].query.$top).toBe('100');
    expect(graph.requests).toHaveLength(3);
    expect(result.items).toHaveLength(250);
    expect(result.truncated).toBe(true);

    await expect(listRecentMessages(graph.client, { mailbox: MAILBOX, maxItems: 0 })).rejects.toThrow(
      'maxItems'
    );
    await expect(
      listRecentMessages(graph.client, { mailbox: MAILBOX, maxItems: 1001 })
    ).rejects.toThrow('maxItems');
    expect(() => resolveMaxItems(1.5, 10, 100)).toThrow('maxItems');
  });

  it('finds by sender and window, time first so $orderby is allowed', async () => {
    const graph = fakeGraph([() => collection([rawMessage])]);
    await findMessagesBySender(graph.client, {
      mailbox: MAILBOX,
      senderAddress: 'sender@example.org',
      receivedFrom: new Date('2026-11-10T00:00:00.000Z'),
      receivedTo: new Date('2026-11-11T00:00:00.000Z'),
    });
    expect(graph.requests[0].query).toEqual({
      $select: SUMMARY_SELECT,
      $filter:
        "receivedDateTime ge 2026-11-10T00:00:00.000Z and receivedDateTime lt 2026-11-11T00:00:00.000Z and from/emailAddress/address eq 'sender@example.org'",
      $orderby: 'receivedDateTime desc',
      $top: '25',
    });
  });

  it('adds an exact, escaped subject', async () => {
    const graph = fakeGraph([() => collection([])]);
    await findMessagesBySender(graph.client, {
      mailbox: MAILBOX,
      senderAddress: 'sender@example.org',
      receivedFrom: new Date('2026-11-10T00:00:00.000Z'),
      receivedTo: new Date('2026-11-11T00:00:00.000Z'),
      subject: "Don't wait",
    });
    expect(graph.requests[0].query.$filter).toBe(
      "receivedDateTime ge 2026-11-10T00:00:00.000Z and receivedDateTime lt 2026-11-11T00:00:00.000Z and from/emailAddress/address eq 'sender@example.org' and subject eq 'Don''t wait'"
    );
  });

  it('refuses a reversed or invalid window before calling Graph', async () => {
    const graph = fakeGraph([]);
    const base = { mailbox: MAILBOX, senderAddress: 'sender@example.org' };
    await expect(
      findMessagesBySender(graph.client, {
        ...base,
        receivedFrom: new Date('2026-11-11T00:00:00Z'),
        receivedTo: new Date('2026-11-10T00:00:00Z'),
      })
    ).rejects.toThrow('after');
    await expect(
      findMessagesBySender(graph.client, {
        ...base,
        receivedFrom: new Date('nope'),
        receivedTo: new Date('2026-11-10T00:00:00Z'),
      })
    ).rejects.toThrow('valid');
    expect(graph.requests).toHaveLength(0);
  });

  it('searches with typed terms and no $orderby', async () => {
    const graph = fakeGraph([() => collection([rawMessage])]);
    await searchMessages(graph.client, {
      mailbox: MAILBOX,
      terms: { from: 'sender@example.org', subject: 'Invoice "overdue"' },
      consistencyLevel: 'eventual',
    });
    expect(graph.requests[0].path).toBe('/users/reporter%40example.com/messages');
    expect(graph.requests[0].query).toEqual({
      $select: SUMMARY_SELECT,
      $top: '25',
      $search: '"from:sender@example.org subject:(invoice overdue)"',
    });
    expect(graph.requests[0].headers.ConsistencyLevel).toBe('eventual');
  });

  it('looks up a folder and the messages /messages returns for it', async () => {
    const graph = fakeGraph([
      request =>
        request.path.endsWith('/mailFolders/junkemail')
          ? jsonResponse({ id: 'junk-folder-id', totalItemCount: 4 })
          : collection([{ id: 'in-junk' }]),
    ]);
    const folder = await getMailFolder(graph.client, { mailbox: MAILBOX, folder: 'junkemail' });
    expect(folder).toEqual({ id: 'junk-folder-id', totalItemCount: 4 });
    expect(graph.requests[0].query).toEqual({ $select: 'id,totalItemCount' });

    await findMessagesByParentFolder(graph.client, {
      mailbox: MAILBOX,
      parentFolderId: folder.id,
      maxItems: 1,
    });
    expect(graph.requests[1].path).toBe('/users/reporter%40example.com/messages');
    expect(graph.requests[1].query.$filter).toBe("parentFolderId eq 'junk-folder-id'");
    expect(graph.requests[1].query.$top).toBe('1');
  });

  it('gets one message summary by ID', async () => {
    const graph = fakeGraph([() => jsonResponse(rawMessage)]);
    const summary = await getMessageSummary(graph.client, {
      mailbox: MAILBOX,
      messageId: 'id/with?odd#chars',
      immutableIds: true,
    });
    expect(graph.requests[0].path).toBe(
      '/users/reporter%40example.com/messages/id%2Fwith%3Fodd%23chars'
    );
    expect(graph.requests[0].query).toEqual({ $select: SUMMARY_SELECT });
    expect(graph.requests[0].headers.Prefer).toBe('IdType="ImmutableId"');
    expect(summary.fromAddress).toBe('sender@example.org');
  });

  it('gets internet headers through $select, capped at 500', async () => {
    const headers = Array.from({ length: 501 }, (_, i) => ({ name: `X-H-${i}`, value: `v${i}` }));
    const graph = fakeGraph([() => jsonResponse({ internetMessageHeaders: headers })]);
    const result = await getMessageHeaders(graph.client, { mailbox: MAILBOX, messageId: GRAPH_ID });
    expect(graph.requests[0].path).toBe(`/users/reporter%40example.com/messages/${GRAPH_ID.replace('=', '%3D')}`);
    expect(graph.requests[0].query).toEqual({ $select: 'internetMessageHeaders' });
    expect(result.items).toHaveLength(500);
    expect(result.truncated).toBe(true);
    expect(result.items[0]).toEqual({ name: 'X-H-0', value: 'v0' });
  });

  it('returns no headers when Graph sends none', async () => {
    const graph = fakeGraph([() => jsonResponse({ id: GRAPH_ID })]);
    expect(
      await getMessageHeaders(graph.client, { mailbox: MAILBOX, messageId: GRAPH_ID })
    ).toEqual({ items: [], truncated: false });
  });

  it('downloads MIME from /$value with a size cap', async () => {
    const mime = 'From: sender@example.org\r\nSubject: Hi\r\n\r\nbody';
    const graph = fakeGraph([() => new Response(mime, { status: 200 })]);
    const text = await getMessageMimeText(graph.client, { mailbox: MAILBOX, messageId: 'm1' });
    expect(text).toBe(mime);
    expect(graph.requests[0].path).toBe('/users/reporter%40example.com/messages/m1/$value');
    expect(graph.requests[0].url.search).toBe('');
    expect(graph.requests[0].method).toBe('GET');

    await expect(
      getMessageMime(graph.client, { mailbox: MAILBOX, messageId: 'm1', maxBytes: 10 })
    ).rejects.toMatchObject({ kind: 'response_too_large' });
    await expect(
      getMessageMime(graph.client, { mailbox: MAILBOX, messageId: 'm1', maxBytes: 0 })
    ).rejects.toThrow('maxBytes');
    await expect(
      getMessageMime(graph.client, { mailbox: MAILBOX, messageId: 'm1', maxBytes: 41 * 1024 * 1024 })
    ).rejects.toThrow('maxBytes');
  });

  it('reads the last-verb extended property', async () => {
    const respond = (value?: string) => () =>
      jsonResponse({
        id: GRAPH_ID,
        ...(value === undefined
          ? {}
          : { singleValueExtendedProperties: [{ id: 'Integer 0x1081', value }] }),
      });

    const graph = fakeGraph([respond('104')]);
    expect(await getLastVerb(graph.client, { mailbox: MAILBOX, messageId: 'm1' })).toEqual({
      action: 'forwarded',
      code: 104,
    });
    expect(graph.requests[0].path).toBe('/users/reporter%40example.com/messages/m1');
    expect(graph.requests[0].query).toEqual({
      $select: 'id',
      $expand: "singleValueExtendedProperties($filter=id eq 'Integer 0x1081')",
    });

    const verb = async (value?: string) =>
      getLastVerb(fakeGraph([respond(value)]).client, { mailbox: MAILBOX, messageId: 'm1' });
    expect(await verb('102')).toEqual({ action: 'replied', code: 102 });
    expect(await verb('103')).toEqual({ action: 'repliedAll', code: 103 });
    expect(await verb('261')).toEqual({ action: 'replied', code: 261 });
    expect(await verb('262')).toEqual({ action: 'forwarded', code: 262 });
    expect(await verb('7')).toEqual({ action: 'other', code: 7 });
    expect(await verb()).toEqual({ action: 'none' });
    expect(await verb('not-a-number')).toEqual({ action: 'none' });
  });

  it('turns an unexpected response shape into a typed error without echoing it', async () => {
    const graph = fakeGraph([() => collection([{ id: 42, subject: 'SHAPE-MARKER' }])]);
    const error = await listRecentMessages(graph.client, { mailbox: MAILBOX }).catch(
      (e: unknown) => e
    );
    expect(error).toBeInstanceOf(GraphError);
    expect((error as GraphError).kind).toBe('invalid_response');
    expect((error as GraphError).message).not.toContain('SHAPE-MARKER');
    expect((error as GraphError).message).toContain('/users/{}/messages');
  });
});

describe('trace operations', () => {
  const NOW = new Date('2026-11-17T12:00:00Z');
  const TRACE_PATH = '/admin/exchange/tracing/messageTraces';
  const row = {
    id: 'trace-1',
    messageId: MESSAGE_ID,
    senderAddress: 'sender@example.org',
    recipientAddress: 'reporter@example.com',
    subject: 'Invoice overdue',
    receivedDateTime: '2026-11-16T08:00:00Z',
    size: 2048,
    fromIP: '192.0.2.10',
    toIP: null,
    status: 'Delivered',
  };

  it('lists recent traces with only $top', async () => {
    const graph = fakeGraph([() => collection([row])]);
    const result = await listRecentMessageTraces(graph.client, { maxItems: 100 });
    expect(graph.requests[0].method).toBe('GET');
    expect(graph.requests[0].path).toBe(TRACE_PATH);
    expect(graph.requests[0].query).toEqual({ $top: '100' });
    expect(result.items[0]).toEqual({ ...row, toIP: undefined });
  });

  it('uses the larger $top the endpoint allows, and no more', async () => {
    const graph = fakeGraph([() => collection([])]);
    await listRecentMessageTraces(graph.client, { maxItems: 5000 });
    expect(graph.requests[0].query.$top).toBe('5000');
    await expect(listRecentMessageTraces(graph.client, { maxItems: 5001 })).rejects.toThrow(
      'maxItems'
    );
  });

  it('traces by message ID alone (service default window)', async () => {
    const graph = fakeGraph([() => collection([row])]);
    await listMessageTracesByMessageId(graph.client, { messageId: MESSAGE_ID });
    expect(graph.requests[0].query).toEqual({
      $filter: `messageId eq '${MESSAGE_ID}'`,
      $top: '1000',
    });
  });

  it('traces by message ID in a window, dates without milliseconds', async () => {
    const graph = fakeGraph([() => collection([row])]);
    await listMessageTracesByMessageId(graph.client, {
      messageId: "x'y@example.net",
      receivedFrom: new Date('2026-11-15T08:00:00.400Z'),
      receivedTo: new Date('2026-11-17T08:00:00.400Z'),
      now: NOW,
      maxItems: 50,
    });
    expect(graph.requests[0].query).toEqual({
      $filter:
        "receivedDateTime ge 2026-11-15T08:00:00Z and receivedDateTime le 2026-11-17T08:00:01Z and messageId eq 'x''y@example.net'",
      $top: '50',
    });
  });

  it('traces by sender, with each subject match form', async () => {
    const graph = fakeGraph([() => collection([row])]);
    const args = {
      senderAddress: 'sender@example.org',
      receivedFrom: new Date('2026-11-15T00:00:00Z'),
      receivedTo: new Date('2026-11-17T00:00:00Z'),
      now: NOW,
    };
    const window = 'receivedDateTime ge 2026-11-15T00:00:00Z and receivedDateTime le 2026-11-17T00:00:00Z';

    await listMessageTracesBySender(graph.client, args);
    await listMessageTracesBySender(graph.client, { ...args, subject: "it's due" });
    await listMessageTracesBySender(graph.client, { ...args, subject: 'RE:', subjectMatch: 'startsWith' });
    await listMessageTracesBySender(graph.client, { ...args, subject: '!', subjectMatch: 'endsWith' });

    expect(graph.requests.map(request => request.query.$filter)).toEqual([
      `${window} and senderAddress eq 'sender@example.org'`,
      `${window} and senderAddress eq 'sender@example.org' and contains(subject, 'it''s due')`,
      `${window} and senderAddress eq 'sender@example.org' and startsWith(subject, 'RE:')`,
      `${window} and senderAddress eq 'sender@example.org' and endsWith(subject, '!')`,
    ]);
    expect(graph.requests.every(request => request.path === TRACE_PATH)).toBe(true);
    expect(graph.requests.every(request => Object.keys(request.query).length === 2)).toBe(true);

    await expect(
      listMessageTracesBySender(graph.client, {
        ...args,
        subject: 'x',
        subjectMatch: 'regex' as 'contains',
      })
    ).rejects.toThrow('subjectMatch');
  });

  it('enforces the documented window limits before calling Graph', async () => {
    const graph = fakeGraph([]);
    expect(() =>
      assertTraceWindow(
        { receivedFrom: new Date('2026-11-01T00:00:00Z'), receivedTo: new Date('2026-11-11T00:00:01Z') },
        NOW
      )
    ).toThrow('10 days');
    expect(() =>
      assertTraceWindow(
        { receivedFrom: new Date('2026-08-01T00:00:00Z'), receivedTo: new Date('2026-08-02T00:00:00Z') },
        NOW
      )
    ).toThrow('90 days');
    await expect(
      listMessageTracesByMessageId(graph.client, {
        messageId: MESSAGE_ID,
        receivedFrom: new Date('2026-11-15T00:00:00Z'),
      })
    ).rejects.toThrow('both');
    await expect(
      listMessageTracesBySender(graph.client, {
        senderAddress: 'sender@example.org',
        receivedFrom: new Date('2026-11-17T00:00:00Z'),
        receivedTo: new Date('2026-11-15T00:00:00Z'),
        now: NOW,
      })
    ).rejects.toThrow('after');
    expect(graph.requests).toHaveLength(0);
  });

  it('follows the next link whole and stops at the page cap', async () => {
    const next = `${FAKE_BASE}${TRACE_PATH}?$skiptoken=opaque-token`;
    const graph = fakeGraph([() => collection([row], next)]);
    const result = await listRecentMessageTraces(graph.client, { maxItems: 1000 });
    expect(graph.requests).toHaveLength(5);
    expect(graph.requests[1].url.href).toBe(next);
    expect(result.truncated).toBe(true);
  });

  it('converts angle-bracket forms', () => {
    expect(stripAngleBrackets('<a@example.net>')).toBe('a@example.net');
    expect(stripAngleBrackets('a@example.net')).toBe('a@example.net');
    expect(stripAngleBrackets('<>')).toBe('<>');
    expect(addAngleBrackets('a@example.net')).toBe('<a@example.net>');
    expect(addAngleBrackets('<a@example.net>')).toBe('<a@example.net>');
    expect(MESSAGE_TRACE_SERVICE_APP_ID).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('directory operations', () => {
  it('lists users with mailbox-relevant fields at the largest page size', async () => {
    const graph = fakeGraph([
      () =>
        collection([
          {
            id: 'u1',
            userPrincipalName: 'reporter@example.com',
            mail: 'reporter@example.com',
            userType: 'Member',
            accountEnabled: true,
            assignedPlans: [
              { service: 'exchange', capabilityStatus: 'Enabled' },
              { service: 'SharePoint', capabilityStatus: 'Enabled' },
            ],
          },
          {
            id: 'u2',
            userPrincipalName: 'guest_example.net#EXT#@example.com',
            mail: null,
            userType: 'Guest',
            accountEnabled: false,
            assignedPlans: [{ service: 'exchange', capabilityStatus: 'Deleted' }],
          },
        ]),
    ]);
    const result = await listUsers(graph.client);
    expect(graph.requests[0].method).toBe('GET');
    expect(graph.requests[0].path).toBe('/users');
    expect(graph.requests[0].query).toEqual({
      $select: 'id,userPrincipalName,mail,userType,accountEnabled,assignedPlans',
      $top: '999',
    });
    expect(result.items).toEqual([
      {
        id: 'u1',
        userPrincipalName: 'reporter@example.com',
        mail: 'reporter@example.com',
        userType: 'Member',
        accountEnabled: true,
        hasExchangePlan: true,
      },
      {
        id: 'u2',
        userPrincipalName: 'guest_example.net#EXT#@example.com',
        mail: undefined,
        userType: 'Guest',
        accountEnabled: false,
        hasExchangePlan: false,
      },
    ]);
  });

  it('bounds the user list', async () => {
    const graph = fakeGraph([
      () => collection([{ id: 'a' }, { id: 'b' }, { id: 'c' }], `${FAKE_BASE}/users?$skiptoken=x`),
    ]);
    const result = await listUsers(graph.client, { maxItems: 2 });
    expect(graph.requests[0].query.$top).toBe('2');
    expect(result.items).toHaveLength(2);
    expect(result.truncated).toBe(true);
    await expect(listUsers(graph.client, { maxItems: 50001 })).rejects.toThrow('maxItems');
  });

  it('summarizes subscribed SKUs into capability flags', async () => {
    const graph = fakeGraph([
      () =>
        collection([
          {
            skuPartNumber: 'EXAMPLE_SUITE_A',
            consumedUnits: 12,
            prepaidUnits: { enabled: 25 },
            servicePlans: [
              { servicePlanName: 'ATP_ENTERPRISE' },
              { servicePlanName: 'AAD_PREMIUM' },
            ],
          },
          {
            // Purchased but nothing assigned: must not count
            skuPartNumber: 'EXAMPLE_SUITE_B',
            consumedUnits: 0,
            prepaidUnits: { enabled: 5 },
            servicePlans: [
              { servicePlanName: 'THREAT_INTELLIGENCE' },
              { servicePlanName: 'AAD_PREMIUM_P2' },
            ],
          },
        ]),
    ]);
    const summary = await listSubscribedSkus(graph.client);
    expect(graph.requests[0].method).toBe('GET');
    expect(graph.requests[0].path).toBe('/subscribedSkus');
    expect(graph.requests[0].url.search).toBe('');
    expect(summary.capabilities).toEqual({
      defenderForOffice365Plan1: true,
      defenderForOffice365Plan2: false,
      entraIdP1: true,
      entraIdP2: false,
    });
    expect(summary.skus[1]).toEqual({
      skuPartNumber: 'EXAMPLE_SUITE_B',
      consumedUnits: 0,
      enabledUnits: 5,
      servicePlanNames: ['THREAT_INTELLIGENCE', 'AAD_PREMIUM_P2'],
    });
  });

  it('reports every capability once its SKU has assigned units', () => {
    expect(
      summarizeCapabilities([
        {
          skuPartNumber: 'X',
          consumedUnits: 1,
          enabledUnits: 1,
          servicePlanNames: ['THREAT_INTELLIGENCE', 'AAD_PREMIUM_P2'],
        },
      ])
    ).toEqual({
      defenderForOffice365Plan1: false,
      defenderForOffice365Plan2: true,
      entraIdP1: false,
      entraIdP2: true,
    });
  });
});

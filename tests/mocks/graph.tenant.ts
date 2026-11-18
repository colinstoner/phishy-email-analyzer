/**
 * An invented Microsoft 365 tenant for Graph probe tests: canned answers
 * for every endpoint the probe calls, in which everything works. Tests
 * prepend responders to change one behaviour at a time.
 *
 * Every identifier here is made up. The MARKER values must never appear in
 * probe output.
 */

import { FakeResponder, RecordedRequest, collection, graphErrorResponse, jsonResponse } from './graph.fake';

export const TENANT = {
  mailbox: 'reporter@example.com',
  sender: 'billing-alerts@example.org',
  subject: 'Invoice 7731 overdue',
  internetMessageId: '<msg-7731.abcdef@mail.example.org>',
  bareMessageId: 'msg-7731.abcdef@mail.example.org',
  graphId: 'AAMkAG-default-id-7731',
  immutableId: 'AAkALg-immutable-id-7731',
  received: '2026-11-16T08:00:00Z',
  recipient: 'colleague@example.com',
  junkFolderId: 'folder-id-junk',
  recoverableFolderId: 'folder-id-recoverable',
  now: new Date('2026-11-17T12:00:00Z'),
} as const;

export const MARKERS = {
  body: 'BODY-CONTENT-MARKER-51ab',
  headerValue: 'HEADER-VALUE-MARKER-93cd',
  attachment: 'ATTACHMENT-CONTENT-MARKER-77ef',
  errorMessage: 'GRAPH-ERROR-MESSAGE-MARKER-12aa',
} as const;

/** Identifiers that must be hashed unless --show-identifiers is given */
export const IDENTIFIERS = [
  TENANT.sender,
  TENANT.subject,
  TENANT.internetMessageId,
  TENANT.bareMessageId,
  TENANT.recipient,
] as const;

export const TEST_MESSAGE = {
  id: TENANT.graphId,
  internetMessageId: TENANT.internetMessageId,
  subject: TENANT.subject,
  from: { emailAddress: { name: 'Billing', address: TENANT.sender } },
  receivedDateTime: TENANT.received,
  parentFolderId: 'folder-id-inbox',
  hasAttachments: true,
  // Graph would not send these for the $select used; present to prove they
  // cannot surface even if it did
  body: { contentType: 'text', content: MARKERS.body },
  bodyPreview: MARKERS.body,
};

export const TRACE_ROW = {
  id: 'trace-row-1',
  messageId: TENANT.internetMessageId,
  senderAddress: TENANT.sender,
  recipientAddress: TENANT.recipient,
  subject: TENANT.subject,
  receivedDateTime: TENANT.received,
  size: 4096,
  fromIP: '192.0.2.25',
  toIP: '198.51.100.7',
  status: 'Delivered',
};

export const MIME =
  `Received: from relay.example.org (${MARKERS.headerValue})\r\n` +
  `From: ${TENANT.sender}\r\nSubject: ${TENANT.subject}\r\n` +
  `Message-ID: ${TENANT.internetMessageId}\r\nContent-Type: text/plain\r\n\r\n` +
  `${MARKERS.body}\r\nNot-A-Header: ${MARKERS.attachment}\r\n`;

const userPrefix = `/users/${encodeURIComponent(TENANT.mailbox)}`;

/** True when the request is for `path` under the test mailbox */
export function mailboxPath(request: RecordedRequest, path: string): boolean {
  return request.path === `${userPrefix}${path}`;
}

export function isMessageItem(request: RecordedRequest): boolean {
  return (
    request.path.startsWith(`${userPrefix}/messages/`) && !request.path.endsWith('/$value')
  );
}

export const TRACE_PATH = '/admin/exchange/tracing/messageTraces';

/** Answers for a tenant where every check passes */
export const workingTenant: FakeResponder = request => {
  const filter = request.query.$filter ?? '';

  if (request.path === '/subscribedSkus') {
    return collection([
      {
        skuPartNumber: 'EXAMPLE_E5',
        consumedUnits: 40,
        prepaidUnits: { enabled: 50 },
        servicePlans: [
          { servicePlanName: 'ATP_ENTERPRISE' },
          { servicePlanName: 'THREAT_INTELLIGENCE' },
          { servicePlanName: 'AAD_PREMIUM' },
        ],
      },
    ]);
  }
  if (request.path === '/users') {
    return collection([
      {
        id: 'user-1',
        userPrincipalName: TENANT.mailbox,
        mail: TENANT.mailbox,
        userType: 'Member',
        accountEnabled: true,
        assignedPlans: [{ service: 'exchange', capabilityStatus: 'Enabled' }],
      },
      {
        id: 'user-2',
        userPrincipalName: 'shared-desk@example.com',
        mail: 'shared-desk@example.com',
        userType: 'Member',
        accountEnabled: false,
        assignedPlans: [],
      },
      { id: 'user-3', userPrincipalName: 'partner_example.net#EXT#@example.com', userType: 'Guest' },
    ]);
  }

  if (mailboxPath(request, '/mailFolders/inbox/messages')) {
    return collection([TEST_MESSAGE]);
  }
  if (mailboxPath(request, '/mailFolders/junkemail')) {
    return jsonResponse({ id: TENANT.junkFolderId, totalItemCount: 3 });
  }
  if (mailboxPath(request, '/mailFolders/recoverableitemsdeletions')) {
    return jsonResponse({ id: TENANT.recoverableFolderId, totalItemCount: 2 });
  }
  if (
    mailboxPath(request, '/mailFolders/junkemail/messages') ||
    mailboxPath(request, '/mailFolders/recoverableitemsdeletions/messages')
  ) {
    return collection([{ ...TEST_MESSAGE, id: 'other-folder-message' }]);
  }

  if (mailboxPath(request, '/messages')) {
    if (request.query.$search !== undefined && request.query.$filter !== undefined) {
      return collection([{ id: TENANT.graphId }]);
    }
    if (filter.startsWith('parentFolderId eq ')) {
      return collection([{ ...TEST_MESSAGE, id: 'other-folder-message' }]);
    }
    return collection([TEST_MESSAGE]);
  }

  if (mailboxPath(request, `/messages/${TENANT.graphId}/$value`)) {
    return new Response(MIME, { status: 200 });
  }
  if (isMessageItem(request)) {
    if (request.query.$select === 'internetMessageHeaders') {
      return jsonResponse({
        id: TENANT.graphId,
        internetMessageHeaders: [
          { name: 'Received', value: MARKERS.headerValue },
          { name: 'Authentication-Results', value: `spf=pass ${MARKERS.headerValue}` },
          { name: 'Received', value: MARKERS.headerValue },
          { name: `X-${MARKERS.headerValue} odd name`, value: 'x' },
        ],
      });
    }
    if (request.query.$expand !== undefined) {
      return jsonResponse({
        id: TENANT.graphId,
        singleValueExtendedProperties: [{ id: 'Integer 0x1081', value: '104' }],
      });
    }
    return jsonResponse({
      ...TEST_MESSAGE,
      id: request.headers.Prefer ? TENANT.immutableId : TENANT.graphId,
    });
  }

  if (request.path === TRACE_PATH) {
    if (filter.includes(`messageId eq '${TENANT.bareMessageId}'`)) {
      return collection([]);
    }
    return collection([TRACE_ROW, { ...TRACE_ROW, id: 'trace-row-2', recipientAddress: TENANT.mailbox }]);
  }
  return undefined;
};

/** A Graph error whose free-text message must never be printed */
export function denied(status = 403, code = 'ErrorAccessDenied', message?: string): Response {
  return graphErrorResponse(status, code, message ?? MARKERS.errorMessage);
}

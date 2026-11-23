/**
 * Original-message fetch: whose mailbox, how the message is found, the
 * unambiguous-match rule and failure behaviour. A real GraphClient over a
 * mocked fetch; no network. Invented data only.
 */

import {
  confirmedReporterMailbox,
  enrichWithOriginalMessage,
  fetchOriginalMessage,
  parseClaimedSentTime,
  plusAddressBase,
  searchWindow,
} from '../../../../src/services/graph';
import { EmailParserService } from '../../../../src/services/email/parser.service';
import { S3Service } from '../../../../src/services/storage/s3.service';
import { EmailMessage, ExtractedEmailData } from '../../../../src/types';
import {
  FakeResponder,
  RecordedRequest,
  collection,
  fakeGraph,
  graphErrorResponse,
  jsonResponse,
} from '../../../mocks/graph.fake';

const REPORTER = 'reporter@example.com';
const SENDER = 'billing-alerts@example.org';
const SUBJECT = 'Invoice 7731 overdue';
const GRAPH_ID = 'AAMkAG-original-7731';
const SAFE_DOMAINS = ['example.com'];
const HEADER_MARKER = 'HEADER-VALUE-MARKER-93cd';

const MAILBOX_PATH = '/users/reporter%40example.com/messages';
const RECOVERABLE_PATH =
  '/users/reporter%40example.com/mailFolders/recoverableitemsdeletions/messages';
const HEADERS_PATH = `/users/reporter%40example.com/messages/${GRAPH_ID}`;

const stored = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: GRAPH_ID,
  internetMessageId: '<msg-7731@mail.example.org>',
  subject: SUBJECT,
  from: { emailAddress: { name: 'Billing', address: SENDER } },
  receivedDateTime: '2026-11-16T16:00:07Z',
  parentFolderId: 'folder-inbox',
  hasAttachments: false,
  body: { content: 'BODY-MUST-NOT-SURFACE' },
  ...overrides,
});

const HEADERS = [
  { name: 'Received', value: 'from mx.example.com by mailbox.example.com' },
  { name: 'Authentication-Results', value: `spf=fail smtp.mailfrom=example.org ${HEADER_MARKER}` },
  { name: 'From', value: `Billing <${SENDER}>` },
  { name: 'Reply-To', value: 'collector@example.net' },
];

const isList = (request: RecordedRequest, path: string): boolean => request.path === path;

/** A mailbox in which the given messages exist in each location */
function mailbox(inMailbox: unknown[], inRecoverable: unknown[] = []): FakeResponder[] {
  return [
    request => (isList(request, MAILBOX_PATH) ? collection(inMailbox) : undefined),
    request => (isList(request, RECOVERABLE_PATH) ? collection(inRecoverable) : undefined),
    request =>
      request.path === HEADERS_PATH ? jsonResponse({ internetMessageHeaders: HEADERS }) : undefined,
  ];
}

const REQUEST = {
  mailbox: REPORTER,
  claimedFrom: `Billing <${SENDER}>`,
  claimedSent: 'Monday, November 16, 2026 8:00 AM',
  claimedSubject: SUBJECT,
};

describe('parseClaimedSentTime', () => {
  it.each([
    ['Monday, November 16, 2026 8:00 AM', '2026-11-16T08:00:00.000Z', false],
    ['Mon, Nov 16, 2026 at 8:00 PM', '2026-11-16T20:00:00.000Z', false],
    ['Mon, Nov 16, 2026 at 12:05 AM', '2026-11-16T00:05:00.000Z', false],
    ['16 November 2026 08:00', '2026-11-16T08:00:00.000Z', false],
    ['November 16, 2026 at 8:00:30 AM PST', '2026-11-16T08:00:30.000Z', false],
    ['Mon, 16 Nov 2026 08:00:00 GMT', '2026-11-16T08:00:00.000Z', true],
    ['Mon, 16 Nov 2026 08:00:00 -0800', '2026-11-16T16:00:00.000Z', true],
    ['Mon, 16 Nov 2026 08:00:00 +05:30', '2026-11-16T02:30:00.000Z', true],
    ['2026-11-16T08:00:00.000Z', '2026-11-16T08:00:00.000Z', true],
    ['2026-11-16 08:00', '2026-11-16T08:00:00.000Z', false],
  ])('reads %s', (text, instant, zoneKnown) => {
    const parsed = parseClaimedSentTime(text);
    expect(parsed?.instant.toISOString()).toBe(instant);
    expect(parsed?.zoneKnown).toBe(zoneKnown);
  });

  it.each([
    [''],
    ['yesterday'],
    ['11/16/2026 8:00 AM'], // day-first or month-first: ambiguous
    ['November 16, 2026'], // no time
    ['February 30, 2026 8:00 AM'],
    ['November 16, 2026 13:00 PM'],
    ['November 16, 2026 25:00'],
    ['November 16, 1999 8:00 AM'],
    ['Mon, 16 Nov 2026 08:00:00 +9900'],
    [`November 16, 2026 8:00 AM ${'x'.repeat(200)}`],
  ])('refuses %s', text => {
    expect(parseClaimedSentTime(text)).toBeUndefined();
  });
});

describe('searchWindow', () => {
  it('is narrow when the zone is known', () => {
    const window = searchWindow({ instant: new Date('2026-11-16T16:00:00Z'), zoneKnown: true });
    expect(window.from.toISOString()).toBe('2026-11-16T13:00:00.000Z');
    expect(window.to.toISOString()).toBe('2026-11-16T19:00:00.000Z');
  });

  it('covers every UTC offset when the zone is unknown', () => {
    const window = searchWindow({ instant: new Date('2026-11-16T08:00:00Z'), zoneKnown: false });
    // 08:00 at UTC+14 is 18:00 the day before; 08:00 at UTC-12 is 20:00 the same day
    expect(window.from.toISOString()).toBe('2026-11-15T15:00:00.000Z');
    expect(window.to.toISOString()).toBe('2026-11-16T23:00:00.000Z');
  });
});

describe('confirmedReporterMailbox', () => {
  const report = (
    overrides: Partial<ExtractedEmailData> = {},
    verdicts: EmailMessage['authVerdicts'] = { spf: 'PASS', dkim: 'FAIL' }
  ): [EmailMessage, ExtractedEmailData, string[]] => {
    const emailData = {
      originalForwarder: REPORTER,
      headers: { From: `Reporter <${REPORTER}>` },
      ...overrides,
    } as ExtractedEmailData;
    return [{ authVerdicts: verdicts } as EmailMessage, emailData, SAFE_DOMAINS];
  };

  it('returns the forwarder when the report is authenticated and From agrees', () => {
    expect(confirmedReporterMailbox(...report())).toBe(REPORTER);
    expect(confirmedReporterMailbox(...report({}, { dkim: 'pass' }))).toBe(REPORTER);
  });

  it('refuses a forwarder that is not the From address', () => {
    // originalForwarder can come from X-Forwarded-For; that must not pick a mailbox
    expect(
      confirmedReporterMailbox(...report({ originalForwarder: 'executive@example.com' }))
    ).toBeUndefined();
  });

  it('refuses a forwarder outside the safe domains', () => {
    expect(
      confirmedReporterMailbox(
        ...report({
          originalForwarder: 'someone@example.net',
          headers: { From: 'someone@example.net' },
        })
      )
    ).toBeUndefined();
  });

  it('refuses a report without an SPF or DKIM pass', () => {
    expect(confirmedReporterMailbox(...report({}, { spf: 'FAIL', dkim: 'GRAY' }))).toBeUndefined();
    expect(confirmedReporterMailbox(...report({}, {}))).toBeUndefined();
  });

  it('refuses an empty forwarder', () => {
    expect(confirmedReporterMailbox(...report({ originalForwarder: '' }))).toBeUndefined();
  });
});

describe('fetchOriginalMessage', () => {
  it('finds a unique message and reads its headers, with GET requests only', async () => {
    const graph = fakeGraph(mailbox([stored()]));
    const result = await fetchOriginalMessage(graph.client, REQUEST);

    expect(result.outcome).toBe('found');
    expect(result.original).toEqual({
      location: 'mailbox',
      receivedAt: '2026-11-16T16:00:07.000Z',
      headers: HEADERS,
      headersTruncated: false,
      // The message as the mailbox stored it: a live removal's anchor
      identity: {
        messageId: 'AAMkAG-original-7731',
        internetMessageId: '<msg-7731@mail.example.org>',
        senderAddress: 'billing-alerts@example.org',
        subject: 'Invoice 7731 overdue',
      },
    });

    expect(graph.requests.map(request => request.method)).toEqual(['GET', 'GET', 'GET']);
    const filter =
      'receivedDateTime ge 2026-11-15T15:00:00.000Z and receivedDateTime lt 2026-11-16T23:00:00.000Z' +
      ` and from/emailAddress/address eq '${SENDER}' and subject eq '${SUBJECT}'`;
    const lists = graph.requests.filter(request => request.path !== HEADERS_PATH);
    expect(lists.map(request => request.path).sort()).toEqual([RECOVERABLE_PATH, MAILBOX_PATH]);
    for (const request of lists) {
      expect(request.query.$filter).toBe(filter);
      expect(request.query.$top).toBe('2');
      expect(request.query.$search).toBeUndefined();
    }
    const headerRequest = graph.requests.find(request => request.path === HEADERS_PATH);
    expect(headerRequest?.query).toEqual({ $select: 'internetMessageHeaders' });
  });

  it('only ever queries the mailbox it was given', async () => {
    const graph = fakeGraph(mailbox([stored()]));
    await fetchOriginalMessage(graph.client, {
      ...REQUEST,
      claimedFrom: 'Chief Executive <executive@example.com>',
    });
    for (const request of graph.requests) {
      expect(request.path.startsWith('/users/reporter%40example.com/')).toBe(true);
    }
  });

  it('finds a message the reporter deleted, in Recoverable Items', async () => {
    const graph = fakeGraph(mailbox([], [stored()]));
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result.outcome).toBe('found');
    expect(result.original?.location).toBe('recoverable_items');
  });

  it('searches without a subject clause when none was claimed', async () => {
    const graph = fakeGraph(mailbox([stored()]));
    const result = await fetchOriginalMessage(graph.client, {
      ...REQUEST,
      claimedSubject: undefined,
    });
    expect(result.outcome).toBe('found');
    expect(graph.requests[0].query.$filter).not.toContain('subject eq');
  });

  it('keeps hostile subject and sender text inside string literals', async () => {
    const hostileSubject = "x' or subject ne '&$top=999#";
    const hostileSender = "o'brien@example.org";
    const graph = fakeGraph(mailbox([]));
    const result = await fetchOriginalMessage(graph.client, {
      ...REQUEST,
      claimedFrom: hostileSender,
      claimedSubject: hostileSubject,
    });

    expect(result.outcome).toBe('not_found');
    expect(graph.requests).toHaveLength(2);
    for (const request of graph.requests) {
      expect(request.query.$filter).toContain("eq 'o''brien@example.org'");
      expect(request.query.$filter).toContain("subject eq 'x'' or subject ne ''&$top=999#'");
      expect(request.query.$top).toBe('2');
      expect(request.url.hash).toBe('');
    }
  });

  it('reports not_found when nothing matches and reads no headers', async () => {
    const graph = fakeGraph(mailbox([]));
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result).toEqual({ outcome: 'not_found', reason: 'no_candidate' });
    expect(graph.requests.some(request => request.path === HEADERS_PATH)).toBe(false);
  });

  it.each([
    ['two in the mailbox', [stored(), stored({ id: 'other-1' })], []],
    ['one in each location', [stored()], [stored({ id: 'other-2' })]],
  ])('reports ambiguous for %s and reads no headers', async (_name, inMailbox, inRecoverable) => {
    const graph = fakeGraph(mailbox(inMailbox, inRecoverable));
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result).toEqual({ outcome: 'ambiguous', reason: 'several_candidates' });
    expect(result.original).toBeUndefined();
    expect(graph.requests.some(request => request.path === HEADERS_PATH)).toBe(false);
  });

  it('reports ambiguous when Graph has more matches than were requested', async () => {
    const graph = fakeGraph([
      request =>
        isList(request, MAILBOX_PATH)
          ? collection([stored()], 'https://graph.microsoft.com/v1.0/users/x/messages?$skip=2')
          : undefined,
      request => (isList(request, RECOVERABLE_PATH) ? collection([]) : undefined),
    ]);
    expect((await fetchOriginalMessage(graph.client, REQUEST)).outcome).toBe('ambiguous');
  });

  it('counts a message returned from both locations once', async () => {
    const graph = fakeGraph(mailbox([stored()], [stored()]));
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result.outcome).toBe('found');
    expect(result.original?.location).toBe('mailbox');
  });

  it.each([
    ['a different sender', { from: { emailAddress: { address: 'other@example.org' } } }],
    ['a different subject', { subject: 'Something else' }],
    ['a time outside the window', { receivedDateTime: '2026-11-20T00:00:00Z' }],
    ['no received time', { receivedDateTime: null }],
  ])('rejects a candidate with %s even though Graph returned it', async (_name, overrides) => {
    const graph = fakeGraph(mailbox([stored(overrides)]));
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result).toEqual({ outcome: 'not_found', reason: 'candidate_failed_recheck' });
  });

  it('accepts sender and subject that differ only in case and spacing', async () => {
    const graph = fakeGraph(
      mailbox([
        stored({
          subject: 'invoice 7731   OVERDUE',
          from: { emailAddress: { address: 'Billing-Alerts@Example.org' } },
        }),
      ])
    );
    expect((await fetchOriginalMessage(graph.client, REQUEST)).outcome).toBe('found');
  });

  it.each([
    ['no sender address', { claimedFrom: 'Billing Department' }, 'no_claimed_sender'],
    ['no sender at all', { claimedFrom: undefined }, 'no_claimed_sender'],
    ['an unreadable sent time', { claimedSent: 'last Tuesday' }, 'no_claimed_time'],
    ['no sent time', { claimedSent: undefined }, 'no_claimed_time'],
    ['an over-long subject', { claimedSubject: 'S'.repeat(300) }, 'subject_too_long'],
  ])('is skipped without any request given %s', async (_name, overrides, reason) => {
    const graph = fakeGraph(mailbox([stored()]));
    const result = await fetchOriginalMessage(graph.client, { ...REQUEST, ...overrides });
    expect(result).toEqual({ outcome: 'skipped', reason });
    expect(graph.requests).toHaveLength(0);
  });

  it('turns a Graph failure into an error outcome without throwing', async () => {
    const graph = fakeGraph([
      () => graphErrorResponse(403, 'ErrorAccessDenied', `denied ${HEADER_MARKER}`),
    ]);
    const result = await fetchOriginalMessage(graph.client, REQUEST);
    expect(result).toEqual({ outcome: 'error', reason: 'graph_http' });
  });

  it('fails as a whole when only the Recoverable Items query fails', async () => {
    const graph = fakeGraph([
      request => (isList(request, MAILBOX_PATH) ? collection([stored()]) : undefined),
      request =>
        isList(request, RECOVERABLE_PATH)
          ? graphErrorResponse(404, 'ErrorItemNotFound')
          : undefined,
    ]);
    // Uniqueness cannot be claimed without seeing both locations
    expect((await fetchOriginalMessage(graph.client, REQUEST)).outcome).toBe('error');
  });

  it('reports an error when the message has no readable headers', async () => {
    const graph = fakeGraph([
      request => (isList(request, MAILBOX_PATH) ? collection([stored()]) : undefined),
      request => (isList(request, RECOVERABLE_PATH) ? collection([]) : undefined),
      request => (request.path === HEADERS_PATH ? jsonResponse({ id: GRAPH_ID }) : undefined),
    ]);
    expect(await fetchOriginalMessage(graph.client, REQUEST)).toEqual({
      outcome: 'error',
      reason: 'no_headers_returned',
    });
  });

  it('gives up when the time budget runs out', async () => {
    // Graph answers, but only after the budget has passed
    const graph = fakeGraph([]);
    graph.fetchMock.mockImplementation(
      () => new Promise<Response>(resolve => setTimeout(() => resolve(collection([stored()])), 250))
    );
    const startedAt = Date.now();
    const result = await fetchOriginalMessage(graph.client, REQUEST, { budgetMs: 30 });
    expect(result).toEqual({ outcome: 'error', reason: 'budget_exceeded' });
    expect(Date.now() - startedAt).toBeLessThan(200);

    // The late answer is discarded: the header read is never started
    await new Promise(resolve => setTimeout(resolve, 350));
    expect(graph.fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('enrichWithOriginalMessage', () => {
  const parser = new EmailParserService({} as S3Service, SAFE_DOMAINS, 'test-bucket');

  const report = (): { msg: EmailMessage; emailData: ExtractedEmailData } => {
    const msg: EmailMessage = {
      from_email: REPORTER,
      subject: `FW: ${SUBJECT}`,
      text: [
        'Is this real?',
        '',
        `From: Billing <${SENDER}>`,
        'Sent: Monday, November 16, 2026 8:00 AM',
        `To: Reporter <${REPORTER}>`,
        `Subject: ${SUBJECT}`,
        '',
        'Please settle the attached invoice today.',
      ].join('\n'),
      html: null,
      headers: { From: `Reporter <${REPORTER}>` },
      to: 'phishy@example.com',
      authVerdicts: { spf: 'PASS', dkim: 'PASS' },
    };
    return { msg, emailData: parser.extractEmailData(msg) };
  };

  let stdout: jest.SpyInstance;
  const savedDisable = process.env.PHISHY_DISABLE_METRICS;

  beforeEach(() => {
    delete process.env.PHISHY_DISABLE_METRICS;
    stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    process.env.PHISHY_DISABLE_METRICS = savedDisable;
  });

  const emitted = (): Array<Record<string, unknown>> =>
    stdout.mock.calls
      .map(call => String(call[0]))
      .filter(line => line.includes('OriginalFetchCount'))
      .map(line => JSON.parse(line) as Record<string, unknown>);

  it('attaches the retrieved headers and emits a found metric', async () => {
    const { msg, emailData } = report();
    const graph = fakeGraph(mailbox([stored()]));
    const result = await enrichWithOriginalMessage(
      graph.client,
      parser,
      msg,
      emailData,
      SAFE_DOMAINS
    );

    expect(result.outcome).toBe('found');
    expect(emailData.retrievedOriginal?.location).toBe('mailbox');
    expect(emailData.retrievedOriginal?.headers).toHaveLength(HEADERS.length);
    expect(emitted()).toHaveLength(1);
    expect(emitted()[0]).toMatchObject({ Outcome: 'found', OriginalFetchCount: 1 });
  });

  it.each([
    ['not_found', mailbox([])],
    ['ambiguous', mailbox([stored(), stored({ id: 'other-1' })])],
    ['error', [(): Response => graphErrorResponse(503, 'ServiceUnavailable')]],
  ])('leaves the email facts exactly as they were on %s', async (outcome, responders) => {
    const { msg, emailData } = report();
    const before = JSON.parse(JSON.stringify(emailData)) as unknown;
    const graph = fakeGraph(responders);

    const result = await enrichWithOriginalMessage(
      graph.client,
      parser,
      msg,
      emailData,
      SAFE_DOMAINS
    );

    expect(result.outcome).toBe(outcome);
    expect(JSON.parse(JSON.stringify(emailData))).toEqual(before);
    expect(emitted()[0]).toMatchObject({ Outcome: outcome });
  });

  it('makes no request when the reporter cannot be confirmed', async () => {
    const { msg, emailData } = report();
    const graph = fakeGraph(mailbox([stored()]));
    const result = await enrichWithOriginalMessage(
      graph.client,
      parser,
      { ...msg, authVerdicts: undefined },
      emailData,
      SAFE_DOMAINS
    );

    expect(result).toEqual({ outcome: 'skipped', reason: 'reporter_not_confirmed' });
    expect(graph.requests).toHaveLength(0);
    expect(emailData.retrievedOriginal).toBeUndefined();
    expect(emitted()[0]).toMatchObject({ Outcome: 'skipped' });
  });

  describe('a reporter address that is not a mailbox name', () => {
    const PLUS = 'reporter+phish@example.com';
    const PLUS_PATH = '/users/reporter%2Bphish%40example.com/';
    const plusReport = (address = PLUS): { msg: EmailMessage; emailData: ExtractedEmailData } => {
      const { msg } = report();
      const plusMsg: EmailMessage = {
        ...msg,
        from_email: address,
        headers: { From: `Reporter <${address}>` },
      };
      return { msg: plusMsg, emailData: parser.extractEmailData(plusMsg) };
    };
    const unknownMailbox =
      (prefix: string): FakeResponder =>
      request =>
        request.path.startsWith(prefix)
          ? graphErrorResponse(404, 'ErrorInvalidUser', 'The requested user is invalid.')
          : undefined;

    it('resolves a plus-address through its base address', async () => {
      const { msg, emailData } = plusReport();
      const graph = fakeGraph([unknownMailbox(PLUS_PATH), ...mailbox([stored()])]);
      const result = await enrichWithOriginalMessage(
        graph.client,
        parser,
        msg,
        emailData,
        SAFE_DOMAINS
      );

      expect(result.outcome).toBe('found');
      expect(emailData.retrievedOriginal?.headers).toHaveLength(HEADERS.length);
      // First the confirmed address, then once its base: never anything else
      const mailboxes = [...new Set(graph.requests.map(r => r.path.split('/')[2]))];
      expect(mailboxes).toEqual(['reporter%2Bphish%40example.com', 'reporter%40example.com']);
      expect(graph.requests.every(r => r.method === 'GET')).toBe(true);
      expect(emitted()).toHaveLength(1);
      expect(emitted()[0]).toMatchObject({ Outcome: 'found' });
    });

    it('ends as not found when the base address is not a mailbox either', async () => {
      const { msg, emailData } = plusReport();
      const graph = fakeGraph([unknownMailbox('/users/')]);
      const result = await enrichWithOriginalMessage(
        graph.client,
        parser,
        msg,
        emailData,
        SAFE_DOMAINS
      );
      expect(result).toEqual({ outcome: 'not_found', reason: 'mailbox_not_found' });
      expect(emailData.retrievedOriginal).toBeUndefined();
      expect(emitted()[0]).toMatchObject({ Outcome: 'not_found' });
      // One retry, not a loop
      const mailboxes = new Set(graph.requests.map(r => r.path.split('/')[2]));
      expect(mailboxes.size).toBe(2);
    });

    it('ends as not found, without a retry, for an unknown address with no +tag', async () => {
      const { msg, emailData } = report();
      const graph = fakeGraph([unknownMailbox('/users/')]);
      const result = await enrichWithOriginalMessage(
        graph.client,
        parser,
        msg,
        emailData,
        SAFE_DOMAINS
      );
      expect(result).toEqual({ outcome: 'not_found', reason: 'mailbox_not_found' });
      expect(graph.requests).toHaveLength(2);
    });

    it('still refuses an address that is not on a safe domain, with or without a +tag', async () => {
      for (const address of ['reporter+phish@example.net', 'reporter@example.net']) {
        const { msg, emailData } = plusReport(address);
        const graph = fakeGraph(mailbox([stored()]));
        const result = await enrichWithOriginalMessage(
          graph.client,
          parser,
          msg,
          emailData,
          SAFE_DOMAINS
        );
        expect(result).toEqual({ outcome: 'skipped', reason: 'reporter_not_confirmed' });
        expect(graph.requests).toHaveLength(0);
      }
      expect(plusAddressBase('reporter+phish@example.net', SAFE_DOMAINS)).toBeUndefined();
      expect(plusAddressBase('reporter+phish@example.com', SAFE_DOMAINS)).toBe(
        'reporter@example.com'
      );
      expect(plusAddressBase('+phish@example.com', SAFE_DOMAINS)).toBeUndefined();
      expect(plusAddressBase('reporter@example.com', SAFE_DOMAINS)).toBeUndefined();
    });

    it('keeps other failures errors: a missing message or folder is not a missing mailbox', async () => {
      const { msg, emailData } = plusReport();
      const graph = fakeGraph([() => graphErrorResponse(404, 'ErrorItemNotFound')]);
      const result = await enrichWithOriginalMessage(
        graph.client,
        parser,
        msg,
        emailData,
        SAFE_DOMAINS
      );
      expect(result).toEqual({ outcome: 'error', reason: 'graph_http' });
    });
  });

  it('survives a parser that throws', async () => {
    const { msg, emailData } = report();
    const graph = fakeGraph(mailbox([stored()]));
    const throwing = {
      attachRetrievedOriginal: (): void => {
        throw new Error('boom');
      },
    };
    const result = await enrichWithOriginalMessage(
      graph.client,
      throwing,
      msg,
      emailData,
      SAFE_DOMAINS
    );
    expect(result).toEqual({ outcome: 'error', reason: 'unexpected' });
    expect(emailData.retrievedOriginal).toBeUndefined();
  });
});

describe('original-message lookup log output', () => {
  // Loggers capture their level at module load, so load the modules fresh
  // with logging at its most verbose
  type GraphModule = typeof import('../../../../src/services/graph');
  const savedLevel = process.env.LOG_LEVEL;
  const savedDisable = process.env.PHISHY_DISABLE_METRICS;
  let fresh: GraphModule;

  beforeAll(async () => {
    process.env.LOG_LEVEL = 'debug';
    jest.resetModules();
    fresh = await import('../../../../src/services/graph');
  });

  afterAll(() => {
    process.env.LOG_LEVEL = savedLevel;
    process.env.PHISHY_DISABLE_METRICS = savedDisable;
    jest.resetModules();
  });

  it('never contains addresses, subjects or header content, even at debug level', async () => {
    delete process.env.PHISHY_DISABLE_METRICS;
    const lines: string[] = [];
    const capture = (...args: unknown[]): boolean => {
      lines.push(args.map(String).join(' '));
      return true;
    };
    jest.spyOn(console, 'log').mockImplementation(capture);
    jest.spyOn(console, 'warn').mockImplementation(capture);
    jest.spyOn(console, 'error').mockImplementation(capture);
    jest.spyOn(process.stdout, 'write').mockImplementation(capture);

    const parser = new EmailParserService({} as S3Service, SAFE_DOMAINS, 'test-bucket');
    const responderSets: FakeResponder[][] = [
      mailbox([stored()]),
      mailbox([stored(), stored({ id: 'other-1' })]),
      [(): Response => graphErrorResponse(403, 'ErrorAccessDenied', `denied ${HEADER_MARKER}`)],
    ];
    for (const responders of responderSets) {
      const fake = fakeGraph(responders);
      const client = new fresh.GraphClient({
        tokenProvider: {
          label: 'read',
          getToken: () => Promise.resolve(fake.token),
          invalidate: () => undefined,
        },
        fetchImpl: fake.fetchMock as unknown as typeof fetch,
        maxAttempts: 1,
      });
      const msg: EmailMessage = {
        from_email: REPORTER,
        subject: `FW: ${SUBJECT}`,
        text: `From: Billing <${SENDER}>\nSent: Monday, November 16, 2026 8:00 AM\nTo: ${REPORTER}\nSubject: ${SUBJECT}\n\nPay now.`,
        html: null,
        headers: { From: REPORTER },
        to: 'phishy@example.com',
        authVerdicts: { spf: 'PASS' },
      };
      await fresh.enrichWithOriginalMessage(
        client,
        parser,
        msg,
        parser.extractEmailData(msg),
        SAFE_DOMAINS
      );
    }

    const written = lines.join('\n');
    expect(written).toContain('Original-message lookup finished');
    expect(written).toContain('"outcome":"found"');
    expect(written).toContain('"outcome":"ambiguous"');
    expect(written).toContain('ErrorAccessDenied');
    for (const hostile of [SENDER, REPORTER, SUBJECT, HEADER_MARKER, 'collector@example.net']) {
      expect(written).not.toContain(hostile);
    }
  });
});

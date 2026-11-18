/**
 * Graph probe checks
 *
 * A fixed list of read-only questions asked of one Microsoft 365 tenant:
 * which Graph calls work there, with which permissions and licences.
 * Microsoft's reference documentation leaves several behaviours unstated
 * (docs/GRAPH_PROBE.md lists them); these checks answer them empirically
 * before any Phishy feature depends on the answer.
 *
 * Rules this module keeps:
 * - GET only. It never calls `postJson`, and uses the operations library
 *   for every request but one experiment (`$search` with `$filter`).
 * - A failed or skipped check never stops the run.
 * - Nothing read from a mailbox is reported except counts, sizes, booleans,
 *   header *names*, status values and Graph error codes. Addresses, subjects
 *   and message IDs go through `Redactor` and are hashed unless the operator
 *   asked to see them. Bodies, attachment content and header values are
 *   never reported at all.
 */

import { createHash, randomBytes } from 'crypto';
import {
  BoundedResult,
  GraphAuthError,
  GraphClient,
  GraphError,
  MESSAGE_TRACE_SERVICE_APP_ID,
  MessageSummary,
  MessageTrace,
  TRACE_MAX_AGE_MS,
  WellKnownMailFolder,
  addAngleBrackets,
  findMessagesByInternetMessageId,
  findMessagesByParentFolder,
  findMessagesBySender,
  getLastVerb,
  getMailFolder,
  getMessageHeaders,
  getMessageMime,
  getMessageSummary,
  graphPath,
  kqlSearch,
  kqlWords,
  listMessageTracesByMessageId,
  listMessageTracesBySender,
  listRecentMessageTraces,
  listRecentMessages,
  listSubscribedSkus,
  listUsers,
  odataFilter,
  searchMessages,
  stripAngleBrackets,
} from '../services/graph';

export type CheckStatus = 'PASS' | 'FAIL' | 'SKIPPED';

export interface CheckDefinition {
  id: string;
  name: string;
  /** The question this check answers */
  question: string;
  /** Application permissions, any one of which the check needs */
  permissions: string[];
}

export interface CheckResult extends CheckDefinition {
  status: CheckStatus;
  /** One line; already redacted */
  detail: string;
  /** HTTP status of the failing request, when there was one */
  httpStatus?: number;
  /** Graph error code of the failing request, when there was one */
  errorCode?: string;
}

interface CheckOutcome {
  status: CheckStatus;
  detail: string;
  httpStatus?: number;
  errorCode?: string;
}

const MAIL_BASIC = ['Mail.ReadBasic.All', 'Mail.Read'];
const MAIL_FULL = ['Mail.Read'];
const TRACE = ['ExchangeMessageTrace.Read.All'];

/** Every check, in the order it runs */
export const PROBE_CHECKS = [
  {
    id: 'token',
    name: 'Token acquired',
    question:
      'Can the app authenticate with its certificate, and which application roles does it hold?',
    permissions: [],
  },
  {
    id: 'licences',
    name: 'Licence capabilities',
    question: 'Which Defender for Office 365 and Entra ID plans have assigned licences?',
    permissions: ['LicenseAssignment.Read.All', 'Organization.Read.All'],
  },
  {
    id: 'users',
    name: 'List users',
    question: 'Can mailbox owners be listed, and how many have a mail address or Exchange plan?',
    permissions: ['User.Read.All'],
  },
  {
    id: 'mailbox-read',
    name: 'Read mailbox metadata',
    question: 'Can the app read message metadata in the test mailbox?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'find-by-message-id',
    name: 'Find by internetMessageId',
    question:
      'Does $filter=internetMessageId eq ... work on /messages (not documented as supported)?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'covers-junkemail',
    name: '/messages covers Junk Email',
    question: 'Does /users/{id}/messages include items in Junk Email (not stated)?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'covers-recoverableitemsdeletions',
    name: '/messages covers Recoverable Items',
    question:
      'Does /users/{id}/messages include items in Recoverable Items > Deletions (not stated)?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'sender-window',
    name: 'Sender + time-window filter',
    question: 'Does filtering by sender, received window and exact subject (with $orderby) work?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'search',
    name: '$search',
    question: 'Does $search with a KQL property work, and does it need ConsistencyLevel?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'search-with-filter',
    name: '$search combined with $filter',
    question: 'Can $search and $filter be used in one request on messages (not in the reference)?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'headers',
    name: 'Internet headers via $select',
    question: 'Are internetMessageHeaders returned with the permissions granted?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'mime',
    name: 'MIME download',
    question: 'Does /messages/{id}/$value work (unstated whether Mail.ReadBasic.All is enough)?',
    permissions: MAIL_FULL,
  },
  {
    id: 'last-verb',
    name: 'Last-verb extended property',
    question:
      "Is PidTagLastVerbExecuted readable with the id 'Integer 0x1081' (constructed, not quoted by Microsoft)?",
    permissions: MAIL_FULL,
  },
  {
    id: 'immutable-id',
    name: 'Immutable ID header',
    question: 'Is Prefer: IdType="ImmutableId" accepted, and can a message be fetched by that ID?',
    permissions: MAIL_BASIC,
  },
  {
    id: 'trace-reachable',
    name: 'Message trace reachable',
    question: 'Does message trace work: service principal provisioned, permission consented?',
    permissions: TRACE,
  },
  {
    id: 'trace-message-id-brackets',
    name: 'Message trace by messageId (with <>)',
    question: 'Does messageId eq ... match when the value keeps its angle brackets (not stated)?',
    permissions: TRACE,
  },
  {
    id: 'trace-message-id-bare',
    name: 'Message trace by messageId (without <>)',
    question: 'Does messageId eq ... match when the angle brackets are removed (not stated)?',
    permissions: TRACE,
  },
  {
    id: 'trace-sender-subject',
    name: 'Message trace by sender + subject',
    question: 'Does filtering traces by senderAddress, contains(subject) and a date range work?',
    permissions: TRACE,
  },
] as const satisfies readonly CheckDefinition[];

export type ProbeCheckId = (typeof PROBE_CHECKS)[number]['id'];

const ALL_IDS: readonly ProbeCheckId[] = PROBE_CHECKS.map(check => check.id);
/** Checks that need a mailbox and a test message in it */
const MAIL_IDS: readonly ProbeCheckId[] = [
  'mailbox-read',
  'find-by-message-id',
  'covers-junkemail',
  'covers-recoverableitemsdeletions',
  'sender-window',
  'search',
  'search-with-filter',
  'headers',
  'mime',
  'last-verb',
  'immutable-id',
];

export interface ProbeOptions {
  /** UPN or user ID of the test mailbox; without it the mail checks are skipped */
  mailbox?: string;
  /** Internet message ID of the test message; default is the newest inbox message */
  messageId?: string;
  /** Show addresses, subjects and message IDs instead of hashes */
  showIdentifiers?: boolean;
  /** Injected for tests */
  now?: () => Date;
  /** Injected for tests; default is random per run */
  salt?: string;
}

export interface ProbeDependencies {
  client: GraphClient;
  /** The access token the client uses; read only to list its `roles` claim */
  getToken: () => Promise<string>;
}

export interface ProbeReport {
  generatedAt: string;
  identifiersShown: boolean;
  /** False when no access token could be obtained (a credential error) */
  tokenAcquired: boolean;
  summary: { pass: number; fail: number; skipped: number };
  checks: CheckResult[];
}

export type IdentifierKind = 'address' | 'subject' | 'message-id';

/**
 * Replaces identifiers with short hashes. The hash is salted per run, so the
 * same value gets the same label throughout one report (labels can be
 * compared within it) but a published report cannot be used to confirm a
 * guessed address or subject.
 */
export class Redactor {
  private readonly salt: string;

  constructor(
    private readonly showIdentifiers: boolean,
    salt?: string
  ) {
    this.salt = salt ?? randomBytes(16).toString('hex');
  }

  id(kind: IdentifierKind, value: string | undefined): string {
    if (value === undefined || value === '') {
      return `${kind}:(none)`;
    }
    if (this.showIdentifiers) {
      // One printable line, whatever the value held
      return value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, ' ').slice(0, 200);
    }
    const digest = createHash('sha256')
      .update(`${this.salt}\0${kind}\0${value.trim().toLowerCase()}`)
      .digest('hex');
    return `${kind}#${digest.slice(0, 8)}`;
  }
}

const HEADER_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
const MAX_HEADER_NAMES = 40;

/**
 * Header names fit to print: de-duplicated, restricted to the characters a
 * header name is made of, and capped. Names are chosen by whoever sent the
 * mail, so anything unusual is counted instead of shown.
 */
export function printableHeaderNames(names: string[]): string {
  const unique = [...new Set(names.map(name => name.trim()))];
  const printable = unique.filter(name => HEADER_NAME_PATTERN.test(name));
  const shown = printable.slice(0, MAX_HEADER_NAMES);
  const hidden = unique.length - shown.length;
  return `${shown.join(', ') || '(none)'}${hidden > 0 ? ` (+${hidden} more not shown)` : ''}`;
}

/** Header names from the top-level header block of a MIME message */
export function mimeHeaderNames(mime: Buffer): string[] {
  const head = mime.subarray(0, 256 * 1024).toString('latin1');
  const end = head.search(/\r?\n\r?\n/);
  const block = end === -1 ? head : head.slice(0, end);
  return block
    .split(/\r?\n/)
    .map(line => /^([^\s:]+):/.exec(line)?.[1])
    .filter((name): name is string => name !== undefined);
}

/**
 * The `roles` claim of an access token. The token is decoded, not
 * verified: this is only a display of what Entra granted. Nothing else from
 * the token is returned.
 */
export function decodeTokenRoles(token: string): string[] | undefined {
  const payload = token.split('.')[1];
  if (!payload) {
    return undefined;
  }
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      roles?: unknown;
    };
    if (!Array.isArray(claims.roles)) {
      return [];
    }
    return claims.roles
      .filter(
        (role): role is string => typeof role === 'string' && /^[A-Za-z0-9._-]{1,100}$/.test(role)
      )
      .sort();
  } catch {
    return undefined;
  }
}

function pass(detail: string): CheckOutcome {
  return { status: 'PASS', detail };
}
function fail(detail: string): CheckOutcome {
  return { status: 'FAIL', detail };
}
function skip(detail: string): CheckOutcome {
  return { status: 'SKIPPED', detail };
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

function graphStatusText(error: GraphError): string {
  return `HTTP ${error.status ?? '?'}${error.code ? ` ${error.code}` : ''}`;
}

/**
 * Turn a thrown error into a FAIL outcome. Only values Phishy or Microsoft
 * chose are reported: status, Graph error code, failure kind, error class.
 * Graph's free-text message can echo request input and is never printed.
 */
export function describeFailure(
  error: unknown,
  permissions: readonly string[],
  roles?: readonly string[]
): CheckOutcome {
  if (error instanceof GraphError) {
    const base = { status: 'FAIL' as const, httpStatus: error.status, errorCode: error.code };
    if (error.status === 401 || error.status === 403) {
      const needed = permissions.join(' or ') || 'an application permission';
      const absent =
        roles !== undefined && permissions.length > 0 && !permissions.some(p => roles.includes(p));
      const hint = !absent
        ? ''
        : permissions.some(p => p.startsWith('Mail.'))
          ? '; not in the token roles (if granted through Exchange RBAC, check its scope covers this mailbox)'
          : '; not in the token roles';
      return {
        ...base,
        detail: `permission missing or not consented: needs ${needed} (${graphStatusText(error)})${hint}`,
      };
    }
    if (error.status === 429) {
      return { ...base, detail: `throttled by Graph; re-run later (${graphStatusText(error)})` };
    }
    if (error.status !== undefined) {
      return { ...base, detail: `Graph rejected the request (${graphStatusText(error)})` };
    }
    return { ...base, detail: `request did not complete (${error.kind})` };
  }
  if (error instanceof GraphAuthError) {
    // Written by graph.auth.ts from status and OAuth/AADSTS codes only
    return {
      status: 'FAIL',
      detail: error.message,
      httpStatus: error.status,
      errorCode: error.code,
    };
  }
  return {
    status: 'FAIL',
    detail: `unexpected ${error instanceof Error ? error.name : 'error'} inside the probe`,
  };
}

function isAuthorizationFailure(error: unknown): error is GraphError {
  return error instanceof GraphError && (error.status === 401 || error.status === 403);
}

function tally(values: (string | undefined)[], pattern: RegExp): string {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = value !== undefined && pattern.test(value) ? value : '(other)';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return (
    [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([key, count]) => `${key} ${count}`)
      .join(', ') || 'none'
  );
}

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

/** A message to run trace checks against, from the mailbox or from a trace row */
interface TraceSubject {
  messageId?: string;
  senderAddress?: string;
  subject?: string;
  received?: Date;
}

function parseDate(value: string | undefined): Date | undefined {
  if (value === undefined) {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * Run every check and return the report. Never throws for a failed check;
 * a token that cannot be obtained is reported through `tokenAcquired`.
 */
export async function runProbe(
  deps: ProbeDependencies,
  options: ProbeOptions = {}
): Promise<ProbeReport> {
  const { client } = deps;
  const now = options.now ?? ((): Date => new Date());
  const redactor = new Redactor(options.showIdentifiers === true, options.salt);
  const results = new Map<ProbeCheckId, CheckOutcome>();
  // Written from inside check closures, so kept on one object
  const state: {
    tokenAcquired: boolean;
    roles?: string[];
    subject?: MessageSummary;
    traceReachable: boolean;
    traceSample?: MessageTrace;
  } = { tokenAcquired: false, traceReachable: false };

  const definition = (id: ProbeCheckId): CheckDefinition =>
    PROBE_CHECKS.find(check => check.id === id) as CheckDefinition;

  const run = async (id: ProbeCheckId, check: () => Promise<CheckOutcome>): Promise<void> => {
    try {
      results.set(id, await check());
    } catch (error) {
      results.set(id, describeFailure(error, definition(id).permissions, state.roles));
    }
  };

  const skipUnrun = (ids: readonly ProbeCheckId[], reason: string): void => {
    for (const id of ids) {
      if (!results.has(id)) {
        results.set(id, skip(reason));
      }
    }
  };

  const finish = (): ProbeReport => {
    const checks: CheckResult[] = PROBE_CHECKS.map(check => ({
      ...check,
      permissions: [...check.permissions],
      ...(results.get(check.id) ?? skip('not run')),
    }));
    return {
      generatedAt: now().toISOString(),
      identifiersShown: options.showIdentifiers === true,
      tokenAcquired: state.tokenAcquired,
      summary: {
        pass: checks.filter(check => check.status === 'PASS').length,
        fail: checks.filter(check => check.status === 'FAIL').length,
        skipped: checks.filter(check => check.status === 'SKIPPED').length,
      },
      checks,
    };
  };

  // --- Token -------------------------------------------------------------
  await run('token', async () => {
    const token = await deps.getToken();
    state.tokenAcquired = true;
    const roles = decodeTokenRoles(token);
    state.roles = roles;
    if (roles === undefined) {
      return pass('token acquired; its roles could not be decoded');
    }
    return pass(
      `token acquired; application roles: ${roles.join(', ') || '(none - mailbox access may still be granted through Exchange RBAC)'}`
    );
  });
  if (!state.tokenAcquired) {
    skipUnrun(ALL_IDS, 'no access token');
    return finish();
  }

  // --- Directory ---------------------------------------------------------
  await run('licences', async () => {
    const { skus, capabilities, truncated } = await listSubscribedSkus(client);
    return pass(
      `${skus.length} SKU(s)${truncated ? ' (list truncated)' : ''}; ` +
        `Defender for Office 365 P1: ${yesNo(capabilities.defenderForOffice365Plan1)}, ` +
        `P2: ${yesNo(capabilities.defenderForOffice365Plan2)}; ` +
        `Entra ID P1: ${yesNo(capabilities.entraIdP1)}, P2: ${yesNo(capabilities.entraIdP2)} ` +
        '(yes = a SKU with the plan has assigned licences)'
    );
  });

  await run('users', async () => {
    const { items, truncated } = await listUsers(client, { maxItems: 5000 });
    return pass(
      `${items.length} user(s)${truncated ? ' (first 5000 only)' : ''}; ` +
        `userType: ${tally(
          items.map(user => user.userType),
          /^[A-Za-z]{1,20}$/
        )}; ` +
        `with mail: ${items.filter(user => user.mail !== undefined).length}; ` +
        `with enabled Exchange plan: ${items.filter(user => user.hasExchangePlan).length}; ` +
        `disabled accounts: ${items.filter(user => user.accountEnabled === false).length}`
    );
  });

  // --- Mailbox -----------------------------------------------------------
  const mailbox = options.mailbox;

  if (mailbox !== undefined) {
    await run('mailbox-read', async () => {
      const { items } = await listRecentMessages(client, { mailbox, folder: 'inbox', maxItems: 1 });
      if (options.messageId === undefined) {
        state.subject = items[0];
      }
      if (items.length === 0) {
        return pass('metadata readable; the inbox is empty, so there is no default test message');
      }
      return pass(
        options.messageId === undefined
          ? `metadata readable; test message is the newest in the inbox: ${describeMessage(redactor, items[0])}`
          : 'metadata readable'
      );
    });

    await run('find-by-message-id', async () => {
      const wanted = options.messageId ?? state.subject?.internetMessageId;
      if (wanted === undefined) {
        return skip('no message ID to look for (give --message-id, or put a message in the inbox)');
      }
      const { items } = await findMessagesByInternetMessageId(client, {
        mailbox,
        internetMessageId: wanted,
        maxItems: 10,
      });
      if (options.messageId !== undefined) {
        state.subject = items[0];
      }
      if (items.length === 0) {
        return fail(
          options.messageId !== undefined
            ? `filter accepted but matched 0 messages for ${redactor.id('message-id', wanted)} (is it in this mailbox, with its angle brackets?)`
            : 'filter accepted but matched 0 messages, although the message is in the inbox: the filter is not effective here'
        );
      }
      return pass(
        `filter accepted; ${items.length} message(s) matched ${redactor.id('message-id', wanted)}` +
          (options.messageId !== undefined ? `: ${describeMessage(redactor, items[0])}` : '')
      );
    });

    for (const folder of ['junkemail', 'recoverableitemsdeletions'] as const) {
      await run(`covers-${folder}`, () => checkFolderCoverage(client, mailbox, folder));
    }
  }

  const testMessage = state.subject;

  if (mailbox !== undefined && testMessage !== undefined) {
    const received = parseDate(testMessage.receivedDateTime);
    const sender = testMessage.fromAddress;

    await run('sender-window', async () => {
      if (sender === undefined || received === undefined) {
        return skip('the test message has no sender address or received time');
      }
      const window = {
        mailbox,
        senderAddress: sender,
        receivedFrom: new Date(received.getTime() - HOUR_MS),
        receivedTo: new Date(received.getTime() + HOUR_MS),
        maxItems: 50,
      };
      const bySender = await findMessagesBySender(client, window);
      const found = bySender.items.some(item => item.id === testMessage.id);
      let withSubject = 'not tried (test message has no subject)';
      if (testMessage.subject) {
        try {
          const exact = await findMessagesBySender(client, {
            ...window,
            subject: testMessage.subject,
          });
          withSubject = `${exact.items.length} matched`;
        } catch (error) {
          withSubject = `rejected: ${describeFailure(error, MAIL_BASIC, state.roles).detail}`;
        }
      }
      const detail = `sender + 2h window: ${bySender.items.length} matched, test message among them: ${yesNo(found)}; adding exact subject: ${withSubject}`;
      return found ? pass(detail) : fail(detail);
    });

    await run('search', async () => {
      if (sender === undefined) {
        return skip('the test message has no sender address to search for');
      }
      const describe = (result: BoundedResult<MessageSummary>): string =>
        `${result.items.length} result(s)${result.truncated ? ' (first 50)' : ''}, test message among them: ${yesNo(
          result.items.some(item => item.id === testMessage.id)
        )}`;
      // A second search exercises the grouped form used for multi-word
      // values, `subject:(word word)`; it adds to the detail, not the result
      const grouped = async (consistencyLevel?: 'eventual'): Promise<string> => {
        if (!testMessage.subject || kqlWords(testMessage.subject).length < 2) {
          return 'grouped subject: search not tried (test subject has fewer than two words)';
        }
        try {
          const bySubject = await searchMessages(client, {
            mailbox,
            terms: { subject: testMessage.subject },
            maxItems: 50,
            consistencyLevel,
          });
          return `grouped subject: search returned ${describe(bySubject)}`;
        } catch (error) {
          return `grouped subject: search failed: ${describeFailure(error, MAIL_BASIC, state.roles).detail}`;
        }
      };
      try {
        const plain = await searchMessages(client, {
          mailbox,
          terms: { from: sender },
          maxItems: 50,
        });
        return pass(
          `accepted without ConsistencyLevel; from: search returned ${describe(plain)}; ${await grouped()}`
        );
      } catch (error) {
        if (!(error instanceof GraphError) || error.status !== 400) {
          throw error;
        }
        const eventual = await searchMessages(client, {
          mailbox,
          terms: { from: sender },
          maxItems: 50,
          consistencyLevel: 'eventual',
        });
        return pass(
          `rejected without ConsistencyLevel (${graphStatusText(error)}), accepted with ConsistencyLevel: eventual; from: search returned ${describe(eventual)}; ${await grouped('eventual')}`
        );
      }
    });

    await run('search-with-filter', async () => {
      if (sender === undefined || received === undefined) {
        return skip('the test message has no sender address or received time');
      }
      try {
        // The one request not made through the operations library: an
        // experiment no feature should rely on until a tenant confirms it
        const result = await client.getPaged(graphPath`/users/${mailbox}/messages`, {
          query: {
            select: ['id'],
            search: kqlSearch({ from: sender }),
            filter: odataFilter`receivedDateTime ge ${new Date(received.getTime() - DAY_MS)}`,
            top: 10,
          },
          maxItems: 10,
          maxPages: 1,
        });
        return pass(`accepted; ${result.items.length} result(s) (capped at 10)`);
      } catch (error) {
        if (error instanceof GraphError && error.status === 400) {
          return {
            ...fail(
              `not supported: Graph rejected $search with $filter (${graphStatusText(error)})`
            ),
            httpStatus: error.status,
            errorCode: error.code,
          };
        }
        throw error;
      }
    });

    await run('headers', async () => {
      const { items, truncated } = await getMessageHeaders(client, {
        mailbox,
        messageId: testMessage.id,
      });
      if (items.length === 0) {
        return fail(
          'request accepted but no headers were returned (expected for sent or draft items; otherwise the permission granted may not include them)'
        );
      }
      return pass(
        `${items.length}${truncated ? '+' : ''} header(s); names: ${printableHeaderNames(items.map(header => header.name))}`
      );
    });

    await run('mime', async () => {
      const mime = await getMessageMime(client, { mailbox, messageId: testMessage.id });
      return pass(
        `${mime.length} bytes; header names: ${printableHeaderNames(mimeHeaderNames(mime))}`
      );
    });

    await run('last-verb', async () => {
      const verb = await getLastVerb(client, { mailbox, messageId: testMessage.id });
      if (verb.code === undefined) {
        return skip(
          'could not determine: request accepted, but the property is not set on the test message (re-run with --message-id of a message that was replied to or forwarded)'
        );
      }
      return pass(`property readable; value ${verb.code} (${verb.action})`);
    });

    await run('immutable-id', async () => {
      const immutable = await getMessageSummary(client, {
        mailbox,
        messageId: testMessage.id,
        immutableIds: true,
      });
      const again = await getMessageSummary(client, {
        mailbox,
        messageId: immutable.id,
        immutableIds: true,
      });
      return pass(
        `header accepted; immutable ID differs from the default ID: ${yesNo(
          immutable.id !== testMessage.id
        )}; message fetched by its immutable ID: ${yesNo(again.id === immutable.id)}`
      );
    });
  }

  skipUnrun(
    MAIL_IDS,
    mailbox === undefined
      ? 'no --mailbox given'
      : "no test message (see 'Read mailbox metadata' and 'Find by internetMessageId')"
  );

  // --- Message trace -----------------------------------------------------

  await run('trace-reachable', async () => {
    try {
      const { items, truncated } = await listRecentMessageTraces(client, { maxItems: 100 });
      state.traceReachable = true;
      state.traceSample = items.find(
        row => row.messageId && row.senderAddress && row.receivedDateTime
      );
      return pass(
        `works; ${items.length}${truncated ? '+' : ''} row(s) in the default 48-hour window; status: ${tally(
          items.map(row => row.status),
          /^[A-Za-z]{1,30}$/
        )}`
      );
    } catch (error) {
      // Graph's message names the missing service principal. It is read
      // only to classify the failure and is never printed.
      if (
        isAuthorizationFailure(error) &&
        (error.detail?.includes(MESSAGE_TRACE_SERVICE_APP_ID) === true ||
          /service principal/i.test(error.detail ?? ''))
      ) {
        return {
          ...fail(
            `service principal not provisioned: Microsoft's message-trace service principal (app ID ${MESSAGE_TRACE_SERVICE_APP_ID}) does not exist in this tenant (${graphStatusText(error)}); see docs/GRAPH_PROBE.md`
          ),
          httpStatus: error.status,
          errorCode: error.code,
        };
      }
      throw error;
    }
  });

  if (!state.traceReachable) {
    skipUnrun(ALL_IDS, "message trace is not reachable (see 'Message trace reachable')");
    return finish();
  }
  const traceSample = state.traceSample;

  const traceSubject: TraceSubject | undefined =
    testMessage?.internetMessageId !== undefined
      ? {
          messageId: testMessage.internetMessageId,
          senderAddress: testMessage.fromAddress,
          subject: testMessage.subject,
          received: parseDate(testMessage.receivedDateTime),
        }
      : traceSample !== undefined
        ? {
            messageId: traceSample.messageId,
            senderAddress: traceSample.senderAddress,
            subject: traceSample.subject,
            received: parseDate(traceSample.receivedDateTime),
          }
        : undefined;
  const traceSource =
    testMessage?.internetMessageId !== undefined ? 'test message' : 'a recent trace row';

  const traceWindow = (): { receivedFrom: Date; receivedTo: Date; now: Date } | CheckOutcome => {
    const current = now();
    if (traceSubject?.received === undefined) {
      return skip(
        'no message with a known received time to trace (give --mailbox, or wait for mail flow)'
      );
    }
    const receivedFrom = new Date(traceSubject.received.getTime() - DAY_MS);
    if (current.getTime() - receivedFrom.getTime() > TRACE_MAX_AGE_MS) {
      return skip(
        'the test message is older than message trace reaches (90 days); use a newer message'
      );
    }
    return {
      receivedFrom,
      receivedTo: new Date(Math.min(traceSubject.received.getTime() + DAY_MS, current.getTime())),
      now: current,
    };
  };

  const traceById = async (form: 'brackets' | 'bare'): Promise<CheckOutcome> => {
    const window = traceWindow();
    if ('status' in window) {
      return window;
    }
    if (!traceSubject?.messageId) {
      return skip('no message ID to trace');
    }
    const messageId =
      form === 'brackets'
        ? addAngleBrackets(traceSubject.messageId)
        : stripAngleBrackets(traceSubject.messageId);
    const { items, truncated } = await listMessageTracesByMessageId(client, {
      ...window,
      messageId,
      maxItems: 1000,
    });
    const detail = `${items.length}${truncated ? '+' : ''} row(s) for ${redactor.id('message-id', messageId)} (${traceSource}, 2-day window)`;
    return items.length > 0
      ? pass(`filter matched: ${detail}`)
      : fail(`filter accepted but matched nothing: ${detail}`);
  };

  await run('trace-message-id-brackets', () => traceById('brackets'));
  await run('trace-message-id-bare', () => traceById('bare'));

  await run('trace-sender-subject', async () => {
    const window = traceWindow();
    if ('status' in window) {
      return window;
    }
    if (!traceSubject?.senderAddress) {
      return skip('no sender address to trace');
    }
    const { items, truncated } = await listMessageTracesBySender(client, {
      ...window,
      senderAddress: traceSubject.senderAddress,
      subject: traceSubject.subject === '' ? undefined : traceSubject.subject,
      maxItems: 1000,
    });
    const recipients = new Set(items.map(row => row.recipientAddress?.toLowerCase())).size;
    const detail = `${items.length}${truncated ? '+' : ''} row(s), ${recipients} distinct recipient(s) for ${redactor.id(
      'address',
      traceSubject.senderAddress
    )}${traceSubject.subject ? ` + ${redactor.id('subject', traceSubject.subject)}` : ''} (${traceSource}, 2-day window)`;
    return items.length > 0
      ? pass(`filter matched: ${detail}`)
      : fail(`filter accepted but matched nothing: ${detail}`);
  });

  return finish();
}

function describeMessage(redactor: Redactor, message: MessageSummary): string {
  return [
    redactor.id('message-id', message.internetMessageId),
    `from ${redactor.id('address', message.fromAddress)}`,
    redactor.id('subject', message.subject),
    `received ${message.receivedDateTime?.slice(0, 10) ?? '(unknown)'}`,
  ].join(', ');
}

async function checkFolderCoverage(
  client: GraphClient,
  mailbox: string,
  folder: WellKnownMailFolder
): Promise<CheckOutcome> {
  const info = await getMailFolder(client, { mailbox, folder });
  if (info.totalItemCount === 0) {
    return skip(`could not determine: ${folder} is empty (put a message there and re-run)`);
  }
  const perFolder = await listRecentMessages(client, { mailbox, folder, maxItems: 1 });
  if (perFolder.items.length === 0) {
    return skip(`could not determine: the per-folder form returned no messages for ${folder}`);
  }
  const viaMessages = await findMessagesByParentFolder(client, {
    mailbox,
    parentFolderId: info.id,
    maxItems: 1,
  });
  const count =
    info.totalItemCount === undefined ? 'an unknown number of' : String(info.totalItemCount);
  return viaMessages.items.length > 0
    ? pass(`covered: ${folder} holds ${count} item(s) and /messages returns items from it`)
    : fail(
        `not covered: ${folder} holds ${count} item(s) but /messages returned none of them; use /mailFolders/${folder}/messages`
      );
}

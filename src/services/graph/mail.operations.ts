/**
 * Read-only mailbox operations on Microsoft Graph.
 *
 * Small typed functions over `GraphClient`. Every one issues GET requests
 * only, to an endpoint fixed in this file, with data entering solely through
 * `graphPath`, `odataFilter` and `kqlSearch`. Message lookups return
 * metadata (`MessageSummary`) — never a body. The two functions that do
 * return message content (`getMessageHeaders`, `getMessageMime`) are for the
 * reporter's own mailbox; what they return is hostile data.
 *
 * Request shapes follow Microsoft's reference documentation. Behaviours the
 * documentation leaves unstated are listed in docs/GRAPH_PROBE.md and tested
 * per tenant by `npm run graph:probe`.
 */

import { z } from 'zod';
import { MAX_MESSAGE_HEADERS as MAX_HEADERS } from './graph.limits';
import { GraphClient } from './graph.client';
import { GraphPath, KqlSearchTerms, graphPath, kqlSearch, odataFilter } from './graph.request';
import {
  BoundedResult,
  assertWindow,
  parseItem,
  parseItems,
  resolveMaxItems,
} from './operations.common';

/** Well-known folder names accepted in place of a folder ID */
export const WELL_KNOWN_MAIL_FOLDERS = [
  'inbox',
  'junkemail',
  'deleteditems',
  'recoverableitemsdeletions',
  'sentitems',
  'archive',
] as const;
export type WellKnownMailFolder = (typeof WELL_KNOWN_MAIL_FOLDERS)[number];

/** Metadata selected for every message lookup. All readable with `Mail.ReadBasic.All`. */
const MESSAGE_SUMMARY_SELECT = [
  'id',
  'internetMessageId',
  'subject',
  'from',
  'receivedDateTime',
  'parentFolderId',
  'hasAttachments',
  'isRead',
];

const DEFAULT_MAX_MESSAGES = 25;
const MAX_MESSAGES = 1000;
const MESSAGE_PAGE_SIZE = 100;
const HEADERS_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MIME_MAX_BYTES = 25 * 1024 * 1024;
const MIME_MAX_BYTES_CEILING = 40 * 1024 * 1024;

/** PidTagLastVerbExecuted (MAPI 0x1081, PT_LONG) */
export const LAST_VERB_PROPERTY = { type: 'Integer', tag: 0x1081 } as const;

const MessageSummarySchema = z.object({
  id: z.string().min(1),
  internetMessageId: z.string().nullish(),
  subject: z.string().nullish(),
  from: z.object({ emailAddress: z.object({ address: z.string().nullish() }).nullish() }).nullish(),
  receivedDateTime: z.string().nullish(),
  parentFolderId: z.string().nullish(),
  hasAttachments: z.boolean().nullish(),
  isRead: z.boolean().nullish(),
});

/** Message metadata. Every string here originates in a mailbox: hostile data. */
export interface MessageSummary {
  /** Graph message ID (immutable form when requested with `immutableIds`) */
  id: string;
  internetMessageId?: string;
  subject?: string;
  fromAddress?: string;
  receivedDateTime?: string;
  parentFolderId?: string;
  hasAttachments?: boolean;
  /** Whether the message is marked read in its mailbox */
  isRead?: boolean;
}

function toSummary(raw: z.infer<typeof MessageSummarySchema>): MessageSummary {
  return {
    id: raw.id,
    internetMessageId: raw.internetMessageId ?? undefined,
    subject: raw.subject ?? undefined,
    fromAddress: raw.from?.emailAddress?.address ?? undefined,
    receivedDateTime: raw.receivedDateTime ?? undefined,
    parentFolderId: raw.parentFolderId ?? undefined,
    hasAttachments: raw.hasAttachments ?? undefined,
    isRead: raw.isRead ?? undefined,
  };
}

interface MailboxScope {
  /** User ID or user principal name of the mailbox owner */
  mailbox: string;
  /** Restrict to one well-known folder; omit to query `/messages` (all folders Graph covers) */
  folder?: WellKnownMailFolder;
}

interface ListOptions {
  /** Most messages to return (default 25, at most 1000) */
  maxItems?: number;
  /** Ask for IDs that stay stable across folder moves */
  immutableIds?: boolean;
}

function messagesPath(scope: MailboxScope): GraphPath {
  if (scope.folder === undefined) {
    return graphPath`/users/${scope.mailbox}/messages`;
  }
  if (!WELL_KNOWN_MAIL_FOLDERS.includes(scope.folder)) {
    throw new Error('folder must be a well-known mail folder name');
  }
  return graphPath`/users/${scope.mailbox}/mailFolders/${scope.folder}/messages`;
}

async function listSummaries(
  client: GraphClient,
  path: GraphPath,
  query: Parameters<GraphClient['getPaged']>[1]['query'],
  options: ListOptions & { consistencyLevel?: 'eventual' }
): Promise<BoundedResult<MessageSummary>> {
  const maxItems = resolveMaxItems(options.maxItems, DEFAULT_MAX_MESSAGES, MAX_MESSAGES);
  const top = Math.min(maxItems, MESSAGE_PAGE_SIZE);
  const result = await client.getPaged(path, {
    query: { ...query, select: MESSAGE_SUMMARY_SELECT, top },
    maxItems,
    maxPages: Math.ceil(maxItems / top),
    immutableIds: options.immutableIds,
    consistencyLevel: options.consistencyLevel,
  });
  return {
    items: parseItems(client, path, MessageSummarySchema, result.items).map(toSummary),
    truncated: result.truncated,
  };
}

export interface FindByInternetMessageIdArgs extends MailboxScope, ListOptions {
  /** RFC 5322 Message-ID, including its angle brackets */
  internetMessageId: string;
}

/**
 * Find messages in a mailbox by Internet message ID.
 * `GET /users/{mailbox}/messages?$filter=internetMessageId eq '<...>'`
 */
export async function findMessagesByInternetMessageId(
  client: GraphClient,
  args: FindByInternetMessageIdArgs
): Promise<BoundedResult<MessageSummary>> {
  return listSummaries(
    client,
    messagesPath(args),
    { filter: odataFilter`internetMessageId eq ${args.internetMessageId}` },
    args
  );
}

export interface FindBySenderArgs extends MailboxScope, ListOptions {
  senderAddress: string;
  /** Received at or after */
  receivedFrom: Date;
  /** Received before */
  receivedTo: Date;
  /** Exact subject match */
  subject?: string;
}

/**
 * Find messages from one sender received in a time window, newest first,
 * optionally with an exact subject.
 *
 * `receivedDateTime` leads the filter because it is also the `$orderby`
 * property (Graph answers `InefficientFilter` otherwise).
 */
export async function findMessagesBySender(
  client: GraphClient,
  args: FindBySenderArgs
): Promise<BoundedResult<MessageSummary>> {
  assertWindow(args.receivedFrom, args.receivedTo);
  // Written flat (no nested, parenthesized filter) so the $orderby property
  // stays the literal start of the expression
  const filter =
    args.subject === undefined
      ? odataFilter`receivedDateTime ge ${args.receivedFrom} and receivedDateTime lt ${args.receivedTo} and from/emailAddress/address eq ${args.senderAddress}`
      : odataFilter`receivedDateTime ge ${args.receivedFrom} and receivedDateTime lt ${args.receivedTo} and from/emailAddress/address eq ${args.senderAddress} and subject eq ${args.subject}`;
  return listSummaries(
    client,
    messagesPath(args),
    { filter, orderBy: ['receivedDateTime desc'] },
    args
  );
}

export interface SearchMessagesArgs extends MailboxScope, ListOptions {
  /** Typed search terms; values are reduced to plain words (see `kqlWords`) */
  terms: KqlSearchTerms;
  /** Send `ConsistencyLevel: eventual` (whether mail search needs it is not documented) */
  consistencyLevel?: 'eventual';
}

/**
 * Search a mailbox with `$search`. Results are relevance-ranked by Graph
 * and limited by it to 1,000.
 */
export async function searchMessages(
  client: GraphClient,
  args: SearchMessagesArgs
): Promise<BoundedResult<MessageSummary>> {
  return listSummaries(client, messagesPath(args), { search: kqlSearch(args.terms) }, args);
}

export interface ListRecentArgs extends MailboxScope, ListOptions {}

/**
 * The most recently received messages in a mailbox or folder (metadata only)
 */
export async function listRecentMessages(
  client: GraphClient,
  args: ListRecentArgs
): Promise<BoundedResult<MessageSummary>> {
  return listSummaries(client, messagesPath(args), { orderBy: ['receivedDateTime desc'] }, args);
}

export interface FindByParentFolderArgs extends ListOptions {
  mailbox: string;
  /** Folder ID as returned by `getMailFolder` */
  parentFolderId: string;
}

/**
 * Messages that `/users/{mailbox}/messages` returns for one parent folder.
 * Used to learn whether the cross-folder collection covers a given folder.
 */
export async function findMessagesByParentFolder(
  client: GraphClient,
  args: FindByParentFolderArgs
): Promise<BoundedResult<MessageSummary>> {
  return listSummaries(
    client,
    messagesPath({ mailbox: args.mailbox }),
    { filter: odataFilter`parentFolderId eq ${args.parentFolderId}` },
    args
  );
}

const MailFolderSchema = z.object({
  id: z.string().min(1),
  totalItemCount: z.number().int().nonnegative().nullish(),
});

export interface MailFolderInfo {
  id: string;
  totalItemCount?: number;
}

/**
 * A well-known folder's ID and item count
 */
export async function getMailFolder(
  client: GraphClient,
  args: { mailbox: string; folder: WellKnownMailFolder }
): Promise<MailFolderInfo> {
  if (!WELL_KNOWN_MAIL_FOLDERS.includes(args.folder)) {
    throw new Error('folder must be a well-known mail folder name');
  }
  const path = graphPath`/users/${args.mailbox}/mailFolders/${args.folder}`;
  const raw = await client.getJson(path, { query: { select: ['id', 'totalItemCount'] } });
  const folder = parseItem(client, path, MailFolderSchema, raw);
  return { id: folder.id, totalItemCount: folder.totalItemCount ?? undefined };
}

interface MessageRef {
  mailbox: string;
  /** Graph message ID */
  messageId: string;
  /** Set when `messageId` is an immutable ID */
  immutableIds?: boolean;
}

/**
 * One message's metadata by Graph ID
 */
export async function getMessageSummary(
  client: GraphClient,
  args: MessageRef
): Promise<MessageSummary> {
  const path = graphPath`/users/${args.mailbox}/messages/${args.messageId}`;
  const raw = await client.getJson(path, {
    query: { select: MESSAGE_SUMMARY_SELECT },
    immutableIds: args.immutableIds,
  });
  return toSummary(parseItem(client, path, MessageSummarySchema, raw));
}

const HeadersSchema = z.object({
  internetMessageHeaders: z.array(z.object({ name: z.string(), value: z.string() })).nullish(),
});

export interface InternetMessageHeader {
  name: string;
  value: string;
}

/**
 * A message's Internet headers, in the order Graph returns them. At most
 * 500 are returned; `truncated` reports a longer list. Names and values are
 * hostile data.
 */
export async function getMessageHeaders(
  client: GraphClient,
  args: MessageRef
): Promise<BoundedResult<InternetMessageHeader>> {
  const path = graphPath`/users/${args.mailbox}/messages/${args.messageId}`;
  const raw = await client.getJson(path, {
    query: { select: ['internetMessageHeaders'] },
    immutableIds: args.immutableIds,
    maxBytes: HEADERS_MAX_BYTES,
  });
  const headers = parseItem(client, path, HeadersSchema, raw).internetMessageHeaders ?? [];
  return { items: headers.slice(0, MAX_HEADERS), truncated: headers.length > MAX_HEADERS };
}

export interface GetMimeArgs extends MessageRef {
  /** Largest MIME size accepted (default 25 MB, at most 40 MB) */
  maxBytes?: number;
}

/**
 * A message in MIME format (`/$value`). A message larger than the cap is an
 * error (`GraphError` kind `response_too_large`), never a silently cut-off
 * message. The content is hostile data: parse it, never log it.
 */
export async function getMessageMime(client: GraphClient, args: GetMimeArgs): Promise<Buffer> {
  const maxBytes = args.maxBytes ?? DEFAULT_MIME_MAX_BYTES;
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > MIME_MAX_BYTES_CEILING) {
    throw new Error(`maxBytes must be an integer between 1 and ${MIME_MAX_BYTES_CEILING}`);
  }
  return client.getBytes(graphPath`/users/${args.mailbox}/messages/${args.messageId}/$value`, {
    immutableIds: args.immutableIds,
    maxBytes,
  });
}

/** `getMessageMime`, decoded as UTF-8 text */
export async function getMessageMimeText(client: GraphClient, args: GetMimeArgs): Promise<string> {
  return (await getMessageMime(client, args)).toString('utf8');
}

const LastVerbSchema = z.object({
  singleValueExtendedProperties: z.array(z.object({ id: z.string(), value: z.string() })).nullish(),
});

export type LastVerbAction = 'none' | 'replied' | 'repliedAll' | 'forwarded' | 'other';

export interface LastVerb {
  action: LastVerbAction;
  /** The raw property value, when the property is set and numeric */
  code?: number;
}

/**
 * Raw value to action. 102/103/104 are the reply / reply-all / forward verbs
 * in the MAPI definition of PidTagLastVerbExecuted; 261/262 are the
 * replied / forwarded values some references give for the same question.
 * Both sets are accepted and the raw code is always returned.
 */
const LAST_VERB_ACTIONS: Readonly<Record<number, LastVerbAction>> = {
  102: 'replied',
  103: 'repliedAll',
  104: 'forwarded',
  261: 'replied',
  262: 'forwarded',
};

/**
 * Whether the mailbox owner replied to or forwarded a message, from the
 * PidTagLastVerbExecuted extended property. Needs `Mail.Read`.
 */
export async function getLastVerb(client: GraphClient, args: MessageRef): Promise<LastVerb> {
  const path = graphPath`/users/${args.mailbox}/messages/${args.messageId}`;
  const raw = await client.getJson(path, {
    query: { select: ['id'], expandExtendedProperty: LAST_VERB_PROPERTY },
    immutableIds: args.immutableIds,
  });
  const properties = parseItem(client, path, LastVerbSchema, raw).singleValueExtendedProperties;
  const value = properties?.[0]?.value;
  if (value === undefined || !/^\d{1,9}$/.test(value)) {
    return { action: 'none' };
  }
  const code = Number(value);
  return { action: LAST_VERB_ACTIONS[code] ?? 'other', code };
}

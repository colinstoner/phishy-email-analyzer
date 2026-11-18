/**
 * Read-only Exchange message trace operations on Microsoft Graph.
 *
 * `GET /admin/exchange/tracing/messageTraces` (v1.0, application permission
 * `ExchangeMessageTrace.Read.All`). One row per message per recipient —
 * delivery metadata only; a trace never contains a body.
 *
 * Documented constraints this file encodes:
 * - only `$filter` and `$top` (1-5000) are sent; paging follows
 *   `@odata.nextLink` whole (the client does that, on the Graph origin only);
 * - a date range needs both bounds, may span at most 10 days and may start
 *   at most 90 days back; dates are written without milliseconds;
 * - throttled at 100 requests per 5 minutes per tenant, so page caps here
 *   are small.
 *
 * The tenant must hold Microsoft's message-trace service principal
 * (`MESSAGE_TRACE_SERVICE_APP_ID`) before any call succeeds.
 */

import { z } from 'zod';
import { GraphClient } from './graph.client';
import { ODataFilter, graphPath, odataFilter, odataSeconds } from './graph.request';
import { BoundedResult, assertWindow, parseItems, resolveMaxItems } from './operations.common';

/** App ID of the Microsoft service principal message trace depends on */
export const MESSAGE_TRACE_SERVICE_APP_ID = '8bd644d1-64a1-4d4b-ae52-2e0cbf64e373';

export const TRACE_MAX_WINDOW_MS = 10 * 24 * 60 * 60 * 1000;
export const TRACE_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;

const DEFAULT_MAX_TRACES = 1000;
const MAX_TRACES = 5000;
const TRACE_MAX_PAGES = 5;

const TRACE_PATH = graphPath`/admin/exchange/tracing/messageTraces`;

const optionalText = z.string().nullish();

const MessageTraceSchema = z.object({
  id: optionalText,
  messageId: optionalText,
  senderAddress: optionalText,
  recipientAddress: optionalText,
  subject: optionalText,
  receivedDateTime: optionalText,
  size: z.number().nullish(),
  fromIP: optionalText,
  toIP: optionalText,
  status: optionalText,
});

/** One delivery record. Every string originates in mail flow: hostile data. */
export interface MessageTrace {
  id?: string;
  messageId?: string;
  senderAddress?: string;
  recipientAddress?: string;
  subject?: string;
  receivedDateTime?: string;
  size?: number;
  fromIP?: string;
  toIP?: string;
  status?: string;
}

function toTrace(raw: z.infer<typeof MessageTraceSchema>): MessageTrace {
  return {
    id: raw.id ?? undefined,
    messageId: raw.messageId ?? undefined,
    senderAddress: raw.senderAddress ?? undefined,
    recipientAddress: raw.recipientAddress ?? undefined,
    subject: raw.subject ?? undefined,
    receivedDateTime: raw.receivedDateTime ?? undefined,
    size: raw.size ?? undefined,
    fromIP: raw.fromIP ?? undefined,
    toIP: raw.toIP ?? undefined,
    status: raw.status ?? undefined,
  };
}

export interface TraceWindow {
  /** Received at or after (required together with `receivedTo`) */
  receivedFrom: Date;
  /** Received at or before */
  receivedTo: Date;
}

interface TraceOptions {
  /** Most rows to return (default 1000, at most 5000) */
  maxItems?: number;
  /** Injected for tests; defaults to the current time */
  now?: Date;
}

/**
 * Check a window against the documented limits before spending one of the
 * tenant's 100 requests on a call that would be refused
 */
export function assertTraceWindow(window: TraceWindow, now: Date = new Date()): void {
  assertWindow(window.receivedFrom, window.receivedTo);
  if (window.receivedTo.getTime() - window.receivedFrom.getTime() > TRACE_MAX_WINDOW_MS) {
    throw new Error('message trace window must be at most 10 days wide');
  }
  if (now.getTime() - window.receivedFrom.getTime() > TRACE_MAX_AGE_MS) {
    throw new Error('message trace window must start at most 90 days ago');
  }
}

async function listTraces(
  client: GraphClient,
  filter: ODataFilter | undefined,
  options: TraceOptions
): Promise<BoundedResult<MessageTrace>> {
  const maxItems = resolveMaxItems(options.maxItems, DEFAULT_MAX_TRACES, MAX_TRACES);
  const result = await client.getPaged(TRACE_PATH, {
    query: { filter, top: maxItems },
    maxItems,
    maxPages: TRACE_MAX_PAGES,
  });
  return {
    items: parseItems(client, TRACE_PATH, MessageTraceSchema, result.items).map(toTrace),
    truncated: result.truncated,
  };
}

/**
 * Recent traces with no filter (Microsoft: the last 48 hours)
 */
export async function listRecentMessageTraces(
  client: GraphClient,
  options: TraceOptions = {}
): Promise<BoundedResult<MessageTrace>> {
  return listTraces(client, undefined, options);
}

export interface TraceByMessageIdArgs extends TraceOptions, Partial<TraceWindow> {
  /**
   * Internet message ID, sent exactly as given. Whether the service wants
   * the angle brackets is not documented; see `stripAngleBrackets`.
   */
  messageId: string;
}

/**
 * Who received a message, by Internet message ID. Without a window the
 * service searches the last 48 hours.
 */
export async function listMessageTracesByMessageId(
  client: GraphClient,
  args: TraceByMessageIdArgs
): Promise<BoundedResult<MessageTrace>> {
  if ((args.receivedFrom === undefined) !== (args.receivedTo === undefined)) {
    throw new Error('message trace needs both receivedFrom and receivedTo, or neither');
  }
  if (args.receivedFrom && args.receivedTo) {
    const window = { receivedFrom: args.receivedFrom, receivedTo: args.receivedTo };
    assertTraceWindow(window, args.now);
    return listTraces(
      client,
      odataFilter`receivedDateTime ge ${odataSeconds(window.receivedFrom)} and receivedDateTime le ${odataSeconds(window.receivedTo, 'ceil')} and messageId eq ${args.messageId}`,
      args
    );
  }
  return listTraces(client, odataFilter`messageId eq ${args.messageId}`, args);
}

export interface TraceBySenderArgs extends TraceOptions, TraceWindow {
  senderAddress: string;
  /** Subject text to match (optional) */
  subject?: string;
  /** How `subject` is matched (default `contains`) */
  subjectMatch?: 'contains' | 'startsWith' | 'endsWith';
}

/**
 * Who received mail from a sender in a time window, optionally narrowed by
 * subject
 */
export async function listMessageTracesBySender(
  client: GraphClient,
  args: TraceBySenderArgs
): Promise<BoundedResult<MessageTrace>> {
  assertTraceWindow(args, args.now);
  const from = odataSeconds(args.receivedFrom);
  const to = odataSeconds(args.receivedTo, 'ceil');

  if (args.subject === undefined) {
    return listTraces(
      client,
      odataFilter`receivedDateTime ge ${from} and receivedDateTime le ${to} and senderAddress eq ${args.senderAddress}`,
      args
    );
  }

  let filter: ODataFilter;
  switch (args.subjectMatch ?? 'contains') {
    case 'contains':
      filter = odataFilter`receivedDateTime ge ${from} and receivedDateTime le ${to} and senderAddress eq ${args.senderAddress} and contains(subject, ${args.subject})`;
      break;
    case 'startsWith':
      filter = odataFilter`receivedDateTime ge ${from} and receivedDateTime le ${to} and senderAddress eq ${args.senderAddress} and startsWith(subject, ${args.subject})`;
      break;
    case 'endsWith':
      filter = odataFilter`receivedDateTime ge ${from} and receivedDateTime le ${to} and senderAddress eq ${args.senderAddress} and endsWith(subject, ${args.subject})`;
      break;
    default:
      throw new Error('subjectMatch must be contains, startsWith or endsWith');
  }
  return listTraces(client, filter, args);
}

/** `<id@host>` to `id@host`; anything else is returned unchanged */
export function stripAngleBrackets(messageId: string): string {
  return messageId.length > 2 && messageId.startsWith('<') && messageId.endsWith('>')
    ? messageId.slice(1, -1)
    : messageId;
}

/** `id@host` to `<id@host>`; an already-bracketed ID is returned unchanged */
export function addAngleBrackets(messageId: string): string {
  return messageId.startsWith('<') && messageId.endsWith('>') ? messageId : `<${messageId}>`;
}

/**
 * An invented tenant for the fan-out scan tests: message trace rows for a
 * recent window (tenant-wide) and per-address history, answered through the
 * fake Graph. No network. Invented `example.*` data only.
 */

import type { MessageTrace } from '../../src/services/graph/trace.operations';
import { FakeResponder, RecordedRequest, collection, graphErrorResponse } from './graph.fake';

export const HOUR = 60 * 60 * 1000;
export const DAY = 24 * HOUR;
export const NOW = Date.parse('2026-11-17T12:00:00Z');
export const INTERNAL_DOMAINS = ['example.com'];
export const SENDER = 'pat@supplier.example.net';
export const SUBJECT = 'Updated remittance details for November';
export const TRACE_PATH = '/admin/exchange/tracing/messageTraces';
export const WINDOW = { receivedFrom: new Date(NOW - 15 * 60 * 1000), receivedTo: new Date(NOW) };

let seq = 0;

export function traceRow(
  sender: string,
  recipient: string,
  atMs: number,
  extra: Partial<MessageTrace> = {}
): MessageTrace {
  seq++;
  return {
    id: `row-${seq}`,
    messageId: `<m${seq}@mail.example.net>`,
    senderAddress: sender,
    recipientAddress: recipient,
    receivedDateTime: new Date(atMs).toISOString(),
    subject: SUBJECT,
    fromIP: '192.0.2.10',
    status: 'Delivered',
    ...extra,
  };
}

/** One subject from `sender` to `count` distinct internal people, inside the window */
export function wave(
  count: number,
  options: {
    sender?: string;
    subject?: string;
    atMs?: number;
    status?: (index: number) => string;
    offset?: number;
  } = {}
): MessageTrace[] {
  const sender = options.sender ?? SENDER;
  const messageId = `<wave-${seq + 1}@mail.example.net>`;
  return Array.from({ length: count }, (_, i) =>
    traceRow(
      sender,
      `person${i + (options.offset ?? 0)}@example.com`,
      (options.atMs ?? NOW - 2 * 60 * 1000) + i * 10,
      {
        subject: options.subject ?? SUBJECT,
        messageId,
        // As in real message trace: rows for the recipients of one message
        // share a row id
        id: `row-${messageId}`,
        status: options.status?.(i) ?? 'Delivered',
        fromIP: '203.0.113.7',
      }
    )
  );
}

/**
 * An established, two-way relationship: three messages over the last weeks
 * to two people, and one reply from the organization
 */
export function establishedHistory(sender: string = SENDER): {
  inbound: MessageTrace[];
  outbound: MessageTrace[];
} {
  return {
    inbound: [
      traceRow(sender, 'alex@example.com', NOW - 5 * DAY, { subject: 'Invoice 1001' }),
      traceRow(sender, 'alex@example.com', NOW - 6 * DAY, { subject: 'Invoice 1002' }),
      traceRow(sender, 'sam@example.com', NOW - 7 * DAY, { subject: 'Delivery note' }),
    ],
    outbound: [
      traceRow('alex@example.com', sender, NOW - 4 * DAY, { subject: 'RE: Invoice 1001' }),
    ],
  };
}

export interface FanoutTenant {
  /** Pages of the tenant-wide window query, in order */
  windowPages: MessageTrace[][];
  /** Per sender address: rows `senderAddress eq` returns (history and burst) */
  inbound?: Record<string, MessageTrace[]>;
  /** Per address: rows `recipientAddress eq` returns */
  outbound?: Record<string, MessageTrace[]>;
  /** Window-page requests that answer 403 before succeeding (counted across all pages) */
  windowForbidden?: number;
  /** Answer every window page after the first with this error status */
  laterPageStatus?: number;
  /**
   * Page per-address (history) answers at this many rows, as the service
   * does at 1000, so a long history costs a second request per query.
   * Unset: every history answer is one page.
   */
  historyPageSize?: number;
}

const NEXT = 'https://graph.microsoft.com/v1.0/admin/exchange/tracing/messageTraces?$skiptoken=';

function quoted(filter: string, field: string): string | undefined {
  const match = filter.match(new RegExp(`${field} eq '((?:[^']|'')*)'`));
  return match?.[1].replace(/''/g, "'");
}

/** One page of a per-address answer, with a next link that keeps the filter */
function historyPage(
  rows: MessageTrace[],
  filter: string,
  token: string | undefined,
  size?: number
): Response {
  if (!size) {
    return collection(rows);
  }
  const index = token === undefined ? 0 : Number(token.slice(1));
  const page = rows.slice(index * size, (index + 1) * size);
  const more = (index + 1) * size < rows.length;
  return collection(
    page,
    more
      ? `https://graph.microsoft.com/v1.0/admin/exchange/tracing/messageTraces?$filter=${encodeURIComponent(filter)}&$skiptoken=h${index + 1}`
      : undefined
  );
}

/** Responder for the fake Graph; counts what it served */
export function fanoutResponder(tenant: FanoutTenant): FakeResponder & { windowRequests: number } {
  let forbiddenLeft = tenant.windowForbidden ?? 0;
  const responder = ((request: RecordedRequest): Response | undefined => {
    if (request.path !== TRACE_PATH) {
      return undefined;
    }
    const filter = request.query.$filter ?? '';
    const token = request.query.$skiptoken;
    const historyToken = token?.startsWith('h') ? token : undefined;
    const isWindow =
      (token !== undefined && historyToken === undefined) ||
      (!filter.includes(' eq ') && filter.length > 0);
    if (isWindow) {
      responder.windowRequests++;
      if (forbiddenLeft > 0) {
        forbiddenLeft--;
        return graphErrorResponse(403, 'Forbidden');
      }
      const index = token === undefined ? 0 : Number(token);
      if (index > 0 && tenant.laterPageStatus) {
        return graphErrorResponse(tenant.laterPageStatus, 'ServiceUnavailable');
      }
      const page = tenant.windowPages[index] ?? [];
      return collection(
        page,
        index + 1 < tenant.windowPages.length ? `${NEXT}${index + 1}` : undefined
      );
    }
    const sender = quoted(filter, 'senderAddress');
    if (sender !== undefined) {
      return historyPage(
        tenant.inbound?.[sender] ?? [],
        filter,
        historyToken,
        tenant.historyPageSize
      );
    }
    const recipient = quoted(filter, 'recipientAddress');
    if (recipient !== undefined) {
      return historyPage(
        tenant.outbound?.[recipient] ?? [],
        filter,
        historyToken,
        tenant.historyPageSize
      );
    }
    return undefined;
  }) as FakeResponder & { windowRequests: number };
  responder.windowRequests = 0;
  return responder;
}

/** The standard takeover: an established sender's one subject to `count` people */
export function takeoverTenant(count = 20, extraWindowRows: MessageTrace[] = []): FanoutTenant {
  const history = establishedHistory();
  const burst = wave(count);
  return {
    windowPages: [[...burst, ...extraWindowRows]],
    inbound: { [SENDER]: [...history.inbound, ...burst] },
    outbound: { [SENDER]: history.outbound },
  };
}

/** A one-hour window, as a scan reads after a gap */
export const WIDE_WINDOW = { receivedFrom: new Date(NOW - HOUR), receivedTo: new Date(NOW) };

/** The candidate senders of `wideWindowTenant`, most recipients first */
export const WIDE_SENDERS = [1, 2, 3, 4, 5, 6].map(n => `contact${n}@vendor${n}.example.net`);

/**
 * The shape of a real one-hour replay that overspent its allowance: 4,497
 * trace rows in the window, six senders each reaching 30-40 people (more
 * candidates than one scan checks), and long two-way histories that come
 * back in two pages per query (the service pages at 1000 rows), so each
 * history lookup costs twelve requests rather than six.
 */
export function wideWindowTenant(
  options: {
    windowPages?: number;
    /** Earliest row in the window (default: an hour before NOW) */
    startMs?: number;
  } = {}
): FanoutTenant {
  const startMs = options.startMs ?? NOW - HOUR;
  const waves = WIDE_SENDERS.map((sender, i) =>
    wave(40 - 2 * i, {
      sender,
      subject: `Payment portal update ${i + 1}`,
      atMs: NOW - 30 * 60 * 1000 + i * 60 * 1000,
    })
  );
  const burstRows = waves.flat();
  const fillerCount = 4497 - burstRows.length;
  // Ordinary inbound mail: many external senders, one recipient each,
  // spread from the start of the window to two minutes before NOW
  const spacing = Math.floor((NOW - 2 * 60 * 1000 - startMs) / fillerCount);
  const filler = Array.from({ length: fillerCount }, (_, i) =>
    traceRow(
      `news${i}@bulk.example.org`,
      `person${i % 300}@example.com`,
      startMs + 1000 + i * spacing,
      { subject: `Weekly digest ${i}` }
    )
  );
  const rows = [...burstRows, ...filler];
  const pageCount = options.windowPages ?? 1;
  const size = Math.ceil(rows.length / pageCount);
  const windowPages = Array.from({ length: pageCount }, (_, i) =>
    rows.slice(i * size, (i + 1) * size)
  );

  const inbound: Record<string, MessageTrace[]> = {};
  const outbound: Record<string, MessageTrace[]> = {};
  WIDE_SENDERS.forEach((sender, i) => {
    // Years of routine mail to two people, and their replies
    const history = Array.from({ length: 1200 }, (_, k) =>
      traceRow(sender, k % 2 ? 'alex@example.com' : 'sam@example.com', NOW - (3 + (k % 25)) * DAY, {
        subject: `Invoice ${k}`,
      })
    );
    inbound[sender] = [...history, ...waves[i]];
    outbound[sender] = Array.from({ length: 1200 }, (_, k) =>
      traceRow(k % 2 ? 'alex@example.com' : 'sam@example.com', sender, NOW - (3 + (k % 25)) * DAY, {
        subject: `RE: Invoice ${k}`,
      })
    );
  });
  return { windowPages, inbound, outbound, historyPageSize: 1000 };
}

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
}

const NEXT = 'https://graph.microsoft.com/v1.0/admin/exchange/tracing/messageTraces?$skiptoken=';

function quoted(filter: string, field: string): string | undefined {
  const match = filter.match(new RegExp(`${field} eq '((?:[^']|'')*)'`));
  return match?.[1].replace(/''/g, "'");
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
    const isWindow = token !== undefined || (!filter.includes(' eq ') && filter.length > 0);
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
      return collection(tenant.inbound?.[sender] ?? []);
    }
    const recipient = quoted(filter, 'recipientAddress');
    if (recipient !== undefined) {
      return collection(tenant.outbound?.[recipient] ?? []);
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

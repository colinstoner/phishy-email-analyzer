/**
 * The Graph broker's wire format: what the main function may ask of the
 * broker, and what it may be told back.
 *
 * The interface is a closed allow-list. A request names one of four
 * operations and carries only that operation's typed inputs. There is no
 * path, URL, filter, query string or "call Graph" operation, and no field of
 * a request is ever used as one: the broker turns typed inputs into requests
 * with the same code (`graphPath`, `odataFilter`) the features have always
 * used. Adding a capability means adding an operation here, in code, where
 * it is reviewed.
 *
 * Both directions are untrusted:
 * - A request is built by the function that parses hostile email, so every
 *   string in `params` is hostile. The broker validates it against
 *   `GraphBrokerRequestSchema` (unknown operations, unknown fields and other
 *   versions are refused) before anything else happens.
 * - A response carries strings that originated in email or in mail-flow
 *   records (headers, addresses, subjects). The main function validates it
 *   against the result schema for the operation it asked for and re-applies
 *   the features' own bounds here, rather than trusting the broker to have
 *   bounded it.
 *
 * This file imports only Zod and the shared limits, so loading it can never
 * construct a Graph client.
 */

import { z } from 'zod';
import {
  DELIVERY_STATUS_PATTERN,
  DIRECTORY_ID_PATTERN,
  GRAPH_ITEM_ID_PATTERN,
  IP_SHAPE,
  MAX_ADDRESS_LENGTH,
  MAX_CLAIMED_TIME_LENGTH,
  MAX_LISTED_RECIPIENTS,
  MAX_MESSAGE_HEADERS,
  MAX_REPORTED_BURST_IPS,
  MAX_REPORTED_COPY_IDS,
  MAX_SUBJECT_LENGTH,
  MESSAGE_ID_PATTERN,
} from './graph.limits';

export const GRAPH_BROKER_VERSION = 1;

export const GRAPH_BROKER_OPERATIONS = [
  'original_message_lookup',
  'blast_radius_lookup',
  'sender_history_lookup',
  'fanout_scan',
] as const;
export type GraphBrokerOperation = (typeof GRAPH_BROKER_OPERATIONS)[number];

/**
 * Why the broker did not run an operation. Fixed words chosen by the
 * broker's code; never derived from a request.
 */
export const GRAPH_BROKER_REFUSALS = [
  'invalid_request',
  'graph_disabled',
  'feature_disabled',
  'misconfigured',
  'internal_error',
] as const;
export type GraphBrokerRefusal = (typeof GRAPH_BROKER_REFUSALS)[number];

/** Longest time a caller may say it will wait (the Lambda maximum) */
const MAX_BUDGET_MS = 900_000;
/** Widest received-time window one message trace query accepts */
const MAX_KEY_WINDOW_MS = 10 * 24 * 60 * 60 * 1000;
const MAX_CLAIMED_DATE_LENGTH = 100;

/** Something@something with no spaces or brackets: an address, used only as data */
const MailAddress = z
  .string()
  .max(MAX_ADDRESS_LENGTH)
  .regex(/^[^\s<>@]+@[^\s<>@]+$/);

const BudgetMs = z.number().int().min(1).max(MAX_BUDGET_MS);

// ── Requests ────────────────────────────────────────────────────────────────

const OriginalMessageLookupParams = z.strictObject({
  /** The reporter's own mailbox, as confirmed by the main function */
  mailbox: MailAddress,
  /** Claimed sender address of the forwarded message (hostile) */
  claimedFrom: MailAddress,
  /** Claimed sent time, as the mail client wrote it (hostile) */
  claimedSent: z.string().min(1).max(MAX_CLAIMED_TIME_LENGTH),
  /** Claimed subject (hostile) */
  claimedSubject: z.string().min(1).max(MAX_SUBJECT_LENGTH).optional(),
  /** How long the caller will wait, in milliseconds */
  budgetMs: BudgetMs,
});

const BlastRadiusKeyParams = z
  .strictObject({
    /** RFC 5322 Message-ID of the original (hostile) */
    internetMessageId: z.string().regex(MESSAGE_ID_PATTERN).optional(),
    /** Claimed sender address (hostile) */
    senderAddress: MailAddress.optional(),
    /** Claimed subject (hostile) */
    subject: z.string().min(1).max(MAX_SUBJECT_LENGTH).optional(),
    receivedFrom: z.iso.datetime(),
    receivedTo: z.iso.datetime(),
  })
  .refine(key => key.internetMessageId !== undefined || key.senderAddress !== undefined, {
    message: 'a Message-ID or a sender address is required',
  })
  .refine(
    key => {
      const span = Date.parse(key.receivedTo) - Date.parse(key.receivedFrom);
      return span >= 0 && span <= MAX_KEY_WINDOW_MS;
    },
    { message: 'the received window is empty or too wide' }
  );

const BlastRadiusLookupParams = z.strictObject({
  key: BlastRadiusKeyParams,
  budgetMs: BudgetMs,
});

const SenderHistoryLookupParams = z.strictObject({
  /** Claimed external sender address (hostile) */
  senderAddress: MailAddress,
  /** The email's claimed date, as text (hostile); only ever parsed to a number */
  claimedDate: z.string().min(1).max(MAX_CLAIMED_DATE_LENGTH).optional(),
  budgetMs: BudgetMs,
});

/** A DNS domain name, lower or upper case; operator configuration, used only as data */
const DomainName = z
  .string()
  .max(253)
  .regex(/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/);

/** Widest window one fan-out scan may cover (two hours) */
const MAX_SCAN_WINDOW_MS = 2 * 60 * 60 * 1000;

const FanoutScanParams = z
  .strictObject({
    /** The window of mail flow to read: at most two hours wide */
    receivedFrom: z.iso.datetime(),
    receivedTo: z.iso.datetime(),
    /**
     * The organization's own domains, from the main function's
     * configuration: what "internal recipient" and "external sender" mean.
     * Operator data, not email data, but still only ever compared as data.
     */
    internalDomains: z.array(DomainName).min(1).max(100),
    /** Trace pages (5000 rows each) the scan may read */
    maxPages: z.number().int().min(1).max(10),
    /** Candidates whose sender history the scan may check */
    maxCandidates: z.number().int().min(1).max(10),
    /** Trace requests the scan may spend, history lookups included */
    maxRequests: z.number().int().min(1).max(100),
    budgetMs: BudgetMs,
  })
  .refine(
    params => {
      const span = Date.parse(params.receivedTo) - Date.parse(params.receivedFrom);
      return span > 0 && span <= MAX_SCAN_WINDOW_MS;
    },
    { message: 'the scan window is empty or too wide' }
  );

const version = z.literal(GRAPH_BROKER_VERSION);

/**
 * A request to the broker. Strict at every level: an unknown operation, an
 * unknown or missing field, a wrong type or another version is not a
 * request. In particular no HTTP event (API Gateway, function URL, load
 * balancer) and no event-source record matches it.
 */
export const GraphBrokerRequestSchema = z.discriminatedUnion('operation', [
  z.strictObject({
    version,
    operation: z.literal('original_message_lookup'),
    params: OriginalMessageLookupParams,
  }),
  z.strictObject({
    version,
    operation: z.literal('blast_radius_lookup'),
    params: BlastRadiusLookupParams,
  }),
  z.strictObject({
    version,
    operation: z.literal('sender_history_lookup'),
    params: SenderHistoryLookupParams,
  }),
  z.strictObject({
    version,
    operation: z.literal('fanout_scan'),
    params: FanoutScanParams,
  }),
]);

export type GraphBrokerRequest = z.infer<typeof GraphBrokerRequestSchema>;
export type GraphBrokerParams<Op extends GraphBrokerOperation> = Extract<
  GraphBrokerRequest,
  { operation: Op }
>['params'];

// ── Responses ───────────────────────────────────────────────────────────────

/**
 * The envelope. `result` is validated separately, against the schema for the
 * operation that was asked for.
 */
export const GraphBrokerResponseSchema = z.discriminatedUnion('ok', [
  z.strictObject({ ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ ok: z.literal(false), reason: z.enum(GRAPH_BROKER_REFUSALS) }),
]);

export type GraphBrokerResponse<Result = unknown> =
  { ok: true; result: Result } | { ok: false; reason: GraphBrokerRefusal };

/** A fixed, code-chosen word for logs (`mailbox`, `graph_timeout`, `no_candidate`) */
const ReasonWord = z.string().regex(/^[a-z][a-z0-9_]{0,39}$/);
const Count = z.number().int().min(0).max(100_000_000);
const IsoInstant = z.string().max(40);

/**
 * Result of `original_message_lookup`. Only `found` carries data. Header
 * names and values are hostile; the list is cut to the same length the
 * direct lookup reads, and the cut is reported. (The parser then reduces
 * each header to one line and drops malformed names, exactly as it does for
 * a direct lookup.)
 */
export const OriginalMessageLookupResultSchema = z
  .strictObject({
    outcome: z.enum(['found', 'not_found', 'ambiguous', 'error', 'skipped']),
    reason: ReasonWord,
    original: z
      .strictObject({
        location: z.enum(['mailbox', 'recoverable_items']),
        receivedAt: IsoInstant.optional(),
        headers: z.array(z.strictObject({ name: z.string(), value: z.string() })),
        headersTruncated: z.boolean(),
      })
      .optional(),
  })
  .refine(result => result.outcome !== 'found' || result.original !== undefined, {
    message: 'a found result must carry the original',
  })
  .transform(result => {
    if (result.outcome !== 'found' || !result.original) {
      return { outcome: result.outcome, reason: result.reason };
    }
    const { headers } = result.original;
    return {
      outcome: result.outcome,
      reason: result.reason,
      original: {
        ...result.original,
        headers: headers.slice(0, MAX_MESSAGE_HEADERS),
        headersTruncated: result.original.headersTruncated || headers.length > MAX_MESSAGE_HEADERS,
      },
    };
  });

const BoundedCountSchema = z.strictObject({ count: Count, atLeast: z.boolean() });

const SenderHistoryFactsSchema = z.strictObject({
  classification: z.enum([
    'no_history',
    'limited_history',
    'established',
    'established_with_anomalous_fanout',
  ]),
  lookbackDays: z.number().int().min(1).max(90),
  burstWindowHours: z
    .number()
    .int()
    .min(1)
    .max(90 * 24),
  history: z.strictObject({
    messages: BoundedCountSchema,
    recipients: BoundedCountSchema,
    firstSeen: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/)
      .optional(),
  }),
  twoWay: z.strictObject({
    messages: BoundedCountSchema,
    internalSenders: BoundedCountSchema,
  }),
  burst: z.strictObject({
    messages: BoundedCountSchema,
    recipients: BoundedCountSchema,
    newRecipients: BoundedCountSchema.nullable(),
    sameSubject: z.strictObject({
      recipients: BoundedCountSchema,
      newRecipients: BoundedCountSchema.nullable(),
    }),
  }),
  sendingIps: z.strictObject({
    burst: Count,
    seenInHistory: Count,
    historyComplete: z.boolean(),
    burstIps: z
      .array(z.strictObject({ ip: z.string().max(100), seenInHistory: z.boolean() }))
      .max(1000)
      .optional(),
    burstIpsOmitted: Count.optional(),
  }),
  truncated: z.boolean(),
});

/**
 * Result of `sender_history_lookup`: the outcome, the facts when there are
 * any, and the two counters the metric needs. The facts are numbers and an
 * enum; the one list, the burst's sending IPs, is re-checked for shape and
 * re-capped here, with whatever is dropped added to the omitted count.
 */
export const SenderHistoryLookupResultSchema = z
  .strictObject({
    outcome: z.enum([
      'ok',
      'cache_hit',
      'skipped',
      'timeout',
      'forbidden',
      'cooldown',
      'rate_limited',
      'error',
    ]),
    facts: SenderHistoryFactsSchema.optional(),
    forbiddenRetries: Count,
    filterMismatch: z.boolean(),
  })
  .refine(
    result => (result.outcome === 'ok' || result.outcome === 'cache_hit') === !!result.facts,
    { message: 'facts accompany exactly the outcomes that produce them' }
  )
  .transform(result => {
    const listed = result.facts?.sendingIps.burstIps;
    if (!result.facts || !listed) {
      return result;
    }
    const burstIps = listed
      .filter(entry => IP_SHAPE.test(entry.ip))
      .slice(0, MAX_REPORTED_BURST_IPS);
    const omitted =
      (result.facts.sendingIps.burstIpsOmitted ?? 0) + listed.length - burstIps.length;
    const { burst, seenInHistory, historyComplete } = result.facts.sendingIps;
    return {
      ...result,
      facts: {
        ...result.facts,
        sendingIps: {
          burst,
          seenInHistory,
          historyComplete,
          ...(burstIps.length > 0 ? { burstIps } : {}),
          ...(omitted > 0 ? { burstIpsOmitted: omitted } : {}),
        },
      },
    };
  });

const FanoutStatusCountsSchema = z.strictObject({
  delivered: Count,
  junk: Count,
  quarantined: Count,
  failed: Count,
  other: Count,
});

const FanoutStatusWord = z.enum(['delivered', 'junk', 'quarantined', 'failed', 'other']);

/** Most flags one scan may return */
const MAX_FANOUT_FLAGS = 10;

/**
 * Result of `fanout_scan`: counts about the scan and, per flagged wave, the
 * facts the security team's alert needs. The sender, the subject and the
 * recipient addresses are hostile mail-flow data; the recipient list is cut
 * to the length a blast-radius report lists, with the rest counted.
 */
export const FanoutScanResultSchema = z
  .strictObject({
    outcome: z.enum(['ok', 'forbidden', 'timeout', 'rate_limited', 'error']),
    rowsScanned: Count,
    inboundRows: Count,
    pages: Count,
    requestsUsed: Count,
    forbiddenRetries: Count,
    filterMismatch: z.boolean(),
    candidates: Count,
    candidatesChecked: Count,
    incomplete: z.boolean(),
    incompleteReasons: z
      .array(
        z.enum([
          'page_limit',
          'page_error',
          'candidate_limit',
          'request_allowance',
          'time_budget',
          'history_unavailable',
        ])
      )
      .max(6),
    flagged: z
      .array(
        z.strictObject({
          senderAddress: MailAddress,
          subject: z.string().max(MAX_SUBJECT_LENGTH),
          firstSeen: z.iso.datetime(),
          lastSeen: z.iso.datetime(),
          windowRecipients: Count,
          windowMessages: Count,
          statuses: FanoutStatusCountsSchema,
          recipients: z
            .array(z.strictObject({ address: MailAddress, status: FanoutStatusWord }))
            .max(10_000),
          recipientsOmitted: Count,
          facts: SenderHistoryFactsSchema,
        })
      )
      .max(1000),
  })
  .transform(result => {
    const flagged = result.flagged.slice(0, MAX_FANOUT_FLAGS).map(flag => {
      const burstIps = flag.facts.sendingIps.burstIps;
      const keptIps = burstIps
        ?.filter(entry => IP_SHAPE.test(entry.ip))
        .slice(0, MAX_REPORTED_BURST_IPS);
      const omittedIps =
        (flag.facts.sendingIps.burstIpsOmitted ?? 0) +
        (burstIps ? burstIps.length - (keptIps?.length ?? 0) : 0);
      const { burst, seenInHistory, historyComplete } = flag.facts.sendingIps;
      return {
        ...flag,
        recipients: flag.recipients.slice(0, MAX_LISTED_RECIPIENTS),
        recipientsOmitted:
          flag.recipientsOmitted + Math.max(0, flag.recipients.length - MAX_LISTED_RECIPIENTS),
        facts: {
          ...flag.facts,
          sendingIps: {
            burst,
            seenInHistory,
            historyComplete,
            ...(keptIps && keptIps.length > 0 ? { burstIps: keptIps } : {}),
            ...(omittedIps > 0 ? { burstIpsOmitted: omittedIps } : {}),
          },
        },
      };
    });
    return { ...result, flagged };
  });

/** Printable, bounded text written by the broker's code (notes and caveats) */
const CodeWrittenLine = z.string().max(600);
/** A directory or trace address: bounded, no whitespace or control characters */
const ListedAddress = z.string().regex(/^[^\s\p{Cc}]{1,320}$/u);

const BlastRadiusRecipientSchema = z.strictObject({
  address: ListedAddress,
  deliveryStatus: z.string().regex(DELIVERY_STATUS_PATTERN).optional(),
  mailbox: z.enum(['found', 'not_found', 'not_checked', 'not_delivered']),
  folder: z.enum(['inbox', 'junk', 'deleted', 'recoverable', 'other', 'unknown']).optional(),
  isRead: z.boolean().optional(),
  response: z.enum(['replied', 'forwarded', 'none', 'unknown']).optional(),
  lastVerbCode: z.number().int().optional(),
  copies: Count.optional(),
  // The identifiers a campaign-response action may name (campaign response)
  mailboxId: z.string().regex(DIRECTORY_ID_PATTERN).optional(),
  messageIds: z
    .array(z.string().regex(GRAPH_ITEM_ID_PATTERN))
    .max(MAX_REPORTED_COPY_IDS)
    .optional(),
  receivedAt: IsoInstant.optional(),
});

const BlastRadiusReportSchema = z.strictObject({
  status: z.enum(['complete', 'partial', 'unavailable']),
  note: CodeWrittenLine.optional(),
  route: z.enum(['trace', 'mailbox']).optional(),
  matchedBy: z.enum(['messageId', 'senderSubject', 'sender']).optional(),
  criteria: z
    .strictObject({
      senderAddress: z.string().max(MAX_ADDRESS_LENGTH).optional(),
      subject: z.string().max(MAX_SUBJECT_LENGTH).optional(),
      receivedFrom: IsoInstant,
      receivedTo: IsoInstant,
    })
    .optional(),
  totals: z
    .strictObject({
      recipients: Count,
      read: Count,
      replied: Count,
      forwarded: Count,
      notDelivered: Count.optional(),
    })
    .optional(),
  recipients: z.array(BlastRadiusRecipientSchema).max(10_000).optional(),
  coverage: z
    .strictObject({
      mailboxesChecked: Count,
      mailboxesEligible: Count,
      eligibleIsLowerBound: z.boolean(),
      recoverableChecked: Count,
      recoverableCandidates: Count,
      detailUnavailable: Count,
    })
    .optional(),
  caveats: z.array(CodeWrittenLine).max(30).optional(),
  lookedUpAt: IsoInstant,
});

/**
 * Result of `blast_radius_lookup`: the report for the security team and the
 * two counters the metric needs. Addresses, the echoed criteria and delivery
 * statuses are hostile; the recipient list is cut to the length the direct
 * lookup lists. The reporter's address is not part of it: the main function
 * marks the reporter itself.
 */
export const BlastRadiusLookupResultSchema = z
  .strictObject({
    report: BlastRadiusReportSchema,
    errors: Count,
    cached: z.boolean(),
  })
  .transform(result =>
    result.report.recipients && result.report.recipients.length > MAX_LISTED_RECIPIENTS
      ? {
          ...result,
          report: {
            ...result.report,
            recipients: result.report.recipients.slice(0, MAX_LISTED_RECIPIENTS),
          },
        }
      : result
  );

/** The result schema for each operation */
export const GRAPH_BROKER_RESULT_SCHEMAS = {
  original_message_lookup: OriginalMessageLookupResultSchema,
  blast_radius_lookup: BlastRadiusLookupResultSchema,
  sender_history_lookup: SenderHistoryLookupResultSchema,
  fanout_scan: FanoutScanResultSchema,
} as const;

export type GraphBrokerResult<Op extends GraphBrokerOperation> = z.infer<
  (typeof GRAPH_BROKER_RESULT_SCHEMAS)[Op]
>;

/**
 * Largest response accepted for each operation, in bytes, checked before the
 * payload is parsed. Sized from what the operation can legitimately return
 * (the header read is capped at 2 MB at the Graph client; a report lists at
 * most 100 recipients; sender history is a handful of numbers).
 */
export const GRAPH_BROKER_MAX_RESPONSE_BYTES: Record<GraphBrokerOperation, number> = {
  original_message_lookup: 3 * 1024 * 1024,
  blast_radius_lookup: 512 * 1024,
  sender_history_lookup: 64 * 1024,
  // Up to 10 flags, each with 100 recipients and a handful of numbers
  fanout_scan: 512 * 1024,
};

/**
 * Time kept back, out of a feature's budget, for the invocation itself (the
 * round trip and a cold start). The broker is asked to finish this much
 * sooner than the main function stops waiting.
 */
export const GRAPH_BROKER_OVERHEAD_MS = 1000;

/**
 * The budget to give the broker when the caller will wait `budgetMs` in all:
 * the budget less the overhead, or less a quarter of it when the budget is
 * short, so a small budget still leaves the broker most of it.
 */
export function brokerBudgetMs(budgetMs: number): number {
  return Math.max(1, Math.floor(budgetMs - Math.min(GRAPH_BROKER_OVERHEAD_MS, budgetMs / 4)));
}

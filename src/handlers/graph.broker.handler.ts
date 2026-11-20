/**
 * Graph broker: the Lambda function that talks to Microsoft Graph, so the
 * function that parses hostile email does not have to.
 *
 * The main function usually runs in a VPC with no internet route. This
 * function runs outside it, holds the read certificate, and does one thing:
 * run one of four typed, read-only operations on request and return a typed
 * result. It never receives, fetches or parses a raw email, and it has no
 * email, AI, database or notification configuration.
 *
 * Rules this file keeps:
 * - **A closed allow-list.** The request is validated against
 *   `GraphBrokerRequestSchema` before anything else. Four operations; no
 *   path, URL, filter or passthrough. Everything else is refused.
 * - **Direct invocation only.** The handler takes the request object itself.
 *   An HTTP event (API Gateway, function URL, load balancer) or an
 *   event-source record does not match the schema and is refused like any
 *   other malformed request; the function is deployed with no such trigger.
 * - **Code-driven** (CLAUDE.md invariant 6). The operations run the existing
 *   feature code, which builds every Graph request from typed values through
 *   `graphPath` and `odataFilter`. Every string in `params` came from an
 *   email and is hostile: it is data to those builders and nothing else.
 * - **Nothing leaks.** The handler never throws; the caller sees
 *   `{ ok: true, result }` or `{ ok: false, reason }` with a fixed reason
 *   word. Logs carry the operation, the outcome, counts and durations: never
 *   a parameter, an address, a subject or a header (invariant 1).
 * - **The main function decides whether to ask; this function decides
 *   whether to answer.** An operation whose feature flag is off in this
 *   function's own configuration is refused.
 *
 * Rate limits and the short-lived caches live here, inside the feature
 * services, because this is the function whose requests Microsoft counts.
 */

import type { Context } from 'aws-lambda';
import { loadGraphBrokerConfig } from '../config';
import { GraphBrokerConfig } from '../config/schema';
import {
  BlastRadiusService,
  createBlastRadiusService,
} from '../services/graph/blast-radius.service';
import {
  GraphBrokerParams,
  GraphBrokerRefusal,
  GraphBrokerRequestSchema,
  GraphBrokerResponse,
} from '../services/graph/broker.protocol';
import { GraphClient } from '../services/graph/graph.client';
import { createGraphReadClient } from '../services/graph/graph.credential';
import {
  ORIGINAL_FETCH_BUDGET_MS,
  ORIGINAL_FETCH_CLIENT_OPTIONS,
  ORIGINAL_FETCH_TOKEN_OPTIONS,
  fetchOriginalMessage,
} from '../services/graph/original.fetch';
import { SenderHistoryService, createSenderHistoryService } from '../services/graph/sender.history';
import { FanoutScanService, createFanoutScanService } from '../services/graph/fanout.scan';
import { addAngleBrackets } from '../services/graph/trace.operations';
import { createLogger } from '../utils/logger';

const logger = createLogger('graph-broker');

interface BrokerServices {
  config: GraphBrokerConfig;
  originalFetchClient?: GraphClient;
  blastRadius?: BlastRadiusService;
  senderHistory?: SenderHistoryService;
  fanoutScan?: FanoutScanService;
}

/** Built once per instance; a failed load is retried on the next invocation */
let cachedServices: BrokerServices | undefined;

/** Forget the loaded configuration and services (for tests) */
export function resetGraphBroker(): void {
  cachedServices = undefined;
}

async function initialize(): Promise<BrokerServices> {
  if (cachedServices) {
    return cachedServices;
  }
  const config = await loadGraphBrokerConfig();
  const graph = config.graph;
  const services: BrokerServices = { config };

  if (graph.enabled) {
    // Each feature has its own client, with the bounds that feature needs,
    // exactly as when it runs in the main function. Nothing is fetched (no
    // secret, no token) until a lookup is made.
    if (graph.originalFetch?.enabled) {
      services.originalFetchClient = createGraphReadClient(graph, {
        clientOptions: ORIGINAL_FETCH_CLIENT_OPTIONS,
        tokenOptions: ORIGINAL_FETCH_TOKEN_OPTIONS,
      });
    }
    services.blastRadius = createBlastRadiusService(graph);
    // Whether a sender is external is decided by the main function, which
    // has the organization's domains; the broker has no email settings
    services.senderHistory = createSenderHistoryService({
      graph,
      email: { safeDomains: [], safeSenders: [], deleteAfterProcessing: false },
    });
    // The scheduled fan-out scan: its own client, its own request allowance
    // (separate from sender history's, so a scan never starves a report)
    services.fanoutScan = createFanoutScanService(graph);
  }

  logger.info('Graph broker initialized', {
    graphEnabled: graph.enabled,
    originalFetch: !!services.originalFetchClient,
    blastRadius: !!services.blastRadius,
    senderHistory: !!services.senderHistory,
    fanoutScan: !!services.fanoutScan,
  });
  cachedServices = services;
  return services;
}

function refuse(reason: GraphBrokerRefusal): GraphBrokerResponse {
  return { ok: false, reason };
}

async function originalMessageLookup(
  services: BrokerServices,
  params: GraphBrokerParams<'original_message_lookup'>
): Promise<{ response: GraphBrokerResponse; summary: Record<string, unknown> }> {
  if (!services.originalFetchClient) {
    return { response: refuse('feature_disabled'), summary: {} };
  }
  const result = await fetchOriginalMessage(
    services.originalFetchClient,
    {
      mailbox: params.mailbox,
      claimedFrom: params.claimedFrom,
      claimedSent: params.claimedSent,
      claimedSubject: params.claimedSubject,
    },
    { budgetMs: Math.min(ORIGINAL_FETCH_BUDGET_MS, params.budgetMs) }
  );
  return {
    response: { ok: true, result },
    summary: {
      outcome: result.outcome,
      reason: result.reason,
      headers: result.original?.headers.length ?? 0,
    },
  };
}

async function blastRadiusLookup(
  services: BrokerServices,
  params: GraphBrokerParams<'blast_radius_lookup'>,
  remainingMs: number | undefined
): Promise<{ response: GraphBrokerResponse; summary: Record<string, unknown> }> {
  if (!services.blastRadius) {
    return { response: refuse('feature_disabled'), summary: {} };
  }
  const { key } = params;
  const { report, metric } = await services.blastRadius.lookupByKey(
    {
      internetMessageId: key.internetMessageId
        ? addAngleBrackets(key.internetMessageId)
        : undefined,
      senderAddress: key.senderAddress?.toLowerCase(),
      subject: key.subject,
      receivedFrom: new Date(key.receivedFrom),
      receivedTo: new Date(key.receivedTo),
    },
    // The caller's budget, and this function's own remaining time
    { budgetMs: params.budgetMs, remainingMs }
  );
  return {
    response: { ok: true, result: { report, errors: metric.errors, cached: !!metric.cached } },
    summary: {
      outcome: metric.outcome,
      route: metric.route,
      matchedBy: report.matchedBy,
      recipientsFound: metric.recipientsFound,
      mailboxesChecked: metric.mailboxesChecked,
      mailboxesEligible: metric.mailboxesEligible,
      errors: metric.errors,
      cached: !!metric.cached,
    },
  };
}

async function senderHistoryLookup(
  services: BrokerServices,
  params: GraphBrokerParams<'sender_history_lookup'>
): Promise<{ response: GraphBrokerResponse; summary: Record<string, unknown> }> {
  if (!services.senderHistory) {
    return { response: refuse('feature_disabled'), summary: {} };
  }
  const { facts, metric } = await services.senderHistory.lookupSender(() => ({
    claimedFrom: params.senderAddress,
    claimedDate: params.claimedDate,
    budgetMs: params.budgetMs,
  }));
  return {
    response: {
      ok: true,
      result: {
        outcome: metric.outcome,
        ...(facts ? { facts } : {}),
        forbiddenRetries: metric.forbiddenRetries ?? 0,
        filterMismatch: !!metric.filterMismatch,
      },
    },
    summary: {
      outcome: metric.outcome,
      classification: facts?.classification,
      truncated: facts?.truncated,
      forbiddenRetries: metric.forbiddenRetries ?? 0,
    },
  };
}

async function fanoutScan(
  services: BrokerServices,
  params: GraphBrokerParams<'fanout_scan'>
): Promise<{ response: GraphBrokerResponse; summary: Record<string, unknown> }> {
  if (!services.fanoutScan) {
    return { response: refuse('feature_disabled'), summary: {} };
  }
  const result = await services.fanoutScan.scan({
    receivedFrom: new Date(params.receivedFrom),
    receivedTo: new Date(params.receivedTo),
    internalDomains: params.internalDomains.map(domain => domain.toLowerCase()),
    maxPages: params.maxPages,
    maxCandidates: params.maxCandidates,
    maxRequests: params.maxRequests,
    budgetMs: params.budgetMs,
  });
  return {
    response: { ok: true, result },
    summary: {
      outcome: result.outcome,
      rowsScanned: result.rowsScanned,
      pages: result.pages,
      candidates: result.candidates,
      flagged: result.flagged.length,
      requestsUsed: result.requestsUsed,
      incomplete: result.incomplete,
    },
  };
}

/**
 * Lambda entry point. `event` is whatever the caller sent: it is validated,
 * never assumed. Always resolves with a `GraphBrokerResponse`.
 */
export async function handler(
  event: unknown,
  context?: Pick<Context, 'getRemainingTimeInMillis'>
): Promise<GraphBrokerResponse> {
  const startedAt = Date.now();
  let operation = 'none';
  let response: GraphBrokerResponse;
  let summary: Record<string, unknown> = {};

  try {
    const request = GraphBrokerRequestSchema.safeParse(event);
    if (!request.success) {
      response = refuse('invalid_request');
    } else {
      operation = request.data.operation;
      let services: BrokerServices | undefined;
      try {
        services = await initialize();
      } catch (error) {
        // The loader has already logged which settings are wrong
        logger.error('Graph broker is not configured', {
          error: error instanceof Error ? error.name : 'unknown',
        });
      }

      if (!services) {
        response = refuse('misconfigured');
      } else if (!services.config.graph.enabled) {
        response = refuse('graph_disabled');
      } else {
        const ran =
          request.data.operation === 'original_message_lookup'
            ? await originalMessageLookup(services, request.data.params)
            : request.data.operation === 'blast_radius_lookup'
              ? await blastRadiusLookup(
                  services,
                  request.data.params,
                  context?.getRemainingTimeInMillis?.()
                )
              : request.data.operation === 'sender_history_lookup'
                ? await senderHistoryLookup(services, request.data.params)
                : await fanoutScan(services, request.data.params);
        response = ran.response;
        summary = ran.summary;
      }
    }
  } catch (error) {
    // The feature code does not throw; if something here does, the caller
    // still gets a fixed word and never an error message
    logger.error('Graph broker request failed unexpectedly', {
      operation,
      error: error instanceof Error ? error.name : 'unknown',
    });
    response = refuse('internal_error');
    summary = {};
  }

  logger.info('Graph broker request finished', {
    operation,
    ok: response.ok,
    ...(response.ok ? {} : { refusal: response.reason }),
    ...summary,
    durationMs: Date.now() - startedAt,
  });
  return response;
}

/**
 * Graph write broker: the mailbox write tier, and the only code in Phishy
 * that changes a mailbox.
 *
 * A third Lambda function, separate from the main function and from the
 * read broker, deployed only when its own parameters are supplied. It holds
 * its own Entra app registration and certificate (`Mail.ReadWrite`,
 * application), which no other function receives, and does exactly one
 * thing: `remove_messages`, which moves named copies to Deleted Items after
 * re-reading each and confirming its Internet Message-ID. Nothing is ever
 * hard-deleted, sent or created. See docs/ARCHITECTURE.md, "The mailbox
 * write tier".
 *
 * Rules this file keeps:
 * - **A closed allow-list.** The request is validated against
 *   `GraphWriteRequestSchema` before anything else: one operation, bounded
 *   lists of shape-checked IDs, nothing that is a path, URL or filter.
 * - **Its own kill switch and allowlist**, from its own environment (never
 *   the shared configuration file): with `PHISHY_GRAPH_WRITE_ENABLED` unset
 *   or anything but `true`, every request is refused `write_disabled` before
 *   a credential is loaded; with `PHISHY_GRAPH_WRITE_ALLOWED_MAILBOX_IDS`
 *   set, any other mailbox is refused `not_allowed`. A mistake in the main
 *   function's configuration cannot turn either off.
 * - **Direct invocation only.** No trigger; an HTTP or event-source event
 *   does not match the schema and is refused.
 * - **Nothing leaks.** The handler never throws; it answers `{ ok: true,
 *   result }` or `{ ok: false, reason }` with a fixed word, and per-message
 *   outcomes carry fixed reason words, never Graph's error text. Logs carry
 *   the action ID, counts, the stop reason and the duration: never a
 *   mailbox, message or Internet Message-ID, and nothing read from a mailbox.
 *
 * What it does not do: decide what to remove. The scope was computed by the
 * main function from Phishy's own blast-radius lookup, approved by the
 * security team with the exact `APPROVE REMOVAL <ref>` reply through the
 * authenticated command channel, and re-checked before it was sent here.
 * This function cannot verify that approval (it has no database); its
 * guarantees are the bounds, the allowlist, the kill switch, the
 * Internet Message-ID check and that the only change it can make is a move
 * to Deleted Items, which the mailbox owner can undo.
 */

import type { Context } from 'aws-lambda';
import { loadGraphWriteBrokerConfig } from '../config';
import { GraphWriteBrokerConfig } from '../config/schema';
import { loadGraphCredential } from '../services/graph/graph.credential';
import { GraphTokenProvider } from '../services/graph/graph.auth';
import { GraphWriteClient } from '../services/graph-write/write.client';
import { removeMessages } from '../services/graph-write/remove.messages';
import {
  GraphWriteRefusal,
  GraphWriteRequestSchema,
  GraphWriteResponse,
  RemovalOutcomeCounts,
  countOutcome,
  emptyRemovalCounts,
} from '../services/graph-write/write.protocol';
import { createLogger } from '../utils/logger';

const logger = createLogger('graph-write-broker');

/** The credential label: the token provider and client only ever act as this */
export const WRITE_CREDENTIAL_LABEL = 'write';

interface WriteServices {
  config: GraphWriteBrokerConfig;
  client?: GraphWriteClient;
  allowed?: ReadonlySet<string>;
}

let cachedServices: WriteServices | undefined;

/** Forget the loaded configuration and client (for tests) */
export function resetGraphWriteBroker(): void {
  cachedServices = undefined;
}

function buildClient(config: GraphWriteBrokerConfig): GraphWriteClient {
  const settings = {
    label: WRITE_CREDENTIAL_LABEL,
    tenantId: config.tenantId ?? '',
    clientId: config.clientId ?? '',
    certificate: config.certificate ?? '',
  };
  // Loaded lazily, on the first request, and held for the instance
  let loading: ReturnType<typeof loadGraphCredential> | undefined;
  const source = (): ReturnType<typeof loadGraphCredential> => {
    loading ??= loadGraphCredential(settings).catch((error: unknown) => {
      loading = undefined;
      throw error;
    });
    return loading;
  };
  return new GraphWriteClient({
    tokenProvider: new GraphTokenProvider(WRITE_CREDENTIAL_LABEL, source, {
      timeoutMs: 8000,
      maxAttempts: 2,
    }),
  });
}

function initialize(): WriteServices {
  if (cachedServices) {
    return cachedServices;
  }
  const config = loadGraphWriteBrokerConfig();
  const services: WriteServices = { config };
  if (config.enabled) {
    services.client = buildClient(config);
    if (config.allowedMailboxIds) {
      services.allowed = new Set(config.allowedMailboxIds.map(id => id.toLowerCase()));
    }
  }
  logger.info('Graph write broker initialized', {
    enabled: config.enabled,
    allowlist: services.allowed ? services.allowed.size : 'none',
  });
  cachedServices = services;
  return services;
}

function refuse(reason: GraphWriteRefusal): GraphWriteResponse {
  return { ok: false, reason };
}

/**
 * Lambda entry point. `event` is whatever the caller sent: validated, never
 * assumed. Always resolves with a `GraphWriteResponse`.
 */
export async function handler(
  event: unknown,
  context?: Pick<Context, 'getRemainingTimeInMillis'>
): Promise<GraphWriteResponse> {
  const startedAt = Date.now();
  let response: GraphWriteResponse;
  let summary: Record<string, unknown> = {};

  try {
    const request = GraphWriteRequestSchema.safeParse(event);
    if (!request.success) {
      response = refuse('invalid_request');
    } else {
      let services: WriteServices | undefined;
      try {
        services = initialize();
      } catch (error) {
        // The loader has already logged which settings are wrong
        logger.error('Graph write broker is not configured', {
          error: error instanceof Error ? error.name : 'unknown',
        });
      }

      if (!services) {
        response = refuse('misconfigured');
      } else if (!services.config.enabled || !services.client) {
        response = refuse('write_disabled');
      } else {
        const params = request.data.params;
        const result = await removeMessages(services.client, params, {
          allowedMailboxIds: services.allowed,
          remainingMs: context?.getRemainingTimeInMillis?.(),
        });
        const counts: RemovalOutcomeCounts = emptyRemovalCounts();
        for (const mailbox of result.mailboxes) {
          for (const message of mailbox.messages) {
            countOutcome(counts, message.outcome);
          }
        }
        response = { ok: true, result };
        summary = {
          actionId: params.actionId,
          mailboxes: params.mailboxes.length,
          ...counts,
          stoppedBy: result.stoppedBy,
        };
      }
    }
  } catch (error) {
    logger.error('Graph write broker request failed unexpectedly', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    response = refuse('internal_error');
    summary = {};
  }

  logger.info('Graph write broker request finished', {
    operation: 'remove_messages',
    ok: response.ok,
    ...(response.ok ? {} : { refusal: response.reason }),
    ...summary,
    durationMs: Date.now() - startedAt,
  });
  return response;
}

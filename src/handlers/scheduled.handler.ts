/**
 * Scheduled tasks of the main function. Today there is one: the Graph
 * fan-out scan (`graph.fanoutScan`), which the main function runs because
 * it owns email sending and the intelligence database. The Graph work itself
 * is the broker's (or, in direct mode, this function's) read-only scan.
 *
 * The event is validated strictly (`scheduled.event.ts`); anything else
 * that claims to be a scheduled task is refused and nothing runs. No model
 * is involved.
 */

import type { APIGatewayProxyResult, Context } from 'aws-lambda';
import { FanoutScanSource, createFanoutScanSource } from '../services/graph/fanout.source';
import { runFanoutScan } from '../services/hunting/fanout.job';
import { createLogger } from '../utils/logger';
import { scheduledTaskServices } from './lambda.handler';
import { ScheduledTaskEventSchema } from './scheduled.event';

const logger = createLogger('scheduled-handler');

/** Built once per instance, from the same configuration as the email pipeline */
let cachedSource: { source?: FanoutScanSource } | undefined;

/** Forget the scan source (for tests) */
export function resetScheduledTasks(): void {
  cachedSource = undefined;
}

function respond(statusCode: number, body: Record<string, unknown>): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}

export async function handleScheduledTask(
  event: unknown,
  context?: Pick<Context, 'getRemainingTimeInMillis'>
): Promise<APIGatewayProxyResult> {
  const parsed = ScheduledTaskEventSchema.safeParse(event);
  if (!parsed.success) {
    // Nothing from the event is logged: it is not a payload Phishy wrote
    logger.warn('Refused a scheduled-task event that does not match the schema');
    return respond(400, { success: false, error: 'invalid scheduled task' });
  }

  try {
    const services = await scheduledTaskServices();
    cachedSource ??= { source: createFanoutScanSource(services.config) };
    const summary = await runFanoutScan(
      {
        config: services.config,
        source: cachedSource.source,
        db: services.intelligenceDb?.featureStore(),
        notifier: services.sesNotifier,
        graph: services.graph,
        // With campaign response on, a flagged wave becomes an incident
        // (one email to the security team) instead of a separate alert
        ...(services.campaignResponse ? { campaignResponse: services.campaignResponse } : {}),
      },
      { remainingMs: () => context?.getRemainingTimeInMillis?.() }
    );
    return respond(200, { success: true, task: parsed.data.phishyScheduledTask, ...summary });
  } catch (error) {
    logger.error('Scheduled task failed', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    return respond(200, { success: false, task: parsed.data.phishyScheduledTask });
  }
}

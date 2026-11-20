/**
 * The main function's way to run a fan-out scan: in this function
 * (`graph.mode: direct`) or as the Graph broker's `fanout_scan` operation
 * (`broker`). The scheduled job (`services/hunting/fanout.job.ts`) does not
 * know which.
 *
 * Whichever ran it, the result is mail-flow data and is re-checked here
 * before the job sees it: a flag whose sender is not an ordinary external
 * address is dropped, and a listed recipient that is not on one of the
 * organization's domains is dropped and counted as omitted. In broker mode
 * the answer has already passed the protocol's strict schema and bounds.
 *
 * In broker mode nothing here builds a Graph client or touches a credential.
 */

import { PhishyConfig } from '../../config/schema';
import { createLogger } from '../../utils/logger';
import { GraphBrokerClient, LambdaInvoker } from './broker.client';
import { brokerBudgetMs } from './broker.protocol';
import {
  FanoutScanRequest,
  FanoutScanResult,
  FanoutScanService,
  createFanoutScanService,
  isInternalAddress,
} from './fanout.scan';
import { GraphClient } from './graph.client';
import { claimedSenderAddress } from './sender.history';

const logger = createLogger('fanout-source');

export type FanoutScanCall =
  { ok: true; result: FanoutScanResult } | { ok: false; failure: 'timeout' | 'unavailable' };

export interface FanoutScanSource {
  readonly mode: 'direct' | 'broker';
  /** Run one scan, waiting at most `waitMs`. Never throws. */
  scan(request: FanoutScanRequest, waitMs: number): Promise<FanoutScanCall>;
}

/** Re-check a result's hostile parts against the organization's own domains */
export function reboundFanoutResult(
  result: FanoutScanResult,
  internalDomains: string[]
): FanoutScanResult {
  const flagged = result.flagged.flatMap(flag => {
    const sender = claimedSenderAddress(flag.senderAddress);
    if (!sender || isInternalAddress(sender, internalDomains)) {
      return [];
    }
    const recipients = flag.recipients.filter(recipient =>
      isInternalAddress(recipient.address.toLowerCase(), internalDomains)
    );
    return [
      {
        ...flag,
        senderAddress: sender,
        recipients,
        recipientsOmitted: flag.recipientsOmitted + (flag.recipients.length - recipients.length),
      },
    ];
  });
  if (flagged.length !== result.flagged.length) {
    logger.warn('Fan-out scan result carried flags that do not describe an external sender', {
      dropped: result.flagged.length - flagged.length,
    });
  }
  return { ...result, flagged };
}

class DirectFanoutScanSource implements FanoutScanSource {
  readonly mode = 'direct' as const;
  constructor(private readonly service: Pick<FanoutScanService, 'scan'>) {}

  async scan(request: FanoutScanRequest, waitMs: number): Promise<FanoutScanCall> {
    const result = await this.service.scan({
      ...request,
      budgetMs: Math.min(request.budgetMs, waitMs),
    });
    return { ok: true, result: reboundFanoutResult(result, request.internalDomains) };
  }
}

class BrokerFanoutScanSource implements FanoutScanSource {
  readonly mode = 'broker' as const;
  constructor(private readonly broker: GraphBrokerClient) {}

  async scan(request: FanoutScanRequest, waitMs: number): Promise<FanoutScanCall> {
    const budgetMs = Math.min(request.budgetMs, waitMs);
    const call = await this.broker.call(
      'fanout_scan',
      {
        receivedFrom: request.receivedFrom.toISOString(),
        receivedTo: request.receivedTo.toISOString(),
        internalDomains: request.internalDomains,
        maxPages: request.maxPages,
        maxCandidates: request.maxCandidates,
        maxRequests: request.maxRequests,
        budgetMs: brokerBudgetMs(budgetMs),
      },
      budgetMs
    );
    if (!call.ok) {
      return { ok: false, failure: call.failure === 'timeout' ? 'timeout' : 'unavailable' };
    }
    return { ok: true, result: reboundFanoutResult(call.result, request.internalDomains) };
  }
}

export interface FanoutScanSourceDeps {
  /** Injected for tests (broker mode) */
  lambda?: LambdaInvoker;
  /** Injected for tests (direct mode) */
  client?: GraphClient;
}

/**
 * The scan source the configuration asks for, or undefined when the feature
 * or Graph is off. In broker mode the broker decides for itself whether it
 * runs scans (its own `graph.fanoutScan.enabled`) and refuses otherwise.
 */
export function createFanoutScanSource(
  config: Pick<PhishyConfig, 'graph'>,
  deps: FanoutScanSourceDeps = {}
): FanoutScanSource | undefined {
  const graph = config.graph;
  if (!graph?.fanoutScan?.enabled) {
    return undefined;
  }
  if (!graph.enabled) {
    logger.warn('graph.fanoutScan.enabled has no effect while graph.enabled is false');
    return undefined;
  }
  if (graph.mode === 'broker') {
    if (!graph.brokerFunctionName) {
      return undefined;
    }
    return new BrokerFanoutScanSource(
      new GraphBrokerClient({ functionName: graph.brokerFunctionName, lambda: deps.lambda })
    );
  }
  const service = createFanoutScanService(graph, deps.client);
  return service ? new DirectFanoutScanSource(service) : undefined;
}

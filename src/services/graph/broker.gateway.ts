/**
 * The three Graph features in broker mode: decided here, run by the Graph
 * broker.
 *
 * The split follows what each side is allowed to know. The main function
 * has the parsed email and the organization's settings, so everything that
 * depends on them stays here: whose mailbox may be read, whether a sender is
 * external, how the message is keyed, how long there is. The broker has the
 * credential and the route to Microsoft, so the requests, their rate limits
 * and their short-lived caches are there. What crosses is the smallest typed
 * input each lookup needs, and a validated, re-bounded result.
 *
 * Each method keeps the direct implementation's contract:
 * - it never throws;
 * - it emits the feature's metric exactly once, here (the broker emits none);
 * - a broker timeout, error, throttle, refusal, oversized or malformed answer
 *   is the feature's ordinary failure: `error` for the original-message
 *   lookup, `timeout` or `error` for sender history, an `unavailable` report
 *   for blast radius. Analysis and reports proceed as they do without Graph.
 *
 * Nothing in this file builds a Graph client, a token provider or a
 * credential: it calls the features' pure helpers and the broker client only.
 */

import { EmailMessage, ExtractedEmailData, SenderHistoryFacts } from '../../types';
import { createLogger } from '../../utils/logger';
import {
  SenderHistoryMetric,
  emitBlastRadiusMetric,
  emitSenderHistoryMetric,
} from '../../utils/metrics';
import {
  BLAST_RADIUS_MIN_BUDGET_MS,
  BlastRadiusLookupOptions,
  BlastRadiusReport,
  blastRadiusBudgetMs,
  blastRadiusMetric,
  deriveBlastRadiusKey,
  unavailableBlastRadius,
} from './blast-radius.service';
import { GraphBrokerClient } from './broker.client';
import { GRAPH_BROKER_OVERHEAD_MS, brokerBudgetMs } from './broker.protocol';
import type { GraphGateway } from './graph.gateway';
import {
  ORIGINAL_FETCH_BUDGET_MS,
  OriginalFetchOptions,
  OriginalFetchRequest,
  OriginalFetchResult,
  RetrievedOriginalSink,
  enrichWithOriginalVia,
  prepareOriginalFetch,
} from './original.fetch';
import { claimedSenderAddress, isExternalSender } from './sender.history';

const logger = createLogger('graph-broker-gateway');

const MAX_CLAIMED_DATE_LENGTH = 100;

export interface BrokerGatewaySettings {
  /** Original-message lookup is on */
  originalFetch?: boolean;
  /** Sender history's deadline when the feature is on; undefined when it is off */
  senderHistoryBudgetMs?: number;
  /** Blast radius's time budget when the feature is on; undefined when it is off */
  blastRadiusTimeBudgetMs?: number;
  /** The organization's own domains: an address on one is not an external sender */
  safeDomains: string[];
  safeSenders: string[];
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
}

export class BrokerGraphGateway implements GraphGateway {
  readonly mode = 'broker' as const;
  private readonly now: () => number;

  /** `broker` is undefined when Graph is off: then no feature is on */
  constructor(
    private readonly broker: GraphBrokerClient | undefined,
    private readonly settings: BrokerGatewaySettings
  ) {
    this.now = settings.now ?? ((): number => Date.now());
  }

  get originalFetch(): boolean {
    return this.broker !== undefined && !!this.settings.originalFetch;
  }

  get senderHistory(): boolean {
    return this.broker !== undefined && this.settings.senderHistoryBudgetMs !== undefined;
  }

  get blastRadius(): boolean {
    return this.broker !== undefined && this.settings.blastRadiusTimeBudgetMs !== undefined;
  }

  /**
   * The same pipeline step as the direct lookup (`enrichWithOriginalVia`
   * confirms the reporter's mailbox, attaches a match through the parser and
   * emits the metric); only the lookup itself is the broker's.
   */
  async enrichWithOriginalMessage(
    parser: RetrievedOriginalSink,
    msg: EmailMessage,
    emailData: ExtractedEmailData,
    safeDomains: string[]
  ): Promise<OriginalFetchResult> {
    return enrichWithOriginalVia(
      (request, options) => this.fetchOriginal(request, options),
      parser,
      msg,
      emailData,
      safeDomains
    );
  }

  private async fetchOriginal(
    request: OriginalFetchRequest,
    options: OriginalFetchOptions
  ): Promise<OriginalFetchResult> {
    if (!this.broker || !this.originalFetch) {
      return { outcome: 'skipped', reason: 'feature_off' };
    }
    // The same checks the lookup makes first, so nothing unusable is sent
    const read = prepareOriginalFetch(request);
    if ('skip' in read) {
      return read.skip;
    }
    const budgetMs = options.budgetMs ?? ORIGINAL_FETCH_BUDGET_MS;
    const call = await this.broker.call(
      'original_message_lookup',
      {
        mailbox: request.mailbox,
        claimedFrom: read.prepared.senderAddress,
        claimedSent: request.claimedSent ?? '',
        ...(read.prepared.subject ? { claimedSubject: read.prepared.subject } : {}),
        budgetMs: brokerBudgetMs(budgetMs),
      },
      budgetMs
    );
    return call.ok ? call.result : { outcome: 'error', reason: `broker_${call.failure}` };
  }

  async lookupSenderHistory(
    emailData: ExtractedEmailData
  ): Promise<SenderHistoryFacts | undefined> {
    const startedAt = this.now();
    let facts: SenderHistoryFacts | undefined;
    let metric: SenderHistoryMetric;
    try {
      const budgetMs = this.settings.senderHistoryBudgetMs;
      const address = claimedSenderAddress(emailData.forwardedHeaders?.['Original-From']);
      if (
        !this.broker ||
        budgetMs === undefined ||
        !address ||
        !isExternalSender(address, this.settings.safeDomains, this.settings.safeSenders)
      ) {
        metric = { outcome: 'skipped', durationMs: 0 };
      } else {
        const claimedDate =
          emailData.forwardedHeaders?.['Original-Date'] ??
          emailData.forwardedHeaders?.['Original-Sent'];
        const usableDate =
          typeof claimedDate === 'string' &&
          claimedDate.length > 0 &&
          claimedDate.length <= MAX_CLAIMED_DATE_LENGTH;
        const call = await this.broker.call(
          'sender_history_lookup',
          {
            senderAddress: address,
            ...(usableDate ? { claimedDate } : {}),
            budgetMs: brokerBudgetMs(budgetMs),
          },
          budgetMs
        );
        if (call.ok) {
          facts = call.result.facts;
          metric = {
            outcome: call.result.outcome,
            durationMs: 0,
            classification: facts?.classification,
            truncated: facts?.truncated,
            forbiddenRetries: call.result.forbiddenRetries,
            filterMismatch: call.result.filterMismatch,
          };
        } else {
          metric = { outcome: call.failure === 'timeout' ? 'timeout' : 'error', durationMs: 0 };
        }
      }
      metric.durationMs = Math.max(0, this.now() - startedAt);
    } catch (error) {
      // Nothing above is expected to throw; a defect here must never cost
      // the reporter their analysis
      logger.warn('Sender history skipped: unexpected failure', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      facts = undefined;
      metric = { outcome: 'error', durationMs: 0 };
    }
    emitSenderHistoryMetric(metric);
    return facts;
  }

  async lookupBlastRadius(
    emailData: ExtractedEmailData,
    options: BlastRadiusLookupOptions
  ): Promise<BlastRadiusReport> {
    const startedAt = this.now();
    let report: BlastRadiusReport;
    let errors = 0;
    let cached = false;

    try {
      const timeBudgetMs = this.settings.blastRadiusTimeBudgetMs;
      const key = deriveBlastRadiusKey(emailData, new Date(startedAt));
      // What this function may wait in all; the broker is asked for less
      const budgetMs = timeBudgetMs === undefined ? 0 : blastRadiusBudgetMs(timeBudgetMs, options);

      if (!this.broker || timeBudgetMs === undefined) {
        report = unavailableBlastRadius('error', startedAt);
      } else if (!key) {
        report = unavailableBlastRadius('no_key', startedAt);
      } else if (budgetMs < BLAST_RADIUS_MIN_BUDGET_MS + GRAPH_BROKER_OVERHEAD_MS) {
        report = unavailableBlastRadius('no_time', startedAt);
      } else {
        const call = await this.broker.call(
          'blast_radius_lookup',
          {
            key: {
              ...(key.internetMessageId ? { internetMessageId: key.internetMessageId } : {}),
              ...(key.senderAddress ? { senderAddress: key.senderAddress } : {}),
              ...(key.subject ? { subject: key.subject } : {}),
              receivedFrom: key.receivedFrom.toISOString(),
              receivedTo: key.receivedTo.toISOString(),
            },
            budgetMs: brokerBudgetMs(budgetMs),
          },
          budgetMs
        );
        if (call.ok) {
          report = call.result.report;
          errors = call.result.errors;
          cached = call.result.cached;
        } else {
          report = unavailableBlastRadius(
            call.failure === 'timeout' ? 'timeout' : 'broker',
            startedAt
          );
          errors = 1;
        }
      }
    } catch (error) {
      logger.error('Blast radius lookup failed unexpectedly', {
        error: error instanceof Error ? error.name : 'unknown',
      });
      report = unavailableBlastRadius('error', startedAt);
      errors += 1;
    }

    const metric = blastRadiusMetric(report, {
      errors,
      durationMs: this.now() - startedAt,
      cached,
    });
    emitBlastRadiusMetric(metric);
    logger.info('Blast radius lookup finished', { ...metric, matchedBy: report.matchedBy });

    return options.reporterAddress
      ? { ...report, reporterAddress: options.reporterAddress.toLowerCase() }
      : report;
  }
}

/**
 * The pipeline's one way to the three Graph features, and the two ways it
 * can be built.
 *
 * - `direct` (the default): this function makes the Graph requests itself.
 *   It holds the read credential and needs a route to Microsoft. This is the
 *   behaviour Phishy has always had, unchanged.
 * - `broker`: this function asks a second function, the Graph broker, to run
 *   one of three typed operations (`broker.gateway.ts`). It holds no Graph
 *   credential, builds no Graph client and never contacts Microsoft.
 *
 * The handler asks whether a feature is on and calls one method; which mode
 * is in use is decided here, once, from configuration. Every method keeps
 * the feature's own contract in both modes: none throws, each emits the
 * feature's metric once, and a failure leaves the pipeline exactly as it is
 * with the feature off.
 */

import { PhishyConfig } from '../../config/schema';
import { EmailMessage, ExtractedEmailData, SenderHistoryFacts } from '../../types';
import { createLogger } from '../../utils/logger';
import {
  BlastRadiusLookupOptions,
  BlastRadiusReport,
  BlastRadiusService,
  createBlastRadiusService,
  unavailableBlastRadius,
} from './blast-radius.service';
import { GraphBrokerClient, LambdaInvoker } from './broker.client';
import { BrokerGraphGateway } from './broker.gateway';
import { GraphClient } from './graph.client';
import { createGraphReadClient } from './graph.credential';
import {
  ORIGINAL_FETCH_CLIENT_OPTIONS,
  ORIGINAL_FETCH_TOKEN_OPTIONS,
  OriginalFetchResult,
  RetrievedOriginalSink,
  enrichWithOriginalMessage,
} from './original.fetch';
import { SenderHistoryService, createSenderHistoryService } from './sender.history';

const logger = createLogger('graph-gateway');

export interface GraphGateway {
  readonly mode: 'direct' | 'broker';
  /** Original-message lookup is on */
  readonly originalFetch: boolean;
  /** Sender-relationship check is on */
  readonly senderHistory: boolean;
  /** Blast radius is on */
  readonly blastRadius: boolean;

  /**
   * Before analysis: add the original's real headers to the email facts when
   * exactly one match is found in the reporter's own mailbox.
   */
  enrichWithOriginalMessage(
    parser: RetrievedOriginalSink,
    msg: EmailMessage,
    emailData: ExtractedEmailData,
    safeDomains: string[]
  ): Promise<OriginalFetchResult>;

  /** Before analysis: facts about the claimed sender's history, or undefined */
  lookupSenderHistory(emailData: ExtractedEmailData): Promise<SenderHistoryFacts | undefined>;

  /** After a malicious verdict: who else received the message */
  lookupBlastRadius(
    emailData: ExtractedEmailData,
    options: BlastRadiusLookupOptions
  ): Promise<BlastRadiusReport>;
}

/** The features as they have always run: in this function, on its own Graph clients */
export class DirectGraphGateway implements GraphGateway {
  readonly mode = 'direct' as const;

  constructor(
    private readonly parts: {
      originalFetchClient?: GraphClient;
      senderHistory?: Pick<SenderHistoryService, 'lookupForEmail'>;
      blastRadius?: Pick<BlastRadiusService, 'lookup'>;
    }
  ) {}

  get originalFetch(): boolean {
    return this.parts.originalFetchClient !== undefined;
  }

  get senderHistory(): boolean {
    return this.parts.senderHistory !== undefined;
  }

  get blastRadius(): boolean {
    return this.parts.blastRadius !== undefined;
  }

  async enrichWithOriginalMessage(
    parser: RetrievedOriginalSink,
    msg: EmailMessage,
    emailData: ExtractedEmailData,
    safeDomains: string[]
  ): Promise<OriginalFetchResult> {
    if (!this.parts.originalFetchClient) {
      return { outcome: 'skipped', reason: 'feature_off' };
    }
    return enrichWithOriginalMessage(
      this.parts.originalFetchClient,
      parser,
      msg,
      emailData,
      safeDomains
    );
  }

  async lookupSenderHistory(
    emailData: ExtractedEmailData
  ): Promise<SenderHistoryFacts | undefined> {
    return this.parts.senderHistory?.lookupForEmail(emailData);
  }

  async lookupBlastRadius(
    emailData: ExtractedEmailData,
    options: BlastRadiusLookupOptions
  ): Promise<BlastRadiusReport> {
    if (!this.parts.blastRadius) {
      return unavailableBlastRadius('error', Date.now());
    }
    return this.parts.blastRadius.lookup(emailData, options);
  }
}

function createDirectGateway(config: Pick<PhishyConfig, 'graph' | 'email'>): DirectGraphGateway {
  // Original-message lookup: read a forwarded email's real headers from the
  // reporter's own mailbox before analysis. Code-driven and read-only; the
  // client is built here but contacts nothing until the first lookup.
  let originalFetchClient: GraphClient | undefined;
  if (config.graph?.originalFetch?.enabled) {
    if (config.graph.enabled) {
      originalFetchClient = createGraphReadClient(config.graph, {
        clientOptions: ORIGINAL_FETCH_CLIENT_OPTIONS,
        tokenOptions: ORIGINAL_FETCH_TOKEN_OPTIONS,
      });
      logger.info('Original-message lookup enabled');
    } else {
      logger.warn('graph.originalFetch.enabled has no effect while graph.enabled is false');
    }
  }

  // Sender-relationship check (optional): message trace facts about the
  // claimed sender. A misconfiguration here must not stop email analysis.
  let senderHistory: SenderHistoryService | undefined;
  try {
    senderHistory = createSenderHistoryService(config);
  } catch (error) {
    logger.warn('Sender history is enabled but could not be set up', {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  return new DirectGraphGateway({
    originalFetchClient,
    senderHistory,
    // Who-else-received-it lookup for malicious verdicts (off by default)
    blastRadius: createBlastRadiusService(config.graph),
  });
}

function createBrokerGateway(
  config: Pick<PhishyConfig, 'graph' | 'email'>,
  lambda?: LambdaInvoker
): BrokerGraphGateway {
  const graph = config.graph;
  const functionName = graph?.brokerFunctionName;
  if (!graph?.enabled || !functionName) {
    // Nothing is on (the schema requires the name when Graph is enabled)
    for (const feature of ['originalFetch', 'senderHistory', 'blastRadius'] as const) {
      if (graph?.[feature]?.enabled) {
        logger.warn(`graph.${feature}.enabled has no effect while graph.enabled is false`);
      }
    }
    return new BrokerGraphGateway(undefined, {
      safeDomains: config.email.safeDomains,
      safeSenders: config.email.safeSenders,
    });
  }

  const gateway = new BrokerGraphGateway(new GraphBrokerClient({ functionName, lambda }), {
    originalFetch: !!graph.originalFetch?.enabled,
    senderHistoryBudgetMs: graph.senderHistory?.enabled ? graph.senderHistory.budgetMs : undefined,
    blastRadiusTimeBudgetMs: graph.blastRadius?.enabled
      ? graph.blastRadius.timeBudgetMs
      : undefined,
    safeDomains: config.email.safeDomains,
    safeSenders: config.email.safeSenders,
  });
  logger.info(
    'Graph features go through the Graph broker; this function holds no Graph credential',
    {
      originalFetch: gateway.originalFetch,
      senderHistory: gateway.senderHistory,
      blastRadius: gateway.blastRadius,
    }
  );
  return gateway;
}

export interface GraphGatewayDeps {
  /** Injected for tests (broker mode only) */
  lambda?: LambdaInvoker;
}

/**
 * Build the gateway the configuration asks for. In `broker` mode nothing
 * here, or reachable from here, constructs a Graph client or a token
 * provider: the direct branch is simply not taken.
 */
export function createGraphGateway(
  config: Pick<PhishyConfig, 'graph' | 'email'>,
  deps: GraphGatewayDeps = {}
): GraphGateway {
  return config.graph?.mode === 'broker'
    ? createBrokerGateway(config, deps.lambda)
    : createDirectGateway(config);
}

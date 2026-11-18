/**
 * The main function's side of the Graph broker: one typed, bounded,
 * validated Lambda invocation per operation.
 *
 * This is the only code in the main function that reaches the broker, and
 * the broker is the only thing in broker mode that reaches Microsoft. The
 * file imports the wire format and the AWS Lambda client; it imports nothing
 * that can build a Graph client, a token provider or a credential.
 *
 * - **Synchronous invocation** (`RequestResponse`) of one named function.
 * - **Bounded in time.** The caller gives the time it will wait (the
 *   feature's own budget); when that passes the request is aborted and the
 *   call reports `timeout`, whatever the SDK is doing. There are no SDK
 *   retries: a second attempt would not fit a budget and would repeat Graph
 *   work.
 * - **The answer is hostile data.** It is size-checked before it is parsed,
 *   then validated against the envelope and against the result schema of the
 *   operation that was asked for. Anything else is `malformed`.
 * - **Never throws.** Every failure is a typed outcome, so each feature can
 *   map it onto what it already does when Graph fails.
 *
 * Logs carry the operation, the outcome, a duration and AWS's error name:
 * never a parameter or any part of a response.
 */

import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { createLogger } from '../../utils/logger';
import { GraphBrokerCallOutcome, emitGraphBrokerCallMetric } from '../../utils/metrics';
import {
  GRAPH_BROKER_MAX_RESPONSE_BYTES,
  GRAPH_BROKER_RESULT_SCHEMAS,
  GRAPH_BROKER_VERSION,
  GraphBrokerOperation,
  GraphBrokerParams,
  GraphBrokerRefusal,
  GraphBrokerRequestSchema,
  GraphBrokerResponseSchema,
  GraphBrokerResult,
} from './broker.protocol';

const logger = createLogger('graph-broker-client');

/** Time allowed to open the connection to the Lambda API (or its VPC endpoint) */
const CONNECTION_TIMEOUT_MS = 3000;

export type GraphBrokerCallFailure = Exclude<GraphBrokerCallOutcome, 'ok'>;

export type GraphBrokerCallResult<Op extends GraphBrokerOperation> =
  | { ok: true; result: GraphBrokerResult<Op> }
  | { ok: false; failure: GraphBrokerCallFailure; refusal?: GraphBrokerRefusal };

/** The one Lambda capability this needs; `LambdaClient` provides it */
export type LambdaInvoker = Pick<LambdaClient, 'send'>;

export interface GraphBrokerClientOptions {
  /** Name or ARN of the broker function */
  functionName: string;
  /** Injected for tests; by default a client is created on the first call */
  lambda?: LambdaInvoker;
  /** Injected for tests; defaults to `Date.now` */
  now?: () => number;
}

class CallTimeoutError extends Error {}

function isThrottle(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
  return error.name === 'TooManyRequestsException' || status === 429;
}

export class GraphBrokerClient {
  private readonly functionName: string;
  private readonly now: () => number;
  private lambda?: LambdaInvoker;

  constructor(options: GraphBrokerClientOptions) {
    this.functionName = options.functionName;
    this.lambda = options.lambda;
    this.now = options.now ?? ((): number => Date.now());
  }

  /**
   * Ask the broker to run one operation and wait at most `timeoutMs` for a
   * validated answer.
   */
  async call<Op extends GraphBrokerOperation>(
    operation: Op,
    params: GraphBrokerParams<Op>,
    timeoutMs: number
  ): Promise<GraphBrokerCallResult<Op>> {
    const startedAt = this.now();
    let detail: Record<string, unknown> = {};
    let outcome: GraphBrokerCallResult<Op>;
    try {
      outcome = await this.invoke(operation, params, timeoutMs);
    } catch (error) {
      const failure: GraphBrokerCallFailure =
        error instanceof CallTimeoutError
          ? 'timeout'
          : isThrottle(error)
            ? 'throttled'
            : 'invoke_error';
      detail = { error: error instanceof Error ? error.name : 'unknown' };
      outcome = { ok: false, failure };
    }

    const durationMs = Math.max(0, this.now() - startedAt);
    const result: GraphBrokerCallOutcome = outcome.ok ? 'ok' : outcome.failure;
    emitGraphBrokerCallMetric(operation, result, durationMs);
    if (!outcome.ok) {
      logger.warn('Graph broker call did not produce a result', {
        operation,
        outcome: result,
        refusal: outcome.refusal,
        durationMs,
        ...detail,
      });
    }
    return outcome;
  }

  private async invoke<Op extends GraphBrokerOperation>(
    operation: Op,
    params: GraphBrokerParams<Op>,
    timeoutMs: number
  ): Promise<GraphBrokerCallResult<Op>> {
    // The same schema the broker applies: nothing it would refuse is sent
    const request = GraphBrokerRequestSchema.safeParse({
      version: GRAPH_BROKER_VERSION,
      operation,
      params,
    });
    if (!request.success) {
      return { ok: false, failure: 'invalid_request' };
    }

    const response = await this.send(Buffer.from(JSON.stringify(request.data)), timeoutMs);
    if (response.FunctionError !== undefined) {
      // The payload is then an error object from the runtime: not read
      return { ok: false, failure: 'function_error' };
    }
    const payload = response.Payload;
    if (payload === undefined || payload.byteLength === 0) {
      return { ok: false, failure: 'malformed' };
    }
    if (payload.byteLength > GRAPH_BROKER_MAX_RESPONSE_BYTES[operation]) {
      return { ok: false, failure: 'oversized' };
    }

    let body: unknown;
    try {
      body = JSON.parse(Buffer.from(payload).toString('utf8'));
    } catch {
      return { ok: false, failure: 'malformed' };
    }
    const envelope = GraphBrokerResponseSchema.safeParse(body);
    if (!envelope.success) {
      return { ok: false, failure: 'malformed' };
    }
    if (!envelope.data.ok) {
      return { ok: false, failure: 'refused', refusal: envelope.data.reason };
    }
    const result = GRAPH_BROKER_RESULT_SCHEMAS[operation].safeParse(envelope.data.result);
    if (!result.success) {
      return { ok: false, failure: 'malformed' };
    }
    return { ok: true, result: result.data as GraphBrokerResult<Op> };
  }

  /** One `Invoke`, abandoned (and aborted) when `timeoutMs` has passed */
  private async send(
    payload: Buffer,
    timeoutMs: number
  ): Promise<{ FunctionError?: string; Payload?: Uint8Array }> {
    this.lambda ??= new LambdaClient({
      maxAttempts: 1,
      requestHandler: { connectionTimeout: CONNECTION_TIMEOUT_MS },
    });
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => {
          controller.abort();
          reject(new CallTimeoutError());
        },
        Math.max(1, timeoutMs)
      );
    });
    const sent = this.lambda.send(
      new InvokeCommand({
        FunctionName: this.functionName,
        InvocationType: 'RequestResponse',
        Payload: payload,
      }),
      { abortSignal: controller.signal }
    );
    // The timer wins even if the SDK ignores the abort
    sent.catch(() => undefined);
    try {
      return await Promise.race([sent, timedOut]);
    } finally {
      clearTimeout(timer);
    }
  }
}

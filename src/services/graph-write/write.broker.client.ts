/**
 * The main function's side of the Graph write broker: one typed, bounded,
 * validated Lambda invocation of `remove_messages`.
 *
 * This file imports the wire format and the AWS Lambda client and nothing
 * that can build a Graph client, a token provider or a credential: the main
 * function never holds the write credential. Mirrors `broker.client.ts`.
 *
 * - **Synchronous invocation** (`RequestResponse`) of one named function,
 *   with no SDK retries: a second attempt could repeat a move.
 * - **Bounded in time.** When `timeoutMs` passes the call is abandoned and
 *   reports `timeout`. The write broker may still be working; the caller
 *   must then treat every message in the request as `unknown`.
 * - **The answer is hostile data.** Size-checked before it is parsed, then
 *   validated against the envelope and the result schema. Anything else is
 *   `malformed`.
 * - **Never throws.**
 *
 * Logs carry the outcome, the refusal word, a duration and AWS's error
 * name: never a parameter or any part of the response.
 */

import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { createLogger } from '../../utils/logger';
import { GraphBrokerCallOutcome, emitGraphBrokerCallMetric } from '../../utils/metrics';
import {
  GRAPH_WRITE_MAX_RESPONSE_BYTES,
  GRAPH_WRITE_VERSION,
  GraphWriteRefusal,
  GraphWriteRequestSchema,
  GraphWriteResponseSchema,
  RemoveMessagesParams,
  RemoveMessagesResult,
  RemoveMessagesResultSchema,
} from './write.protocol';

const logger = createLogger('graph-write-broker-client');

const CONNECTION_TIMEOUT_MS = 3000;

export type GraphWriteCallFailure = Exclude<GraphBrokerCallOutcome, 'ok'>;

export type GraphWriteCallResult =
  | { ok: true; result: RemoveMessagesResult }
  | { ok: false; failure: GraphWriteCallFailure; refusal?: GraphWriteRefusal };

export type LambdaInvoker = Pick<LambdaClient, 'send'>;

export interface GraphWriteBrokerClientOptions {
  /** Name or ARN of the write broker function */
  functionName: string;
  /** Injected for tests; by default a client is created on the first call */
  lambda?: LambdaInvoker;
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

/**
 * Lambda API errors raised before the function runs at all: the caller may
 * not invoke it, it does not exist, or the request itself was refused. The
 * write broker certainly did nothing. Listed by name; anything else is
 * `invoke_error`, whose effect is unknown.
 * https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html#API_Invoke_Errors
 */
const PRE_EXECUTION_ERRORS = new Set([
  'AccessDeniedException',
  'ResourceNotFoundException',
  'InvalidParameterValueException',
  'InvalidRequestContentException',
  'RequestTooLargeException',
  'ResourceConflictException',
  'ResourceNotReadyException',
  'UnsupportedMediaTypeException',
]);

function isPreExecution(error: unknown): boolean {
  return error instanceof Error && PRE_EXECUTION_ERRORS.has(error.name);
}

/**
 * Failures after which the write broker certainly did nothing: the request
 * was never sent, Lambda refused or rejected the invocation before running
 * it, or the broker answered with a refusal it gives before any Graph
 * request (`invalid_request`, `write_disabled`, `misconfigured`). A refusal
 * of `internal_error` can follow work already done, so it is not one of
 * them; neither is a timeout, a crash, an unexpected invoke error or an
 * unusable answer. For those the broker may have moved some messages.
 */
export function failureChangedNothing(
  failure: GraphWriteCallFailure,
  refusal?: GraphWriteRefusal
): boolean {
  if (failure === 'refused') {
    return refusal !== undefined && refusal !== 'internal_error';
  }
  return failure === 'invalid_request' || failure === 'throttled' || failure === 'invoke_rejected';
}

export class GraphWriteBrokerClient {
  private readonly functionName: string;
  private readonly now: () => number;
  private lambda?: LambdaInvoker;

  constructor(options: GraphWriteBrokerClientOptions) {
    this.functionName = options.functionName;
    this.lambda = options.lambda;
    this.now = options.now ?? ((): number => Date.now());
  }

  async removeMessages(
    params: RemoveMessagesParams,
    timeoutMs: number
  ): Promise<GraphWriteCallResult> {
    const startedAt = this.now();
    let detail: Record<string, unknown> = {};
    let outcome: GraphWriteCallResult;
    try {
      outcome = await this.invoke(params, timeoutMs);
    } catch (error) {
      const failure: GraphWriteCallFailure =
        error instanceof CallTimeoutError
          ? 'timeout'
          : isThrottle(error)
            ? 'throttled'
            : isPreExecution(error)
              ? 'invoke_rejected'
              : 'invoke_error';
      detail = { error: error instanceof Error ? error.name : 'unknown' };
      outcome = { ok: false, failure };
    }
    const durationMs = Math.max(0, this.now() - startedAt);
    emitGraphBrokerCallMetric('remove_messages', outcome.ok ? 'ok' : outcome.failure, durationMs);
    if (!outcome.ok) {
      logger.warn('Graph write broker call did not produce a result', {
        outcome: outcome.failure,
        refusal: outcome.refusal,
        durationMs,
        ...detail,
      });
    }
    return outcome;
  }

  private async invoke(
    params: RemoveMessagesParams,
    timeoutMs: number
  ): Promise<GraphWriteCallResult> {
    // The same schema the write broker applies: nothing it would refuse is sent
    const request = GraphWriteRequestSchema.safeParse({
      version: GRAPH_WRITE_VERSION,
      operation: 'remove_messages',
      params,
    });
    if (!request.success) {
      return { ok: false, failure: 'invalid_request' };
    }
    const response = await this.send(Buffer.from(JSON.stringify(request.data)), timeoutMs);
    if (response.FunctionError !== undefined) {
      return { ok: false, failure: 'function_error' };
    }
    const payload = response.Payload;
    if (payload === undefined || payload.byteLength === 0) {
      return { ok: false, failure: 'malformed' };
    }
    if (payload.byteLength > GRAPH_WRITE_MAX_RESPONSE_BYTES) {
      return { ok: false, failure: 'oversized' };
    }
    let body: unknown;
    try {
      body = JSON.parse(Buffer.from(payload).toString('utf8'));
    } catch {
      return { ok: false, failure: 'malformed' };
    }
    const envelope = GraphWriteResponseSchema.safeParse(body);
    if (!envelope.success) {
      return { ok: false, failure: 'malformed' };
    }
    if (!envelope.data.ok) {
      return { ok: false, failure: 'refused', refusal: envelope.data.reason };
    }
    const result = RemoveMessagesResultSchema.safeParse(envelope.data.result);
    if (!result.success) {
      return { ok: false, failure: 'malformed' };
    }
    return { ok: true, result: result.data };
  }

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
    sent.catch(() => undefined);
    try {
      return await Promise.race([sent, timedOut]);
    } finally {
      clearTimeout(timer);
    }
  }
}

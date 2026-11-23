/**
 * The main function's write broker client: one bounded, validated Lambda
 * invocation. Lambda is mocked; nothing is invoked. Invented data only.
 */

import { InvokeCommand } from '@aws-sdk/client-lambda';
import {
  GraphWriteBrokerClient,
  LambdaInvoker,
  failureChangedNothing,
} from '../../../../src/services/graph-write/write.broker.client';
import { GRAPH_WRITE_MAX_RESPONSE_BYTES } from '../../../../src/services/graph-write/write.protocol';
import * as metrics from '../../../../src/utils/metrics';
import { ACTION_ID, IMID, MAILBOX_ID } from '../../../mocks/graph.write.fake';

type SendArgs = [InvokeCommand, { abortSignal?: AbortSignal }?];

const PARAMS = {
  actionId: ACTION_ID,
  mailboxes: [
    { mailboxId: MAILBOX_ID(1), messageIds: ['AAMkAG-1'], expectedInternetMessageIds: [IMID(1)] },
  ],
  budgetMs: 30_000,
};
const RESULT = {
  mailboxes: [
    { mailboxId: MAILBOX_ID(1), messages: [{ messageId: 'AAMkAG-1', outcome: 'moved' }] },
  ],
  bounds: {
    maxMailboxes: 50,
    maxMessagesPerMailbox: 5,
    maxMessages: 100,
    budgetMs: 29000,
    concurrency: 4,
  },
  durationMs: 40,
};

function answering(payload: unknown, extra: Record<string, unknown> = {}) {
  return jest.fn<Promise<unknown>, SendArgs>(() =>
    Promise.resolve({
      StatusCode: 200,
      Payload: Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)),
      ...extra,
    })
  );
}

function client(send: jest.Mock): GraphWriteBrokerClient {
  return new GraphWriteBrokerClient({
    functionName: 'phishy-graph-write-broker',
    lambda: { send } as unknown as LambdaInvoker,
  });
}

describe('GraphWriteBrokerClient', () => {
  let metric: jest.SpyInstance;
  beforeEach(() => {
    metric = jest.spyOn(metrics, 'emitGraphBrokerCallMetric').mockImplementation(() => undefined);
  });

  it('invokes the named function synchronously with the versioned request', async () => {
    const send = answering({ ok: true, result: RESULT });
    const result = await client(send).removeMessages(PARAMS, 35_000);
    expect(result).toEqual({ ok: true, result: RESULT });
    const [command] = send.mock.calls[0] as SendArgs;
    expect(command.input.FunctionName).toBe('phishy-graph-write-broker');
    expect(command.input.InvocationType).toBe('RequestResponse');
    expect(JSON.parse(Buffer.from(command.input.Payload as Uint8Array).toString('utf8'))).toEqual({
      version: 1,
      operation: 'remove_messages',
      params: PARAMS,
    });
    expect(metric).toHaveBeenCalledWith('remove_messages', 'ok', expect.any(Number));
  });

  it('does not send a request the write broker would refuse', async () => {
    const send = answering({ ok: true, result: RESULT });
    const result = await client(send).removeMessages({ ...PARAMS, budgetMs: 999_999 }, 1000);
    expect(result).toEqual({ ok: false, failure: 'invalid_request' });
    expect(send).not.toHaveBeenCalled();
  });

  it.each([
    [
      'a refusal',
      answering({ ok: false, reason: 'write_disabled' }),
      { failure: 'refused', refusal: 'write_disabled' },
    ],
    [
      'a function error',
      answering('{}', { FunctionError: 'Unhandled' }),
      { failure: 'function_error' },
    ],
    ['an empty payload', answering(''), { failure: 'malformed' }],
    ['not JSON', answering('not json'), { failure: 'malformed' }],
    ['a bad envelope', answering({ ok: 'yes' }), { failure: 'malformed' }],
    [
      'a bad result',
      answering({ ok: true, result: { ...RESULT, extra: 1 } }),
      { failure: 'malformed' },
    ],
    [
      'an oversized answer',
      answering('x'.repeat(GRAPH_WRITE_MAX_RESPONSE_BYTES + 1)),
      { failure: 'oversized' },
    ],
  ])('maps %s to a typed failure', async (_label, send, expected) => {
    expect(await client(send).removeMessages(PARAMS, 5000)).toEqual({ ok: false, ...expected });
  });

  it('reports a throttled invoke and an invoke error', async () => {
    const throttled = Object.assign(new Error('rate'), { name: 'TooManyRequestsException' });
    const send1 = jest.fn(() => Promise.reject(throttled));
    expect(await client(send1).removeMessages(PARAMS, 5000)).toEqual({
      ok: false,
      failure: 'throttled',
    });
    const send2 = jest.fn(() => Promise.reject(new Error('network')));
    expect(await client(send2).removeMessages(PARAMS, 5000)).toEqual({
      ok: false,
      failure: 'invoke_error',
    });
  });

  it('stops waiting at its timeout', async () => {
    const send = jest.fn(() => new Promise(() => undefined));
    expect(await client(send).removeMessages(PARAMS, 5)).toEqual({ ok: false, failure: 'timeout' });
  });

  it('knows which failures certainly changed nothing', () => {
    expect(failureChangedNothing('refused')).toBe(true);
    expect(failureChangedNothing('invalid_request')).toBe(true);
    expect(failureChangedNothing('throttled')).toBe(true);
    for (const failure of [
      'timeout',
      'invoke_error',
      'function_error',
      'malformed',
      'oversized',
    ] as const) {
      expect(failureChangedNothing(failure)).toBe(false);
    }
  });
});

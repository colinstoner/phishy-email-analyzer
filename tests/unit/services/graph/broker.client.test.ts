/**
 * The main function's Graph broker client: one bounded, validated Lambda
 * invocation, with every failure a typed outcome and a metric. The Lambda
 * API is mocked; nothing is invoked. Invented data only.
 */

import { InvokeCommand } from '@aws-sdk/client-lambda';
import { GraphBrokerClient, LambdaInvoker } from '../../../../src/services/graph/broker.client';
import { GRAPH_BROKER_MAX_RESPONSE_BYTES } from '../../../../src/services/graph/broker.protocol';
import * as metrics from '../../../../src/utils/metrics';

const FUNCTION = 'phishy-graph-broker';
const PARAMS = {
  mailbox: 'reporter@example.com',
  claimedFrom: 'billing-alerts@example.org',
  claimedSent: 'Monday, November 16, 2026 8:00 AM',
  claimedSubject: 'Invoice 7731 overdue',
  budgetMs: 7000,
};
const NOT_FOUND = { ok: true, result: { outcome: 'not_found', reason: 'no_candidate' } };

type SendArgs = [InvokeCommand, { abortSignal?: AbortSignal }?];
type Send = jest.Mock<Promise<unknown>, SendArgs>;

function mockSend(implementation: (...args: SendArgs) => Promise<unknown>): Send {
  return jest.fn<Promise<unknown>, SendArgs>(implementation);
}

function answering(body: unknown): Send {
  return mockSend(() =>
    Promise.resolve({ StatusCode: 200, Payload: Buffer.from(JSON.stringify(body)) })
  );
}

function client(send: Send): GraphBrokerClient {
  return new GraphBrokerClient({
    functionName: FUNCTION,
    lambda: { send } as unknown as LambdaInvoker,
  });
}

describe('GraphBrokerClient', () => {
  let metricSpy: jest.SpyInstance;

  beforeEach(() => {
    metricSpy = jest
      .spyOn(metrics, 'emitGraphBrokerCallMetric')
      .mockImplementation(() => undefined);
  });

  const lastMetric = (): unknown[] => metricSpy.mock.calls[metricSpy.mock.calls.length - 1];

  it('invokes the named function synchronously with the versioned request', async () => {
    const send = answering(NOT_FOUND);
    const result = await client(send).call('original_message_lookup', PARAMS, 8000);

    expect(result).toEqual({ ok: true, result: { outcome: 'not_found', reason: 'no_candidate' } });
    expect(send).toHaveBeenCalledTimes(1);
    const [command, options] = send.mock.calls[0];
    expect(command).toBeInstanceOf(InvokeCommand);
    expect(command.input.FunctionName).toBe(FUNCTION);
    expect(command.input.InvocationType).toBe('RequestResponse');
    expect(JSON.parse(Buffer.from(command.input.Payload as Uint8Array).toString('utf8'))).toEqual({
      version: 1,
      operation: 'original_message_lookup',
      params: PARAMS,
    });
    expect(options?.abortSignal).toBeInstanceOf(AbortSignal);
    expect(lastMetric().slice(0, 2)).toEqual(['original_message_lookup', 'ok']);
  });

  it('does not send a request the broker would refuse', async () => {
    const send = answering(NOT_FOUND);
    const result = await client(send).call(
      'original_message_lookup',
      { ...PARAMS, claimedSubject: 'x'.repeat(300) },
      8000
    );

    expect(result).toEqual({ ok: false, failure: 'invalid_request' });
    expect(send).not.toHaveBeenCalled();
    expect(lastMetric()[1]).toBe('invalid_request');
  });

  it('stops waiting at the timeout and aborts the request', async () => {
    let signal: AbortSignal | undefined;
    const send = mockSend((_command, options) => {
      signal = options?.abortSignal;
      return new Promise(() => undefined); // never answers
    });

    const started = Date.now();
    const result = await client(send).call('original_message_lookup', PARAMS, 40);

    expect(result).toEqual({ ok: false, failure: 'timeout' });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(signal?.aborted).toBe(true);
    expect(lastMetric()[1]).toBe('timeout');
  });

  it('reports a Lambda throttle as throttled', async () => {
    const byName = Object.assign(new Error('Rate Exceeded.'), { name: 'TooManyRequestsException' });
    const byStatus = Object.assign(new Error('slow down'), { $metadata: { httpStatusCode: 429 } });
    for (const error of [byName, byStatus]) {
      const send = mockSend(() => Promise.reject(error));
      expect(await client(send).call('original_message_lookup', PARAMS, 8000)).toEqual({
        ok: false,
        failure: 'throttled',
      });
      expect(lastMetric()[1]).toBe('throttled');
    }
  });

  it('reports any other Invoke failure as invoke_error', async () => {
    for (const error of [
      Object.assign(new Error('not authorized'), { name: 'AccessDeniedException' }),
      Object.assign(new Error('no such function'), { name: 'ResourceNotFoundException' }),
      'a string, not an Error',
    ]) {
      const send = mockSend(() => Promise.reject(error));
      expect(await client(send).call('original_message_lookup', PARAMS, 8000)).toEqual({
        ok: false,
        failure: 'invoke_error',
      });
    }
    expect(lastMetric()[1]).toBe('invoke_error');
  });

  it('does not read the payload of a crashed or timed-out broker', async () => {
    const send = mockSend(() =>
      Promise.resolve({
        StatusCode: 200,
        FunctionError: 'Unhandled',
        // Shaped like a good answer on purpose: it must not be used
        Payload: Buffer.from(JSON.stringify(NOT_FOUND)),
      })
    );
    expect(await client(send).call('original_message_lookup', PARAMS, 8000)).toEqual({
      ok: false,
      failure: 'function_error',
    });
    expect(lastMetric()[1]).toBe('function_error');
  });

  it('refuses an oversized response before parsing it', async () => {
    const parse = jest.spyOn(JSON, 'parse');
    const oversized = Buffer.alloc(GRAPH_BROKER_MAX_RESPONSE_BYTES.sender_history_lookup + 1, 0x20);
    const send = mockSend(() => Promise.resolve({ StatusCode: 200, Payload: oversized }));

    const result = await client(send).call(
      'sender_history_lookup',
      { senderAddress: 'pat@supplier.example.net', budgetMs: 7000 },
      8000
    );

    expect(result).toEqual({ ok: false, failure: 'oversized' });
    expect(parse).not.toHaveBeenCalled();
    expect(lastMetric().slice(0, 2)).toEqual(['sender_history_lookup', 'oversized']);
  });

  it.each([
    ['no payload', undefined],
    ['an empty payload', Buffer.alloc(0)],
    ['text that is not JSON', Buffer.from('<html>502 Bad Gateway</html>')],
    ['JSON that is not an envelope', Buffer.from(JSON.stringify({ statusCode: 200, body: '{}' }))],
    ['an envelope with extra fields', Buffer.from(JSON.stringify({ ...NOT_FOUND, debug: 'x' }))],
    [
      'a result for another operation',
      Buffer.from(
        JSON.stringify({
          ok: true,
          result: { outcome: 'timeout', forbiddenRetries: 0, filterMismatch: false },
        })
      ),
    ],
    [
      'a result with a field the schema does not know',
      Buffer.from(
        JSON.stringify({
          ok: true,
          result: { outcome: 'not_found', reason: 'no_candidate', body: 'raw message text' },
        })
      ),
    ],
    ['an unknown refusal', Buffer.from(JSON.stringify({ ok: false, reason: 'made_up' }))],
  ])('treats %s as malformed', async (_name, payload) => {
    const send = mockSend(() => Promise.resolve({ StatusCode: 200, Payload: payload }));
    expect(await client(send).call('original_message_lookup', PARAMS, 8000)).toEqual({
      ok: false,
      failure: 'malformed',
    });
    expect(lastMetric()[1]).toBe('malformed');
  });

  it('passes on a refusal with the broker’s fixed reason', async () => {
    const send = answering({ ok: false, reason: 'feature_disabled' });
    expect(await client(send).call('original_message_lookup', PARAMS, 8000)).toEqual({
      ok: false,
      failure: 'refused',
      refusal: 'feature_disabled',
    });
    expect(lastMetric()[1]).toBe('refused');
  });

  it('logs the outcome and AWS’s error name, never a parameter or the error text', async () => {
    const lines: string[] = [];
    jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    });
    jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    });
    const send = mockSend(() =>
      Promise.reject(
        Object.assign(new Error(`could not invoke for ${PARAMS.mailbox}`), {
          name: 'ServiceException',
        })
      )
    );

    await client(send).call('original_message_lookup', PARAMS, 8000);

    const output = lines.join('\n');
    for (const hostile of [
      PARAMS.mailbox,
      PARAMS.claimedFrom,
      PARAMS.claimedSubject,
      'could not',
    ]) {
      expect(output).not.toContain(hostile);
    }
  });

  it('emits one metric line per call, by operation and outcome', async () => {
    metricSpy.mockRestore();
    const saved = process.env.PHISHY_DISABLE_METRICS;
    delete process.env.PHISHY_DISABLE_METRICS;
    const stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await client(answering(NOT_FOUND)).call('original_message_lookup', PARAMS, 8000);
    } finally {
      process.env.PHISHY_DISABLE_METRICS = saved;
    }

    const lines = stdout.mock.calls
      .map(call => String(call[0]))
      .filter(line => line.includes('GraphBrokerCalls'));
    expect(lines).toHaveLength(1);
    const emf = JSON.parse(lines[0]) as Record<string, unknown> & {
      _aws: { CloudWatchMetrics: Array<{ Namespace: string; Dimensions: string[][] }> };
    };
    expect(emf._aws.CloudWatchMetrics[0].Namespace).toBe('Phishy');
    expect(emf._aws.CloudWatchMetrics[0].Dimensions).toEqual([['Operation', 'Outcome']]);
    expect(emf.Operation).toBe('original_message_lookup');
    expect(emf.Outcome).toBe('ok');
    expect(emf.GraphBrokerCalls).toBe(1);
  });
});

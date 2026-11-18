/**
 * The entry points the Graph broker uses on the existing feature services:
 * the same lookups, keyed by typed inputs instead of a parsed email, with a
 * caller-supplied budget and without emitting the feature metric (the main
 * function emits it). A real GraphClient over a mocked fetch; no network.
 * Invented data only.
 */

import {
  BlastRadiusService,
  SenderHistoryService,
  blastRadiusBudgetMs,
  deriveBlastRadiusKey,
  prepareOriginalFetch,
} from '../../../../src/services/graph';
import { ExtractedEmailData } from '../../../../src/types';
import * as metrics from '../../../../src/utils/metrics';
import { collection, fakeGraph } from '../../../mocks/graph.fake';

const NOW = Date.parse('2026-11-17T12:00:00Z');
const SENDER = 'pat@supplier.example.net';
const SETTINGS = {
  lookbackDays: 30,
  burstWindowHours: 24,
  budgetMs: 8000,
  fanoutMinRecipients: 15,
  fanoutMultiplier: 3,
  safeDomains: [],
  safeSenders: [],
};

function email(): ExtractedEmailData {
  return {
    from_email: 'alice@example.com',
    subject: 'FW: RFQ 1001',
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: {
      'Original-From': `Pat Doe <${SENDER}>`,
      'Original-Subject': 'RFQ 1001',
      'Original-Date': 'Mon, 16 Nov 2026 08:00:00 +0000',
    },
    attachments: [],
    sender: 'alice@example.com',
    to: 'phishy@example.com',
    original_sender: 'alice@example.com',
    originalForwarder: 'alice@example.com',
    links: [],
  };
}

describe('SenderHistoryService.lookupSender', () => {
  it('returns the facts and the metric line without emitting it', async () => {
    const emit = jest.spyOn(metrics, 'emitSenderHistoryMetric').mockImplementation(() => undefined);
    const graph = fakeGraph([() => collection([])]);
    const service = new SenderHistoryService(graph.client, SETTINGS, { now: () => NOW });

    const result = await service.lookupSender(() => ({
      claimedFrom: SENDER,
      claimedDate: undefined,
    }));

    expect(result.facts?.classification).toBe('no_history');
    expect(result.metric).toMatchObject({ outcome: 'ok', classification: 'no_history' });
    expect(emit).not.toHaveBeenCalled();

    // lookupForEmail is the same lookup plus the metric
    await service.lookupForEmail(email());
    expect(emit).toHaveBeenCalledTimes(1);
    expect(emit.mock.calls[0][0]).toMatchObject({ outcome: 'cache_hit' });
  });

  it('keeps to a caller’s budget when it is tighter than the configured one', async () => {
    const hanging = jest.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        })
    );
    const { GraphClient } = await import('../../../../src/services/graph');
    const client = new GraphClient({
      tokenProvider: {
        label: 'read',
        getToken: () => Promise.resolve('t'),
        invalidate: () => undefined,
      },
      fetchImpl: hanging as unknown as typeof fetch,
      maxAttempts: 1,
    });
    const service = new SenderHistoryService(client, SETTINGS);

    const started = Date.now();
    const result = await service.lookupSender(() => ({
      claimedFrom: SENDER,
      claimedDate: undefined,
      budgetMs: 40,
    }));

    expect(Date.now() - started).toBeLessThan(3000);
    expect(result.facts).toBeUndefined();
    expect(result.metric.outcome).toBe('timeout');
  });

  it('reports a defect in reading the inputs as an error, not an exception', async () => {
    const service = new SenderHistoryService(fakeGraph([]).client, SETTINGS);
    const result = await service.lookupSender(() => {
      throw new Error('defect');
    });
    expect(result).toEqual({ metric: { outcome: 'error', durationMs: 0 } });
  });
});

describe('BlastRadiusService.lookupByKey', () => {
  const service = (): { blast: BlastRadiusService; requests: number } => {
    const graph = fakeGraph([() => collection([])]);
    const blast = new BlastRadiusService({ client: graph.client, now: () => NOW, concurrency: 2 });
    return {
      blast,
      get requests(): number {
        return graph.requests.length;
      },
    };
  };

  it('runs the same lookup as `lookup` for the key that email derives, without emitting the metric', async () => {
    const emit = jest.spyOn(metrics, 'emitBlastRadiusMetric').mockImplementation(() => undefined);
    const key = deriveBlastRadiusKey(email(), new Date(NOW));
    expect(key).toBeDefined();

    const byKey = await service().blast.lookupByKey(key!);
    expect(emit).not.toHaveBeenCalled();

    const byEmail = await service().blast.lookup(email());
    expect(emit).toHaveBeenCalledTimes(1);
    expect(byKey.report).toEqual(byEmail);
    expect(byKey.metric).toEqual(emit.mock.calls[0][0]);
  });

  it('does not start with less time than a lookup needs', async () => {
    const tenant = service();
    const key = deriveBlastRadiusKey(email(), new Date(NOW))!;

    const { report, metric } = await tenant.blast.lookupByKey(key, { budgetMs: 1500 });

    expect(report.status).toBe('unavailable');
    expect(report.note).toContain('not enough processing time remained');
    expect(metric).toMatchObject({ route: 'none', outcome: 'unavailable' });
    expect(tenant.requests).toBe(0);
  });
});

describe('blastRadiusBudgetMs', () => {
  it('is the smallest of the configured budget, the caller’s budget and the time left less the send reserve', () => {
    expect(blastRadiusBudgetMs(45_000, {})).toBe(45_000);
    expect(blastRadiusBudgetMs(45_000, { remainingMs: 170_000 })).toBe(45_000);
    expect(blastRadiusBudgetMs(45_000, { remainingMs: 50_000 })).toBe(30_000);
    expect(blastRadiusBudgetMs(45_000, { budgetMs: 12_000 })).toBe(12_000);
    expect(blastRadiusBudgetMs(45_000, { budgetMs: 44_000, remainingMs: 30_000 })).toBe(10_000);
  });
});

describe('prepareOriginalFetch', () => {
  it('reads the bare address, the time and the subject', () => {
    const read = prepareOriginalFetch({
      claimedFrom: 'Billing <Billing-Alerts@example.org>',
      claimedSent: 'Mon, 16 Nov 2026 08:00:00 +0000',
      claimedSubject: '  Invoice 7731 overdue ',
    });
    expect(read).toEqual({
      prepared: {
        // In its original letter case, as the lookup has always sent it
        senderAddress: 'Billing-Alerts@example.org',
        claimedTime: { instant: new Date('2026-11-16T08:00:00Z'), zoneKnown: true },
        subject: 'Invoice 7731 overdue',
      },
    });
  });

  it.each([
    [
      { claimedFrom: 'Billing', claimedSent: 'Mon, 16 Nov 2026 08:00:00 +0000' },
      'no_claimed_sender',
    ],
    [{ claimedFrom: 'a@example.org', claimedSent: '11/16/2026' }, 'no_claimed_time'],
    [
      {
        claimedFrom: 'a@example.org',
        claimedSent: 'Mon, 16 Nov 2026 08:00:00 +0000',
        claimedSubject: 'x'.repeat(256),
      },
      'subject_too_long',
    ],
  ])('skips, with the reason the lookup itself gives (%#)', (request, reason) => {
    expect(prepareOriginalFetch(request)).toEqual({ skip: { outcome: 'skipped', reason } });
  });
});

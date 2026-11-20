/**
 * The fan-out scan's database store (migration 005): parameterized
 * statements only, the lock, claims and their undo, and the seam a later
 * response-action feature will use to find a wave. In-memory stand-in for
 * the tables; invented data only.
 */

import {
  FanoutScanStore,
  FanoutStoreMissingError,
  fanoutWaveKey,
  newFanoutReference,
} from '../../../../src/services/hunting/fanout.store';
import { FakeFanoutDb } from '../../../mocks/fanout.db';

const NOW = new Date('2026-11-17T12:00:00Z');
const HOSTILE_SUBJECT = "Invoice'); DROP TABLE fanout_scan_waves; --";

const sighting = (recipients: number) => ({
  waveKey: fanoutWaveKey('Pat@Supplier.example.net', 'invoice 7731'),
  senderAddress: 'pat@supplier.example.net',
  subject: HOSTILE_SUBJECT,
  firstSeen: new Date('2026-11-17T11:58:00Z'),
  lastSeen: new Date('2026-11-17T11:59:00Z'),
  recipients,
});

describe('FanoutScanStore', () => {
  it('keys a wave by lower-cased sender and normalized subject, and makes distinct references', () => {
    expect(fanoutWaveKey('Pat@Supplier.example.net', 'x')).toBe(
      fanoutWaveKey('pat@supplier.example.net', 'x')
    );
    expect(fanoutWaveKey('pat@supplier.example.net', 'x')).not.toBe(
      fanoutWaveKey('pat@supplier.example.net', 'y')
    );
    expect(newFanoutReference()).toMatch(/^FANOUT-[0-9A-F]{10}$/);
    expect(newFanoutReference()).not.toBe(newFanoutReference());
  });

  it('passes mail-flow text only as parameters, never in the SQL', async () => {
    const db = new FakeFanoutDb();
    const store = new FanoutScanStore(db);
    await store.claimAlert(sighting(20), { dedupeMs: 86_400_000, minRecipients: 15, now: NOW });
    for (const statement of db.statements) {
      expect(statement.sql).not.toContain('Invoice');
      expect(statement.sql).not.toContain('supplier');
    }
    expect(db.waves[0].subject).toBe(HOSTILE_SUBJECT);
  });

  it('undoes a growth claim back to the previous count', async () => {
    const db = new FakeFanoutDb();
    const store = new FanoutScanStore(db);
    const options = { dedupeMs: 86_400_000, minRecipients: 15, now: NOW };
    await store.claimAlert(sighting(20), options);
    const growth = await store.claimAlert(sighting(50), options);
    expect(growth.kind).toBe('growth');
    expect(db.waves[0].alerts_sent).toBe(2);
    await store.revertClaim(growth);
    expect(db.waves[0].alerted_recipients).toBe(20);
    expect(db.waves[0].alerts_sent).toBe(1);
    // Nothing to undo for a sighting that did not alert
    await store.revertClaim({ kind: 'none', reference: growth.reference });
    expect(db.waves).toHaveLength(1);
  });

  it('reads the request log whether the driver returns JSON or text, dropping malformed entries', async () => {
    const db = new FakeFanoutDb();
    db.state = {
      lock_token: null,
      lock_until: null,
      last_window_end: '2026-11-17T11:55:00Z' as never,
      last_started_at: null,
      recent_requests: JSON.stringify([
        { at: '2026-11-17T11:58:00Z', requests: 7 },
        { at: 5, requests: 'x' },
      ]),
    };
    const lock = await new FanoutScanStore(db).acquireLock(
      'token-1',
      new Date(NOW.getTime() + 60_000),
      NOW
    );
    expect(lock).toEqual({
      acquired: true,
      lastWindowEnd: new Date('2026-11-17T11:55:00Z'),
      recentRequests: [{ at: '2026-11-17T11:58:00Z', requests: 7 }],
    });
  });

  it('only releases the lock it holds', async () => {
    const db = new FakeFanoutDb();
    const store = new FanoutScanStore(db);
    await store.acquireLock('mine', new Date(NOW.getTime() + 60_000), NOW);
    await store.releaseLock('someone-else', { windowEnd: NOW, recentRequests: [] });
    expect(db.state?.lock_token).toBe('mine');
    await store.releaseLock('mine', { windowEnd: NOW, recentRequests: [] });
    expect(db.state?.lock_token).toBeNull();
    expect(db.state?.last_window_end).toEqual(NOW);
  });

  describe('the response-action seam: findWave', () => {
    it('finds a wave by its reference or by the alert it answers', async () => {
      const db = new FakeFanoutDb();
      const store = new FanoutScanStore(db);
      const claim = await store.claimAlert(sighting(20), {
        dedupeMs: 86_400_000,
        minRecipients: 15,
        now: NOW,
      });
      if (claim.kind !== 'new') throw new Error('expected a new wave');
      await store.recordAlertMessageId(claim.id, 'ses-alert-7');

      const byReference = await store.findWave({ reference: claim.reference });
      expect(byReference).toMatchObject({
        reference: claim.reference,
        senderAddress: 'pat@supplier.example.net',
        subject: HOSTILE_SUBJECT,
        alertedRecipients: 20,
        maxRecipients: 20,
        alertsSent: 1,
        reportMessageId: 'ses-alert-7',
      });
      expect(byReference?.firstSeen).toEqual(new Date('2026-11-17T11:58:00Z'));
      expect(await store.findWave({ reportMessageId: 'ses-alert-7' })).toMatchObject({
        reference: claim.reference,
      });
      expect(await store.findWave({ reference: 'FANOUT-0000000000' })).toBeUndefined();
      expect(await store.findWave({})).toBeUndefined();
    });
  });

  it.each(['42P01', '42703'])(
    'reports a missing migration (%s) by name, from every method',
    async code => {
      const db = new FakeFanoutDb();
      db.failWith = code;
      const store = new FanoutScanStore(db);
      const calls: Array<Promise<unknown>> = [
        store.acquireLock('t', NOW, NOW),
        store.releaseLock('t', { recentRequests: [] }),
        store.claimAlert(sighting(20), { dedupeMs: 1, minRecipients: 15, now: NOW }),
        store.revertClaim({ kind: 'new', id: 'wave-1', reference: 'FANOUT-0000000001' }),
        store.recordAlertMessageId('wave-1', 'ses-1'),
        store.findWave({ reference: 'FANOUT-0000000001' }),
      ];
      for (const call of calls) {
        await expect(call).rejects.toBeInstanceOf(FanoutStoreMissingError);
      }
      await expect(store.acquireLock('t', NOW, NOW)).rejects.toThrow(
        'apply migrations/005_fanout_scan.sql'
      );
    }
  );

  it('passes other database errors through', async () => {
    const db = new FakeFanoutDb();
    db.failWith = '57P01';
    await expect(new FanoutScanStore(db).findWave({ reference: 'FANOUT-1' })).rejects.toThrow(
      'fake database error'
    );
  });
});

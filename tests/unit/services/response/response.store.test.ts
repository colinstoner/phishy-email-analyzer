/**
 * ResponseStore: parameterized SQL, the conditional approval that makes
 * approvals idempotent, migration-missing degradation, and the migration's
 * append-only audit table.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  ResponseStore,
  ResponseStoreUnavailableError,
  resetResponseStoreWarning,
} from '../../../../src/services/response/response.store';
import { emptyReach } from '../../../../src/services/response/scope';

function fakeDb(rows: Record<string, unknown>[][] = []) {
  const calls: Array<{ text: string; params: unknown[] }> = [];
  const query = jest.fn(async (text: string, params: unknown[]) => {
    calls.push({ text, params });
    return { rows: rows.shift() ?? [] };
  });
  return { calls, db: { query } };
}

function pgError(code: string): Error {
  return Object.assign(new Error('relation does not exist'), { code });
}

const ACTION_ROW = {
  id: 'a1',
  incident_id: 'i1',
  reference: 'PHY-AAAA-AAAA-AAAA-AAAA',
  action_type: 'send_warning',
  status: 'approved',
  authorization_mode: 'approve',
  scope: JSON.stringify({
    kind: 'send_warning',
    recipients: [],
    reporters: [],
    distribution: false,
    skipped: {},
  }),
  scope_hash: 'h',
  proposed_at: new Date('2026-11-17T10:00:00Z'),
  expires_at: '2026-11-17T14:00:00Z',
  approved_by: 'soc@example.com',
  approved_at: new Date('2026-11-17T10:05:00Z'),
};

describe('ResponseStore', () => {
  beforeEach(() => resetResponseStoreWarning());

  it('approves only a proposed, unexpired action, in one conditional statement', async () => {
    const { calls, db } = fakeDb([[ACTION_ROW], []]);
    const store = new ResponseStore(db);
    const approved = await store.approveAction('a1', 'soc@example.com');
    expect(approved).toMatchObject({ id: 'a1', status: 'approved', approvedBy: 'soc@example.com' });
    expect(approved?.expiresAt).toEqual(new Date('2026-11-17T14:00:00Z'));
    expect(calls[0].text).toMatch(
      /WHERE id = \$1 AND status = 'proposed' AND expires_at > NOW\(\)/
    );
    expect(calls[0].params).toEqual(['a1', 'soc@example.com']);
    // Second approval: the UPDATE matches nothing
    expect(await store.approveAction('a1', 'soc@example.com')).toBeUndefined();
  });

  it('passes every value as a parameter, never in the SQL text', async () => {
    const hostile = "x'); DROP TABLE campaign_incidents; --";
    const { calls, db } = fakeDb([
      [],
      [
        {
          id: 'i1',
          campaign_signature: hostile,
          reference: 'r',
          trigger_source: 'reports',
          status: 'open',
          summary: {},
          reach: emptyReach('unavailable'),
        },
      ],
    ]);
    const store = new ResponseStore(db);
    await store.createIncident({
      campaignSignature: hostile,
      reference: 'PHY-AAAA-AAAA-AAAA-AAAA',
      trigger: 'reports',
      summary: {
        verdict: 'phishing',
        riskScore: 90,
        riskLevel: 'critical',
        reasons: [hostile],
        detectedBy: 'x',
      },
      reach: emptyReach('unavailable'),
      reportCount: 3,
    });
    for (const call of calls) {
      expect(call.text).not.toContain('DROP TABLE');
    }
  });

  it('returns the existing incident when the insert conflicts', async () => {
    const existing = {
      id: 'i1',
      campaign_signature: 'sig',
      reference: 'PHY-AAAA-AAAA-AAAA-AAAA',
      trigger_source: 'reports',
      status: 'open',
      summary: {
        verdict: 'phishing',
        riskScore: 1,
        riskLevel: 'low',
        reasons: [],
        detectedBy: 'x',
      },
      reach: emptyReach('unavailable'),
      report_count: 3,
    };
    const { db } = fakeDb([[], [existing]]);
    const result = await new ResponseStore(db).createIncident({
      campaignSignature: 'sig',
      reference: 'PHY-BBBB-BBBB-BBBB-BBBB',
      trigger: 'reports',
      summary: existing.summary,
      reach: emptyReach('unavailable'),
      reportCount: 3,
    });
    expect(result).toMatchObject({ created: false, incident: { id: 'i1', reportCount: 3 } });
  });

  it('only ever INSERTs audit rows', async () => {
    const { calls, db } = fakeDb();
    await new ResponseStore(db).appendAudit({
      incidentId: 'i1',
      actionId: 'a1',
      event: 'action_approved',
      actor: 'soc@example.com',
      detail: { scopeHash: 'h' },
    });
    expect(calls[0].text).toMatch(/^\s*INSERT INTO response_action_audit/);
    expect(calls[0].params).toEqual([
      'i1',
      'a1',
      'action_approved',
      'soc@example.com',
      '{"scopeHash":"h"}',
    ]);
  });

  it.each(['42P01', '42703'])(
    'degrades with an instructive line when the migration is missing (%s)',
    async code => {
      const warn = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
      const db = { query: jest.fn().mockRejectedValue(pgError(code)) };
      const store = new ResponseStore(db);
      await expect(store.getIncidentBySignature('sig')).rejects.toBeInstanceOf(
        ResponseStoreUnavailableError
      );
      await expect(store.listActions('i1')).rejects.toThrow(
        'apply migrations/006_campaign_response.sql'
      );
      warn.mockRestore();
    }
  );

  it('passes other database errors through', async () => {
    const db = { query: jest.fn().mockRejectedValue(pgError('57P01')) };
    await expect(new ResponseStore(db).listActions('i1')).rejects.not.toBeInstanceOf(
      ResponseStoreUnavailableError
    );
  });

  it('writes only the fields a patch sets', async () => {
    const { calls, db } = fakeDb();
    const store = new ResponseStore(db);
    await store.updateIncident('i1', {
      reportCount: 5,
      lastUpdateSentAt: new Date('2026-11-17T11:00:00Z'),
    });
    expect(calls[0].text).toContain('report_count = $1, last_update_sent_at = $2');
    expect(calls[0].params[2]).toBe('i1');
    await store.updateIncident('i1', {});
    expect(calls).toHaveLength(1);
  });

  it('keeps a stored removal anchor: a summary write can set it once, never replace or drop it', async () => {
    const { calls, db } = fakeDb();
    const store = new ResponseStore(db);
    await store.updateIncident('i1', { summary: { removalAnchor: { messageId: 'b' } } as never });
    // One statement: under concurrency Postgres re-evaluates it on the row
    // another writer just committed, so the first anchor written survives
    expect(calls[0].text).toContain(
      "summary = CASE WHEN summary ? 'removalAnchor' THEN $1::jsonb || jsonb_build_object('removalAnchor', summary->'removalAnchor') ELSE $1::jsonb END"
    );
    expect(calls[0].params[0]).toBe(JSON.stringify({ removalAnchor: { messageId: 'b' } }));
  });

  it('expires and cancels with conditional updates', async () => {
    const { calls, db } = fakeDb([[ACTION_ROW], [ACTION_ROW]]);
    const store = new ResponseStore(db);
    expect(await store.expireDue('i1')).toHaveLength(1);
    expect(calls[0].text).toMatch(/status = 'proposed' AND expires_at <= NOW\(\)/);
    expect(await store.cancelProposed('i1', 'send_warning')).toHaveLength(1);
    expect(calls[1].params).toEqual(['i1', 'send_warning']);
  });
});

describe('migration 006', () => {
  const sql = readFileSync(
    join(__dirname, '../../../../migrations/006_campaign_response.sql'),
    'utf8'
  );

  it('creates the three tables idempotently', () => {
    for (const table of ['campaign_incidents', 'response_actions', 'response_action_audit']) {
      expect(sql).toContain(`CREATE TABLE IF NOT EXISTS ${table}`);
    }
  });

  it('makes the audit table append-only', () => {
    expect(sql).toMatch(/BEFORE UPDATE OR DELETE ON response_action_audit/);
    expect(sql).toMatch(/BEFORE TRUNCATE ON response_action_audit/);
    expect(sql).toContain("RAISE EXCEPTION 'response_action_audit is append-only'");
  });

  it('constrains statuses and action types to the model', () => {
    expect(sql).toContain("action_type IN ('send_warning', 'remove_messages')");
    expect(sql).toContain(
      "'proposed', 'approved', 'completed', 'dry_run_completed', 'expired', 'cancelled', 'failed'"
    );
  });
});

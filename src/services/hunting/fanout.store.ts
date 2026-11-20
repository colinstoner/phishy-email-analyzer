/**
 * The fan-out scan's state in the intelligence database (migration 005):
 * the scan lock, the window and the shared request allowance
 * (`fanout_scan_state`), and one row per alerted wave (`fanout_scan_waves`).
 *
 * State lives in the database, not in the Lambda instance, because the
 * scheduled invocations land on whichever instance is free: an in-memory
 * dedupe would alert again after every cold start, and an in-memory lock
 * could not stop two instances scanning at once.
 *
 * Every value that came from mail flow (sender, subject) is a bound
 * parameter. Migration 005 is applied manually; a missing table or column
 * (42P01 / 42703) is reported as `FanoutStoreMissingError` so the job can
 * log what to apply and stop.
 */

import { createHash, randomBytes } from 'crypto';

/** The one capability the store needs; `pg`'s Pool and Client both provide it */
export interface SqlQueryable {
  query(
    sql: string,
    params?: unknown[]
  ): Promise<{ rows: Array<Record<string, unknown>>; rowCount?: number | null }>;
}

export const FANOUT_MIGRATION = 'migrations/005_fanout_scan.sql';

/** Migration 005 has not been applied */
export class FanoutStoreMissingError extends Error {
  constructor() {
    super(`fan-out scan tables are missing: apply ${FANOUT_MIGRATION}`);
    this.name = 'FanoutStoreMissingError';
  }
}

function rethrow(error: unknown): never {
  const code = (error as { code?: string } | undefined)?.code;
  if (code === '42P01' || code === '42703') {
    throw new FanoutStoreMissingError();
  }
  throw error;
}

/** Trace requests one scan spent, kept for five minutes for the shared allowance */
export interface RequestEntry {
  at: string;
  requests: number;
}

export type LockResult =
  { acquired: false } | { acquired: true; lastWindowEnd?: Date; recentRequests: RequestEntry[] };

/** The identity of a wave: one external sender and one normalized subject */
export function fanoutWaveKey(senderAddress: string, subjectKey: string): string {
  return createHash('sha256').update(`${senderAddress.toLowerCase()}\n${subjectKey}`).digest('hex');
}

/** A stable, unguessable-enough reference for the alert: `FANOUT-` and 10 hex digits */
export function newFanoutReference(): string {
  return `FANOUT-${randomBytes(5).toString('hex').toUpperCase()}`;
}

/**
 * Whether a wave has grown enough to send an update: at least double the
 * recipients the last alert reported, and at least `minRecipients` more.
 * Doubling keeps updates logarithmic in the wave's size (a wave of 1000
 * recipients first flagged at 20 produces at most six emails).
 */
export function isMaterialGrowth(
  alertedRecipients: number,
  currentRecipients: number,
  minRecipients: number
): boolean {
  return (
    currentRecipients >= 2 * alertedRecipients &&
    currentRecipients - alertedRecipients >= minRecipients
  );
}

export interface WaveSighting {
  waveKey: string;
  senderAddress: string;
  subject: string;
  firstSeen: Date;
  lastSeen: Date;
  /** Distinct internal recipients of the wave so far */
  recipients: number;
}

export type AlertClaim =
  | { kind: 'none'; reference: string }
  | { kind: 'new'; id: string; reference: string }
  | {
      kind: 'growth';
      id: string;
      reference: string;
      previousRecipients: number;
      firstSeen: Date;
    };

/** A wave as stored: what a response action, later, would need to act on it */
export interface FanoutWaveRecord {
  id: string;
  reference: string;
  senderAddress: string;
  subject: string;
  firstSeen: Date;
  lastSeen: Date;
  alertedRecipients: number;
  maxRecipients: number;
  alertsSent: number;
  reportMessageId?: string;
}

function toDate(value: unknown): Date | undefined {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date;
  }
  return undefined;
}

function toRequestEntries(value: unknown): RequestEntry[] {
  const list = typeof value === 'string' ? (JSON.parse(value) as unknown) : value;
  if (!Array.isArray(list)) {
    return [];
  }
  return list.flatMap(item => {
    const entry = item as { at?: unknown; requests?: unknown };
    return typeof entry?.at === 'string' &&
      typeof entry.requests === 'number' &&
      Number.isFinite(entry.requests)
      ? [{ at: entry.at, requests: entry.requests }]
      : [];
  });
}

function toWave(row: Record<string, unknown>): FanoutWaveRecord {
  return {
    id: String(row.id),
    reference: String(row.reference),
    senderAddress: String(row.sender_address),
    subject: typeof row.subject === 'string' ? row.subject : '',
    firstSeen: toDate(row.first_seen_at) ?? new Date(0),
    lastSeen: toDate(row.last_seen_at) ?? new Date(0),
    alertedRecipients: Number(row.alerted_recipients),
    maxRecipients: Number(row.max_recipients),
    alertsSent: Number(row.alerts_sent),
    ...(typeof row.report_message_id === 'string'
      ? { reportMessageId: row.report_message_id }
      : {}),
  };
}

export class FanoutScanStore {
  constructor(private readonly db: SqlQueryable) {}

  /**
   * Take the scan lock unless another scan holds an unexpired one. Returns
   * where the previous window ended and the recent request log.
   */
  async acquireLock(token: string, leaseUntil: Date, now: Date): Promise<LockResult> {
    try {
      const result = await this.db.query(
        `INSERT INTO fanout_scan_state (id, lock_token, lock_until, last_started_at, updated_at)
         VALUES (1, $1, $2, $3, $3)
         ON CONFLICT (id) DO UPDATE SET
           lock_token = EXCLUDED.lock_token,
           lock_until = EXCLUDED.lock_until,
           last_started_at = EXCLUDED.last_started_at,
           updated_at = EXCLUDED.updated_at
         WHERE fanout_scan_state.lock_until IS NULL OR fanout_scan_state.lock_until < $3
         RETURNING last_window_end, recent_requests`,
        [token, leaseUntil, now]
      );
      if (result.rows.length === 0) {
        return { acquired: false };
      }
      const row = result.rows[0];
      const lastWindowEnd = toDate(row.last_window_end);
      return {
        acquired: true,
        ...(lastWindowEnd ? { lastWindowEnd } : {}),
        recentRequests: toRequestEntries(row.recent_requests),
      };
    } catch (error) {
      rethrow(error);
    }
  }

  /**
   * Release the lock this scan holds. `windowEnd` advances the window (left
   * out when the scan read nothing, so the next one covers it again);
   * `recentRequests` replaces the request log.
   */
  async releaseLock(
    token: string,
    update: { windowEnd?: Date; recentRequests: RequestEntry[] }
  ): Promise<void> {
    try {
      await this.db.query(
        `UPDATE fanout_scan_state SET
           lock_token = NULL,
           lock_until = NULL,
           last_window_end = COALESCE($2, last_window_end),
           recent_requests = $3::jsonb,
           updated_at = NOW()
         WHERE id = 1 AND lock_token = $1`,
        [token, update.windowEnd ?? null, JSON.stringify(update.recentRequests)]
      );
    } catch (error) {
      rethrow(error);
    }
  }

  /**
   * Decide whether a sighting deserves an alert, and record it. A wave seen
   * within `dedupeMs` of its last sighting is the same wave: it alerts again
   * only on material growth. Scans never overlap (the lock), so reading and
   * then writing here cannot race another scan.
   */
  async claimAlert(
    sighting: WaveSighting,
    options: { dedupeMs: number; minRecipients: number; now: Date }
  ): Promise<AlertClaim> {
    try {
      const existing = await this.db.query(
        `SELECT id, reference, alerted_recipients, first_seen_at
           FROM fanout_scan_waves
          WHERE wave_key = $1 AND last_seen_at > $2
          ORDER BY last_seen_at DESC
          LIMIT 1`,
        [sighting.waveKey, new Date(options.now.getTime() - options.dedupeMs)]
      );

      if (existing.rows.length === 0) {
        const reference = newFanoutReference();
        const inserted = await this.db.query(
          `INSERT INTO fanout_scan_waves
             (wave_key, reference, sender_address, subject, first_seen_at, last_seen_at,
              alerted_recipients, max_recipients, alerts_sent, last_alert_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 1, $8)
           RETURNING id`,
          [
            sighting.waveKey,
            reference,
            sighting.senderAddress,
            sighting.subject,
            sighting.firstSeen,
            sighting.lastSeen,
            sighting.recipients,
            options.now,
          ]
        );
        return { kind: 'new', id: String(inserted.rows[0].id), reference };
      }

      const row = existing.rows[0];
      const id = String(row.id);
      const reference = String(row.reference);
      const alerted = Number(row.alerted_recipients);
      const grows = isMaterialGrowth(alerted, sighting.recipients, options.minRecipients);
      await this.db.query(
        `UPDATE fanout_scan_waves SET
           last_seen_at = GREATEST(last_seen_at, $2),
           first_seen_at = LEAST(first_seen_at, $3),
           max_recipients = GREATEST(max_recipients, $4),
           alerted_recipients = CASE WHEN $5 THEN $4 ELSE alerted_recipients END,
           alerts_sent = CASE WHEN $5 THEN alerts_sent + 1 ELSE alerts_sent END,
           last_alert_at = CASE WHEN $5 THEN $6 ELSE last_alert_at END,
           updated_at = NOW()
         WHERE id = $1`,
        [id, sighting.lastSeen, sighting.firstSeen, sighting.recipients, grows, options.now]
      );
      if (!grows) {
        return { kind: 'none', reference };
      }
      const firstSeen = toDate(row.first_seen_at) ?? sighting.firstSeen;
      return {
        kind: 'growth',
        id,
        reference,
        previousRecipients: alerted,
        firstSeen: firstSeen < sighting.firstSeen ? firstSeen : sighting.firstSeen,
      };
    } catch (error) {
      rethrow(error);
    }
  }

  /** Undo a claim whose alert could not be sent, so the next scan tries again */
  async revertClaim(claim: AlertClaim): Promise<void> {
    try {
      if (claim.kind === 'new') {
        await this.db.query('DELETE FROM fanout_scan_waves WHERE id = $1', [claim.id]);
      } else if (claim.kind === 'growth') {
        await this.db.query(
          `UPDATE fanout_scan_waves SET
             alerted_recipients = $2,
             alerts_sent = GREATEST(alerts_sent - 1, 1),
             updated_at = NOW()
           WHERE id = $1`,
          [claim.id, claim.previousRecipients]
        );
      }
    } catch (error) {
      rethrow(error);
    }
  }

  /** Remember the SES message ID of the alert, so a reply can be matched to the wave */
  async recordAlertMessageId(id: string, messageId: string): Promise<void> {
    try {
      await this.db.query(
        'UPDATE fanout_scan_waves SET report_message_id = $2, updated_at = NOW() WHERE id = $1',
        [id, messageId]
      );
    } catch (error) {
      rethrow(error);
    }
  }

  /**
   * SEAM for security-team-approved response actions (not wired up here).
   *
   * Find the wave a security-team reply refers to, by the reference quoted
   * in the alert or by the SES message ID the reply answers (In-Reply-To).
   * Whoever calls this must already have authenticated the reply exactly as
   * the command channel does (distribution-list membership and SES SPF/DKIM
   * PASS, CLAUDE.md invariant 2); the record says what was seen, it
   * authorizes nothing. The sender and subject in it are hostile mail-flow
   * text.
   */
  async findWave(match: {
    reference?: string;
    reportMessageId?: string;
  }): Promise<FanoutWaveRecord | undefined> {
    if (!match.reference && !match.reportMessageId) {
      return undefined;
    }
    try {
      const result = await this.db.query(
        `SELECT id, reference, sender_address, subject, first_seen_at, last_seen_at,
                alerted_recipients, max_recipients, alerts_sent, report_message_id
           FROM fanout_scan_waves
          WHERE ($1::text IS NOT NULL AND reference = $1)
             OR ($2::text IS NOT NULL AND report_message_id = $2)
          ORDER BY last_seen_at DESC
          LIMIT 1`,
        [match.reference ?? null, match.reportMessageId ?? null]
      );
      return result.rows.length > 0 ? toWave(result.rows[0]) : undefined;
    } catch (error) {
      rethrow(error);
    }
  }
}

/**
 * An in-memory stand-in for the two fan-out scan tables (migration 005),
 * answering exactly the parameterized statements `FanoutScanStore` sends.
 * Any other statement fails the test. No database. Invented data only.
 */

import type { SqlQueryable } from '../../src/services/hunting/fanout.store';

export interface StateRow {
  lock_token: string | null;
  lock_until: Date | null;
  last_window_end: Date | null;
  last_started_at: Date | null;
  recent_requests: unknown;
}

export interface WaveRow {
  id: string;
  wave_key: string;
  reference: string;
  sender_address: string;
  subject: string;
  first_seen_at: Date;
  last_seen_at: Date;
  alerted_recipients: number;
  max_recipients: number;
  alerts_sent: number;
  last_alert_at: Date | null;
  report_message_id: string | null;
}

export class FakeFanoutDb implements SqlQueryable {
  state?: StateRow;
  waves: WaveRow[] = [];
  statements: Array<{ sql: string; params: unknown[] }> = [];
  /** Make every statement fail with this Postgres error code */
  failWith?: string;
  private nextId = 1;

  async query(
    sql: string,
    params: unknown[] = []
  ): Promise<{ rows: Array<Record<string, unknown>>; rowCount: number }> {
    this.statements.push({ sql, params });
    if (this.failWith) {
      throw Object.assign(new Error('fake database error'), { code: this.failWith });
    }
    const text = sql.replace(/\s+/g, ' ').trim();
    const ms = (value: unknown): number => (value as Date).getTime();

    if (text.startsWith('INSERT INTO fanout_scan_state')) {
      const [token, leaseUntil, now] = params as [string, Date, Date];
      if (this.state && this.state.lock_until && ms(this.state.lock_until) >= ms(now)) {
        return { rows: [], rowCount: 0 };
      }
      this.state = {
        lock_token: token,
        lock_until: leaseUntil,
        last_window_end: this.state?.last_window_end ?? null,
        last_started_at: now,
        recent_requests: this.state?.recent_requests ?? [],
      };
      return {
        rows: [
          {
            last_window_end: this.state.last_window_end,
            recent_requests: this.state.recent_requests,
          },
        ],
        rowCount: 1,
      };
    }
    if (text.startsWith('UPDATE fanout_scan_state')) {
      const [token, windowEnd, recent] = params as [string, Date | null, string];
      if (!this.state || this.state.lock_token !== token) {
        return { rows: [], rowCount: 0 };
      }
      this.state.lock_token = null;
      this.state.lock_until = null;
      this.state.last_window_end = windowEnd ?? this.state.last_window_end;
      this.state.recent_requests = JSON.parse(recent) as unknown;
      return { rows: [], rowCount: 1 };
    }
    if (text.startsWith('SELECT id, reference, alerted_recipients, first_seen_at')) {
      const [key, since] = params as [string, Date];
      const match = this.waves
        .filter(wave => wave.wave_key === key && ms(wave.last_seen_at) > ms(since))
        .sort((a, b) => ms(b.last_seen_at) - ms(a.last_seen_at))[0];
      return { rows: match ? [{ ...match }] : [], rowCount: match ? 1 : 0 };
    }
    if (text.startsWith('INSERT INTO fanout_scan_waves')) {
      const [key, reference, sender, subject, first, last, recipients, now] = params as [
        string,
        string,
        string,
        string,
        Date,
        Date,
        number,
        Date,
      ];
      const id = `wave-${this.nextId++}`;
      this.waves.push({
        id,
        wave_key: key,
        reference,
        sender_address: sender,
        subject,
        first_seen_at: first,
        last_seen_at: last,
        alerted_recipients: recipients,
        max_recipients: recipients,
        alerts_sent: 1,
        last_alert_at: now,
        report_message_id: null,
      });
      return { rows: [{ id }], rowCount: 1 };
    }
    if (text.startsWith('UPDATE fanout_scan_waves SET last_seen_at')) {
      const [id, last, first, recipients, grows, now] = params as [
        string,
        Date,
        Date,
        number,
        boolean,
        Date,
      ];
      const wave = this.waves.find(row => row.id === id);
      if (wave) {
        wave.last_seen_at = ms(last) > ms(wave.last_seen_at) ? last : wave.last_seen_at;
        wave.first_seen_at = ms(first) < ms(wave.first_seen_at) ? first : wave.first_seen_at;
        wave.max_recipients = Math.max(wave.max_recipients, recipients);
        if (grows) {
          wave.alerted_recipients = recipients;
          wave.alerts_sent++;
          wave.last_alert_at = now;
        }
      }
      return { rows: [], rowCount: wave ? 1 : 0 };
    }
    if (text.startsWith('UPDATE fanout_scan_waves SET alerted_recipients = $2')) {
      const [id, previous] = params as [string, number];
      const wave = this.waves.find(row => row.id === id);
      if (wave) {
        wave.alerted_recipients = previous;
        wave.alerts_sent = Math.max(1, wave.alerts_sent - 1);
      }
      return { rows: [], rowCount: wave ? 1 : 0 };
    }
    if (text.startsWith('UPDATE fanout_scan_waves SET report_message_id')) {
      const [id, messageId] = params as [string, string];
      const wave = this.waves.find(row => row.id === id);
      if (wave) {
        wave.report_message_id = messageId;
      }
      return { rows: [], rowCount: wave ? 1 : 0 };
    }
    if (text.startsWith('DELETE FROM fanout_scan_waves')) {
      const [id] = params as [string];
      this.waves = this.waves.filter(row => row.id !== id);
      return { rows: [], rowCount: 1 };
    }
    if (text.startsWith('SELECT id, reference, sender_address')) {
      const [reference, messageId] = params as [string | null, string | null];
      const match = this.waves.find(
        wave =>
          (reference !== null && wave.reference === reference) ||
          (messageId !== null && wave.report_message_id === messageId)
      );
      return { rows: match ? [{ ...match }] : [], rowCount: match ? 1 : 0 };
    }
    throw new Error(`FakeFanoutDb: unexpected statement: ${text.slice(0, 80)}`);
  }
}

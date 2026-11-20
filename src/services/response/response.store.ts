/**
 * Campaign response persistence (migration 006, applied manually).
 *
 * Three tables: `campaign_incidents`, `response_actions` and the append-only
 * `response_action_audit`. Every statement is parameterized. A missing table
 * or column (42P01 / 42703: the migration has not been applied) raises
 * `ResponseStoreUnavailableError` after one instructive log line, and the
 * caller falls back to the campaign alert's behaviour without campaign
 * response.
 *
 * Approval is a single conditional UPDATE (`WHERE status = 'proposed' AND
 * expires_at > NOW()`), so two approvals of one action, in one Lambda or in
 * two at once, approve it once.
 */

import { createLogger } from '../../utils/logger';
import {
  ActionAuthorization,
  ActionResult,
  ActionScope,
  AuditEntry,
  CampaignIncident,
  IncidentReach,
  IncidentStatus,
  IncidentSummary,
  IncidentTrigger,
  ResponseAction,
  ResponseActionStatus,
  ResponseActionType,
} from './response.types';
import { emptyReach } from './scope';

const logger = createLogger('campaign-response-store');

export const RESPONSE_MIGRATION = '006_campaign_response.sql';

/** Anything that runs one parameterized statement */
export interface Queryable {
  query(text: string, params: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export class ResponseStoreUnavailableError extends Error {
  constructor() {
    super(
      `campaign response tables are missing — apply migrations/${RESPONSE_MIGRATION} to enable campaign response`
    );
    this.name = 'ResponseStoreUnavailableError';
  }
}

let warnedMissing = false;

function asDate(value: unknown): Date | undefined {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) {
    return new Date(value);
  }
  return undefined;
}

function asJson<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) {
    return fallback;
  }
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

function mapIncident(row: Record<string, unknown>): CampaignIncident {
  return {
    id: row.id as string,
    campaignId: (row.campaign_id as string | null) ?? undefined,
    campaignSignature: row.campaign_signature as string,
    reference: row.reference as string,
    trigger: row.trigger_source as IncidentTrigger,
    status: row.status as IncidentStatus,
    summary: asJson<IncidentSummary>(row.summary, {
      verdict: 'unknown',
      riskScore: 0,
      riskLevel: 'unknown',
      reasons: [],
      detectedBy: 'unknown',
    }),
    reach: asJson<IncidentReach>(row.reach, emptyReach('unavailable')),
    reportCount: Number(row.report_count ?? 0),
    threadMessageId: (row.thread_message_id as string | null) ?? undefined,
    lastUpdateSentAt: asDate(row.last_update_sent_at),
    notifiedReportCount: Number(row.notified_report_count ?? 0),
    notifiedRecipientCount: Number(row.notified_recipient_count ?? 0),
    createdAt: asDate(row.created_at) ?? new Date(0),
  };
}

function mapAction(row: Record<string, unknown>): ResponseAction {
  return {
    id: row.id as string,
    incidentId: row.incident_id as string,
    reference: row.reference as string,
    type: row.action_type as ResponseActionType,
    status: row.status as ResponseActionStatus,
    authorization: row.authorization_mode as ActionAuthorization,
    scope: asJson<ActionScope>(row.scope, {
      kind: 'remove_messages',
      mailboxes: [],
      messageCount: 0,
      limits: { maxMailboxes: 0, maxMessages: 0 },
      skipped: { noIdentifiers: 0, alreadyPurged: 0, overMailboxCap: 0, overMessageCap: 0 },
    }),
    scopeHash: row.scope_hash as string,
    proposedAt: asDate(row.proposed_at) ?? new Date(0),
    expiresAt: asDate(row.expires_at) ?? new Date(0),
    approvedBy: (row.approved_by as string | null) ?? undefined,
    approvedAt: asDate(row.approved_at),
    executedAt: asDate(row.executed_at),
    executor: (row.executor as string | null) ?? undefined,
    result: row.result ? asJson<ActionResult | undefined>(row.result, undefined) : undefined,
  };
}

export interface NewIncident {
  campaignId?: string;
  campaignSignature: string;
  reference: string;
  trigger: IncidentTrigger;
  summary: IncidentSummary;
  reach: IncidentReach;
  reportCount: number;
}

export interface IncidentPatch {
  status?: IncidentStatus;
  summary?: IncidentSummary;
  reach?: IncidentReach;
  reportCount?: number;
  threadMessageId?: string;
  lastUpdateSentAt?: Date;
  notifiedReportCount?: number;
  notifiedRecipientCount?: number;
}

export interface NewAction {
  incidentId: string;
  reference: string;
  type: ResponseActionType;
  authorization: ActionAuthorization;
  scope: ActionScope;
  scopeHash: string;
  expiresAt: Date;
}

const INCIDENT_COLUMNS: Record<keyof IncidentPatch, string> = {
  status: 'status',
  summary: 'summary',
  reach: 'reach',
  reportCount: 'report_count',
  threadMessageId: 'thread_message_id',
  lastUpdateSentAt: 'last_update_sent_at',
  notifiedReportCount: 'notified_report_count',
  notifiedRecipientCount: 'notified_recipient_count',
};

export class ResponseStore {
  constructor(private readonly db: Queryable) {}

  private async run(text: string, params: unknown[]): Promise<Record<string, unknown>[]> {
    try {
      return (await this.db.query(text, params)).rows;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === '42P01' || code === '42703') {
        if (!warnedMissing) {
          warnedMissing = true;
          logger.warn(
            `Campaign response tables are missing — apply migrations/${RESPONSE_MIGRATION}. Falling back to the campaign alert without campaign response.`
          );
        }
        throw new ResponseStoreUnavailableError();
      }
      throw error;
    }
  }

  async getIncidentBySignature(signature: string): Promise<CampaignIncident | undefined> {
    const rows = await this.run('SELECT * FROM campaign_incidents WHERE campaign_signature = $1', [
      signature,
    ]);
    return rows[0] ? mapIncident(rows[0]) : undefined;
  }

  async getIncident(id: string): Promise<CampaignIncident | undefined> {
    const rows = await this.run('SELECT * FROM campaign_incidents WHERE id = $1', [id]);
    return rows[0] ? mapIncident(rows[0]) : undefined;
  }

  /**
   * Create the incident for a campaign, or return the one that already
   * exists (two reports crossing the threshold at once open one incident).
   * `created` says which.
   */
  async createIncident(
    incident: NewIncident
  ): Promise<{ incident: CampaignIncident; created: boolean }> {
    const rows = await this.run(
      `INSERT INTO campaign_incidents
         (campaign_id, campaign_signature, reference, trigger_source, status, summary, reach, report_count)
       VALUES ($1, $2, $3, $4, 'open', $5, $6, $7)
       ON CONFLICT (campaign_signature) DO NOTHING
       RETURNING *`,
      [
        incident.campaignId ?? null,
        incident.campaignSignature,
        incident.reference,
        incident.trigger,
        JSON.stringify(incident.summary),
        JSON.stringify(incident.reach),
        incident.reportCount,
      ]
    );
    if (rows[0]) {
      return { incident: mapIncident(rows[0]), created: true };
    }
    const existing = await this.getIncidentBySignature(incident.campaignSignature);
    if (!existing) {
      throw new Error('Incident insert conflicted but no incident was found');
    }
    return { incident: existing, created: false };
  }

  async updateIncident(id: string, patch: IncidentPatch): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    for (const [key, column] of Object.entries(INCIDENT_COLUMNS) as [
      keyof IncidentPatch,
      string,
    ][]) {
      const value = patch[key];
      if (value === undefined) {
        continue;
      }
      params.push(
        typeof value === 'object' && !(value instanceof Date) ? JSON.stringify(value) : value
      );
      sets.push(`${column} = $${params.length}`);
    }
    if (sets.length === 0) {
      return;
    }
    params.push(id);
    await this.run(
      `UPDATE campaign_incidents SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $${params.length}`,
      params
    );
  }

  /** Find the incident for the campaign an analysis belongs to (needs migration 003) */
  async getIncidentForAnalysis(analysisId: string): Promise<CampaignIncident | undefined> {
    const rows = await this.run(
      `SELECT ci.* FROM campaign_incidents ci
         JOIN email_analyses ea ON ea.campaign_signature = ci.campaign_signature
        WHERE ea.id = $1
        LIMIT 1`,
      [analysisId]
    );
    return rows[0] ? mapIncident(rows[0]) : undefined;
  }

  async createAction(action: NewAction): Promise<ResponseAction> {
    const rows = await this.run(
      `INSERT INTO response_actions
         (incident_id, reference, action_type, status, authorization_mode, scope, scope_hash, expires_at)
       VALUES ($1, $2, $3, 'proposed', $4, $5, $6, $7)
       RETURNING *`,
      [
        action.incidentId,
        action.reference,
        action.type,
        action.authorization,
        JSON.stringify(action.scope),
        action.scopeHash,
        action.expiresAt,
      ]
    );
    return mapAction(rows[0]);
  }

  async getActionByReference(reference: string): Promise<ResponseAction | undefined> {
    const rows = await this.run('SELECT * FROM response_actions WHERE reference = $1', [reference]);
    return rows[0] ? mapAction(rows[0]) : undefined;
  }

  async listActions(incidentId: string): Promise<ResponseAction[]> {
    const rows = await this.run(
      'SELECT * FROM response_actions WHERE incident_id = $1 ORDER BY proposed_at ASC',
      [incidentId]
    );
    return rows.map(mapAction);
  }

  /**
   * Approve a proposed, unexpired action. Returns the approved action, or
   * undefined when it was not in that state (already approved, expired,
   * cancelled): the conditional UPDATE is what makes approval idempotent.
   */
  async approveAction(id: string, approver: string): Promise<ResponseAction | undefined> {
    const rows = await this.run(
      `UPDATE response_actions
          SET status = 'approved', approved_by = $2, approved_at = NOW()
        WHERE id = $1 AND status = 'proposed' AND expires_at > NOW()
        RETURNING *`,
      [id, approver]
    );
    return rows[0] ? mapAction(rows[0]) : undefined;
  }

  /** Record an `auto` action's authorization: no human approver */
  async markAutoApproved(id: string): Promise<ResponseAction | undefined> {
    const rows = await this.run(
      `UPDATE response_actions
          SET status = 'approved', approved_by = 'auto', approved_at = NOW()
        WHERE id = $1 AND status = 'proposed'
        RETURNING *`,
      [id]
    );
    return rows[0] ? mapAction(rows[0]) : undefined;
  }

  async finishAction(
    id: string,
    status: Extract<ResponseActionStatus, 'completed' | 'dry_run_completed' | 'failed'>,
    result: ActionResult
  ): Promise<void> {
    await this.run(
      `UPDATE response_actions
          SET status = $2, result = $3, executor = $4, executed_at = NOW()
        WHERE id = $1 AND status = 'approved'`,
      [id, status, JSON.stringify(result), result.executor]
    );
  }

  /** Expire every proposed action past its window; returns what was expired */
  async expireDue(incidentId?: string): Promise<ResponseAction[]> {
    const rows = await this.run(
      `UPDATE response_actions
          SET status = 'expired'
        WHERE status = 'proposed' AND expires_at <= NOW()
          AND ($1::uuid IS NULL OR incident_id = $1::uuid)
        RETURNING *`,
      [incidentId ?? null]
    );
    return rows.map(mapAction);
  }

  /** Cancel proposed actions (superseded, or the incident was ruled a false positive) */
  async cancelProposed(incidentId: string, type?: ResponseActionType): Promise<ResponseAction[]> {
    const rows = await this.run(
      `UPDATE response_actions
          SET status = 'cancelled'
        WHERE incident_id = $1 AND status = 'proposed'
          AND ($2::text IS NULL OR action_type = $2::text)
        RETURNING *`,
      [incidentId, type ?? null]
    );
    return rows.map(mapAction);
  }

  /** Append one audit row. The table rejects UPDATE and DELETE (migration 006). */
  async appendAudit(entry: AuditEntry): Promise<void> {
    await this.run(
      `INSERT INTO response_action_audit (incident_id, action_id, event, actor, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        entry.incidentId,
        entry.actionId ?? null,
        entry.event,
        entry.actor,
        entry.detail ? JSON.stringify(entry.detail) : null,
      ]
    );
  }
}

/** Test hook: forget that the missing-table warning was logged */
export function resetResponseStoreWarning(): void {
  warnedMissing = false;
}

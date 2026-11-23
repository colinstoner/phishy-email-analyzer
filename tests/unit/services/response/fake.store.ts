/**
 * In-memory stand-in for ResponseStore with the same semantics the SQL has:
 * one incident per signature, conditional approval, expiry by time,
 * append-only audit. Tests only.
 */

import { randomUUID } from 'crypto';
import {
  ResponseStore,
  ResponseStoreUnavailableError,
  IncidentPatch,
  NewAction,
  NewIncident,
} from '../../../../src/services/response/response.store';
import type {
  ActionResult,
  AuditEntry,
  CampaignIncident,
  ResponseAction,
  ResponseActionStatus,
  ResponseActionType,
} from '../../../../src/services/response/response.types';

export class FakeResponseStore {
  incidents: CampaignIncident[] = [];
  actions: ResponseAction[] = [];
  audit: AuditEntry[] = [];
  /** Analysis ID → campaign signature (email_analyses.campaign_signature) */
  analyses = new Map<string, string>();
  unavailable = false;

  constructor(private readonly clock: () => Date) {}

  asStore(): ResponseStore {
    return this as unknown as ResponseStore;
  }

  private check(): void {
    if (this.unavailable) {
      throw new ResponseStoreUnavailableError();
    }
  }

  async getIncidentBySignature(signature: string): Promise<CampaignIncident | undefined> {
    this.check();
    const found = this.incidents.find(i => i.campaignSignature === signature);
    return found ? structuredClone(found) : undefined;
  }

  async getIncident(id: string): Promise<CampaignIncident | undefined> {
    this.check();
    const found = this.incidents.find(i => i.id === id);
    return found ? structuredClone(found) : undefined;
  }

  async createIncident(
    incident: NewIncident
  ): Promise<{ incident: CampaignIncident; created: boolean }> {
    this.check();
    const existing = this.incidents.find(i => i.campaignSignature === incident.campaignSignature);
    if (existing) {
      return { incident: structuredClone(existing), created: false };
    }
    const row: CampaignIncident = {
      id: randomUUID(),
      campaignId: incident.campaignId,
      campaignSignature: incident.campaignSignature,
      reference: incident.reference,
      trigger: incident.trigger,
      status: 'open',
      summary: structuredClone(incident.summary),
      reach: structuredClone(incident.reach),
      reportCount: incident.reportCount,
      notifiedReportCount: 0,
      notifiedRecipientCount: 0,
      createdAt: this.clock(),
    };
    this.incidents.push(row);
    return { incident: structuredClone(row), created: true };
  }

  async updateIncident(id: string, patch: IncidentPatch): Promise<void> {
    this.check();
    const row = this.incidents.find(i => i.id === id);
    if (row) {
      const stored = row.summary.removalAnchor;
      Object.assign(row, structuredClone(patch));
      // As the real store's UPDATE: a stored anchor is write-once
      if (patch.summary && stored) {
        row.summary.removalAnchor = structuredClone(stored);
      }
    }
  }

  async getIncidentForAnalysis(analysisId: string): Promise<CampaignIncident | undefined> {
    this.check();
    const signature = this.analyses.get(analysisId);
    return signature ? this.getIncidentBySignature(signature) : undefined;
  }

  async createAction(action: NewAction): Promise<ResponseAction> {
    this.check();
    const row: ResponseAction = {
      id: randomUUID(),
      incidentId: action.incidentId,
      reference: action.reference,
      type: action.type,
      status: 'proposed',
      authorization: action.authorization,
      scope: structuredClone(action.scope),
      scopeHash: action.scopeHash,
      proposedAt: this.clock(),
      expiresAt: action.expiresAt,
    };
    this.actions.push(row);
    return structuredClone(row);
  }

  async getActionByReference(reference: string): Promise<ResponseAction | undefined> {
    this.check();
    const found = this.actions.find(a => a.reference === reference);
    return found ? structuredClone(found) : undefined;
  }

  async listActions(incidentId: string): Promise<ResponseAction[]> {
    this.check();
    return structuredClone(this.actions.filter(a => a.incidentId === incidentId));
  }

  async approveAction(id: string, approver: string): Promise<ResponseAction | undefined> {
    this.check();
    const row = this.actions.find(a => a.id === id);
    if (!row || row.status !== 'proposed' || row.expiresAt <= this.clock()) {
      return undefined;
    }
    row.status = 'approved';
    row.approvedBy = approver;
    row.approvedAt = this.clock();
    return structuredClone(row);
  }

  async markAutoApproved(id: string): Promise<ResponseAction | undefined> {
    return this.approveAction(id, 'auto');
  }

  async finishAction(
    id: string,
    status: Extract<ResponseActionStatus, 'completed' | 'dry_run_completed' | 'failed'>,
    result: ActionResult
  ): Promise<void> {
    this.check();
    const row = this.actions.find(a => a.id === id);
    if (row && row.status === 'approved') {
      row.status = status;
      row.result = structuredClone(result);
      row.executor = result.executor;
      row.executedAt = this.clock();
    }
  }

  async expireDue(incidentId?: string): Promise<ResponseAction[]> {
    this.check();
    const due = this.actions.filter(
      a =>
        a.status === 'proposed' &&
        a.expiresAt <= this.clock() &&
        (!incidentId || a.incidentId === incidentId)
    );
    for (const row of due) {
      row.status = 'expired';
    }
    return structuredClone(due);
  }

  async cancelProposed(incidentId: string, type?: ResponseActionType): Promise<ResponseAction[]> {
    this.check();
    const due = this.actions.filter(
      a => a.incidentId === incidentId && a.status === 'proposed' && (!type || a.type === type)
    );
    for (const row of due) {
      row.status = 'cancelled';
    }
    return structuredClone(due);
  }

  async appendAudit(entry: AuditEntry): Promise<void> {
    this.check();
    this.audit.push(Object.freeze(structuredClone(entry)));
  }

  async findIncidentEmail(
    messageId: string
  ): Promise<{ incidentId: string; proposed: string[] } | undefined> {
    this.check();
    const entry = [...this.audit]
      .reverse()
      .find(e => e.event === 'incident_email_sent' && e.detail?.messageId === messageId);
    return entry
      ? { incidentId: entry.incidentId, proposed: (entry.detail?.proposed as string[]) ?? [] }
      : undefined;
  }

  events(): string[] {
    return this.audit.map(entry => entry.event);
  }
}

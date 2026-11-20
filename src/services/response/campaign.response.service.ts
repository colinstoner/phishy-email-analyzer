/**
 * Campaign response: what Phishy does once it knows an attack is hitting
 * several people.
 *
 * Off by default (`campaignResponse.enabled`). When on, a campaign that
 * crosses the alert threshold becomes an **incident**:
 *
 * 1. the security team gets an incident email built for a decision (what the
 *    attack is, timeline, blast radius, what Phishy has done, proposed
 *    actions with the exact reply that approves each);
 * 2. the people blast radius found get a targeted warning, one email each,
 *    either after a security-team approval (`employeeWarning: approve`, the
 *    default) or at once (`auto`); the people who reported it get a shorter
 *    thank-you note; the distribution list gets its broadcast as before
 *    (`distributionWarning: auto`) unless the operator changes that;
 * 3. "remove remaining copies" is proposed with a scope of exact message IDs
 *    per mailbox; approving it runs a DRY RUN only (no Graph write exists);
 * 4. later reports and wider reach update the incident in the same thread,
 *    rate-limited.
 *
 * Trust rules:
 * - Approvals arrive only through the command channel (security-team
 *   membership AND SES SPF/DKIM PASS, checked there) and are re-checked here
 *   against the security team; they name an unguessable action reference
 *   and are idempotent (one conditional UPDATE).
 * - Every address emailed is on a configured safe domain (invariant 4,
 *   extended to blast-radius recipients), checked when the scope is computed
 *   and again when each email is sent. Warnings go one per person; the
 *   attack's links are never included and its strings are defanged.
 * - A missing migration degrades to the campaign alert's behaviour without
 *   campaign response.
 */

import { createLogger } from '../../utils/logger';
import { emitCampaignResponseMetric } from '../../utils/metrics';
import type { CampaignResponseConfig } from '../../config/schema';
import type { AnalysisResult, EmailSendResult, ExtractedEmailData } from '../../types';
import type { BlastRadiusReport } from '../graph/blast-radius.service';
import type { CampaignMatch, CampaignRecord } from '../intelligence/database.service';
import { computeCampaignSignature } from '../intelligence/database.service';
import type { ApprovalCommand } from '../commands/response.commands';
import type { ReportRisk } from '../../templates/report.html';
import {
  WarningContext,
  approvalLine,
  buildIncidentEmail,
} from '../../templates/campaign.response.html';
import { displayTime } from './display';
import {
  DryRunRemovalExecutor,
  RemovalExecutor,
  SesWarningExecutor,
  WarningMailer,
} from './executors';
import { generateReference } from './reference';
import { ResponseStore, ResponseStoreUnavailableError } from './response.store';
import {
  ActionAuthorization,
  ActionScope,
  CampaignIncident,
  FanoutIncidentInput,
  IncidentReach,
  IncidentSummary,
  ResponseAction,
  ResponseActionType,
  WarningScope,
} from './response.types';
import {
  computeRemovalScope,
  computeWarningScope,
  firstDelivery,
  isEmptyScope,
  isSafeRecipient,
  mergeReach,
  scopeHash,
} from './scope';

const logger = createLogger('campaign-response');

/** Sends the incident email and threaded updates to the security team */
export interface IncidentMailer extends WarningMailer {
  sendThreadedEmail(
    recipients: string[],
    subject: string,
    htmlBody: string,
    textBody: string,
    inReplyTo?: string
  ): Promise<EmailSendResult>;
}

export interface CampaignResponseDeps {
  store: ResponseStore;
  mailer: IncidentMailer;
  config: CampaignResponseConfig;
  safeDomains: string[];
  securityTeam: string[];
  distributionList?: string;
  /** The command channel is on, so approvals can arrive */
  commandsEnabled: boolean;
  /** The campaign alert's own broadcast: used when the response tables are missing */
  legacyAlert: (match: CampaignMatch) => Promise<boolean>;
  markCampaignAlerted: (campaignId: string) => Promise<void>;
  removalExecutor?: RemovalExecutor;
  now?: () => Date;
  newReference?: () => string;
}

export interface CampaignReportInput {
  match: CampaignMatch;
  campaign: CampaignRecord;
  risk: ReportRisk;
  analysis: Pick<AnalysisResult, 'summary' | 'indicators'>;
  emailData: Pick<ExtractedEmailData, 'subject' | 'forwardedHeaders'>;
  analysisId?: string;
  /** This report's blast-radius lookup, when one ran */
  blastRadius?: BlastRadiusReport;
  blastRadiusEnabled: boolean;
  getRemainingMs?: () => number | undefined;
}

export type CampaignResponseOutcome =
  | 'below_threshold'
  | 'opened'
  | 'updated'
  | 'unchanged'
  | 'update_deferred'
  | 'incident_closed'
  | 'fallback'
  | 'error';

/** The reply the command channel sends back to an approver */
export interface ApprovalReply {
  heading: string;
  body: string[];
}

const ADDRESS = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/;
const FORWARD_PREFIX = /^(?:\s*(?:fw|fwd|re)\s*:\s*)+/i;
const PHISHY = 'phishy';

function senderParts(from: string | undefined): { address?: string; name?: string } {
  if (!from) {
    return {};
  }
  const address = from.match(ADDRESS)?.[0]?.toLowerCase();
  const name = from
    .replace(/<[^>]*>/g, '')
    .replace(ADDRESS, '')
    .replace(/["']/g, '')
    .trim();
  return { address, ...(name ? { name: name.slice(0, 120) } : {}) };
}

function levelFor(score: number): string {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

/** Addresses already warned or thanked, or about to be (an approved action in flight) */
function contactedBy(actions: ResponseAction[], except?: string): Set<string> {
  const contacted = new Set<string>();
  for (const action of actions) {
    if (action.type !== 'send_warning' || action.id === except) {
      continue;
    }
    if (action.result) {
      for (const address of [...(action.result.warned ?? []), ...(action.result.thanked ?? [])]) {
        contacted.add(address.toLowerCase());
      }
    } else if (action.status === 'approved' && action.scope.kind === 'send_warning') {
      for (const recipient of action.scope.recipients) {
        contacted.add(recipient.address);
      }
      for (const reporter of action.scope.reporters) {
        contacted.add(reporter);
      }
    }
  }
  return contacted;
}

function distributionDone(actions: ResponseAction[], except?: string): boolean {
  return actions.some(
    action =>
      action.id !== except &&
      action.type === 'send_warning' &&
      action.scope.kind === 'send_warning' &&
      action.scope.distribution &&
      (action.result ? action.result.distributionSent === true : action.status === 'approved')
  );
}

function actionTitle(type: ResponseActionType): string {
  return type === 'send_warning' ? 'targeted warning' : 'removal of remaining copies (dry run)';
}

export class CampaignResponseService {
  private readonly store: ResponseStore;
  private readonly now: () => Date;
  private readonly newReference: () => string;
  private readonly warningExecutor: SesWarningExecutor;
  private readonly removalExecutor: RemovalExecutor;

  constructor(private readonly deps: CampaignResponseDeps) {
    this.store = deps.store;
    this.now = deps.now ?? ((): Date => new Date());
    this.newReference = deps.newReference ?? ((): string => generateReference());
    this.warningExecutor = new SesWarningExecutor(deps.mailer);
    this.removalExecutor = deps.removalExecutor ?? new DryRunRemovalExecutor();
  }

  private get config(): CampaignResponseConfig {
    return this.deps.config;
  }

  // -------------------------------------------------------------------------
  // Trigger 1: employee reports
  // -------------------------------------------------------------------------

  /**
   * Called for every malicious report the campaign tracker counted, after
   * the reports have been sent. Opens the incident when the campaign has
   * just crossed the threshold, updates it afterwards. Never throws.
   */
  async handleCampaignReport(input: CampaignReportInput): Promise<CampaignResponseOutcome> {
    try {
      const existing = await this.store.getIncidentBySignature(input.match.signature);
      if (!existing) {
        if (!input.match.shouldAlert) {
          return 'below_threshold';
        }
        return await this.open(input);
      }
      return await this.update(existing, input);
    } catch (error) {
      if (error instanceof ResponseStoreUnavailableError) {
        // Migration 006 missing: exactly the campaign alert without campaign response
        if (input.match.shouldAlert) {
          await this.deps.legacyAlert(input.match);
        }
        return 'fallback';
      }
      logger.error('Campaign response failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      return 'error';
    }
  }

  private summaryFrom(input: CampaignReportInput, previous?: IncidentSummary): IncidentSummary {
    const forwarded = input.emailData.forwardedHeaders ?? {};
    const sender = senderParts(forwarded['Original-From']);
    const criteria = input.blastRadius?.criteria;
    const subject =
      criteria?.subject ??
      forwarded['Original-Subject'] ??
      (input.emailData.subject ?? '').replace(FORWARD_PREFIX, '').trim();
    const nowIso = this.now().toISOString();
    return {
      verdict: input.risk.verdict,
      riskScore: input.risk.riskScore,
      riskLevel: input.risk.riskLevel,
      ...(input.risk.confidence ? { confidence: input.risk.confidence } : {}),
      ...(input.risk.confidenceBasis ? { confidenceBasis: input.risk.confidenceBasis } : {}),
      reasons: [...(input.analysis.indicators ?? []), ...input.risk.reasons].slice(0, 5),
      ...(input.analysis.summary ? { lure: input.analysis.summary.slice(0, 1000) } : {}),
      ...(subject
        ? { subject: subject.slice(0, 300) }
        : previous?.subject
          ? { subject: previous.subject }
          : {}),
      ...((criteria?.senderAddress ?? sender.address ?? previous?.senderAddress)
        ? { senderAddress: criteria?.senderAddress ?? sender.address ?? previous?.senderAddress }
        : {}),
      ...((sender.name ?? previous?.senderName)
        ? { senderName: sender.name ?? previous?.senderName }
        : {}),
      firstReportAt:
        previous?.firstReportAt ??
        (input.campaign.firstSeenAt instanceof Date
          ? input.campaign.firstSeenAt.toISOString()
          : nowIso),
      lastReportAt: nowIso,
      reporters: (input.campaign.uniqueRecipients ?? [])
        .map(address => address.trim().toLowerCase())
        .slice(0, 200),
      ...((input.analysisId ?? previous?.analysisId)
        ? { analysisId: input.analysisId ?? previous?.analysisId }
        : {}),
      detectedBy: previous?.detectedBy.startsWith('fan-out scan')
        ? 'fan-out scan, then employee reports'
        : (previous?.detectedBy ?? 'employee reports (the campaign alert threshold)'),
    };
  }

  private withDelivery(summary: IncidentSummary, reach: IncidentReach): IncidentSummary {
    const first = firstDelivery(reach);
    const earliest =
      first && summary.firstDeliveryAt
        ? Date.parse(first) < Date.parse(summary.firstDeliveryAt)
          ? first
          : summary.firstDeliveryAt
        : (first ?? summary.firstDeliveryAt);
    return earliest ? { ...summary, firstDeliveryAt: earliest } : summary;
  }

  private async open(input: CampaignReportInput): Promise<CampaignResponseOutcome> {
    const reach = mergeReach(undefined, input.blastRadius, input.blastRadiusEnabled);
    const summary = this.withDelivery(this.summaryFrom(input), reach);
    const { incident, created } = await this.store.createIncident({
      campaignId: input.campaign.id,
      campaignSignature: input.match.signature,
      reference: this.newReference(),
      trigger: 'reports',
      summary,
      reach,
      reportCount: input.match.detectionCount,
    });
    if (!created) {
      return this.update(incident, input);
    }
    await this.store.appendAudit({
      incidentId: incident.id,
      event: 'incident_opened',
      actor: PHISHY,
      detail: {
        trigger: 'reports',
        reports: incident.reportCount,
        recipients: reach.totals.recipients,
      },
    });
    emitCampaignResponseMetric('CampaignIncidentsOpened', 1, { Trigger: 'reports' });
    logger.info('Campaign incident opened', {
      incidentId: incident.id,
      reports: incident.reportCount,
      recipients: reach.totals.recipients,
      reachStatus: reach.status,
    });

    await this.respond(incident, {
      done: ['Sent each reporter their own analysis.'],
      forceApprove: false,
      getRemainingMs: input.getRemainingMs,
    });
    if (input.campaign.id) {
      await this.deps.markCampaignAlerted(input.campaign.id);
    }
    return 'opened';
  }

  private async update(
    stored: CampaignIncident,
    input: CampaignReportInput
  ): Promise<CampaignResponseOutcome> {
    const reportCount = Math.max(input.match.detectionCount, stored.reportCount);
    if (stored.status !== 'open') {
      await this.store.updateIncident(stored.id, { reportCount });
      return 'incident_closed';
    }
    const reach = mergeReach(stored.reach, input.blastRadius, input.blastRadiusEnabled);
    const summary = this.withDelivery(this.summaryFrom(input, stored.summary), reach);
    await this.store.updateIncident(stored.id, { reach, summary, reportCount });
    const incident: CampaignIncident = { ...stored, reach, summary, reportCount };

    const expired = await this.expire(incident);
    const changes: string[] = [];
    if (reportCount > incident.notifiedReportCount) {
      changes.push(
        `${reportCount - incident.notifiedReportCount} new report(s) since the last email (${reportCount} in all).`
      );
    }
    if (reach.totals.recipients > incident.notifiedRecipientCount) {
      changes.push(
        `Blast radius now ${reach.totals.recipients} recipient(s) (was ${incident.notifiedRecipientCount}).`
      );
    }
    if (expired.length > 0) {
      changes.push(`${expired.length} proposed action(s) expired without approval.`);
    }
    if (changes.length === 0) {
      return 'unchanged';
    }

    const intervalMs = this.config.updateIntervalMinutes * 60_000;
    // An incident whose first email has not gone yet (a report racing the one
    // that opened it) counts from its creation, so it is not emailed twice
    const last = (incident.lastUpdateSentAt ?? incident.createdAt).getTime();
    if (this.now().getTime() - last < intervalMs) {
      // Folded into the next update; proposals are not changed without one
      return 'update_deferred';
    }

    await this.respond(incident, {
      done: [],
      changes,
      forceApprove: incident.trigger === 'fanout_scan' && incident.reportCount === 0,
      getRemainingMs: input.getRemainingMs,
    });
    return 'updated';
  }

  // -------------------------------------------------------------------------
  // Trigger 2: the behaviour-based fan-out scan
  // -------------------------------------------------------------------------

  /**
   * Open an incident for an alert raised before anyone reported the message
   * (a campaign with zero reports). For the scheduled fan-out scan to call.
   * Nothing is sent to employees without a security-team approval on this
   * path, whatever `employeeWarning` says: there is no model verdict yet.
   * Reports of the same message later join the incident (same campaign
   * signature) and update it. Never throws; undefined when the response
   * tables are missing or the incident could not be opened.
   */
  async openIncidentFromFanoutAlert(
    input: FanoutIncidentInput
  ): Promise<{ incidentId: string; reference: string; created: boolean } | undefined> {
    try {
      const signature =
        input.campaignSignature ??
        computeCampaignSignature(this.deps.safeDomains[0] ?? 'unknown', input.subject);
      const reach = mergeReach(undefined, input.reach, true);
      const score = Math.max(0, Math.min(100, Math.round(input.riskScore ?? 50)));
      const sender = senderParts(
        input.senderName ? `${input.senderName} <${input.senderAddress}>` : input.senderAddress
      );
      const summary: IncidentSummary = this.withDelivery(
        {
          verdict: 'suspicious',
          riskScore: score,
          riskLevel: levelFor(score),
          confidenceBasis: 'unassessed',
          reasons: input.reasons.slice(0, 5),
          subject: input.subject.slice(0, 300),
          ...(sender.address ? { senderAddress: sender.address } : {}),
          ...(sender.name ? { senderName: sender.name } : {}),
          ...(input.firstDeliveryAt ? { firstDeliveryAt: input.firstDeliveryAt } : {}),
          detectedBy: 'fan-out scan (no reports yet)',
        },
        reach
      );
      const { incident, created } = await this.store.createIncident({
        campaignSignature: signature,
        reference: this.newReference(),
        trigger: 'fanout_scan',
        summary,
        reach,
        reportCount: 0,
      });
      if (!created) {
        const merged = mergeReach(incident.reach, input.reach, true);
        await this.store.updateIncident(incident.id, { reach: merged });
        return { incidentId: incident.id, reference: incident.reference, created: false };
      }
      await this.store.appendAudit({
        incidentId: incident.id,
        event: 'incident_opened',
        actor: PHISHY,
        detail: { trigger: 'fanout_scan', recipients: reach.totals.recipients },
      });
      emitCampaignResponseMetric('CampaignIncidentsOpened', 1, { Trigger: 'fanout_scan' });
      await this.respond(incident, { done: [], forceApprove: true });
      return { incidentId: incident.id, reference: incident.reference, created: true };
    } catch (error) {
      logger.error('Could not open an incident from the fan-out alert', {
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }

  // -------------------------------------------------------------------------
  // Planning, the incident email, auto actions
  // -------------------------------------------------------------------------

  private async expire(incident: CampaignIncident): Promise<ResponseAction[]> {
    const expired = await this.store.expireDue(incident.id);
    for (const action of expired) {
      await this.store.appendAudit({
        incidentId: incident.id,
        actionId: action.id,
        event: 'action_expired',
        actor: PHISHY,
        detail: { type: action.type, expiresAt: action.expiresAt.toISOString() },
      });
      emitCampaignResponseMetric('ResponseActionsExpired', 1, { ActionType: action.type });
    }
    return expired;
  }

  private modes(
    incident: CampaignIncident,
    forceApprove: boolean
  ): {
    targeted: 'off' | 'approve' | 'auto';
    distribution: 'off' | 'approve' | 'auto';
    notes: string[];
  } {
    const notes: string[] = [];
    const audience = this.config.audience;
    let targeted: 'off' | 'approve' | 'auto' =
      audience === 'distribution' ? 'off' : this.config.employeeWarning;
    let distribution: 'off' | 'approve' | 'auto' =
      audience === 'recipients' ? 'off' : this.config.distributionWarning;
    if (distribution !== 'off' && !this.deps.distributionList) {
      notes.push(
        'No distribution list is configured (PHISHY_CAMPAIGN_ALERTS_DISTRIBUTION), so no broadcast was sent or proposed.'
      );
      distribution = 'off';
    }
    if (targeted !== 'off' && incident.reach.status === 'not_enabled') {
      notes.push(
        'No targeted warning is possible: blast radius is not enabled, so Phishy does not know who received it.'
      );
      targeted = 'off';
    }
    if (forceApprove) {
      targeted = targeted === 'auto' ? 'approve' : targeted;
      distribution = distribution === 'auto' ? 'approve' : distribution;
    }
    return { targeted, distribution, notes };
  }

  private async propose(
    incident: CampaignIncident,
    type: ResponseActionType,
    scope: ActionScope,
    authorization: ActionAuthorization,
    existing: ResponseAction[]
  ): Promise<ResponseAction | undefined> {
    const hash = scopeHash(scope);
    if (authorization === 'approve') {
      const same = existing.find(
        a =>
          a.type === type &&
          a.status === 'proposed' &&
          a.scopeHash === hash &&
          a.expiresAt > this.now()
      );
      if (same) {
        return same; // nothing changed: keep its reference
      }
      if (
        type === 'remove_messages' &&
        existing.some(
          a => a.type === type && a.status === 'dry_run_completed' && a.scopeHash === hash
        )
      ) {
        return undefined; // that exact scope was already dry-run
      }
      for (const cancelled of await this.store.cancelProposed(incident.id, type)) {
        await this.store.appendAudit({
          incidentId: incident.id,
          actionId: cancelled.id,
          event: 'action_cancelled',
          actor: PHISHY,
          detail: { reason: 'superseded' },
        });
      }
    }
    const action = await this.store.createAction({
      incidentId: incident.id,
      reference: this.newReference(),
      type,
      authorization,
      scope,
      scopeHash: hash,
      expiresAt: new Date(this.now().getTime() + this.config.approvalTtlHours * 3_600_000),
    });
    await this.store.appendAudit({
      incidentId: incident.id,
      actionId: action.id,
      event: 'action_proposed',
      actor: PHISHY,
      detail: { type, authorization, scopeHash: hash, ...this.scopeCounts(scope) },
    });
    emitCampaignResponseMetric('ResponseActionsProposed', 1, { ActionType: type });
    return action;
  }

  private scopeCounts(scope: ActionScope): Record<string, number | boolean> {
    return scope.kind === 'send_warning'
      ? {
          recipients: scope.recipients.length,
          reporters: scope.reporters.length,
          distribution: scope.distribution,
        }
      : { mailboxes: scope.mailboxes.length, messages: scope.messageCount };
  }

  private warningScope(
    incident: CampaignIncident,
    actions: ResponseAction[],
    targeted: boolean,
    distribution: boolean,
    extraContacted: Set<string> = new Set()
  ): WarningScope {
    const contacted = contactedBy(actions);
    for (const address of extraContacted) {
      contacted.add(address);
    }
    return computeWarningScope({
      reach: incident.reach,
      reporters:
        incident.trigger === 'fanout_scan' && incident.reportCount === 0
          ? []
          : this.reportersOf(incident),
      safeDomains: this.deps.safeDomains,
      alreadyContacted: contacted,
      remaining: this.config.maxWarningsPerCampaign - contacted.size,
      targeted,
      distribution: distribution && !distributionDone(actions),
    });
  }

  private reportersOf(incident: CampaignIncident): string[] {
    return incident.summary.reporters ?? [];
  }

  /**
   * Work out the actions for the incident's current state, send the incident
   * email (or the threaded update), then run whatever `auto` allows.
   */
  private async respond(
    incident: CampaignIncident,
    options: {
      done: string[];
      changes?: string[];
      forceApprove: boolean;
      getRemainingMs?: () => number | undefined;
    }
  ): Promise<void> {
    const modes = this.modes(incident, options.forceApprove);
    const actions = await this.store.listActions(incident.id);
    const done = [...options.done, ...this.history(actions)];
    const notes = [...modes.notes];

    // Auto parts first (computed now, executed after the email has gone)
    let auto: ResponseAction | undefined;
    const autoScope = this.warningScope(
      incident,
      actions,
      modes.targeted === 'auto',
      modes.distribution === 'auto'
    );
    if (!isEmptyScope(autoScope)) {
      auto = await this.propose(incident, 'send_warning', autoScope, 'auto', actions);
      if (auto) {
        auto = (await this.store.markAutoApproved(auto.id)) ?? auto;
        done.push(this.autoLine(autoScope));
      }
    }

    // Approval parts
    const autoContacted = new Set([
      ...autoScope.recipients.map(r => r.address),
      ...autoScope.reporters,
    ]);
    const approveScope = this.warningScope(
      incident,
      actions,
      modes.targeted === 'approve',
      modes.distribution === 'approve' && !autoScope.distribution,
      autoContacted
    );
    if (!isEmptyScope(approveScope)) {
      await this.propose(incident, 'send_warning', approveScope, 'approve', actions);
    } else if (
      modes.targeted !== 'off' &&
      autoScope.recipients.length === 0 &&
      incident.reach.recipients.length === 0
    ) {
      notes.push(
        'No targeted warning was proposed: the blast-radius lookup has not found any recipient yet.'
      );
    }

    const removal = computeRemovalScope(incident.reach, {
      maxMailboxes: this.config.maxRemovalMailboxes,
      maxMessages: this.config.maxRemovalMessages,
    });
    if (!isEmptyScope(removal)) {
      await this.propose(incident, 'remove_messages', removal, 'approve', actions);
    }

    const current = await this.store.listActions(incident.id);
    const proposed = current.filter(a => a.status === 'proposed' && a.authorization === 'approve');
    if (proposed.length > 0) {
      done.push(
        this.deps.commandsEnabled
          ? 'The proposed actions below are waiting for your approval.'
          : 'Actions are proposed below, but approvals cannot be received while the command channel is off.'
      );
    }

    await this.sendIncidentEmail(incident, { proposed, done, notes, changes: options.changes });

    if (auto?.scope.kind === 'send_warning') {
      await this.runWarning(incident, auto, auto.scope, options.getRemainingMs);
    }
  }

  private autoLine(scope: WarningScope): string {
    const parts: string[] = [];
    if (scope.recipients.length) {
      parts.push(`the warning to ${scope.recipients.length} recipient(s)`);
    }
    if (scope.reporters.length) {
      parts.push(`a thank-you note to ${scope.reporters.length} reporter(s)`);
    }
    if (scope.distribution) {
      parts.push('the warning to the distribution list');
    }
    return `Sending ${parts.join(', ')} now (set to send automatically).`;
  }

  /** What earlier actions did, one line each */
  private history(actions: ResponseAction[]): string[] {
    const lines: string[] = [];
    for (const action of actions) {
      if (!action.result) {
        continue;
      }
      const by =
        action.approvedBy && action.approvedBy !== 'auto'
          ? `approved by ${action.approvedBy}`
          : 'sent automatically';
      const at = action.executedAt
        ? ` at ${displayTime(action.executedAt.toISOString(), this.config.timeZone) ?? ''}`
        : '';
      if (action.type === 'send_warning') {
        const r = action.result;
        lines.push(
          `Warned ${r.warned?.length ?? 0} recipient(s) and thanked ${r.thanked?.length ?? 0} reporter(s)${r.distributionSent ? ', and warned the distribution list' : ''} (${by}${at}).${r.failed ? ` ${r.failed} email(s) failed.` : ''}`
        );
      } else {
        const counts = action.result.wouldRemove;
        lines.push(
          `Ran the removal dry run (${by}${at}): it would remove ${counts?.messages ?? 0} message(s) from ${counts?.mailboxes ?? 0} mailbox(es). No mailbox was changed.`
        );
      }
    }
    return lines;
  }

  private async sendIncidentEmail(
    incident: CampaignIncident,
    content: { proposed: ResponseAction[]; done: string[]; notes: string[]; changes?: string[] }
  ): Promise<void> {
    const team = this.deps.securityTeam;
    if (team.length === 0) {
      logger.warn(
        'Campaign incident has no security team to tell (notification.securityTeamDistribution is empty)'
      );
      return;
    }
    const email = buildIncidentEmail({
      incident,
      proposed: content.proposed,
      done: content.done,
      notes: content.notes,
      ...(content.changes ? { changes: content.changes } : {}),
      commandsEnabled: this.deps.commandsEnabled,
      timeZone: this.config.timeZone,
    });
    let result: EmailSendResult;
    try {
      result =
        content.changes && incident.threadMessageId
          ? await this.deps.mailer.sendThreadedEmail(
              team,
              email.subject,
              email.html,
              email.text,
              incident.threadMessageId
            )
          : await this.deps.mailer.sendEmail(
              team[0],
              email.subject,
              email.html,
              email.text,
              team.slice(1)
            );
    } catch (error) {
      result = { success: false, error: error instanceof Error ? error.message : String(error) };
    }
    if (!result.success) {
      logger.error('Campaign incident email was not sent', {
        incidentId: incident.id,
        error: result.error,
      });
      return;
    }
    await this.store.updateIncident(incident.id, {
      ...(incident.threadMessageId || !result.messageId
        ? {}
        : { threadMessageId: result.messageId }),
      lastUpdateSentAt: this.now(),
      notifiedReportCount: incident.reportCount,
      notifiedRecipientCount: incident.reach.totals.recipients,
    });
    if (content.changes) {
      await this.store.appendAudit({
        incidentId: incident.id,
        event: 'incident_updated',
        actor: PHISHY,
        detail: { reports: incident.reportCount, recipients: incident.reach.totals.recipients },
      });
      emitCampaignResponseMetric('CampaignIncidentUpdates', 1);
    }
  }

  private warningContext(
    incident: CampaignIncident,
    confirmedBy: WarningContext['confirmedBy']
  ): Omit<WarningContext, 'warnedCount'> {
    return {
      summary: incident.summary,
      reportCount: incident.reportCount,
      timeZone: this.config.timeZone,
      alreadyClickedInstructions: this.config.alreadyClickedInstructions,
      incidentReference: incident.reference,
      confirmedBy,
    };
  }

  private async runWarning(
    incident: CampaignIncident,
    action: ResponseAction,
    scope: WarningScope,
    getRemainingMs?: () => number | undefined
  ): Promise<string[]> {
    const confirmedBy = action.authorization === 'approve' ? 'security_team' : 'phishy';
    try {
      const result = await this.warningExecutor.execute(scope, {
        incident,
        warning: this.warningContext(incident, confirmedBy),
        safeDomains: this.deps.safeDomains,
        distributionList: this.deps.distributionList,
        getRemainingMs,
      });
      await this.store.finishAction(action.id, 'completed', result);
      await this.store.appendAudit({
        incidentId: incident.id,
        actionId: action.id,
        event: 'action_executed',
        actor: action.approvedBy ?? PHISHY,
        detail: {
          executor: result.executor,
          warned: result.warned?.length ?? 0,
          thanked: result.thanked?.length ?? 0,
          distributionSent: result.distributionSent ?? false,
          failed: result.failed ?? 0,
          notSentForTime: result.notSentForTime ?? 0,
        },
      });
      return result.summary;
    } catch (error) {
      logger.error('Campaign warning failed', {
        incidentId: incident.id,
        error: error instanceof Error ? error.message : String(error),
      });
      await this.store.finishAction(action.id, 'failed', {
        executor: this.warningExecutor.name,
        dryRun: false,
        summary: ['The warning could not be sent.'],
      });
      await this.store.appendAudit({
        incidentId: incident.id,
        actionId: action.id,
        event: 'action_failed',
        actor: PHISHY,
      });
      return ['The warning could not be sent. See the logs.'];
    }
  }

  // -------------------------------------------------------------------------
  // Approvals (from the command channel)
  // -------------------------------------------------------------------------

  private isSecurityTeam(address: string): boolean {
    const sender = address.trim().toLowerCase();
    return this.deps.securityTeam.some(member => member.trim().toLowerCase() === sender);
  }

  /**
   * Carry out approvals the command channel has authenticated (security-team
   * membership AND SPF/DKIM PASS) and parsed strictly. Each names an action
   * by its reference. Never throws.
   */
  async handleApprovals(
    commands: ApprovalCommand[],
    approver: string,
    getRemainingMs?: () => number | undefined
  ): Promise<ApprovalReply> {
    if (!this.isSecurityTeam(approver)) {
      // The channel checked this already; a second check costs nothing
      emitCampaignResponseMetric('ResponseActionApprovalsRejected', 1, {
        Reason: 'not_security_team',
      });
      return {
        heading: 'Phishy did not act on that approval',
        body: ['You are not on the security team.'],
      };
    }
    const body: string[] = [];
    let acted = false;
    for (const command of commands) {
      try {
        const lines = await this.approve(command, approver.trim().toLowerCase(), getRemainingMs);
        acted = acted || lines.acted;
        body.push(...lines.body, '');
      } catch (error) {
        if (error instanceof ResponseStoreUnavailableError) {
          return {
            heading: 'Phishy could not act on that approval',
            body: [
              `Campaign response is not available: apply migrations/006_campaign_response.sql.`,
            ],
          };
        }
        logger.error('Approval failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        body.push(
          `${command.reference}: Phishy could not process this approval. Nothing was done.`,
          ''
        );
      }
    }
    return {
      heading: acted ? 'Done: approval carried out' : 'Phishy did not carry out an approval',
      body: body.length ? body : ['Nothing to do.'],
    };
  }

  private async reject(
    action: ResponseAction | undefined,
    incidentId: string | undefined,
    reason: string,
    approver: string
  ): Promise<void> {
    emitCampaignResponseMetric('ResponseActionApprovalsRejected', 1, {
      ActionType: action?.type ?? 'unknown',
      Reason: reason,
    });
    if (incidentId) {
      await this.store.appendAudit({
        incidentId,
        ...(action ? { actionId: action.id } : {}),
        event: 'approval_rejected',
        actor: approver,
        detail: { reason },
      });
    }
  }

  private async approve(
    command: ApprovalCommand,
    approver: string,
    getRemainingMs?: () => number | undefined
  ): Promise<{ acted: boolean; body: string[] }> {
    const action = await this.store.getActionByReference(command.reference);
    const expected: ResponseActionType =
      command.verb === 'WARNING' ? 'send_warning' : 'remove_messages';
    if (!action) {
      await this.reject(undefined, undefined, 'unknown_reference', approver);
      return {
        acted: false,
        body: [
          `${command.reference}: no proposed action has this reference. Use the reference from the latest incident email.`,
        ],
      };
    }
    const incident = await this.store.getIncident(action.incidentId);
    if (!incident) {
      await this.reject(action, undefined, 'unknown_incident', approver);
      return {
        acted: false,
        body: [
          `${command.reference}: the incident for this action was not found. Nothing was done.`,
        ],
      };
    }
    if (action.type !== expected) {
      await this.reject(action, incident.id, 'wrong_type', approver);
      return {
        acted: false,
        body: [
          `${command.reference} is not a ${actionTitle(expected)}. Nothing was done. Check the line in the incident email.`,
        ],
      };
    }
    if (incident.status !== 'open') {
      await this.reject(action, incident.id, 'incident_closed', approver);
      return {
        acted: false,
        body: [
          `${command.reference}: incident ${incident.reference} is ${incident.status === 'false_positive' ? 'marked a false positive' : 'closed'}. Nothing was done.`,
        ],
      };
    }
    if (action.status !== 'proposed') {
      return this.alreadyHandled(action, incident, approver);
    }
    if (action.expiresAt <= this.now()) {
      return this.expired(action, incident, approver);
    }

    const approved = await this.store.approveAction(action.id, approver);
    if (!approved) {
      // Approved by someone else a moment ago, or expired in between
      const latest = (await this.store.getActionByReference(command.reference)) ?? action;
      return latest.status === 'proposed' || latest.status === 'expired'
        ? this.expired(latest, incident, approver)
        : this.alreadyHandled(latest, incident, approver);
    }
    await this.store.appendAudit({
      incidentId: incident.id,
      actionId: approved.id,
      event: 'action_approved',
      actor: approver,
      detail: { scopeHash: approved.scopeHash },
    });
    emitCampaignResponseMetric('ResponseActionApprovals', 1, { ActionType: approved.type });
    logger.info('Response action approved', {
      incidentId: incident.id,
      actionId: approved.id,
      type: approved.type,
    });

    const heading = `Approved: ${actionTitle(approved.type)} for incident ${incident.reference} (${approved.reference}).`;
    if (approved.scope.kind === 'send_warning') {
      const scope = this.recheckWarning(approved, await this.store.listActions(incident.id));
      const summary = await this.runWarning(incident, approved, scope, getRemainingMs);
      return { acted: true, body: [heading, ...summary] };
    }

    // remove_messages: the dry run, against the incident's latest reach
    try {
      const result = await this.removalExecutor.execute(approved, approved.scope, incident.reach);
      await this.store.finishAction(
        approved.id,
        result.dryRun ? 'dry_run_completed' : 'completed',
        result
      );
      await this.store.appendAudit({
        incidentId: incident.id,
        actionId: approved.id,
        event: result.dryRun ? 'action_dry_run' : 'action_executed',
        actor: approver,
        detail: { executor: result.executor, ...(result.wouldRemove ?? {}) },
      });
      return { acted: true, body: [heading, ...result.summary] };
    } catch (error) {
      logger.error('Removal dry run failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      await this.store.finishAction(approved.id, 'failed', {
        executor: this.removalExecutor.name,
        dryRun: true,
        summary: ['The dry run could not be completed.'],
      });
      return {
        acted: false,
        body: [heading, 'The dry run could not be completed. No mailbox was changed.'],
      };
    }
  }

  /**
   * Re-check an approved warning before sending: only people the approved
   * scope named, still on a safe domain, not contacted since, within the
   * cap. Never adds anyone.
   */
  private recheckWarning(action: ResponseAction, actions: ResponseAction[]): WarningScope {
    const scope = action.scope as WarningScope;
    const contacted = contactedBy(actions, action.id);
    let remaining = Math.max(0, this.config.maxWarningsPerCampaign - contacted.size);
    const keep = (address: string): boolean => {
      if (
        remaining <= 0 ||
        contacted.has(address) ||
        !isSafeRecipient(address, this.deps.safeDomains)
      ) {
        return false;
      }
      remaining -= 1;
      return true;
    };
    return {
      ...scope,
      recipients: scope.recipients.filter(r => keep(r.address)),
      reporters: scope.reporters.filter(keep),
      distribution: scope.distribution && !distributionDone(actions, action.id),
    };
  }

  private async alreadyHandled(
    action: ResponseAction,
    incident: CampaignIncident,
    approver: string
  ): Promise<{ acted: boolean; body: string[] }> {
    await this.reject(
      action,
      incident.id,
      action.status === 'cancelled' ? 'superseded' : 'duplicate',
      approver
    );
    if (action.status === 'cancelled') {
      return {
        acted: false,
        body: [
          `${action.reference}: this proposal was replaced by a newer one. Nothing was done. Use the reference in the latest incident update.`,
        ],
      };
    }
    const when = action.approvedAt
      ? displayTime(action.approvedAt.toISOString(), this.config.timeZone)
      : undefined;
    return {
      acted: false,
      body: [
        `${action.reference}: already approved${action.approvedBy ? ` by ${action.approvedBy}` : ''}${when ? ` at ${when}` : ''}. Nothing was done again.`,
        ...(action.result?.summary ?? []),
      ],
    };
  }

  /** An approval that arrived too late: expire it and propose the same kind again */
  private async expired(
    action: ResponseAction,
    incident: CampaignIncident,
    approver: string
  ): Promise<{ acted: boolean; body: string[] }> {
    await this.expire(incident);
    await this.reject(action, incident.id, 'expired', approver);
    const expiredAt =
      displayTime(action.expiresAt.toISOString(), this.config.timeZone) ??
      action.expiresAt.toISOString();
    const actions = await this.store.listActions(incident.id);
    let scope: ActionScope;
    if (action.type === 'send_warning') {
      const modes = this.modes(incident, true);
      scope = this.warningScope(
        incident,
        actions,
        modes.targeted !== 'off',
        modes.distribution !== 'off'
      );
    } else {
      scope = computeRemovalScope(incident.reach, {
        maxMailboxes: this.config.maxRemovalMailboxes,
        maxMessages: this.config.maxRemovalMessages,
      });
    }
    const fresh = isEmptyScope(scope)
      ? undefined
      : await this.propose(incident, action.type, scope, 'approve', actions);
    if (!fresh) {
      return {
        acted: false,
        body: [
          `${action.reference}: this approval expired at ${expiredAt}. Nothing was done, and there is nothing left to propose.`,
        ],
      };
    }
    return {
      acted: false,
      body: [
        `${action.reference}: this approval expired at ${expiredAt}. Nothing was done.`,
        'Phishy re-checked the scope and proposed it again. To approve it, reply with this line, on a line of its own:',
        `  ${approvalLine(fresh)}`,
        `It is good until ${displayTime(fresh.expiresAt.toISOString(), this.config.timeZone) ?? fresh.expiresAt.toISOString()}.`,
      ],
    };
  }

  // -------------------------------------------------------------------------
  // Verdict feedback (the existing "false positive" command)
  // -------------------------------------------------------------------------

  /**
   * A security-team verdict on an analysis. A false positive closes the
   * campaign's incident and cancels its proposed actions. Returns a line for
   * the command reply, or undefined. Never throws.
   */
  async onVerdict(
    analysisId: string,
    verdict: 'confirmed_phishing' | 'false_positive',
    by: string
  ): Promise<string | undefined> {
    if (verdict !== 'false_positive') {
      return undefined;
    }
    try {
      const incident = await this.store.getIncidentForAnalysis(analysisId);
      if (incident?.status !== 'open') {
        return undefined;
      }
      await this.store.updateIncident(incident.id, { status: 'false_positive' });
      const cancelled = await this.store.cancelProposed(incident.id);
      await this.store.appendAudit({
        incidentId: incident.id,
        event: 'incident_false_positive',
        actor: by.trim().toLowerCase(),
        detail: { analysisId, cancelled: cancelled.length },
      });
      for (const action of cancelled) {
        await this.store.appendAudit({
          incidentId: incident.id,
          actionId: action.id,
          event: 'action_cancelled',
          actor: by.trim().toLowerCase(),
          detail: { reason: 'false_positive' },
        });
      }
      return `Incident ${incident.reference} is marked a false positive; ${cancelled.length} proposed action(s) cancelled. No further warning will be sent for it.`;
    } catch (error) {
      logger.warn('Could not apply the verdict to a campaign incident', {
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }
}

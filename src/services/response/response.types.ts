/**
 * Campaign response: the data model.
 *
 * An **incident** is a campaign Phishy is responding to: opened when a
 * campaign crosses the alert threshold (employee reports), when one
 * malicious report's blast radius shows enough reach (the reach trigger,
 * stored as `reports`), or by a
 * behaviour-based alert before anyone has reported it (the fan-out scan).
 * A **response action** is one thing Phishy may do about an incident, with a
 * scope computed by code, an approver, an approval window and a result.
 * Every state change is written to an append-only audit trail.
 *
 * The model is shaped so a mailbox write tier can be added later without
 * redesign: a removal action already names the exact Graph message IDs per
 * mailbox, its caps and its approver; only the executor differs (see
 * `executors.ts`). In this version the only removal executor is a dry run.
 */

import type {
  BlastRadiusFolder,
  BlastRadiusRecipient,
  BlastRadiusReport,
} from '../graph/blast-radius.service';

export type IncidentTrigger = 'reports' | 'fanout_scan';
export type IncidentStatus = 'open' | 'false_positive' | 'closed';

export type ResponseActionType = 'send_warning' | 'remove_messages';

/**
 * - `proposed`: waiting for a security-team approval until `expiresAt`
 * - `approved`: approved; the executor is running (or was interrupted)
 * - `completed`: the executor ran (warnings sent; see `result`)
 * - `dry_run_completed`: a dry-run executor ran; nothing was changed
 * - `expired`: not approved in time
 * - `cancelled`: superseded by a newer proposal, or the incident was ruled a false positive
 * - `failed`: the executor could not run
 */
export type ResponseActionStatus =
  'proposed' | 'approved' | 'completed' | 'dry_run_completed' | 'expired' | 'cancelled' | 'failed';

/** How an action is authorized: a security-team approval, or the operator's `auto` setting */
export type ActionAuthorization = 'approve' | 'auto';

/** One person a warning goes to. The address came from Phishy's own Graph lookup. */
export interface WarningRecipient {
  address: string;
  /** When their mailbox received the copy (ISO), when known */
  receivedAt?: string;
  folder?: BlastRadiusFolder;
}

export interface WarningSkips {
  /** Message trace says delivery failed, or the mailbox did not hold it */
  notDelivered: number;
  /** Address not on a configured safe domain, or not a plain address */
  unsafeAddress: number;
  /** Already emailed for this campaign (warned, sent a removal notice, or thanked by an earlier version) */
  alreadyContacted: number;
  /** Over `maxWarningsPerCampaign` */
  overCap: number;
  /** Counted by blast radius but not listed (the listing is capped), so no address is known */
  unlisted: number;
}

export interface WarningScope {
  kind: 'send_warning';
  /**
   * People who received the attack: each gets the warning, individually.
   * Reporters are never in it: they reported it themselves. (Scopes
   * stored by an earlier version may also carry a `reporters` list for a
   * thank-you note; it is ignored.)
   */
  recipients: WarningRecipient[];
  /** Also send the broadcast to the distribution list */
  distribution: boolean;
  skipped: WarningSkips;
}

/** One mailbox and the exact copies a removal would act on */
export interface RemovalMailbox {
  address: string;
  /** Entra directory object ID of the mailbox */
  mailboxId: string;
  /** Graph message IDs Phishy's blast-radius lookup matched for this campaign */
  messageIds: string[];
  folder: BlastRadiusFolder;
  isRead?: boolean;
}

export interface RemovalScope {
  kind: 'remove_messages';
  mailboxes: RemovalMailbox[];
  messageCount: number;
  limits: { maxMailboxes: number; maxMessages: number };
  skipped: {
    /** Found, but the lookup returned no usable mailbox or message ID */
    noIdentifiers: number;
    /** Already purged (Recoverable Items): nothing left to remove */
    alreadyPurged: number;
    overMailboxCap: number;
    overMessageCap: number;
  };
  /** When the blast-radius data behind this scope was looked up */
  reachLookedUpAt?: string;
}

export type ActionScope = WarningScope | RemovalScope;

export interface ResponseAction {
  id: string;
  incidentId: string;
  /** Unguessable reference the security team quotes to approve it */
  reference: string;
  type: ResponseActionType;
  status: ResponseActionStatus;
  authorization: ActionAuthorization;
  scope: ActionScope;
  /** SHA-256 of the canonical scope: what was approved is exactly what was proposed */
  scopeHash: string;
  proposedAt: Date;
  expiresAt: Date;
  approvedBy?: string;
  approvedAt?: Date;
  executedAt?: Date;
  executor?: string;
  result?: ActionResult;
}

/** What an executor did. Counts and code-written lines; addresses only where listed. */
export interface ActionResult {
  /** Executor name, e.g. `ses_warning` or `dry_run_removal` */
  executor: string;
  /** True when the executor changed nothing (a dry run) */
  dryRun: boolean;
  summary: string[];
  /** Warnings: who was emailed (so nobody is emailed twice) */
  warned?: string[];
  /**
   * Reporters sent a thank-you note by an earlier version (the note no
   * longer exists). Only read: still counted as already contacted.
   */
  thanked?: string[];
  distributionSent?: boolean;
  failed?: number;
  notSentForTime?: number;
  /** Removal dry run: what it would do */
  wouldRemove?: RemovalCounts;
  /**
   * A real (non-dry-run) removal: the mailboxes a copy was actually moved
   * out of, as the executor reports them. Only the future write tier sets
   * it; the dry-run executor never does. Removal notices go only to these.
   */
  removed?: RemovedMailbox[];
  /** Removal notices: who was emailed (so nobody gets one twice) */
  notified?: string[];
  noticesFailed?: number;
  noticesNotSentForTime?: number;
}

/** One mailbox a removal executor actually moved copies out of */
export interface RemovedMailbox {
  /** Entra directory object ID: must be a mailbox the approved scope named */
  mailboxId: string;
  /** Copies moved to Deleted Items in this mailbox (a notice needs at least 1) */
  messages: number;
}

export interface RemovalCounts {
  mailboxes: number;
  messages: number;
  unreadInInbox: number;
  readInInbox: number;
  inJunk: number;
  alreadyInDeletedItems: number;
  elsewhere: number;
  /** In the approved scope but no longer matched by the latest lookup */
  noLongerMatched: number;
  /** Copies the latest lookup found that the approved scope did not name (not acted on) */
  newSinceApproval: number;
}

export type AuditEvent =
  | 'incident_opened'
  | 'incident_updated'
  | 'incident_email_sent'
  | 'incident_false_positive'
  | 'action_proposed'
  | 'action_approved'
  | 'approval_rejected'
  | 'action_expired'
  | 'action_cancelled'
  | 'action_executed'
  | 'action_dry_run'
  | 'action_failed';

export interface AuditEntry {
  incidentId: string;
  actionId?: string;
  event: AuditEvent;
  /** `phishy` for Phishy's own decisions, otherwise the authenticated approver's address */
  actor: string;
  detail?: Record<string, unknown>;
}

/**
 * What the incident email says about the attack. Every string from the
 * suspicious email (subject, sender, the model's summary of it) is hostile
 * and is defanged and escaped where it is shown.
 */
export interface IncidentSummary {
  verdict: string;
  riskScore: number;
  riskLevel: string;
  confidence?: string;
  confidenceBasis?:
    'model' | 'security_team' | 'threat_intel' | 'attachment_inspection' | 'unassessed';
  /** The main reasons (model indicators and intelligence reasons), at most 5 */
  reasons: string[];
  /** The model's one-paragraph summary of the lure */
  lure?: string;
  subject?: string;
  senderAddress?: string;
  senderName?: string;
  /** Earliest delivery any mailbox recorded (ISO), when known */
  firstDeliveryAt?: string;
  /** First and latest report (ISO); absent for an incident with no report yet */
  firstReportAt?: string;
  lastReportAt?: string;
  /**
   * Who reported it (`originalForwarder` of each report, from the campaign
   * tracker; at most 200). Never warned (they reported it themselves);
   * sent a removal notice only if their own copy is actually removed.
   */
  reporters?: string[];
  /** Latest analysis in the campaign, quoted so "false positive" replies match it */
  analysisId?: string;
  /** Plain words for what opened the incident */
  detectedBy: string;
  /**
   * Set when the reach trigger opened the incident (a malicious report whose
   * blast-radius lookup found enough delivered recipients) rather than the
   * report-count threshold. `trigger_source` stays `reports`.
   */
  openedOnReach?: {
    reports: number;
    reporters: number;
    recipients: number;
    threshold: number;
  };
}

/** Blast radius merged across the incident's lookups */
export interface IncidentReach {
  status: 'complete' | 'partial' | 'unavailable' | 'not_enabled';
  note?: string;
  lookedUpAt?: string;
  totals: {
    recipients: number;
    read: number;
    replied: number;
    forwarded: number;
    stillInInbox: number;
    notDelivered: number;
  };
  /** Recipients counted by a lookup but not listed by it (its listing is capped) */
  unlisted: number;
  recipients: BlastRadiusRecipient[];
  caveats: string[];
  coverage?: { mailboxesChecked: number; mailboxesEligible: number; lowerBound: boolean };
}

export interface CampaignIncident {
  id: string;
  campaignId?: string;
  campaignSignature: string;
  reference: string;
  trigger: IncidentTrigger;
  status: IncidentStatus;
  summary: IncidentSummary;
  reach: IncidentReach;
  reportCount: number;
  /** SES message ID of the first incident email, which updates reply to */
  threadMessageId?: string;
  lastUpdateSentAt?: Date;
  notifiedReportCount: number;
  notifiedRecipientCount: number;
  createdAt: Date;
}

/**
 * What the scheduled fan-out scan hands over when it alerts before anyone
 * has reported the message. Every string is hostile (it came from mail
 * flow). See `CampaignResponseService.openIncidentFromFanoutAlert`.
 */
export interface FanoutIncidentInput {
  /** The campaign signature reports of this message will compute, when the caller knows it */
  campaignSignature?: string;
  subject: string;
  senderAddress: string;
  senderName?: string;
  /** Earliest delivery the scan saw (ISO) */
  firstDeliveryAt?: string;
  /** The scan's reach: same shape as a blast-radius report */
  reach: BlastRadiusReport;
  /** Code-written reasons the scan alerted (e.g. "reached 48 people in 6 minutes") */
  reasons: string[];
  /** The scan's own 0-100 score, when it has one (no model verdict exists yet) */
  riskScore?: number;
}

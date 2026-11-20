/**
 * The scheduled fan-out scan, as the main function runs it: take the scan
 * lock, work out the window and the request allowance, have the scan run
 * (in the Graph broker, or here in direct mode), then dedupe each flag
 * against the intelligence database and alert the security team.
 *
 * - **No model, no writes to the tenant.** Code decides everything; the
 *   only Graph work is the read-only scan (and, when enabled, the read-only
 *   blast-radius lookup). Nothing here is an agentic tool.
 * - **Security team only.** Alerts go to `notification.securityTeamDistribution`
 *   and to nobody else: no address from mail flow ever becomes a recipient.
 * - **State in the database.** The lock, the window and the shared request
 *   allowance (`fanout_scan_state`) and the alerted waves
 *   (`fanout_scan_waves`, migration 005). Without the database the scan does
 *   not run (see docs/ARCHITECTURE.md for why).
 * - **Overlap without duplicates.** Each window starts `overlapMinutes`
 *   before the previous one ended, so rows message trace records late are
 *   still seen; a wave already alerted is recognized by its sender and
 *   subject and alerts again only when it grows materially.
 * - **Bounded.** The scan's trace requests come out of a tenant-wide
 *   allowance shared by all scans (`requestAllowancePer5Min`) that sits well
 *   under the tenant's 100 per 5 minutes and apart from the on-report
 *   checks' own allowance; a scan has a hard time budget; a scan that finds
 *   the previous one still running does nothing.
 * - **One email per wave.** With campaign response on, a flagged wave opens
 *   (or updates) a campaign-response incident and the incident email takes
 *   the alert's place; the plain alert is sent only when no incident email
 *   went out (tables missing, the incident is closed, or the send failed).
 * - Never throws; emits one `FanoutScans` metric line per invocation.
 */

import { randomUUID } from 'crypto';
import { PhishyConfig } from '../../config/schema';
import { EmailSendResult, ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';
import {
  FanoutScanMetric,
  FanoutScanMetricOutcome,
  emitFanoutScanMetric,
} from '../../utils/metrics';
import type { BlastRadiusReport } from '../graph/blast-radius.service';
import { FanoutFlag, FanoutScanResult } from '../graph/fanout.scan';
import type { FanoutScanSource } from '../graph/fanout.source';
import type { GraphGateway } from '../graph/graph.gateway';
import { DEFAULT_FANOUT_MIN_RECIPIENTS, subjectGroupKey } from '../graph/sender.history';
import { computeCampaignSignature } from '../intelligence/database.service';
import type { CampaignResponseService } from '../response/campaign.response.service';
import type { FanoutIncidentInput } from '../response/response.types';
import {
  FANOUT_NOT_A_VERDICT,
  buildFanoutAlert,
  incompleteLine,
} from '../../templates/fanout.alert';
import {
  AlertClaim,
  FANOUT_MIGRATION,
  FanoutScanStore,
  FanoutStoreMissingError,
  RequestEntry,
  SqlQueryable,
  fanoutWaveKey,
} from './fanout.store';

const logger = createLogger('fanout-job');

const MINUTE_MS = 60 * 1000;
const FIVE_MINUTES_MS = 5 * MINUTE_MS;
/** How far back the very first scan (no previous window) reaches, beyond the overlap */
const FIRST_SCAN_EXTRA_MS = 5 * MINUTE_MS;
/** Lambda time kept back after the scan for dedupe, blast radius and sending */
const AFTER_SCAN_RESERVE_MS = 40_000;
/** A scan is not started with less time than this */
const MIN_SCAN_MS = 5000;
/** The lock outlives the invocation by this much, then expires on its own */
const LOCK_MARGIN_MS = 30_000;
const MIN_LOCK_MS = 60_000;
const MAX_LOCK_MS = 16 * MINUTE_MS;
/** Assumed when the Lambda context gives no remaining time */
const DEFAULT_REMAINING_MS = 180_000;
/**
 * Trace requests charged for one blast-radius lookup (it reads message trace
 * once, sometimes twice, before reading mailboxes, and does not report how
 * many it made)
 */
export const BLAST_RADIUS_TRACE_REQUEST_ESTIMATE = 2;

export type FanoutRunOutcome = FanoutScanMetricOutcome | 'disabled';

export interface FanoutRunSummary {
  outcome: FanoutRunOutcome;
  rowsScanned: number;
  candidates: number;
  flagged: number;
  alertsSent: number;
  incomplete: boolean;
  traceRequests: number;
}

export interface FanoutJobDeps {
  config: Pick<PhishyConfig, 'graph' | 'email' | 'notification'>;
  /** Undefined when the feature is off */
  source?: FanoutScanSource;
  /** The intelligence database; undefined when it is not configured */
  db?: SqlQueryable;
  notifier: {
    sendEmail(
      recipient: string,
      subject: string,
      htmlBody: string,
      textBody: string,
      ccAddresses?: string[]
    ): Promise<EmailSendResult>;
  };
  /** For the blast-radius section, when that feature is on */
  graph?: Pick<GraphGateway, 'blastRadius' | 'lookupBlastRadius'>;
  /**
   * Campaign response, when it is enabled: a flagged wave opens (or
   * updates) an incident, whose email replaces the alert
   */
  campaignResponse?: Pick<CampaignResponseService, 'openIncidentFromFanoutAlert'>;
  /** Injected for tests */
  now?: () => number;
  newToken?: () => string;
}

/**
 * The parts of a blast-radius key, as the existing lookup derives them from
 * a forward: the flagged sender, the subject and the first sighting as the
 * claimed date (the lookup searches a day either side, up to now). Code-made
 * from the flag; nothing here is a reported email.
 */
export function blastRadiusEmailFor(flag: FanoutFlag, firstSeen: string): ExtractedEmailData {
  return {
    from_email: '',
    subject: flag.subject,
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: {
      'Original-From': flag.senderAddress,
      ...(flag.subject ? { 'Original-Subject': flag.subject } : {}),
      'Original-Date': firstSeen,
    },
    attachments: [],
    sender: '',
    to: '',
    original_sender: '',
    originalForwarder: '',
    links: [],
  };
}

/**
 * The domain a report of this wave will most likely come from. A report's
 * campaign signature is computed from the reporting employee's own address
 * (the SES envelope sender) and the subject, so a scan-opened incident must
 * use the domain the recipients' own addresses carry for a later report to
 * find it: the most common domain among the listed recipients that is one
 * of the organization's domains (ties: the first in configuration order,
 * then alphabetical), else the first configured domain. Recipient addresses
 * are mail-flow data, used here only as a grouping key and compared to
 * operator configuration.
 */
export function likelyReporterDomain(flag: FanoutFlag, safeDomains: string[]): string {
  const configured = safeDomains.map(domain => domain.toLowerCase());
  const counts = new Map<string, number>();
  for (const recipient of flag.recipients) {
    const domain = recipient.address.slice(recipient.address.lastIndexOf('@') + 1).toLowerCase();
    const internal = configured.some(
      safe => domain === safe || (domain.endsWith(`.${safe}`) && domain.length > safe.length + 1)
    );
    if (internal) {
      counts.set(domain, (counts.get(domain) ?? 0) + 1);
    }
  }
  const rank = (domain: string): number => {
    const index = configured.indexOf(domain);
    return index === -1 ? configured.length : index;
  };
  const best = [...counts.entries()].sort(
    ([a, countA], [b, countB]) => countB - countA || rank(a) - rank(b) || a.localeCompare(b)
  )[0];
  return best?.[0] ?? configured[0] ?? 'unknown';
}

function bounded(count: { count: number; atLeast: boolean } | null): string {
  if (!count) {
    return 'unknown';
  }
  return `${count.atLeast ? 'at least ' : ''}${count.count}`;
}

/**
 * What campaign response is given for a flagged wave. Every line here is
 * written by code from counts; the sender and subject travel only as the
 * incident's own (escaped, defanged) sender and subject fields.
 */
export function fanoutIncidentInput(
  deps: Pick<FanoutJobDeps, 'config'>,
  flag: FanoutFlag,
  wave: {
    claim: Exclude<AlertClaim, { kind: 'none' }>;
    waveRecipients: number;
    waveFirstSeen: string;
    incompleteReasons: FanoutScanResult['incompleteReasons'];
    blastRadius?: BlastRadiusReport;
  }
): FanoutIncidentInput {
  const { facts, statuses } = flag;
  const incomplete = incompleteLine(wave.incompleteReasons);
  const reasons = [
    `The fan-out scan saw one external sender reach ${wave.waveRecipients} internal recipient(s) ` +
      `(${flag.windowRecipients} in the scanned window, in ${flag.windowMessages} message(s)).`,
    ...(incomplete ? [incomplete] : []),
    `Sender history: two-way contact in the last ${facts.lookbackDays} days ` +
      `(${bounded(facts.twoWay.messages)} message(s) sent to it by ${bounded(facts.twoWay.internalSenders)} of our people), ` +
      `usually reaching ${bounded(facts.history.recipients)} recipient(s); this subject reached ` +
      `${bounded(facts.burst.sameSubject.recipients)}, ${bounded(facts.burst.sameSubject.newRecipients)} of them new to it.`,
    `Delivery in the scanned window: ${statuses.delivered} reached a mailbox, ${statuses.quarantined} quarantined, ` +
      `${statuses.junk} sent to Junk Email, ${statuses.failed} failed.`,
    FANOUT_NOT_A_VERDICT,
  ];
  const changes =
    wave.claim.kind === 'growth'
      ? [
          `The fan-out scan has now seen it reach ${wave.waveRecipients} internal recipient(s); the previous fan-out sighting reported ${wave.claim.previousRecipients}.`,
        ]
      : [
          `The fan-out scan saw it reach ${wave.waveRecipients} internal recipient(s) in mail-flow records.`,
        ];
  return {
    campaignSignature: computeCampaignSignature(
      likelyReporterDomain(flag, deps.config.email.safeDomains),
      flag.subject
    ),
    subject: flag.subject,
    senderAddress: flag.senderAddress,
    firstDeliveryAt: wave.waveFirstSeen,
    ...(wave.blastRadius ? { reach: wave.blastRadius } : {}),
    reasons,
    changes: incomplete ? [...changes, incomplete] : changes,
  };
}

function lockLeaseMs(remainingMs: number): number {
  return Math.min(MAX_LOCK_MS, Math.max(MIN_LOCK_MS, remainingMs + LOCK_MARGIN_MS));
}

function recentEntries(entries: RequestEntry[], nowMs: number): RequestEntry[] {
  return entries.filter(entry => {
    const at = Date.parse(entry.at);
    return Number.isFinite(at) && at > nowMs - FIVE_MINUTES_MS && at <= nowMs + MINUTE_MS;
  });
}

async function safeSend(
  deps: FanoutJobDeps,
  to: string,
  cc: string[],
  email: { subject: string; html: string; text: string }
): Promise<EmailSendResult> {
  try {
    return await deps.notifier.sendEmail(to, email.subject, email.html, email.text, cc);
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.name : 'unknown' };
  }
}

/**
 * Run one scheduled scan. Never throws.
 */
export async function runFanoutScan(
  deps: FanoutJobDeps,
  options: { remainingMs?: () => number | undefined } = {}
): Promise<FanoutRunSummary> {
  const now = deps.now ?? Date.now;
  const startedAt = now();
  const summary: FanoutRunSummary = {
    outcome: 'error',
    rowsScanned: 0,
    candidates: 0,
    flagged: 0,
    alertsSent: 0,
    incomplete: false,
    traceRequests: 0,
  };
  const finish = (outcome: FanoutRunOutcome): FanoutRunSummary => {
    summary.outcome = outcome;
    if (outcome !== 'disabled') {
      const metric: FanoutScanMetric = {
        ...summary,
        outcome,
        durationMs: Math.max(0, now() - startedAt),
      };
      emitFanoutScanMetric(metric);
    }
    return summary;
  };

  const settings = deps.config.graph?.fanoutScan;
  if (!deps.source || !settings?.enabled) {
    logger.info('Scheduled fan-out scan invoked while the feature is off; nothing to do');
    return finish('disabled');
  }
  if (!deps.db) {
    logger.warn(
      'Fan-out scan skipped: it needs the intelligence database for its state (dedupe, lock, ' +
        `window). Set PHISHY_INTELLIGENCE_ENABLED and PHISHY_DB_CONNECTION and apply ${FANOUT_MIGRATION}`
    );
    return finish('no_database');
  }
  const securityTeam = deps.config.notification.securityTeamDistribution;
  if (securityTeam.length === 0) {
    logger.warn(
      'Fan-out scan skipped: notification.securityTeamDistribution is empty, so there is nobody to alert'
    );
    return finish('error');
  }

  const store = new FanoutScanStore(deps.db);
  const remaining = (): number => options.remainingMs?.() ?? DEFAULT_REMAINING_MS;
  const token = (deps.newToken ?? randomUUID)();
  const nowDate = new Date(startedAt);

  let lock;
  try {
    lock = await store.acquireLock(token, new Date(startedAt + lockLeaseMs(remaining())), nowDate);
  } catch (error) {
    if (error instanceof FanoutStoreMissingError) {
      logger.warn(`Fan-out scan skipped: its tables are missing. Apply ${FANOUT_MIGRATION}`);
      return finish('migration_missing');
    }
    logger.error('Fan-out scan skipped: could not take the scan lock', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    return finish('error');
  }
  if (!lock.acquired) {
    logger.info('Fan-out scan skipped: the previous scan is still running');
    return finish('skipped_running');
  }

  const recent = recentEntries(lock.recentRequests, startedAt);
  let windowEnd: Date | undefined;
  let outcome: FanoutRunOutcome;
  try {
    outcome = await scanAndAlert(deps, store, {
      settings,
      securityTeam,
      startedAt,
      lastWindowEnd: lock.lastWindowEnd,
      allowance: Math.max(
        0,
        settings.requestAllowancePer5Min - recent.reduce((sum, entry) => sum + entry.requests, 0)
      ),
      remaining,
      summary,
      advance: end => {
        windowEnd = end;
      },
    });
  } catch (error) {
    // Nothing above is expected to throw; the lock is still released below
    logger.error('Fan-out scan failed unexpectedly', {
      error: error instanceof Error ? error.name : 'unknown',
    });
    outcome = error instanceof FanoutStoreMissingError ? 'migration_missing' : 'error';
  } finally {
    const entries =
      summary.traceRequests > 0
        ? [...recent, { at: new Date(startedAt).toISOString(), requests: summary.traceRequests }]
        : recent;
    try {
      await store.releaseLock(token, { windowEnd, recentRequests: entries });
    } catch (error) {
      // The lease expires on its own
      logger.warn('Fan-out scan could not release its lock; it will expire', {
        error: error instanceof Error ? error.name : 'unknown',
      });
    }
  }
  return finish(outcome);
}

interface ScanContext {
  settings: NonNullable<NonNullable<PhishyConfig['graph']>['fanoutScan']>;
  securityTeam: string[];
  startedAt: number;
  lastWindowEnd?: Date;
  /** Trace requests left in the shared 5-minute allowance */
  allowance: number;
  remaining: () => number;
  summary: FanoutRunSummary;
  advance: (windowEnd: Date) => void;
}

/** The scan window: from a little before the previous end, at most `maxWindowMinutes` wide */
export function fanoutWindow(
  startedAt: number,
  lastWindowEnd: Date | undefined,
  settings: { overlapMinutes: number; maxWindowMinutes: number }
): { from: Date; to: Date; gapSkipped: boolean } {
  const overlapMs = settings.overlapMinutes * MINUTE_MS;
  const maxWindowMs = settings.maxWindowMinutes * MINUTE_MS;
  const to = startedAt;
  const previous = lastWindowEnd?.getTime();
  let from =
    previous !== undefined && Number.isFinite(previous) && previous <= to
      ? previous - overlapMs
      : to - overlapMs - FIRST_SCAN_EXTRA_MS;
  let gapSkipped = false;
  if (to - from > maxWindowMs) {
    from = to - maxWindowMs;
    gapSkipped = previous !== undefined;
  }
  return { from: new Date(from), to: new Date(to), gapSkipped };
}

async function scanAndAlert(
  deps: FanoutJobDeps,
  store: FanoutScanStore,
  context: ScanContext
): Promise<FanoutRunOutcome> {
  const { settings, summary } = context;
  if (context.allowance < 1) {
    logger.warn('Fan-out scan skipped: scans have used their message trace allowance', {
      allowancePer5Min: settings.requestAllowancePer5Min,
    });
    return 'rate_limited';
  }

  const window = fanoutWindow(context.startedAt, context.lastWindowEnd, settings);
  if (window.gapSkipped) {
    summary.incomplete = true;
    logger.warn('Fan-out scan: the previous scan ended long ago; the oldest part was not scanned', {
      maxWindowMinutes: settings.maxWindowMinutes,
    });
  }

  const waitMs = Math.min(settings.budgetMs, context.remaining() - AFTER_SCAN_RESERVE_MS);
  if (waitMs < MIN_SCAN_MS) {
    logger.warn('Fan-out scan skipped: not enough invocation time left');
    return 'timeout';
  }

  const internalDomains = deps.config.email.safeDomains.map(domain => domain.toLowerCase());
  const call = await deps.source!.scan(
    {
      receivedFrom: window.from,
      receivedTo: window.to,
      internalDomains,
      maxPages: settings.maxPages,
      maxCandidates: settings.maxCandidates,
      maxRequests: context.allowance,
      budgetMs: waitMs,
    },
    waitMs
  );
  if (!call.ok) {
    // The broker may have spent requests before it stopped answering:
    // charge the whole allowance this scan was given
    summary.traceRequests = context.allowance;
    return call.failure === 'timeout' ? 'timeout' : 'error';
  }

  const result: FanoutScanResult = call.result;
  summary.traceRequests = result.requestsUsed;
  summary.rowsScanned = result.rowsScanned;
  summary.candidates = result.candidates;
  summary.flagged = result.flagged.length;
  summary.incomplete ||= result.incomplete;
  if (result.outcome !== 'ok') {
    return result.outcome;
  }
  const minRecipients =
    deps.config.graph?.senderHistory?.fanoutMinRecipients ?? DEFAULT_FANOUT_MIN_RECIPIENTS;
  let failures = 0;
  for (const flag of result.flagged) {
    try {
      await alertOnFlag(deps, store, context, flag, {
        window: { from: window.from.toISOString(), to: window.to.toISOString() },
        incompleteReasons: result.incompleteReasons,
        minRecipients,
      });
    } catch (error) {
      if (error instanceof FanoutStoreMissingError) {
        throw error;
      }
      failures++;
      logger.error('Fan-out flag could not be recorded or alerted', {
        error: error instanceof Error ? error.name : 'unknown',
      });
    }
  }
  // The window was read and every flag handled: the next scan starts from
  // here (less the overlap). Otherwise the window is read again next time,
  // and the waves already alerted are recognized and not alerted twice.
  // Rows the request allowance left unread are read again too: the
  // allowance is a rolling five minutes, so the next scan has room, and
  // advancing would skip that mail flow without anyone seeing it. (A
  // window cut short by the page cap still advances, disclosed as
  // incomplete: reading it again would hit the same cap.)
  const unreadByAllowance = result.windowUnread === 'request_allowance';
  if (unreadByAllowance) {
    logger.warn(
      'Fan-out scan: the request allowance ran out before every page of the window was read; the next scan reads this window again',
      { pages: result.pages, requestsUsed: result.requestsUsed, allowance: context.allowance }
    );
  }
  if (failures === 0 && !unreadByAllowance) {
    context.advance(window.to);
  }
  return failures === 0 ? 'ok' : 'error';
}

async function alertOnFlag(
  deps: FanoutJobDeps,
  store: FanoutScanStore,
  context: ScanContext,
  flag: FanoutFlag,
  scan: {
    window: { from: string; to: string };
    incompleteReasons: FanoutScanResult['incompleteReasons'];
    minRecipients: number;
  }
): Promise<void> {
  const now = deps.now ?? Date.now;
  const waveRecipients = Math.max(
    flag.windowRecipients,
    flag.facts.burst.sameSubject.recipients.count
  );
  const claim: AlertClaim = await store.claimAlert(
    {
      waveKey: fanoutWaveKey(flag.senderAddress, subjectGroupKey(flag.subject)),
      senderAddress: flag.senderAddress,
      subject: flag.subject,
      firstSeen: new Date(flag.firstSeen),
      lastSeen: new Date(flag.lastSeen),
      recipients: waveRecipients,
    },
    {
      dedupeMs: context.settings.dedupeHours * 60 * MINUTE_MS,
      minRecipients: scan.minRecipients,
      now: new Date(now()),
    }
  );
  if (claim.kind === 'none') {
    logger.info('Fan-out wave already alerted; no material growth', {
      reference: claim.reference,
      recipients: waveRecipients,
    });
    return;
  }

  const waveFirstSeen = claim.kind === 'growth' ? claim.firstSeen.toISOString() : flag.firstSeen;
  let blastRadius: BlastRadiusReport | undefined;
  if (deps.graph?.blastRadius) {
    blastRadius = await deps.graph.lookupBlastRadius(blastRadiusEmailFor(flag, waveFirstSeen), {
      remainingMs: context.remaining(),
    });
    context.summary.traceRequests += BLAST_RADIUS_TRACE_REQUEST_ESTIMATE;
  }

  if (deps.campaignResponse) {
    const incident = await deps.campaignResponse.openIncidentFromFanoutAlert(
      fanoutIncidentInput(deps, flag, {
        claim,
        waveRecipients,
        waveFirstSeen,
        incompleteReasons: scan.incompleteReasons,
        blastRadius,
      })
    );
    if (incident && (incident.email === 'opened' || incident.email === 'updated')) {
      // The incident email is the one email about this wave
      context.summary.alertsSent++;
      logger.info('Fan-out wave sent to the security team as a campaign-response incident', {
        reference: claim.reference,
        incident: incident.reference,
        kind: claim.kind,
        email: incident.email,
        recipients: waveRecipients,
      });
      return;
    }
    if (incident?.email === 'unchanged') {
      logger.info('Fan-out wave already in its incident; nothing new to send', {
        reference: claim.reference,
        incident: incident.reference,
      });
      return;
    }
    // No incident email went out (tables missing, the incident is closed or
    // a false positive, or the send failed): the plain alert, exactly as
    // with campaign response off
    logger.warn('Fan-out wave: no incident email was sent; sending the plain fan-out alert', {
      reference: claim.reference,
      incident: incident ? incident.email : 'unavailable',
    });
  }

  const email = buildFanoutAlert({
    reference: claim.reference,
    kind: claim.kind,
    ...(claim.kind === 'growth' ? { previousRecipients: claim.previousRecipients } : {}),
    flag,
    waveRecipients,
    waveFirstSeen,
    window: scan.window,
    incompleteReasons: scan.incompleteReasons,
    ...(blastRadius ? { blastRadius } : {}),
  });

  // The security team and nobody else: To the first address, Cc the rest
  const [first, ...rest] = context.securityTeam;
  const sent = await safeSend(deps, first, rest, email);
  if (!sent.success) {
    logger.error('Fan-out alert was not sent; the next scan will try again', {
      reference: claim.reference,
      error: sent.error,
    });
    await store.revertClaim(claim);
    // Counted as a failure so the window is not advanced past this wave
    throw new Error('fan-out alert was not sent');
  }
  context.summary.alertsSent++;
  logger.info('Fan-out alert sent to the security team', {
    reference: claim.reference,
    kind: claim.kind,
    recipients: waveRecipients,
  });
  if (sent.messageId) {
    try {
      await store.recordAlertMessageId(claim.id, sent.messageId);
    } catch (error) {
      // The alert is out; only reply matching by message ID is lost
      logger.warn('Fan-out alert message ID could not be stored', {
        reference: claim.reference,
        error: error instanceof Error ? error.name : 'unknown',
      });
    }
  }
}

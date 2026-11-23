/**
 * Core type definitions for Phishy Email Analyzer
 */

import type { AttachmentInspection } from '../services/attachments/types';
import type { ChecklistOutcome } from '../services/ai/checklist';
import type { AnchorMismatchKind, TextObfuscationKind } from '../utils/canonicalize';

/**
 * Email message structure as received from various sources
 */
export interface EmailMessage {
  from_email: string;
  subject: string;
  text: string;
  html: string | null;
  headers: Record<string, string>;
  to: string;
  original_sender?: string;
  messageId?: string;
  sesMailTimestamp?: string;
  s3Reference?: string | null;
  s3Location?: S3Location | null;
  attachments?: EmailAttachment[];
  rawContentSnippet?: string;
  /** SES receipt authentication verdicts (SPF/DKIM/DMARC), when available */
  authVerdicts?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  /**
   * Set when the message is an Outlook Report-button submission rather than a
   * forward. Derived only from SES-delivered mail by the parser — the external
   * payload schema strips it.
   */
  userReport?: UserReport;
}

/** What the employee chose in Outlook's Report menu */
export type UserReportKind = 'phishing' | 'junk' | 'not_junk';

/**
 * An Outlook Report-button submission: the reporter clicked a button and is
 * not waiting for an answer, so these are handled without replying to them.
 */
export interface UserReport {
  source: 'outlook-report-button';
  reportedAs: UserReportKind;
  /** Exchange network message ID of the reported (original) message */
  networkMessageId: string;
}

/**
 * S3 storage location reference
 */
export interface S3Location {
  bucket: string;
  key: string;
}

/**
 * Email attachment structure
 */
export interface EmailAttachment {
  filename: string;
  contentType: string;
  size: number;
  /** SHA-256 of the attachment body — metadata for analysis; content is never executed or forwarded */
  sha256?: string;
  content?: string | Buffer;
  /**
   * Phishy's static inspection of the bytes (optional feature,
   * `attachments.analysis.enabled`). Set by the parser on SES-delivered
   * mail only; the external payload schema carries no attachments.
   */
  analysis?: AttachmentInspection;
}

/**
 * Extracted and normalized email data for analysis
 */
export interface ExtractedEmailData {
  from_email: string;
  subject: string;
  text: string;
  html: string;
  headers: Record<string, string>;
  forwardedHeaders: Record<string, string>;
  attachments: EmailAttachment[];
  sender: string;
  to: string;
  original_sender: string;
  originalForwarder: string;
  /** Canonical (unwrapped, deduplicated) link destinations */
  links: string[];
  /** Per-link raw → canonical mapping with divergence flags */
  linkFacts?: LinkFact[];
  /** Canonicalized body text (NFKC, invisibles stripped, entities decoded) */
  canonicalText?: string;
  /** Obfuscation indicators found during canonicalization — themselves signals */
  contentFlags?: string[];
  /**
   * The structured twin of `contentFlags`, set by the parser from the same
   * computation: fixed codes for what canonicalizing the body text undid,
   * and for each anchor trick found (`anchors` is absent when there was no
   * HTML body to check). Read by code (the checklist's code-computed
   * answers), never rendered.
   */
  contentFindings?: {
    text: TextObfuscationKind[];
    anchors?: AnchorMismatchKind[];
  };
  /** Present when this is an Outlook Report-button submission (handled silently) */
  userReport?: UserReport;
  /**
   * Internet headers of the original message, read by Phishy from the
   * reporter's own mailbox (optional Graph feature). Absent whenever the
   * lookup is off, failed, or did not find exactly one match.
   */
  retrievedOriginal?: RetrievedOriginal;
  /**
   * Sender-relationship facts computed by Phishy from the organization's own
   * mail-flow records (optional Graph feature). Counts and an enum, plus the
   * burst's sending IPs for a security-team-only report; never an address.
   * Absent when the check is off, skipped or failed.
   */
  senderHistory?: SenderHistoryFacts;
}

/** One Internet header of a retrieved original. Name and value are hostile data. */
export interface RetrievedHeader {
  name: string;
  value: string;
}

/**
 * The original of a forwarded message as Phishy itself found it in the
 * reporter's mailbox. What is verified is the retrieval (Phishy read this
 * from the stored copy; nothing here was pasted by the forwarder) and the
 * two fields the mailbox system stamps: `location` and `receivedAt`. The
 * header contents are written by the sender and by every server the message
 * passed through, so they stay hostile data.
 */
export interface RetrievedOriginal {
  /** `recoverable_items`: the reporter deleted the message after forwarding it */
  location: 'mailbox' | 'recoverable_items';
  /** When the mailbox received the message (ISO 8601), stamped by the mail system */
  receivedAt?: string;
  /** Headers in stored order, top of the message first */
  headers: RetrievedHeader[];
  /** True when the stored copy had more headers than were read */
  headersTruncated: boolean;
  /**
   * The message as the reporter's mailbox stored it, from the lookup's own
   * search (not from the forward's text): its Graph ID in that mailbox, its
   * Internet Message-ID, From address and subject. Hostile values (the
   * sender wrote them) used only as data: the anchor a live campaign
   * removal is checked against. Never rendered into the prompt.
   */
  identity?: RetrievedOriginalIdentity;
}

export interface RetrievedOriginalIdentity {
  /** Graph message ID in the reporter's mailbox */
  messageId: string;
  internetMessageId?: string;
  senderAddress?: string;
  subject?: string;
}

/** A count that may have been cut short by a row cap: `atLeast` means "N or more" */
export interface BoundedCount {
  count: number;
  atLeast: boolean;
}

/**
 * How the claimed sender address relates to the organization, decided by code
 * from message-trace counts. None of these is a statement about safety: an
 * established sender is exactly what a mailbox takeover borrows.
 */
export type SenderRelationshipClass =
  'no_history' | 'limited_history' | 'established' | 'established_with_anomalous_fanout';

/** One sending IP seen in the burst window, as message trace recorded it */
export interface SenderBurstIp {
  ip: string;
  /** Also recorded for this sender in the history period */
  seenInHistory: boolean;
}

/**
 * What the organization's message trace says about one external sender
 * address. Counts and an enum; no recipient or sender address is kept. The
 * one exception to "counts only" is `sendingIps.burstIps`, which exists for
 * a report addressed to the security team alone.
 */
export interface SenderHistoryFacts {
  classification: SenderRelationshipClass;
  /** Days of mail-flow records examined, burst window included */
  lookbackDays: number;
  /** Length of the burst window (it always ends at lookup time), in hours */
  burstWindowHours: number;
  /** Mail from the address before the burst window */
  history: {
    messages: BoundedCount;
    recipients: BoundedCount;
    /** UTC date (YYYY-MM-DD) of the earliest message found in the lookback */
    firstSeen?: string;
  };
  /** Mail the organization sent TO the address before the burst window */
  twoWay: {
    messages: BoundedCount;
    internalSenders: BoundedCount;
  };
  /** Mail from the address inside the burst window */
  burst: {
    messages: BoundedCount;
    recipients: BoundedCount;
    /** Burst recipients with no mail from the address in the history period; null when history was cut short */
    newRecipients: BoundedCount | null;
    /**
     * The largest group of burst recipients that received the same subject
     * (the figure fan-out is judged on), and how many of them are new to the
     * address. Counts only: the subject itself is never kept.
     */
    sameSubject: {
      recipients: BoundedCount;
      newRecipients: BoundedCount | null;
    };
  };
  sendingIps: {
    /** Distinct sending IPs in the burst window */
    burst: number;
    /** How many of those also appear in the history period */
    seenInHistory: number;
    /** False when history was cut short, so `seenInHistory` is a minimum */
    historyComplete: boolean;
    /**
     * The burst's sending IPs themselves, capped. **Security-team-only
     * report copies only**: never the prompt, the reporter's copy, the
     * combined report, or a log line at info level.
     */
    burstIps?: SenderBurstIp[];
    /** Burst IPs left out of `burstIps` by the cap (or not shaped like an IP) */
    burstIpsOmitted?: number;
  };
  /** True when any count above was cut short by a row cap */
  truncated: boolean;
}

/**
 * A link as found (raw) and as it truly resolves (canonical), with
 * divergence flags — produced by the canonicalizer
 */
export interface LinkFact {
  raw: string;
  canonical: string;
  flags: string[];
  /** Set when the canonical destination is a file share on a known hosting platform */
  fileShare?: FileShareFact;
}

/**
 * What a file-share link's host and path reveal about where the file is
 * hosted (src/utils/file-share.ts). Every string field comes from the URL,
 * which the sender wrote: each is shape-checked, and is hostile data.
 */
export interface FileShareFact {
  /** Hosting platform, from a fixed list */
  platform: string;
  /** Whose space: a person's site, a team/organization site, a consumer account, or not shown */
  space: 'personal' | 'team' | 'consumer' | 'unknown';
  /** Tenant or account label from the host (SharePoint tenant, Box/Egnyte/ShareFile subdomain) */
  tenantLabel?: string;
  /** SharePoint/OneDrive personal site owner segment: the owner's sign-in name, `@` and `.` written as `_` */
  ownerSegment?: string;
  /** Google Workspace domain from an `/a/<domain>/` path */
  ownerDomain?: string;
}

/**
 * Token usage for cost tracking
 */
export interface TokenUsage {
  inputTokens: number;
  /** Billed output tokens. Includes thinking tokens on models that think. */
  outputTokens: number;
  totalTokens: number;
  /**
   * The share of outputTokens spent on thinking, when the API reports it
   * (`usage.output_tokens_details.thinking_tokens`). Already counted in
   * outputTokens — never add it on top.
   */
  thinkingTokens?: number;
}

/**
 * An indicator of compromise nominated by the AI analysis itself.
 * Regex extraction misses context (which domain is the attacker vs the
 * victim, where a redirect chain really lands); the model does not.
 */
export interface AINominatedIOC {
  type: 'domain' | 'url' | 'email' | 'ip';
  value: string;
  /** sender = who sent the phish, payload = where its links lead, infrastructure = relays/trackers in between */
  role: 'sender' | 'payload' | 'infrastructure';
}

/**
 * What kind of email this is. Distinct from risk: a verdict says what the
 * message *is*, riskScore says how much damage acting on it would cause.
 */
export type ThreatVerdict =
  | 'bec' // business email compromise / executive impersonation
  | 'phishing' // credential harvesting
  | 'malware_delivery' // malicious attachment or payload link
  | 'spam' // unsolicited bulk, no clear harm
  | 'graymail' // legitimate bulk the user may not want (marketing, surveys)
  | 'suspicious' // can't confirm malicious, but off
  | 'legitimate'
  | 'undetermined'; // analysis could not be completed (model unreachable) — NOT a clean bill of health

/** The mechanism by which a malicious email causes harm */
export type ThreatVector =
  | 'credential_harvest'
  | 'wire_fraud'
  | 'gift_card_fraud'
  | 'malware'
  | 'reconnaissance' // probing / establishing a back-channel before the ask
  | 'data_exfiltration'
  | 'extortion'
  | 'other';

/** Whether the email was aimed at this org/person or sent en masse */
export type Targeting = 'targeted' | 'mass' | 'unknown';

/** Verdicts that count as malicious for downstream isPhishing-style gating */
export const MALICIOUS_VERDICTS: readonly ThreatVerdict[] = ['bec', 'phishing', 'malware_delivery'];

/**
 * The structured verdict the model produces. Risk and confidence are separate
 * axes: a confidently-legitimate email is high confidence, zero risk.
 */
export interface ThreatAssessment {
  verdict: ThreatVerdict;
  /** Harm if the recipient acts on the email, 0 (none) – 100 (catastrophic) */
  riskScore: number;
  /** Model's certainty in the verdict, 0.0 – 1.0 */
  verdictConfidence: number;
  threatVectors: ThreatVector[];
  targeting: Targeting;
}

/**
 * AI analysis result structure
 */
export interface AnalysisResult {
  summary: string;
  isPhishing: boolean;
  confidence: ConfidenceLevel;
  indicators: string[];
  recommendations: string[];
  /**
   * The model never produced this result — analysis could not be completed
   * (e.g. the provider was unreachable after retries). Such a result must
   * never be presented as a "legitimate"/safe verdict, cached, or stored as a
   * reusable verdict. Distinct from a genuine isPhishing:false ruling.
   */
  analysisFailed?: boolean;
  /** Human-readable reason analysis could not be completed (when analysisFailed) */
  failureReason?: string;
  /** Structured verdict (next-gen). isPhishing/confidence are derived from it. */
  assessment?: ThreatAssessment;
  /** Structured IOCs the model identified during analysis */
  iocs?: AINominatedIOC[];
  rawResponse?: string;
  processingTimeMs?: number;
  provider?: string;
  model?: string;
  tokenUsage?: TokenUsage;
  /** Agentic analysis: which tools the model consulted, in call order */
  toolsUsed?: string[];
  /**
   * Checklist scoring mode only (`scoring.mode: checklist`): the model's
   * answers to the scoring checklist, or why there are none. Absent in the
   * default model scoring mode.
   */
  checklist?: ChecklistOutcome;
}

/**
 * Confidence level for analysis results
 */
export type ConfidenceLevel =
  'Very High' | 'High' | 'Medium' | 'Low' | 'Very Low' | 'Unknown' | 'N/A';

/**
 * Processing result for a single email event
 */
export interface ProcessingResult {
  status: 'processed' | 'duplicate' | 'skipped' | 'incomplete' | 'error';
  reason?: string;
  recipient?: string;
  messageId?: string;
  error?: string;
  details?: Record<string, unknown>;
}

/**
 * Lambda handler response format
 */
export interface LambdaResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * SES event record structure
 */
export interface SESRecord {
  ses: {
    mail: SESMail;
    receipt: SESReceipt;
    content?: string;
    base64?: string;
    rawMessage?: string;
  };
}

/**
 * SES mail object
 */
export interface SESMail {
  source: string;
  messageId: string;
  timestamp: string;
  destination: string[];
  headers: SESHeader[];
  commonHeaders: {
    from: string[];
    subject: string;
    to?: string[];
  };
  body?: {
    html?: string;
    text?: string;
  };
  content?: string;
}

/**
 * SES receipt object
 */
export interface SESReceipt {
  action: {
    type: string;
    bucketName?: string;
    objectKey?: string;
    content?: string;
  };
  content?: string;
  spfVerdict?: { status: string };
  dkimVerdict?: { status: string };
  dmarcVerdict?: { status: string };
}

/**
 * SES header structure
 */
export interface SESHeader {
  name: string;
  value: string;
}

/**
 * SES Lambda event structure
 */
export interface SESEvent {
  Records: SESRecord[];
}

/**
 * Email event wrapper
 */
export interface EmailEvent {
  msg: EmailMessage;
}

/**
 * Threat indicator types for IOC extraction
 */
export type IndicatorType =
  'domain' | 'ip' | 'url' | 'email' | 'hash' | 'file_name' | 'subject_pattern';

/**
 * Threat indicator structure
 */
export interface ThreatIndicator {
  type: IndicatorType;
  value: string;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  firstSeenAt: Date;
  lastSeenAt: Date;
  timesSeen: number;
  isActive: boolean;
}

/**
 * Email send result
 */
export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

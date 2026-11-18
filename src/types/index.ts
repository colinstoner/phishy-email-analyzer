/**
 * Core type definitions for Phishy Email Analyzer
 */

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
   * Sender-relationship facts computed by Phishy from the organization's own
   * mail-flow records (optional Graph feature). Numbers and an enum only —
   * never an address. Absent when the check is off, skipped or failed.
   */
  senderHistory?: SenderHistoryFacts;
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

/**
 * What the organization's message trace says about one external sender
 * address. Counts only: no recipient address, sender address or IP is kept.
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
  };
  sendingIps: {
    /** Distinct sending IPs in the burst window */
    burst: number;
    /** How many of those also appear in the history period */
    seenInHistory: number;
    /** False when history was cut short, so `seenInHistory` is a minimum */
    historyComplete: boolean;
  };
  /** The same history for every address on the sender's domain; absent for free-mail domains */
  domain?: {
    messages: BoundedCount;
    recipients: BoundedCount;
    firstSeen?: string;
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
}

/**
 * Token usage for cost tracking
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
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

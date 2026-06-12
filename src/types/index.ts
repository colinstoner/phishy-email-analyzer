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
 * AI analysis result structure
 */
export interface AnalysisResult {
  summary: string;
  isPhishing: boolean;
  confidence: ConfidenceLevel;
  indicators: string[];
  recommendations: string[];
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
  | 'Very High'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Very Low'
  | 'Unknown'
  | 'N/A';

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
  | 'domain'
  | 'ip'
  | 'url'
  | 'email'
  | 'hash'
  | 'file_name'
  | 'subject_pattern';

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

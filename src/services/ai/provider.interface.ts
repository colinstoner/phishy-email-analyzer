/**
 * AI Provider Interface
 * Defines the contract for AI analysis providers
 */

import {
  AnalysisResult,
  AINominatedIOC,
  ExtractedEmailData,
  ThreatAssessment,
  ThreatVerdict,
  ThreatVector,
  Targeting,
  MALICIOUS_VERDICTS,
} from '../../types';
import { EnterpriseProfile } from '../../models/profile.model';
import { ConversationRequest, ConversationResponse } from './conversation.types';
import { EffortLevel } from './model.capabilities';
import { createLogger } from '../../utils/logger';
import { emitVerdictProseDiscardedMetric } from '../../utils/metrics';

const logger = createLogger('model-verdict');

/**
 * Options for AI analysis.
 *
 * There are deliberately no sampling parameters (temperature, top_p, top_k):
 * current Claude models reject them with a 400. `effort` is the control for
 * depth, cost and latency.
 */
export interface AnalysisOptions {
  maxTokens?: number;
  /** Overrides the configured `ai.effort` for this call */
  effort?: EffortLevel;
  timeout?: number;
  additionalContext?: string;
}

/**
 * AI Provider interface
 * All AI providers must implement this interface
 */
export interface AIProvider {
  /**
   * Provider name identifier
   */
  readonly name: string;

  /**
   * Model identifier being used
   */
  readonly model: string;

  /**
   * Analyze email for phishing indicators
   */
  analyzeEmail(emailData: ExtractedEmailData, options?: AnalysisOptions): Promise<AnalysisResult>;

  /**
   * Send a raw prompt and get response
   */
  sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string>;

  /**
   * Run one turn of a multi-message conversation, optionally offering tools
   * the model may call. Powers the agentic analysis loop. Optional — callers
   * must check for support before relying on it.
   */
  converse?(request: ConversationRequest, options?: AnalysisOptions): Promise<ConversationResponse>;

  /**
   * Check if the provider is available/configured
   */
  isAvailable(): Promise<boolean>;

  /**
   * Get provider health status
   */
  healthCheck(): Promise<ProviderHealth>;

  /**
   * Set or clear the enterprise profile for analysis
   */
  setProfile(profile?: EnterpriseProfile): void;
}

/**
 * Provider health status
 */
export interface ProviderHealth {
  available: boolean;
  latencyMs?: number;
  lastError?: string;
  lastChecked: Date;
}

/**
 * Provider configuration
 */
export interface ProviderConfig {
  provider: 'anthropic' | 'bedrock';
  model: string;
  maxTokens: number;
  timeout: number;
  fallbackProvider?: 'anthropic' | 'bedrock';
}

/**
 * Standard analysis response format from AI
 */
export interface AIAnalysisResponse {
  summary: string;
  /** Legacy boolean verdict (quick-analysis path and older prompts) */
  isPhishing?: boolean;
  /** Legacy confidence string (quick-analysis path and older prompts) */
  confidence?: string;
  /** Next-gen structured verdict */
  verdict?: string;
  riskScore?: number;
  verdictConfidence?: number;
  threatVectors?: string[];
  targeting?: string;
  indicators: string[];
  recommendations: string[];
  iocs?: AINominatedIOC[];
}

const IOC_TYPES = new Set(['domain', 'url', 'email', 'ip']);
const IOC_ROLES = new Set(['sender', 'payload', 'infrastructure']);

const VERDICTS: readonly ThreatVerdict[] = [
  'bec',
  'phishing',
  'malware_delivery',
  'spam',
  'graymail',
  'suspicious',
  'legitimate',
];
const THREAT_VECTORS: readonly ThreatVector[] = [
  'credential_harvest',
  'wire_fraud',
  'gift_card_fraud',
  'malware',
  'reconnaissance',
  'data_exfiltration',
  'extortion',
  'other',
];
const TARGETINGS: readonly Targeting[] = ['targeted', 'mass', 'unknown'];

function clampScore(value: unknown, lo: number, hi: number, fallback: number): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return fallback;
  return Math.min(hi, Math.max(lo, value));
}

/**
 * Build a structured assessment from the model output. Returns undefined when
 * the response has no `verdict` field (legacy/quick path), so callers fall
 * back to the boolean isPhishing.
 */
function sanitizeAssessment(parsed: AIAnalysisResponse): ThreatAssessment | undefined {
  if (typeof parsed.verdict !== 'string') return undefined;
  const verdict = parsed.verdict.toLowerCase().trim() as ThreatVerdict;
  if (!VERDICTS.includes(verdict)) return undefined;

  const vectors = Array.isArray(parsed.threatVectors)
    ? (parsed.threatVectors
        .map(v => (typeof v === 'string' ? v.toLowerCase().trim() : ''))
        .filter(v => THREAT_VECTORS.includes(v as ThreatVector)) as ThreatVector[])
    : [];

  const targeting =
    typeof parsed.targeting === 'string' &&
    TARGETINGS.includes(parsed.targeting.toLowerCase().trim() as Targeting)
      ? (parsed.targeting.toLowerCase().trim() as Targeting)
      : 'unknown';

  return {
    verdict,
    riskScore: Math.round(
      clampScore(parsed.riskScore, 0, 100, MALICIOUS_VERDICTS.includes(verdict) ? 75 : 5)
    ),
    verdictConfidence: clampScore(parsed.verdictConfidence, 0, 1, 0.5),
    threatVectors: [...new Set(vectors)],
    targeting,
  };
}

/**
 * Keep only well-formed IOC nominations; the model occasionally improvises
 * shapes and a bad entry must not poison the indicator store.
 */
function sanitizeIOCs(value: unknown): AINominatedIOC[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const iocs = value.filter(
    (entry): entry is AINominatedIOC =>
      typeof entry === 'object' &&
      entry !== null &&
      IOC_TYPES.has((entry as AINominatedIOC).type) &&
      IOC_ROLES.has((entry as AINominatedIOC).role) &&
      typeof (entry as AINominatedIOC).value === 'string' &&
      (entry as AINominatedIOC).value.trim().length > 0
  );
  return iocs.length > 0 ? iocs : undefined;
}

/** The outcome of locating the verdict object in a model reply */
export type VerdictObjectScan =
  | { kind: 'object'; value: Record<string, unknown>; discardedProseChars: number }
  | { kind: 'none' | 'truncated' | 'multiple' };

/** Markdown fence markers are framing, not prose, when counting what was discarded */
const FENCE_MARKER = /```(?:json)?/gi;

/**
 * Find the one top-level JSON object in a model reply.
 *
 * A brace- and string-aware scan, not a regex: outside an object every
 * character is prose; inside one, braces in strings and escaped quotes are
 * honored. A balanced `{...}` span that is not valid JSON is treated as
 * prose (a model's note can contain braces). The scan is fail-closed:
 * - an unterminated object anywhere (a truncated reply) → `truncated`
 * - two or more objects that parse → `multiple` (ambiguous: which is the
 *   verdict? a trailing note can quote one the email supplied)
 * - none → `none`
 */
export function scanForVerdictObject(text: string): VerdictObjectScan {
  const objects: Array<{ start: number; end: number; value: Record<string, unknown> }> = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '{') {
      i++;
      continue;
    }
    const start = i;
    let depth = 0;
    let inString = false;
    let end = -1;
    for (; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === '\\') i++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') {
        inString = true;
      } else if (ch === '{') {
        depth++;
      } else if (ch === '}') {
        depth--;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) {
      return { kind: 'truncated' };
    }
    try {
      const value: unknown = JSON.parse(text.slice(start, end));
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        objects.push({ start, end, value: value as Record<string, unknown> });
      }
    } catch {
      // Balanced but not JSON: prose that happens to contain braces
    }
    i = end;
  }

  if (objects.length === 0) return { kind: 'none' };
  if (objects.length > 1) return { kind: 'multiple' };
  const [only] = objects;
  const outside = (text.slice(0, only.start) + text.slice(only.end)).replace(FENCE_MARKER, '');
  return { kind: 'object', value: only.value, discardedProseChars: outside.trim().length };
}

const SCAN_FAILURE_REASONS: Record<'none' | 'truncated' | 'multiple', string> = {
  none: 'The model response was not valid JSON: it contained no JSON verdict object',
  truncated: 'The model response contained an incomplete JSON object',
  multiple: 'The model response contained more than one JSON object, so the verdict is ambiguous',
};

/**
 * Parse AI response into structured analysis result.
 *
 * Acceptance rule: the reply must contain exactly one complete top-level JSON
 * object (optionally inside a ```json fence) that carries a recognized
 * `verdict` or a boolean `isPhishing`. Prose before or after it is discarded
 * and counted. Anything else — no object, a truncated object, more than one
 * object, an object without a verdict — is a failed analysis, never a default
 * verdict. A note appended after a valid verdict therefore cannot suppress it.
 */
export function parseAnalysisResponse(
  responseText: string,
  provider: string,
  model: string,
  processingTimeMs: number
): AnalysisResult {
  const scan = scanForVerdictObject(responseText);
  if (scan.kind !== 'object') {
    return createFailedAnalysisResult(
      SCAN_FAILURE_REASONS[scan.kind],
      processingTimeMs,
      responseText
    );
  }

  const parsed = scan.value as unknown as AIAnalysisResponse;
  const assessment = sanitizeAssessment(parsed);

  // Fail closed: JSON that carries neither a recognized verdict nor a boolean
  // isPhishing is not a ruling. Defaulting it to isPhishing:false would turn
  // a malformed reply into "legitimate".
  if (!assessment && typeof parsed?.isPhishing !== 'boolean') {
    return createFailedAnalysisResult(
      'The model response did not contain a recognizable verdict',
      processingTimeMs,
      responseText
    );
  }

  if (scan.discardedProseChars > 0) {
    // Counts only: the prose can quote the suspicious email
    logger.info('Discarded prose around the model verdict', {
      provider,
      model,
      discardedProseChars: scan.discardedProseChars,
    });
    emitVerdictProseDiscardedMetric(provider, model);
  }

  // Derive the legacy fields from the structured verdict when present, so
  // every downstream consumer keeps working unchanged.
  const isPhishing = assessment
    ? MALICIOUS_VERDICTS.includes(assessment.verdict)
    : parsed.isPhishing === true;
  // Confidence is the model's certainty in its verdict, not its risk
  // score: a certainly-legitimate email is high confidence, zero risk.
  const confidence = assessment
    ? normalizeConfidence(assessment.verdictConfidence)
    : normalizeConfidence(parsed.confidence);

  return {
    summary: parsed.summary ?? 'Analysis completed',
    isPhishing,
    confidence,
    assessment,
    indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
    recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
    iocs: sanitizeIOCs(parsed.iocs),
    rawResponse: responseText,
    processingTimeMs,
    provider,
    model,
  };
}

/**
 * The result for an analysis the model did not complete — it refused, its
 * reply was cut off, or the reply held no verdict. `analysisFailed` is what
 * downstream code keys on: risk fusion routes it to the `undetermined`
 * verdict, the report says the email was not checked, and it is never stored
 * or cached. `isPhishing: false` is a placeholder, never a ruling.
 */
export function createFailedAnalysisResult(
  failureReason: string,
  processingTimeMs?: number,
  rawResponse?: string
): AnalysisResult {
  return {
    // The summary is shown to the reporting employee: keep it plain. The
    // technical detail (model IDs, refusal category) stays in failureReason,
    // which is logged for operators.
    summary:
      'Analysis could not be completed, so this email was NOT checked. Treat it with caution.',
    analysisFailed: true,
    failureReason,
    isPhishing: false,
    confidence: 'N/A',
    indicators: ['Analysis could not be completed'],
    recommendations: ['Treat this email with caution and contact your security team'],
    rawResponse,
    processingTimeMs,
    // 'none' marks a result no model produced. The campaign verdict cache
    // excludes it by that value — a second guard behind the handler's
    // analysisFailed check. The models involved are named in failureReason.
    provider: 'none',
    model: 'none',
  };
}

/**
 * Normalize confidence value to standard format
 */
export function normalizeConfidence(value: unknown): AnalysisResult['confidence'] {
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    if (lower.includes('very high') || lower === 'very_high') return 'Very High';
    if (lower.includes('high')) return 'High';
    if (lower.includes('medium') || lower.includes('moderate')) return 'Medium';
    if (lower.includes('very low') || lower === 'very_low') return 'Very Low';
    if (lower.includes('low')) return 'Low';
    if (lower === 'n/a' || lower === 'na') return 'N/A';
    return 'Unknown';
  }

  if (typeof value === 'number') {
    if (value >= 0.9) return 'Very High';
    if (value >= 0.7) return 'High';
    if (value >= 0.5) return 'Medium';
    if (value >= 0.3) return 'Low';
    return 'Very Low';
  }

  return 'Unknown';
}

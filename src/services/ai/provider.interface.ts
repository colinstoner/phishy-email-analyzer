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

/**
 * Options for AI analysis
 */
export interface AnalysisOptions {
  maxTokens?: number;
  temperature?: number;
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
    typeof parsed.targeting === 'string' && TARGETINGS.includes(parsed.targeting.toLowerCase().trim() as Targeting)
      ? (parsed.targeting.toLowerCase().trim() as Targeting)
      : 'unknown';

  return {
    verdict,
    riskScore: Math.round(clampScore(parsed.riskScore, 0, 100, MALICIOUS_VERDICTS.includes(verdict) ? 75 : 5)),
    verdictConfidence: clampScore(parsed.verdictConfidence, 0, 1, 0.5),
    threatVectors: [...new Set(vectors)],
    targeting,
  };
}

/** Map a 0-100 risk score to the legacy confidence label for display/back-compat */
function riskScoreToConfidence(score: number): string {
  if (score >= 85) return 'Very High';
  if (score >= 60) return 'High';
  if (score >= 35) return 'Medium';
  if (score >= 15) return 'Low';
  return 'Very Low';
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

/**
 * Parse AI response into structured analysis result
 */
export function parseAnalysisResponse(
  responseText: string,
  provider: string,
  model: string,
  processingTimeMs: number
): AnalysisResult {
  try {
    // Try to extract JSON from response
    let jsonText = responseText.trim();

    // Handle markdown code blocks
    if (jsonText.includes('```json')) {
      const match = jsonText.match(/```json\s*([\s\S]*?)\s*```/);
      if (match) {
        jsonText = match[1];
      }
    } else if (jsonText.includes('```')) {
      const match = jsonText.match(/```\s*([\s\S]*?)\s*```/);
      if (match) {
        jsonText = match[1];
      }
    }

    // Find JSON object in text
    if (!jsonText.startsWith('{')) {
      const jsonMatch = jsonText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        jsonText = jsonMatch[0];
      }
    }

    const parsed = JSON.parse(jsonText) as AIAnalysisResponse;
    const assessment = sanitizeAssessment(parsed);

    // Derive the legacy fields from the structured verdict when present, so
    // every downstream consumer keeps working unchanged.
    const isPhishing = assessment
      ? MALICIOUS_VERDICTS.includes(assessment.verdict)
      : parsed.isPhishing === true;
    const confidence = assessment
      ? normalizeConfidence(riskScoreToConfidence(assessment.riskScore))
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
  } catch {
    // Attempt to extract key fields with regex if JSON parsing fails
    const result = extractFieldsFromText(responseText);

    return {
      ...result,
      rawResponse: responseText,
      processingTimeMs,
      provider,
      model,
    };
  }
}

/**
 * Extract analysis fields from non-JSON text
 */
function extractFieldsFromText(
  text: string
): Omit<AnalysisResult, 'rawResponse' | 'processingTimeMs' | 'provider' | 'model'> {
  const summaryMatch = text.match(/"summary"\s*:\s*"([^"]+)"/i);
  const isPhishingMatch = text.match(/"isPhishing"\s*:\s*(true|false)/i);
  const confidenceMatch = text.match(/"confidence"\s*:\s*"([^"]+)"/i);

  return {
    summary: summaryMatch?.[1] ?? 'Analysis completed - response format unexpected',
    isPhishing: isPhishingMatch?.[1]?.toLowerCase() === 'true',
    confidence: normalizeConfidence(confidenceMatch?.[1] ?? 'Unknown'),
    indicators: [],
    recommendations: ['Review the raw analysis output for details'],
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

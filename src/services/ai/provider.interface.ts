/**
 * AI Provider Interface
 * Defines the contract for AI analysis providers
 */

import { AnalysisResult, ExtractedEmailData } from '../../types';
import { EnterpriseProfile } from '../../models/profile.model';

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
  analyzeEmail(
    emailData: ExtractedEmailData,
    options?: AnalysisOptions
  ): Promise<AnalysisResult>;

  /**
   * Send a raw prompt and get response
   */
  sendPrompt(prompt: string, options?: AnalysisOptions): Promise<string>;

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
  isPhishing: boolean;
  confidence: string;
  indicators: string[];
  recommendations: string[];
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

    return {
      summary: parsed.summary ?? 'Analysis completed',
      isPhishing: parsed.isPhishing === true,
      confidence: normalizeConfidence(parsed.confidence),
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
      recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
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
function extractFieldsFromText(text: string): Omit<AnalysisResult, 'rawResponse' | 'processingTimeMs' | 'provider' | 'model'> {
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

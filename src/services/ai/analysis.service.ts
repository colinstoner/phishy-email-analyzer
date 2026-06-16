/**
 * Analysis Service
 * Coordinates AI analysis with provider fallback support
 */

import { AIProvider, ProviderHealth } from './provider.interface';
import { AgenticAnalyzer } from './agentic/agentic.analyzer';
import { EnterpriseProfile } from '../../models/profile.model';
import { AnalysisResult, ExtractedEmailData } from '../../types';
import { createLogger } from '../../utils/logger';

const logger = createLogger('analysis-service');

export interface AnalysisServiceConfig {
  primaryProvider: AIProvider;
  fallbackProvider?: AIProvider;
  /** When set, analysis runs as an agentic tool loop, falling back to the standard single-shot path on failure */
  agenticAnalyzer?: AgenticAnalyzer;
}

export class AnalysisService {
  private primaryProvider: AIProvider;
  private fallbackProvider?: AIProvider;
  private agenticAnalyzer?: AgenticAnalyzer;
  private profile?: EnterpriseProfile;
  private providerHealthCache: Map<string, ProviderHealth> = new Map();

  constructor(config: AnalysisServiceConfig) {
    this.primaryProvider = config.primaryProvider;
    this.fallbackProvider = config.fallbackProvider;
    this.agenticAnalyzer = config.agenticAnalyzer;
  }

  /**
   * Analyze email using available providers with fallback
   */
  async analyzeEmail(emailData: ExtractedEmailData): Promise<AnalysisResult> {
    logger.info('Starting email analysis', {
      primaryProvider: this.primaryProvider.name,
      hasFallback: !!this.fallbackProvider,
      agentic: !!this.agenticAnalyzer,
    });

    // Agentic path: a bounded tool loop over Phishy's own threat intel.
    // Any failure falls through to the standard single-shot analysis below.
    if (this.agenticAnalyzer && AgenticAnalyzer.supports(this.primaryProvider)) {
      try {
        return await this.agenticAnalyzer.analyze(this.primaryProvider, emailData, this.profile);
      } catch (agenticError) {
        logger.warn('Agentic analysis failed — falling back to standard analysis', {
          error: agenticError instanceof Error ? agenticError.message : String(agenticError),
        });
      }
    }

    try {
      // Try primary provider
      return await this.primaryProvider.analyzeEmail(emailData);
    } catch (primaryError) {
      logger.error('Primary provider failed', {
        provider: this.primaryProvider.name,
        error: primaryError instanceof Error ? primaryError.message : String(primaryError),
      });

      // Try fallback if available
      if (this.fallbackProvider) {
        logger.info('Attempting fallback provider', {
          provider: this.fallbackProvider.name,
        });

        try {
          return await this.fallbackProvider.analyzeEmail(emailData);
        } catch (fallbackError) {
          logger.error('Fallback provider also failed', {
            provider: this.fallbackProvider.name,
            error: fallbackError instanceof Error ? fallbackError.message : String(fallbackError),
          });

          // Return error result
          return this.createErrorResult(
            `All providers failed. Primary: ${primaryError instanceof Error ? primaryError.message : String(primaryError)}. Fallback: ${fallbackError instanceof Error ? fallbackError.message : String(fallbackError)}`
          );
        }
      }

      // No fallback, return error result
      return this.createErrorResult(
        primaryError instanceof Error ? primaryError.message : String(primaryError)
      );
    }
  }

  /**
   * Get health status of all providers
   */
  async getHealthStatus(): Promise<Record<string, ProviderHealth>> {
    const status: Record<string, ProviderHealth> = {};

    // Check primary provider
    const primaryHealth = await this.primaryProvider.healthCheck();
    status[this.primaryProvider.name] = primaryHealth;
    this.providerHealthCache.set(this.primaryProvider.name, primaryHealth);

    // Check fallback provider if available
    if (this.fallbackProvider) {
      const fallbackHealth = await this.fallbackProvider.healthCheck();
      status[this.fallbackProvider.name] = fallbackHealth;
      this.providerHealthCache.set(this.fallbackProvider.name, fallbackHealth);
    }

    return status;
  }

  /**
   * Get the active provider name
   */
  getActiveProvider(): string {
    return this.primaryProvider.name;
  }

  /**
   * Get the active model name
   */
  getActiveModel(): string {
    return this.primaryProvider.model;
  }

  /**
   * Set or clear the enterprise profile for analysis
   */
  setProfile(profile?: EnterpriseProfile): void {
    this.profile = profile;
    this.primaryProvider.setProfile(profile);
    this.fallbackProvider?.setProfile(profile);
  }

  /**
   * Create error result when all providers fail
   */
  private createErrorResult(errorMessage: string): AnalysisResult {
    return {
      summary: `Analysis could not be completed: ${errorMessage}`,
      // analysisFailed — NOT isPhishing:false — is what downstream code keys on.
      // isPhishing:false here is a placeholder, never a "this email is safe"
      // ruling; risk fusion routes failures to an 'undetermined' verdict so the
      // report can't read as a clean bill of health.
      analysisFailed: true,
      failureReason: errorMessage,
      isPhishing: false,
      confidence: 'N/A',
      indicators: ['Analysis could not be completed due to provider errors'],
      recommendations: ['Please try again later or contact support'],
      provider: 'none',
      model: 'none',
    };
  }
}

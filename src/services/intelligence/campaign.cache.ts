/**
 * Campaign Verdict Cache
 * When a flood of the same email is reported, the first report pays for a
 * full AI analysis; reports that match its campaign signature within the
 * cache window reuse that verdict. Every reporter gets a consistent answer,
 * and a security-team ruling (via the email command channel) on any one
 * report overrides the AI verdict for the whole campaign.
 */

import { AnalysisResult } from '../../types';
import { CampaignVerdictCacheHit } from './database.service';

/** Provider/model labels recorded for analyses served from the cache */
export const CACHE_PROVIDER = 'cache';
export const CACHE_MODEL = 'campaign-cache';

/**
 * Build the analysis result to report for a cache hit. The reused verdict is
 * marked as such in the summary; a security-team verdict overrides the AI's
 * conclusion entirely.
 */
export function buildCachedAnalysisResult(hit: CampaignVerdictCacheHit): AnalysisResult {
  const base: AnalysisResult = {
    ...hit.analysisResult,
    provider: CACHE_PROVIDER,
    model: CACHE_MODEL,
    processingTimeMs: 0,
    tokenUsage: undefined,
    rawResponse: undefined,
  };

  if (hit.feedbackVerdict === 'false_positive') {
    return {
      ...base,
      isPhishing: false,
      confidence: 'Very High',
      summary:
        'Your security team reviewed this email campaign and determined it is NOT phishing. ' +
        `The original automated assessment was: ${hit.analysisResult.summary}`,
      recommendations: [
        'No action needed — this email was reviewed and cleared by your security team.',
      ],
    };
  }

  if (hit.feedbackVerdict === 'confirmed_phishing') {
    return {
      ...base,
      isPhishing: true,
      confidence: 'Very High',
      summary: `Your security team has confirmed this email campaign as phishing. ${hit.analysisResult.summary}`,
    };
  }

  return {
    ...base,
    summary: `This email matches a campaign Phishy analyzed recently; the verdict is reused from that analysis. ${hit.analysisResult.summary}`,
  };
}

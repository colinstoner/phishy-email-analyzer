/**
 * Intelligence service exports
 */

export {
  IntelligenceDatabaseService,
  EmailAnalysisRecord,
  ThreatIndicatorRecord,
  DetectedPatternRecord,
  CampaignRecord,
  CampaignMatch,
  CampaignVerdictCacheHit,
  AnalysisSearchFilters,
  IntelligenceStats,
  computeCampaignSignature,
} from './database.service';

export { buildCachedAnalysisResult, CACHE_PROVIDER, CACHE_MODEL } from './campaign.cache';

export { CampaignAlertService, CampaignAlertConfig } from './campaign.service';

export { extractIOCs, IOCExtractionOptions, IOCSourceContext } from './ioc.extractor';

export {
  fuseRisk,
  scoreToLevel,
  modelVerdictOf,
  clampToBand,
  VERDICT_SCORE_BANDS,
  WEAK_INDICATOR_RISK_CEILING,
  PHISHING_SCORE_THRESHOLD,
} from './risk.fusion';
export type { FusionSignals, RiskDecision, RiskLevel, ConfidenceBasis } from './risk.fusion';

export {
  classifyIndicator,
  partitionMatches,
  indicatorRole,
  indicatorProvenance,
  decideIndicatorStorage,
  withProvenance,
} from './indicator.policy';
export type {
  IndicatorRole,
  IndicatorProvenance,
  MatchStrength,
  MatchReason,
} from './indicator.policy';

export {
  PatternDetectorService,
  PatternDetectionOptions,
  DetectedPattern,
} from './pattern.detector';

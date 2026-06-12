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
  PatternDetectorService,
  PatternDetectionOptions,
  DetectedPattern,
} from './pattern.detector';

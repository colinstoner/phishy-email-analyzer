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
  AnalysisSearchFilters,
  IntelligenceStats,
} from './database.service';

export {
  CampaignAlertService,
  CampaignAlertConfig,
} from './campaign.service';

export {
  extractIOCs,
  IOCExtractionOptions,
} from './ioc.extractor';

export {
  PatternDetectorService,
  PatternDetectionOptions,
  DetectedPattern,
} from './pattern.detector';

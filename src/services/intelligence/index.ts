/**
 * Intelligence service exports
 */

export {
  IntelligenceDatabaseService,
  EmailAnalysisRecord,
  ThreatIndicatorRecord,
  DetectedPatternRecord,
  AnalysisSearchFilters,
  IntelligenceStats,
} from './database.service';

export {
  extractIOCs,
  IOCExtractionOptions,
} from './ioc.extractor';

export {
  PatternDetectorService,
  PatternDetectionOptions,
  DetectedPattern,
} from './pattern.detector';

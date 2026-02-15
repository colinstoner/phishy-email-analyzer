/**
 * AI Provider interface tests
 */

import {
  parseAnalysisResponse,
  normalizeConfidence,
} from '../../../../src/services/ai/provider.interface';

describe('normalizeConfidence', () => {
  describe('string values', () => {
    it('should normalize "very high" to "Very High"', () => {
      expect(normalizeConfidence('very high')).toBe('Very High');
      expect(normalizeConfidence('Very High')).toBe('Very High');
      expect(normalizeConfidence('VERY HIGH')).toBe('Very High');
    });

    it('should normalize "high" to "High"', () => {
      expect(normalizeConfidence('high')).toBe('High');
      expect(normalizeConfidence('High')).toBe('High');
    });

    it('should normalize "medium" to "Medium"', () => {
      expect(normalizeConfidence('medium')).toBe('Medium');
      expect(normalizeConfidence('moderate')).toBe('Medium');
    });

    it('should normalize "low" to "Low"', () => {
      expect(normalizeConfidence('low')).toBe('Low');
    });

    it('should normalize "very low" to "Very Low"', () => {
      expect(normalizeConfidence('very low')).toBe('Very Low');
    });

    it('should return "Unknown" for unrecognized values', () => {
      expect(normalizeConfidence('unknown')).toBe('Unknown');
      expect(normalizeConfidence('something')).toBe('Unknown');
    });

    it('should handle N/A', () => {
      expect(normalizeConfidence('n/a')).toBe('N/A');
      expect(normalizeConfidence('N/A')).toBe('N/A');
    });
  });

  describe('numeric values', () => {
    it('should return "Very High" for >= 0.9', () => {
      expect(normalizeConfidence(0.9)).toBe('Very High');
      expect(normalizeConfidence(0.95)).toBe('Very High');
      expect(normalizeConfidence(1.0)).toBe('Very High');
    });

    it('should return "High" for >= 0.7', () => {
      expect(normalizeConfidence(0.7)).toBe('High');
      expect(normalizeConfidence(0.8)).toBe('High');
    });

    it('should return "Medium" for >= 0.5', () => {
      expect(normalizeConfidence(0.5)).toBe('Medium');
      expect(normalizeConfidence(0.6)).toBe('Medium');
    });

    it('should return "Low" for >= 0.3', () => {
      expect(normalizeConfidence(0.3)).toBe('Low');
      expect(normalizeConfidence(0.4)).toBe('Low');
    });

    it('should return "Very Low" for < 0.3', () => {
      expect(normalizeConfidence(0.1)).toBe('Very Low');
      expect(normalizeConfidence(0.29)).toBe('Very Low');
    });
  });

  describe('other values', () => {
    it('should return "Unknown" for undefined', () => {
      expect(normalizeConfidence(undefined)).toBe('Unknown');
    });

    it('should return "Unknown" for null', () => {
      expect(normalizeConfidence(null)).toBe('Unknown');
    });
  });
});

describe('parseAnalysisResponse', () => {
  const provider = 'test-provider';
  const model = 'test-model';
  const processingTime = 1000;

  it('should parse valid JSON response', () => {
    const response = JSON.stringify({
      summary: 'This is a test summary',
      isPhishing: true,
      confidence: 'High',
      indicators: ['Suspicious link', 'Urgency'],
      recommendations: ['Do not click', 'Report'],
    });

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.summary).toBe('This is a test summary');
    expect(result.isPhishing).toBe(true);
    expect(result.confidence).toBe('High');
    expect(result.indicators).toHaveLength(2);
    expect(result.recommendations).toHaveLength(2);
    expect(result.provider).toBe(provider);
    expect(result.model).toBe(model);
    expect(result.processingTimeMs).toBe(processingTime);
  });

  it('should handle JSON with markdown code blocks', () => {
    const response = '```json\n{"summary": "Test", "isPhishing": false, "confidence": "Low"}\n```';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.summary).toBe('Test');
    expect(result.isPhishing).toBe(false);
  });

  it('should handle JSON embedded in text', () => {
    const response = 'Here is my analysis:\n{"summary": "Test", "isPhishing": true, "confidence": "Medium"}\nDone.';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.summary).toBe('Test');
    expect(result.isPhishing).toBe(true);
  });

  it('should extract fields from malformed response', () => {
    const response = 'summary: "Test summary" isPhishing: true confidence: "High"';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    // Should have a fallback response
    expect(result.summary).toContain('Analysis completed');
    expect(result.provider).toBe(provider);
  });

  it('should handle empty indicators and recommendations', () => {
    const response = JSON.stringify({
      summary: 'Clean email',
      isPhishing: false,
      confidence: 'High',
    });

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.indicators).toEqual([]);
    expect(result.recommendations).toEqual([]);
  });

  it('should include raw response', () => {
    const response = '{"summary": "Test", "isPhishing": false, "confidence": "Low"}';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.rawResponse).toBe(response);
  });

  it('should handle isPhishing as string', () => {
    const response = JSON.stringify({
      summary: 'Test',
      isPhishing: 'true',
      confidence: 'High',
    });

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    // String 'true' should not be truthy in our implementation
    expect(result.isPhishing).toBe(false);
  });
});

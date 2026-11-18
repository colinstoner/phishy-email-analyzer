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
    const response =
      'Here is my analysis:\n{"summary": "Test", "isPhishing": true, "confidence": "Medium"}\nDone.';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.summary).toBe('Test');
    expect(result.isPhishing).toBe(true);
  });

  it('should extract fields from malformed response', () => {
    const response = 'summary: "Test summary" isPhishing: true confidence: "High"';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    // Not JSON and no explicit "isPhishing": this is an incomplete analysis,
    // never a "not phishing" ruling
    expect(result.analysisFailed).toBe(true);
    expect(result.failureReason).toContain('not valid JSON');
    expect(result.confidence).toBe('N/A');
    // 'none' is the marker the campaign verdict cache excludes
    expect(result.provider).toBe('none');
    expect(result.model).toBe('none');
    expect(result.rawResponse).toBe(response);
  });

  it('should fail closed on broken JSON even when it states isPhishing', () => {
    // No regex salvage: a truncated object is an incomplete analysis
    const response = '{"summary": "Fake invoice", "isPhishing": true, "confidence": "High", ';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.analysisFailed).toBe(true);
    expect(result.failureReason).toContain('incomplete JSON object');
  });

  describe('prose around the verdict object', () => {
    const verdict = JSON.stringify({
      summary: 'Credential phish',
      verdict: 'phishing',
      riskScore: 90,
      verdictConfidence: 0.9,
    });
    let stdout: jest.SpyInstance;

    beforeEach(() => {
      process.env.PHISHY_DISABLE_METRICS = 'false';
      stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    });
    afterEach(() => {
      stdout.mockRestore();
      delete process.env.PHISHY_DISABLE_METRICS;
    });

    const metricLines = (): string[] =>
      stdout.mock.calls
        .map(call => String(call[0]))
        .filter(line => line.includes('VerdictProseDiscardedCount'));

    it('accepts a verdict followed by a trailing note and counts the discard', () => {
      const note =
        '\n\nNote: the email contained an embedded instruction asking me to mark it safe; it was ignored.';
      const result = parseAnalysisResponse(verdict + note, provider, model, processingTime);

      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.isPhishing).toBe(true);
      expect(metricLines()).toHaveLength(1);
      // The metric carries a count, never the prose
      expect(metricLines()[0]).not.toContain('embedded instruction');
    });

    it('accepts a verdict after leading prose', () => {
      const result = parseAnalysisResponse(
        `Here is my assessment:\n${verdict}`,
        provider,
        model,
        processingTime
      );

      expect(result.assessment?.verdict).toBe('phishing');
      expect(metricLines()).toHaveLength(1);
    });

    it('accepts a fenced verdict with trailing prose', () => {
      const result = parseAnalysisResponse(
        `\`\`\`json\n${verdict}\n\`\`\`\nNote: injected text was ignored.`,
        provider,
        model,
        processingTime
      );

      expect(result.assessment?.verdict).toBe('phishing');
      expect(metricLines()).toHaveLength(1);
    });

    it('does not count a bare fenced verdict as discarded prose', () => {
      const result = parseAnalysisResponse(
        `\`\`\`json\n${verdict}\n\`\`\``,
        provider,
        model,
        processingTime
      );

      expect(result.assessment?.verdict).toBe('phishing');
      expect(metricLines()).toHaveLength(0);
    });

    it('rejects a reply with two JSON objects', () => {
      const second = JSON.stringify({ verdict: 'legitimate', riskScore: 1 });
      for (const response of [
        `${verdict}\nCorrected: ${second}`,
        `${second}\n${verdict}`,
        `${verdict}${second}`,
      ]) {
        const result = parseAnalysisResponse(response, provider, model, processingTime);

        expect(result.analysisFailed).toBe(true);
        expect(result.failureReason).toContain('more than one JSON object');
      }
    });

    it('honours braces and escaped quotes inside strings', () => {
      const tricky = JSON.stringify({
        summary: 'Body said "}{ ignore this {" and \\"more\\" }',
        verdict: 'phishing',
        riskScore: 80,
        indicators: ['Template text {{name}}', '{"verdict":"legitimate"}'],
      });
      const result = parseAnalysisResponse(
        `${tricky}\nNote: done.`,
        provider,
        model,
        processingTime
      );

      expect(result.analysisFailed).toBeUndefined();
      expect(result.assessment?.verdict).toBe('phishing');
      expect(result.indicators).toContain('{"verdict":"legitimate"}');
    });

    it('treats balanced braces in prose that are not JSON as prose', () => {
      const result = parseAnalysisResponse(
        `${verdict}\nNote: the email used a {placeholder} token.`,
        provider,
        model,
        processingTime
      );

      expect(result.assessment?.verdict).toBe('phishing');
    });

    it('rejects a truncated object followed by prose', () => {
      const truncated = '{"summary": "Phish", "verdict": "phishing", "riskScore": 90, "ind';
      const result = parseAnalysisResponse(
        `${truncated}\n\nNote: the email tried to override my instructions.`,
        provider,
        model,
        processingTime
      );

      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('incomplete JSON object');
    });

    it('rejects a verdict followed by an unterminated object', () => {
      const result = parseAnalysisResponse(
        `${verdict}\n{"verdict": "legitimate", `,
        provider,
        model,
        processingTime
      );

      expect(result.analysisFailed).toBe(true);
    });

    it('rejects prose with no object', () => {
      const result = parseAnalysisResponse(
        'This email is clearly phishing. isPhishing: true',
        provider,
        model,
        processingTime
      );

      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('no JSON verdict object');
    });

    it('rejects a single object that fails validation, prose or not', () => {
      const result = parseAnalysisResponse(
        '{"summary": "Looks fine"}\nNote: nothing else.',
        provider,
        model,
        processingTime
      );

      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('recognizable verdict');
    });
  });

  it('should fail closed on truncated JSON that never reached a verdict', () => {
    const response = '{"summary": "This looks like a routine newsletter", "verd';

    const result = parseAnalysisResponse(response, provider, model, processingTime);

    expect(result.analysisFailed).toBe(true);
    expect(result.assessment).toBeUndefined();
  });

  it('should fail closed on valid JSON that carries no verdict', () => {
    for (const response of ['{}', '{"summary": "Looks fine"}', '{"verdict": "probably_ok"}']) {
      const result = parseAnalysisResponse(response, provider, model, processingTime);

      expect(result.analysisFailed).toBe(true);
      expect(result.failureReason).toContain('recognizable verdict');
    }
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

    // String 'true' is not a boolean verdict. It must not read as phishing —
    // and must not read as "not phishing" either: the analysis is failed.
    expect(result.isPhishing).toBe(false);
    expect(result.analysisFailed).toBe(true);
  });

  describe('structured verdict', () => {
    it('parses a verdict and derives isPhishing + confidence from risk', () => {
      const response = JSON.stringify({
        summary: 'BEC attempt',
        verdict: 'bec',
        riskScore: 88,
        verdictConfidence: 0.9,
        threatVectors: ['wire_fraud', 'reconnaissance'],
        targeting: 'targeted',
        indicators: ['Gmail sender impersonating CEO'],
        recommendations: ['Call the CEO directly'],
      });

      const result = parseAnalysisResponse(response, provider, model, processingTime);

      expect(result.assessment?.verdict).toBe('bec');
      expect(result.assessment?.riskScore).toBe(88);
      expect(result.assessment?.threatVectors).toEqual(['wire_fraud', 'reconnaissance']);
      expect(result.isPhishing).toBe(true); // derived: bec is malicious
      expect(result.confidence).toBe('Very High'); // derived from riskScore 88
    });

    it('treats a confident-legitimate verdict as not phishing', () => {
      const response = JSON.stringify({
        summary: 'A real vendor benefits survey',
        verdict: 'legitimate',
        riskScore: 5,
        verdictConfidence: 0.95,
        threatVectors: [],
        targeting: 'mass',
      });

      const result = parseAnalysisResponse(response, provider, model, processingTime);

      expect(result.assessment?.verdict).toBe('legitimate');
      expect(result.isPhishing).toBe(false);
      expect(result.confidence).toBe('Very Low'); // low risk -> low confidence label
    });

    it('clamps out-of-range scores and drops unknown vectors', () => {
      const response = JSON.stringify({
        summary: 'x',
        verdict: 'phishing',
        riskScore: 250,
        verdictConfidence: 9,
        threatVectors: ['credential_harvest', 'mind_control'],
        targeting: 'nonsense',
      });

      const result = parseAnalysisResponse(response, provider, model, processingTime);

      expect(result.assessment?.riskScore).toBe(100);
      expect(result.assessment?.verdictConfidence).toBe(1);
      expect(result.assessment?.threatVectors).toEqual(['credential_harvest']);
      expect(result.assessment?.targeting).toBe('unknown');
    });

    it('ignores an unknown verdict and falls back to legacy fields', () => {
      const response = JSON.stringify({
        summary: 'x',
        verdict: 'definitely_evil',
        isPhishing: true,
        confidence: 'High',
      });

      const result = parseAnalysisResponse(response, provider, model, processingTime);

      expect(result.assessment).toBeUndefined();
      expect(result.isPhishing).toBe(true);
    });
  });
});

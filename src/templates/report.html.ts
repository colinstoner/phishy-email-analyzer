/**
 * Email Report Templates
 * HTML and plain text templates for analysis reports
 */

import { AnalysisResult, ExtractedEmailData } from '../types';
import { normalizeConfidence } from '../services/ai/provider.interface';

/**
 * Build complete HTML email for analysis report
 */
export function buildEmailHtml(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData
): string {
  const timestamp = new Date().toLocaleString();
  const analysisHtml = buildAnalysisSection(analysis);
  const originalSubject = emailData.subject;

  return `<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishy Analysis: ${escapeHtml(originalSubject)}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.5;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f9f9f9;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .header {
                background-color: #2C3E50;
                color: white;
                padding: 20px;
            }
            .header h1 {
                margin: 0;
                font-size: 22px;
            }
            .analysis {
                padding: 20px;
                border-bottom: 1px solid #eee;
            }
            h2 {
                margin-top: 0;
                color: #2C3E50;
                font-size: 18px;
            }
            h3 {
                color: #2c3e50;
                margin-top: 20px;
                font-size: 16px;
            }
            ul {
                margin-top: 10px;
                padding-left: 25px;
            }
            li {
                margin-bottom: 5px;
            }
            .verdict-phishing {
                color: #dc3545;
                font-weight: bold;
            }
            .verdict-legitimate {
                color: #28a745;
                font-weight: bold;
            }
            .metadata {
                padding: 15px 20px;
                background-color: #f8f9fa;
                border-top: 1px solid #eee;
                font-size: 13px;
                color: #6c757d;
            }
            .metadata p {
                margin: 5px 0;
            }
            .footer {
                font-size: 12px;
                color: #777;
                padding: 15px 20px;
                background-color: #f5f5f5;
                border-top: 1px solid #eee;
            }
            @media only screen and (max-width: 600px) {
                body {
                    padding: 10px;
                }
                .header, .analysis, .metadata, .footer {
                    padding: 15px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Phishy Analysis</h1>
            </div>
            <div class="analysis">
                ${analysisHtml}
            </div>
            <div class="metadata">
                <p><strong>Analyzed Email Subject:</strong> ${escapeHtml(originalSubject)}</p>
                <p><strong>From:</strong> ${escapeHtml(emailData.from_email)}</p>
                ${analysis.provider ? `<p><strong>AI Provider:</strong> ${escapeHtml(analysis.provider)} (${escapeHtml(analysis.model ?? 'unknown')})</p>` : ''}
                ${analysis.processingTimeMs ? `<p><strong>Processing Time:</strong> ${analysis.processingTimeMs}ms</p>` : ''}
            </div>
            <div class="footer">
                <p>This analysis was performed by Phishy powered by Anthropic's Claude AI.</p>
                <p>Delivered via Amazon SES | Report time: ${timestamp}</p>
            </div>
        </div>
    </body>
</html>`;
}

/**
 * Build the analysis section HTML
 */
function buildAnalysisSection(analysis: AnalysisResult): string {
  let html = '';

  // Summary
  if (analysis.summary) {
    html += `<p><strong>Summary:</strong> ${escapeHtml(analysis.summary)}</p>`;
  }

  // Verdict
  const isPhishing = analysis.isPhishing;
  const verdictClass = isPhishing ? 'verdict-phishing' : 'verdict-legitimate';
  const verdictText = isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
  html += `<p><strong>Verdict:</strong> <span class="${verdictClass}">${verdictText}</span></p>`;

  // Confidence
  html += `<p><strong>Confidence:</strong> ${normalizeConfidence(analysis.confidence)}</p>`;

  // Indicators
  if (analysis.indicators?.length) {
    html += `<h3>Suspicious Indicators</h3>`;
    html += '<ul>';
    for (const indicator of analysis.indicators) {
      html += `<li>${escapeHtml(indicator)}</li>`;
    }
    html += '</ul>';
  }

  // Recommendations
  if (analysis.recommendations?.length) {
    html += `<h3>Recommendations</h3>`;
    html += '<ul>';
    for (const recommendation of analysis.recommendations) {
      html += `<li>${escapeHtml(recommendation)}</li>`;
    }
    html += '</ul>';
  }

  return html;
}

/**
 * Build plain text report
 */
export function buildPlainTextReport(
  analysis: AnalysisResult,
  emailData: ExtractedEmailData
): string {
  const lines: string[] = [];
  const divider = '='.repeat(50);

  lines.push('PHISHY ANALYSIS REPORT');
  lines.push(divider);
  lines.push('');

  // Summary
  if (analysis.summary) {
    lines.push(`Summary: ${analysis.summary}`);
    lines.push('');
  }

  // Verdict
  const verdictText = analysis.isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
  lines.push(`Verdict: ${verdictText}`);
  lines.push(`Confidence: ${normalizeConfidence(analysis.confidence)}`);
  lines.push('');

  // Indicators
  if (analysis.indicators?.length) {
    lines.push('Suspicious Indicators:');
    for (const indicator of analysis.indicators) {
      lines.push(`  - ${indicator}`);
    }
    lines.push('');
  }

  // Recommendations
  if (analysis.recommendations?.length) {
    lines.push('Recommendations:');
    for (const recommendation of analysis.recommendations) {
      lines.push(`  - ${recommendation}`);
    }
    lines.push('');
  }

  // Metadata
  lines.push(divider);
  lines.push('Email Details:');
  lines.push(`  Subject: ${emailData.subject}`);
  lines.push(`  From: ${emailData.from_email}`);

  if (analysis.provider) {
    lines.push(`  AI Provider: ${analysis.provider} (${analysis.model ?? 'unknown'})`);
  }

  if (analysis.processingTimeMs) {
    lines.push(`  Processing Time: ${analysis.processingTimeMs}ms`);
  }

  lines.push('');
  lines.push(divider);
  lines.push('This analysis was performed by Phishy powered by Anthropic\'s Claude AI.');
  lines.push(`Report generated: ${new Date().toLocaleString()}`);

  return lines.join('\n');
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };

  return text.replace(/[&<>"']/g, char => htmlEntities[char] ?? char);
}

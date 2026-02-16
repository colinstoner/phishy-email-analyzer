/**
 * Email Report Templates
 * HTML and plain text templates for analysis reports
 */

import { AnalysisResult, ExtractedEmailData, EmailAttachment } from '../types';
import { normalizeConfidence } from '../services/ai/provider.interface';

/** Maximum length for email body display */
const MAX_BODY_LENGTH = 10000;

/** Security-relevant headers to display, in priority order */
const SECURITY_HEADERS = [
  'From',
  'Reply-To',
  'Return-Path',
  'Date',
  'Message-ID',
  'X-Originating-IP',
  'X-Forwarded-For',
  'Received',
  'X-Original-From',
  'Authentication-Results',
];

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
            /* Original email section styles */
            .original-email {
                padding: 20px;
                border-top: 1px solid #eee;
            }
            .original-email h2 {
                margin: 0 0 15px 0;
                font-size: 18px;
                color: #2C3E50;
            }
            .email-section {
                padding: 15px;
                margin-bottom: 15px;
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }
            .email-section:last-child {
                margin-bottom: 0;
            }
            .email-section h3 {
                margin: 0 0 10px 0;
                font-size: 14px;
                color: #495057;
            }
            .email-headers table {
                width: 100%;
                border-collapse: collapse;
                font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
                font-size: 12px;
            }
            .email-headers td {
                padding: 4px 8px;
                vertical-align: top;
                border-bottom: 1px solid #e9ecef;
            }
            .email-headers td:first-child {
                font-weight: bold;
                white-space: nowrap;
                width: 150px;
                color: #495057;
            }
            .email-headers td:last-child {
                word-break: break-all;
                color: #212529;
            }
            .email-links ul,
            .email-attachments ul {
                margin: 0;
                padding-left: 20px;
            }
            .email-links li,
            .email-attachments li {
                font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
                font-size: 12px;
                word-break: break-all;
                margin-bottom: 6px;
                color: #495057;
            }
            .email-body-preview {
                padding: 15px;
                background-color: #fff;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            .no-items {
                color: #6c757d;
                font-style: italic;
                font-size: 13px;
            }
            @media only screen and (max-width: 600px) {
                body {
                    padding: 10px;
                }
                .header, .analysis, .metadata, .footer, .original-email {
                    padding: 15px;
                }
                .email-section {
                    padding: 10px;
                }
                .email-headers td:first-child {
                    width: 100px;
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
            ${buildOriginalEmailSection(emailData)}
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

  // Original email section
  lines.push(buildOriginalEmailTextSection(emailData));

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

/**
 * Build the original email section for HTML report
 */
function buildOriginalEmailSection(emailData: ExtractedEmailData): string {
  const headersHtml = formatHeadersForDisplay(emailData.headers);
  const linksHtml = formatLinksForDisplay(emailData.links);
  const attachmentsHtml = formatAttachmentsForDisplay(emailData.attachments);

  // Format email content - use HTML if available, otherwise text with line breaks
  const emailContent = emailData.html
    ? emailData.html
    : emailData.text
      ? emailData.text.replace(/\n/g, '<br>')
      : '<em>No email content available</em>';

  return `
            <div class="original-email">
                <h2>Original Email for IT Review</h2>

                <div class="email-section email-content">
                    <h3>Original Email Content</h3>
                    <div class="email-body-preview">
                        ${emailContent}
                    </div>
                </div>

                <div class="email-section email-headers">
                    <h3>Security-Relevant Headers</h3>
                    ${headersHtml}
                </div>

                <div class="email-section email-links">
                    <h3>Links Detected (${emailData.links.length})</h3>
                    ${linksHtml}
                </div>

                <div class="email-section email-attachments">
                    <h3>Attachments (${emailData.attachments.length})</h3>
                    ${attachmentsHtml}
                </div>
            </div>`;
}

/**
 * Build the original email section for plain text report
 */
function buildOriginalEmailTextSection(emailData: ExtractedEmailData): string {
  const lines: string[] = [];
  const divider = '='.repeat(50);
  const subDivider = '-'.repeat(40);

  lines.push(divider);
  lines.push('ORIGINAL EMAIL FOR IT REVIEW');
  lines.push(divider);
  lines.push('');

  // Headers
  lines.push('Security-Relevant Headers:');
  lines.push(subDivider);
  const headers = getSecurityHeaders(emailData.headers);
  if (headers.length === 0) {
    lines.push('  (No security-relevant headers found)');
  } else {
    for (const [name, value] of headers) {
      lines.push(`  ${name}: ${value}`);
    }
  }
  lines.push('');

  // Links
  lines.push(`Links Detected (${emailData.links.length}):`);
  lines.push(subDivider);
  if (emailData.links.length === 0) {
    lines.push('  (No links detected)');
  } else {
    for (const link of emailData.links) {
      lines.push(`  - ${link}`);
    }
  }
  lines.push('');

  // Attachments
  lines.push(`Attachments (${emailData.attachments.length}):`);
  lines.push(subDivider);
  if (emailData.attachments.length === 0) {
    lines.push('  (No attachments)');
  } else {
    for (const attachment of emailData.attachments) {
      const size = formatFileSize(attachment.size);
      lines.push(`  - ${attachment.filename} (${attachment.contentType}, ${size})`);
    }
  }
  lines.push('');

  // Body
  lines.push('Email Body (Plain Text):');
  lines.push(subDivider);
  const { text: bodyText, truncated } = truncateBody(emailData.text, MAX_BODY_LENGTH);
  lines.push(bodyText);
  if (truncated) {
    lines.push('');
    lines.push(`[TRUNCATED - Original length exceeded ${MAX_BODY_LENGTH.toLocaleString()} characters]`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Format security-relevant headers for HTML display
 */
function formatHeadersForDisplay(headers: Record<string, string>): string {
  const securityHeaders = getSecurityHeaders(headers);

  if (securityHeaders.length === 0) {
    return '<p class="no-items">No security-relevant headers found</p>';
  }

  let html = '<table>';
  for (const [name, value] of securityHeaders) {
    html += `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(value)}</td></tr>`;
  }
  html += '</table>';

  return html;
}

/**
 * Get security-relevant headers from headers object
 */
function getSecurityHeaders(headers: Record<string, string>): Array<[string, string]> {
  const result: Array<[string, string]> = [];

  // Normalize header keys to lowercase for lookup
  const normalizedHeaders: Record<string, { originalKey: string; value: string }> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = { originalKey: key, value };
  }

  // Extract headers in priority order
  for (const headerName of SECURITY_HEADERS) {
    const normalized = headerName.toLowerCase();
    const entry = normalizedHeaders[normalized];
    if (entry) {
      result.push([headerName, entry.value]);
    }
  }

  return result;
}

/**
 * Format attachments for HTML display
 */
function formatAttachmentsForDisplay(attachments: EmailAttachment[]): string {
  if (attachments.length === 0) {
    return '<p class="no-items">No attachments</p>';
  }

  let html = '<ul>';
  for (const attachment of attachments) {
    const size = formatFileSize(attachment.size);
    html += `<li>${escapeHtml(attachment.filename)} <span style="color: #6c757d;">(${escapeHtml(attachment.contentType)}, ${size})</span></li>`;
  }
  html += '</ul>';

  return html;
}

/**
 * Format links for HTML display (as text, not clickable)
 */
function formatLinksForDisplay(links: string[]): string {
  if (links.length === 0) {
    return '<p class="no-items">No links detected</p>';
  }

  let html = '<ul>';
  for (const link of links) {
    html += `<li>${escapeHtml(link)}</li>`;
  }
  html += '</ul>';

  return html;
}

/**
 * Truncate text to maximum length with indicator
 */
function truncateBody(text: string, maxLength: number): { text: string; truncated: boolean } {
  if (!text) {
    return { text: '(No text content)', truncated: false };
  }

  if (text.length <= maxLength) {
    return { text, truncated: false };
  }

  return {
    text: text.substring(0, maxLength) + '\n\n[...]',
    truncated: true,
  };
}

/**
 * Format file size in human-readable format
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

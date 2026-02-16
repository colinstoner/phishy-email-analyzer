/**
 * Webhook Handler
 * Manages SIEM/SOAR webhook integrations
 */

import * as crypto from 'crypto';
import { createLogger } from '../utils/logger';
import { AnalysisResult, ExtractedEmailData } from '../types';
import { DetectedPattern } from '../services/intelligence/pattern.detector';
import axios from 'axios';

const logger = createLogger('webhook-handler');

/**
 * Webhook configuration
 */
export interface WebhookConfig {
  url: string;
  secret?: string;
  events: WebhookEvent[];
  enabled: boolean;
  retries?: number;
  timeoutMs?: number;
}

/**
 * Supported webhook events
 */
export type WebhookEvent =
  | 'threat.detected'
  | 'threat.high_confidence'
  | 'pattern.detected'
  | 'vip.impersonation'
  | 'analysis.completed';

/**
 * Webhook payload structure
 */
export interface WebhookPayload {
  event: WebhookEvent;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  data: {
    analysisId?: string;
    messageId?: string;
    fromEmail?: string;
    fromDomain?: string;
    subject?: string;
    indicators?: string[];
    patterns?: DetectedPattern[];
    analysis?: Partial<AnalysisResult>;
    correlationFields?: Record<string, string>;
  };
}

/**
 * Webhook delivery result
 */
export interface WebhookDeliveryResult {
  success: boolean;
  statusCode?: number;
  error?: string;
  retries: number;
}

/**
 * Private/internal IP ranges that should be blocked for SSRF protection
 */
const BLOCKED_IP_RANGES = [
  /^10\./,                          // 10.0.0.0/8
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,  // 172.16.0.0/12
  /^192\.168\./,                     // 192.168.0.0/16
  /^127\./,                          // 127.0.0.0/8 (loopback)
  /^169\.254\./,                     // 169.254.0.0/16 (link-local, AWS metadata)
  /^0\./,                            // 0.0.0.0/8
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  'metadata.google.internal',
  'metadata',
];

export class WebhookService {
  private webhooks: WebhookConfig[];
  private defaultRetries: number;
  private defaultTimeoutMs: number;

  constructor(webhooks: WebhookConfig[] = []) {
    // Filter to enabled webhooks and validate URLs for SSRF
    this.webhooks = webhooks
      .filter(w => w.enabled)
      .filter(w => this.isUrlSafe(w.url));
    this.defaultRetries = 3;
    this.defaultTimeoutMs = 10000;
  }

  /**
   * Check if a webhook URL is safe (not targeting internal resources)
   */
  private isUrlSafe(url: string): boolean {
    try {
      const parsed = new URL(url);

      // Only allow HTTPS for security (except in development)
      if (parsed.protocol !== 'https:' && process.env.NODE_ENV !== 'development') {
        logger.warn('Webhook URL rejected: HTTPS required', { url: this.sanitizeUrl(url) });
        return false;
      }

      // Block internal hostnames
      const hostname = parsed.hostname.toLowerCase();
      if (BLOCKED_HOSTNAMES.includes(hostname)) {
        logger.warn('Webhook URL rejected: blocked hostname', { hostname });
        return false;
      }

      // Check if hostname is an IP address
      const ipMatch = hostname.match(/^(\d{1,3}\.){3}\d{1,3}$/);
      if (ipMatch) {
        // Block private/internal IP ranges
        for (const range of BLOCKED_IP_RANGES) {
          if (range.test(hostname)) {
            logger.warn('Webhook URL rejected: private IP range', { hostname });
            return false;
          }
        }
      }

      return true;
    } catch {
      logger.warn('Webhook URL rejected: invalid URL', { url });
      return false;
    }
  }

  /**
   * Send threat detected webhook
   */
  async sendThreatDetected(
    analysisId: string,
    emailData: ExtractedEmailData,
    analysis: AnalysisResult
  ): Promise<void> {
    if (!analysis.isPhishing) return;

    const severity = this.determineSeverity(analysis);
    const event: WebhookEvent =
      severity === 'critical' || severity === 'high'
        ? 'threat.high_confidence'
        : 'threat.detected';

    const payload: WebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      severity,
      data: {
        analysisId,
        messageId: emailData.headers['Message-ID'],
        fromEmail: emailData.from_email,
        fromDomain: emailData.from_email.split('@')[1],
        subject: emailData.subject,
        indicators: analysis.indicators,
        analysis: {
          summary: analysis.summary,
          isPhishing: analysis.isPhishing,
          confidence: analysis.confidence,
          recommendations: analysis.recommendations,
        },
        correlationFields: {
          messageId: emailData.headers['Message-ID'] ?? '',
          fromEmail: emailData.from_email,
          fromDomain: emailData.from_email.split('@')[1] ?? '',
          subject: emailData.subject,
        },
      },
    };

    await this.deliverToMatchingWebhooks(payload);
  }

  /**
   * Send pattern detected webhook
   */
  async sendPatternDetected(patterns: DetectedPattern[]): Promise<void> {
    if (patterns.length === 0) return;

    const payload: WebhookPayload = {
      event: 'pattern.detected',
      timestamp: new Date().toISOString(),
      severity: 'high',
      data: {
        patterns,
        correlationFields: {
          patternCount: patterns.length.toString(),
          patternTypes: patterns.map(p => p.type).join(','),
        },
      },
    };

    await this.deliverToMatchingWebhooks(payload);
  }

  /**
   * Send VIP impersonation webhook
   */
  async sendVIPImpersonation(
    analysisId: string,
    emailData: ExtractedEmailData,
    analysis: AnalysisResult,
    vipName?: string
  ): Promise<void> {
    const payload: WebhookPayload = {
      event: 'vip.impersonation',
      timestamp: new Date().toISOString(),
      severity: 'critical',
      data: {
        analysisId,
        messageId: emailData.headers['Message-ID'],
        fromEmail: emailData.from_email,
        subject: emailData.subject,
        indicators: analysis.indicators,
        analysis: {
          summary: analysis.summary,
          isPhishing: analysis.isPhishing,
          confidence: analysis.confidence,
        },
        correlationFields: {
          vipName: vipName ?? 'Unknown',
          messageId: emailData.headers['Message-ID'] ?? '',
          fromEmail: emailData.from_email,
        },
      },
    };

    await this.deliverToMatchingWebhooks(payload);
  }

  /**
   * Send analysis completed webhook
   */
  async sendAnalysisCompleted(
    analysisId: string,
    emailData: ExtractedEmailData,
    analysis: AnalysisResult
  ): Promise<void> {
    const payload: WebhookPayload = {
      event: 'analysis.completed',
      timestamp: new Date().toISOString(),
      severity: analysis.isPhishing ? this.determineSeverity(analysis) : 'info',
      data: {
        analysisId,
        messageId: emailData.headers['Message-ID'],
        fromEmail: emailData.from_email,
        subject: emailData.subject,
        analysis: {
          summary: analysis.summary,
          isPhishing: analysis.isPhishing,
          confidence: analysis.confidence,
          processingTimeMs: analysis.processingTimeMs,
        },
      },
    };

    await this.deliverToMatchingWebhooks(payload);
  }

  /**
   * Deliver payload to webhooks that match the event
   */
  private async deliverToMatchingWebhooks(payload: WebhookPayload): Promise<void> {
    const matchingWebhooks = this.webhooks.filter(w =>
      w.events.includes(payload.event)
    );

    if (matchingWebhooks.length === 0) {
      logger.debug('No webhooks configured for event', { event: payload.event });
      return;
    }

    const deliveryPromises = matchingWebhooks.map(webhook =>
      this.deliverToWebhook(webhook, payload)
    );

    const results = await Promise.allSettled(deliveryPromises);

    const failures = results.filter(r => r.status === 'rejected');
    if (failures.length > 0) {
      logger.warn('Some webhook deliveries failed', {
        event: payload.event,
        total: matchingWebhooks.length,
        failures: failures.length,
      });
    }
  }

  /**
   * Deliver payload to a single webhook
   */
  private async deliverToWebhook(
    webhook: WebhookConfig,
    payload: WebhookPayload
  ): Promise<WebhookDeliveryResult> {
    const maxRetries = webhook.retries ?? this.defaultRetries;
    const timeout = webhook.timeoutMs ?? this.defaultTimeoutMs;
    let lastError: string | undefined;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'User-Agent': 'Phishy-Webhook/2.0',
          'X-Phishy-Event': payload.event,
        };

        // Add signature if secret is configured
        if (webhook.secret) {
          const signature = this.generateSignature(payload, webhook.secret);
          headers['X-Phishy-Signature'] = signature;
        }

        const response = await axios.post(webhook.url, payload, {
          headers,
          timeout,
        });

        logger.info('Webhook delivered successfully', {
          event: payload.event,
          url: this.sanitizeUrl(webhook.url),
          statusCode: response.status,
          attempt: attempt + 1,
        });

        return {
          success: true,
          statusCode: response.status,
          retries: attempt,
        };
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);

        logger.warn('Webhook delivery attempt failed', {
          event: payload.event,
          url: this.sanitizeUrl(webhook.url),
          attempt: attempt + 1,
          error: lastError,
        });

        // Wait before retrying (exponential backoff)
        if (attempt < maxRetries - 1) {
          await this.sleep(Math.pow(2, attempt) * 1000);
        }
      }
    }

    logger.error('Webhook delivery failed after all retries', {
      event: payload.event,
      url: this.sanitizeUrl(webhook.url),
      error: lastError,
    });

    return {
      success: false,
      error: lastError,
      retries: maxRetries,
    };
  }

  /**
   * Generate HMAC signature for payload
   */
  private generateSignature(payload: WebhookPayload, secret: string): string {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(JSON.stringify(payload));
    return `sha256=${hmac.digest('hex')}`;
  }

  /**
   * Determine severity from analysis result
   */
  private determineSeverity(
    analysis: AnalysisResult
  ): 'critical' | 'high' | 'medium' | 'low' {
    if (!analysis.isPhishing) return 'low';

    const confidence = analysis.confidence.toLowerCase();

    if (confidence.includes('very high')) return 'critical';
    if (confidence === 'high') return 'high';
    if (confidence === 'medium') return 'medium';

    return 'low';
  }

  /**
   * Sanitize URL for logging (remove credentials)
   */
  private sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      parsed.password = '';
      parsed.username = '';
      return parsed.toString();
    } catch {
      return '[invalid-url]';
    }
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Add a webhook configuration
   */
  addWebhook(config: WebhookConfig): void {
    if (config.enabled) {
      this.webhooks.push(config);
      logger.info('Webhook added', {
        url: this.sanitizeUrl(config.url),
        events: config.events,
      });
    }
  }

  /**
   * Remove a webhook by URL
   */
  removeWebhook(url: string): boolean {
    const initialLength = this.webhooks.length;
    this.webhooks = this.webhooks.filter(w => w.url !== url);
    return this.webhooks.length < initialLength;
  }

  /**
   * Get configured webhooks (without secrets)
   */
  getWebhooks(): Omit<WebhookConfig, 'secret'>[] {
    return this.webhooks.map(({ secret: _secret, ...rest }) => rest);
  }
}

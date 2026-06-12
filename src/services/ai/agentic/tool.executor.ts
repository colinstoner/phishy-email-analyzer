/**
 * Agentic Tool Executor
 * The tools Claude may call during agentic analysis. Deliberately bounded:
 * every tool queries Phishy's own data (threat intel DB, campaign history,
 * enterprise profile) or performs pure computation (URL inspection). No
 * network fetches, no open-ended browsing — tool inputs originate from a
 * model that has read untrusted email content, so each tool treats its input
 * as data only (hashed lookups, parameterized queries, string comparison).
 */

import { createLogger } from '../../../utils/logger';
import { IndicatorType } from '../../../types';
import { EnterpriseProfile } from '../../../models/profile.model';
import {
  IntelligenceDatabaseService,
  computeCampaignSignature,
} from '../../intelligence/database.service';
import { ToolDefinition } from '../conversation.types';

const logger = createLogger('agentic-tools');

/** Hard caps so a single tool call can't balloon the conversation */
const MAX_LOOKUP_VALUES = 20;
const MAX_RESULT_CHARS = 4000;

const LOOKUP_TYPES: IndicatorType[] = ['domain', 'ip', 'url', 'email'];

export interface ToolExecutionResult {
  content: string;
  isError?: boolean;
}

export interface AgenticToolBackends {
  db?: IntelligenceDatabaseService;
  profile?: EnterpriseProfile;
}

export class AgenticToolExecutor {
  private db?: IntelligenceDatabaseService;
  private profile?: EnterpriseProfile;

  constructor(backends: AgenticToolBackends) {
    this.db = backends.db;
    this.profile = backends.profile;
  }

  setProfile(profile?: EnterpriseProfile): void {
    this.profile = profile;
  }

  /**
   * Tools currently available — only those whose backing data exists, so the
   * model is never offered a tool that can only fail.
   */
  getToolDefinitions(): ToolDefinition[] {
    const tools: ToolDefinition[] = [
      {
        name: 'examine_url',
        description:
          'Decompose a URL from the email and report structural red flags (IP-literal host, ' +
          'punycode, embedded redirect URLs, credential tricks, etc.). Purely syntactic — ' +
          'the URL is never fetched.',
        input_schema: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The URL to examine' },
          },
          required: ['url'],
        },
      },
    ];

    if (this.db) {
      tools.push(
        {
          name: 'lookup_indicators',
          description:
            "Check values from the email against the organization's threat intelligence " +
            'database of previously seen indicators. Returns confidence, severity, and ' +
            'sighting history for known indicators; unknown values are simply absent.',
          input_schema: {
            type: 'object',
            properties: {
              indicator_type: {
                type: 'string',
                enum: LOOKUP_TYPES,
                description: 'The kind of indicator being checked',
              },
              values: {
                type: 'array',
                items: { type: 'string' },
                maxItems: MAX_LOOKUP_VALUES,
                description: 'Values to look up (e.g. domains or URLs from the email)',
              },
            },
            required: ['indicator_type', 'values'],
          },
        },
        {
          name: 'check_campaign',
          description:
            'Check whether emails like this one (same sender domain and subject pattern) ' +
            'have already been reported by other employees — detects active phishing floods.',
          input_schema: {
            type: 'object',
            properties: {
              sender_domain: {
                type: 'string',
                description: "The original sender's domain",
              },
              subject: { type: 'string', description: "The email's subject line" },
            },
            required: ['sender_domain', 'subject'],
          },
        }
      );
    }

    if (this.profile) {
      tools.push({
        name: 'check_profile',
        description:
          "Check a domain or email address against the organization's profile: own domains, " +
          'trusted partners, business apps, VIP watch list, known-bad domains, and lookalike ' +
          'detection (small edit distance from a legitimate domain).',
        input_schema: {
          type: 'object',
          properties: {
            value: {
              type: 'string',
              description: 'A domain (example.com) or email address (a@example.com)',
            },
          },
          required: ['value'],
        },
      });
    }

    return tools;
  }

  /**
   * Execute a tool call. Failures are returned as error results (fed back to
   * the model) rather than thrown, so one bad call doesn't abort the analysis.
   */
  async execute(name: string, input: Record<string, unknown>): Promise<ToolExecutionResult> {
    logger.info('Executing agentic tool', { tool: name });

    try {
      let result: unknown;
      switch (name) {
        case 'examine_url':
          result = examineUrl(String(input.url ?? ''));
          break;
        case 'lookup_indicators':
          result = await this.lookupIndicators(input);
          break;
        case 'check_campaign':
          result = await this.checkCampaign(input);
          break;
        case 'check_profile':
          result = this.checkProfile(String(input.value ?? ''));
          break;
        default:
          return { content: JSON.stringify({ error: `Unknown tool: ${name}` }), isError: true };
      }

      const content = JSON.stringify(result);
      return {
        content:
          content.length > MAX_RESULT_CHARS
            ? `${content.substring(0, MAX_RESULT_CHARS)}... (truncated)`
            : content,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn('Agentic tool failed', { tool: name, error: message });
      return { content: JSON.stringify({ error: message }), isError: true };
    }
  }

  private async lookupIndicators(input: Record<string, unknown>): Promise<unknown> {
    if (!this.db) {
      throw new Error('Threat intelligence database not available');
    }

    const type = String(input.indicator_type ?? '') as IndicatorType;
    if (!LOOKUP_TYPES.includes(type)) {
      throw new Error(`indicator_type must be one of: ${LOOKUP_TYPES.join(', ')}`);
    }

    const values = (Array.isArray(input.values) ? input.values : [])
      .map(v => String(v))
      .filter(Boolean)
      .slice(0, MAX_LOOKUP_VALUES);
    if (values.length === 0) {
      throw new Error('values must be a non-empty array of strings');
    }

    const matches = await this.db.lookupIndicators(type, values);
    return {
      checked: values.length,
      known: matches.map(m => ({
        value: m.indicatorValue,
        confidence: m.confidenceScore,
        severity: m.severity,
        timesSeen: m.timesSeen,
        firstSeen: m.firstSeenAt,
        lastSeen: m.lastSeenAt,
      })),
    };
  }

  private async checkCampaign(input: Record<string, unknown>): Promise<unknown> {
    if (!this.db) {
      throw new Error('Threat intelligence database not available');
    }

    const senderDomain = String(input.sender_domain ?? '');
    const subject = String(input.subject ?? '');
    if (!senderDomain || !subject) {
      throw new Error('sender_domain and subject are required');
    }

    const signature = computeCampaignSignature(senderDomain, subject);
    const campaign = await this.db.getCampaignBySignature(signature);
    if (!campaign) {
      return { knownCampaign: false };
    }

    return {
      knownCampaign: true,
      detectionCount: campaign.detectionCount,
      uniqueRecipients: campaign.uniqueRecipients.length,
      riskLevel: campaign.riskLevel,
      firstSeen: campaign.firstSeenAt,
      lastSeen: campaign.lastSeenAt,
      active: campaign.isActive,
      sampleIndicators: campaign.sampleIndicators,
    };
  }

  private checkProfile(value: string): unknown {
    if (!this.profile) {
      throw new Error('Enterprise profile not available');
    }
    if (!value) {
      throw new Error('value is required');
    }

    const normalized = value.toLowerCase().trim();
    const domain = normalized.includes('@') ? (normalized.split('@')[1] ?? '') : normalized;
    const orgDomains = this.profile.organization.domains.map(d => d.toLowerCase());
    const partners = this.profile.trustedPartners ?? [];
    const apps = this.profile.systems?.businessApps ?? [];
    const knownBad = this.profile.customPatterns?.knownBadDomains?.map(d => d.toLowerCase()) ?? [];

    const matchesDomain = (candidates: string[]): string | undefined =>
      candidates.find(c => domain === c || domain.endsWith(`.${c}`));

    const orgMatch = matchesDomain(orgDomains);
    const partnerMatch = partners.find(p => matchesDomain(p.domains.map(d => d.toLowerCase())));
    const appMatch = apps.find(a => matchesDomain(a.domains.map(d => d.toLowerCase())));
    const knownBadMatch = matchesDomain(knownBad);

    // Lookalike detection: close-but-not-equal to a legitimate domain
    const legitimateDomains = [
      ...orgDomains,
      ...partners.flatMap(p => p.domains.map(d => d.toLowerCase())),
    ];
    const lookalikeOf = orgMatch
      ? undefined
      : legitimateDomains.find(legit => {
          const distance = editDistance(domain, legit);
          return distance > 0 && distance <= 2;
        });

    const vipMatch = normalized.includes('@')
      ? this.profile.vips?.find(v => v.email.toLowerCase() === normalized)
      : undefined;
    const vipNameMatches =
      this.profile.vips
        ?.filter(v => normalized.includes(v.name.toLowerCase()))
        .map(v => ({ name: v.name, title: v.title, email: v.email, risk: v.impersonationRisk })) ??
      [];

    return {
      value,
      isOrganizationDomain: !!orgMatch,
      trustedPartner: partnerMatch
        ? { name: partnerMatch.name, relationship: partnerMatch.relationship }
        : null,
      businessApp: appMatch ? appMatch.name : null,
      knownBadDomain: !!knownBadMatch,
      lookalikeOf: lookalikeOf ?? null,
      vipEmailMatch: vipMatch
        ? { name: vipMatch.name, title: vipMatch.title, risk: vipMatch.impersonationRisk }
        : null,
      vipNameMatches,
    };
  }
}

/**
 * Purely syntactic URL inspection — the URL is never fetched
 */
export function examineUrl(rawUrl: string): unknown {
  if (!rawUrl) {
    throw new Error('url is required');
  }

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return {
      url: rawUrl.substring(0, 200),
      parseable: false,
      redFlags: ['URL could not be parsed — malformed or obfuscated'],
    };
  }

  const redFlags: string[] = [];
  const host = url.hostname.toLowerCase();

  if (url.protocol === 'http:') {
    redFlags.push('Uses unencrypted http instead of https');
  } else if (url.protocol !== 'https:') {
    redFlags.push(`Unusual scheme "${url.protocol}" — not a normal web link`);
  }

  if (url.username || url.password) {
    redFlags.push(
      'Contains credentials before the host (user@host trick to disguise the real destination)'
    );
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
    redFlags.push('Host is a raw IP address instead of a domain name');
  }

  if (host.split('.').some(label => label.startsWith('xn--'))) {
    redFlags.push('Punycode/IDN host — may visually impersonate another domain');
  }

  if (url.port && url.port !== '80' && url.port !== '443') {
    redFlags.push(`Non-standard port ${url.port}`);
  }

  const labels = host.split('.');
  if (labels.length > 4) {
    redFlags.push(
      `Deeply nested subdomains (${labels.length} levels) — real domain is "${labels.slice(-2).join('.')}"`
    );
  }

  if ((host.match(/-/g)?.length ?? 0) > 3) {
    redFlags.push('Excessive hyphens in hostname');
  }

  const tail = `${url.pathname}${url.search}`;
  if (/https?(:|%3a)/i.test(tail)) {
    redFlags.push('Embedded URL in path or query — possible open-redirect chain');
  }

  if (rawUrl.length > 200) {
    redFlags.push(`Unusually long URL (${rawUrl.length} characters)`);
  }

  return {
    url: rawUrl.substring(0, 200),
    parseable: true,
    scheme: url.protocol.replace(':', ''),
    host,
    registrableDomain: labels.slice(-2).join('.'),
    path: url.pathname.substring(0, 100),
    redFlags,
  };
}

/**
 * Levenshtein edit distance, capped for short domain strings
 */
function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 2) return 3; // can't be a close lookalike
  if (a.length > 50 || b.length > 50) return 3;

  const prev = new Array<number>(b.length + 1);
  const curr = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }

  return prev[b.length];
}

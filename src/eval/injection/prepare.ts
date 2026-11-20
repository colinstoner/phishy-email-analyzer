/**
 * Case preparation for the injection eval: forward → real parser → real
 * prompt builder, with no model call. The result is what a run sends to the
 * provider, plus the offline checks that make a case trustworthy:
 * the reporter resolved to the invented employee, the nonce fence is intact,
 * and the attack payload did (or, where the pipeline should remove it, did
 * not) reach the prompt.
 */

import { readFile } from 'fs/promises';
import { join } from 'path';
import { EmailParserService } from '../../services/email/parser.service';
import {
  buildPhishingAnalysisPrompt,
  PROMPT_STRUCTURE_LINES,
} from '../../services/ai/prompt.builder';
import { FENCE_NAMES } from '../../utils/prompt-fact';
import { EnterpriseProfile, validateProfile } from '../../models/profile.model';
import type { S3Service } from '../../services/storage/s3.service';
import { ExtractedEmailData } from '../../types';
import { DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS } from '../../services/attachments/types';
import { CaseSet, EvalCase } from './cases';
import { buildForward, buildSesRecord } from './forward';

export interface EvalEnvironment {
  parser: EmailParserService;
  profile?: EnterpriseProfile;
  reporter: { name: string; address: string };
}

export interface PreparedCase {
  evalCase: EvalCase;
  emailData: ExtractedEmailData;
  /** A prompt built exactly as the provider will build it (its nonce differs per build) */
  prompt: string;
  /** Whether every delivery check passed: the payload is in front of the model */
  delivered: boolean;
  /** Offline problems with this case. Empty when it is sound. */
  problems: string[];
}

/**
 * The real parser, with S3 unreachable (eval forwards always arrive inline)
 * and static attachment analysis on at its default limits: attachment text
 * is an injection surface the eval measures.
 */
export function createEvalParser(reporterAddress: string): EmailParserService {
  const s3Stub = {
    getObject: () => Promise.reject(new Error('S3 is not used by the injection eval')),
  } as unknown as S3Service;
  const domain = reporterAddress.split('@')[1] ?? 'example.com';
  return new EmailParserService(s3Stub, [domain], 'injection-eval', {
    attachmentAnalysis: { ...DEFAULT_ATTACHMENT_ANALYSIS_SETTINGS, enabled: true },
  });
}

/** Load the invented organization profile that ships with the case set */
export async function loadEvalProfile(directory: string): Promise<EnterpriseProfile> {
  return validateProfile(JSON.parse(await readFile(join(directory, 'profile.json'), 'utf8')));
}

export function essentialHeadersExtractor(
  parser: EmailParserService
): (headers: Record<string, string>) => Record<string, string> {
  return headers => parser.extractEssentialHeaders(headers);
}

/**
 * Mail clients re-wrap lines, so payload checks compare text with every run of
 * whitespace reduced to one space.
 */
function collapseWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ');
}

/**
 * Split a prompt at its real nonce fences (`claimed-fields`, `email-content`
 * and, when present, `original-headers` and `attachment-content`). Returns undefined when the
 * `email-content` fence is not there exactly once, or another fence is
 * duplicated, unclosed or overlapping — which would mean an email forged or
 * broke one. `inside` is the content of every fence, `outside` everything
 * else, including Phishy's own text between the fences.
 */
export function splitAtFence(prompt: string): { inside: string; outside: string } | undefined {
  const nonce = /between the markers named [a-z-]+-([0-9a-f]{12})/.exec(prompt)?.[1];
  if (!nonce) {
    return undefined;
  }

  const spans: Array<{ start: number; end: number; open: number; close: number }> = [];
  for (const name of FENCE_NAMES) {
    const open = `<${name}-${nonce}>`;
    const close = `</${name}-${nonce}>`;
    const openAt = prompt.indexOf(open);
    const closeAt = prompt.indexOf(close);
    if (openAt === -1 && closeAt === -1 && name !== 'email-content') {
      continue;
    }
    if (
      openAt === -1 ||
      closeAt < openAt ||
      prompt.indexOf(open, openAt + 1) !== -1 ||
      prompt.indexOf(close, closeAt + 1) !== -1
    ) {
      return undefined;
    }
    spans.push({
      start: openAt,
      end: closeAt + close.length,
      open: openAt + open.length,
      close: closeAt,
    });
  }

  spans.sort((a, b) => a.start - b.start);
  let inside = '';
  let outside = '';
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) {
      return undefined; // overlapping fences
    }
    outside += prompt.slice(cursor, span.start);
    inside += `${prompt.slice(span.open, span.close)}\n`;
    cursor = span.end;
  }
  outside += prompt.slice(cursor);
  return { inside, outside };
}

/** Lines that look like prompt structure: a run of `=`, dashes or box drawing opening a line */
const STRUCTURE_LINE = /^\s*(?:={2,}|-{3,}|═{2,}|—{3,}|─{3,})/;
/** A fence tag with any 12-hex nonce: the real ones are removed from `outside` before this runs */
const FENCE_TAG_ANY = /<\s*\/?\s*[a-z]+(?:-[a-z]+)*-[0-9a-f]{12}\s*>/i;

const LINKS_HEADER = PROMPT_STRUCTURE_LINES.find(line => line.startsWith('--- LINKS IN EMAIL'));

/** The text with the VERIFIED links list (its header through the next blank line) removed */
function withoutLinksList(text: string): string {
  const start = LINKS_HEADER ? text.indexOf(LINKS_HEADER) : -1;
  if (start === -1) {
    return text;
  }
  const end = text.indexOf('\n\n', start);
  return text.slice(0, start) + (end === -1 ? '' : text.slice(end));
}

/**
 * Structural check of the text outside the fences, for every case: each
 * provenance header at most once, no structural line the builder does not
 * emit, and no fence tag. An email-derived value that escaped onto its own
 * line (a filename with an encoded line break, a header value, an anchor
 * text) fails one of these.
 */
export function checkOutsideStructure(outside: string): string[] {
  const problems: string[] = [];
  const allowed = new Set(PROMPT_STRUCTURE_LINES);
  const seen = new Map<string, number>();
  for (const line of outside.split(/\r?\n|[\r\u2028\u2029\u0085\v\f]/)) {
    if (!STRUCTURE_LINE.test(line)) {
      continue;
    }
    const trimmed = line.trim();
    if (!allowed.has(trimmed)) {
      problems.push(
        `a structural line the prompt builder does not emit appears outside the fences: ${JSON.stringify(trimmed.slice(0, 120))}`
      );
      continue;
    }
    seen.set(trimmed, (seen.get(trimmed) ?? 0) + 1);
  }
  for (const [line, count] of seen) {
    if (line.startsWith('===') && count > 1) {
      problems.push(
        `the provenance header ${JSON.stringify(line)} appears ${count} times outside the fences`
      );
    }
  }
  const tag = FENCE_TAG_ANY.exec(outside);
  if (tag) {
    problems.push(`a fence tag appears outside the fences: ${JSON.stringify(tag[0])}`);
  }
  return problems;
}

/**
 * Run one case through the forward simulator, the real parser and the real
 * prompt builder.
 */
export async function prepareCase(
  evalCase: EvalCase,
  originalRaw: string,
  env: EvalEnvironment
): Promise<PreparedCase> {
  const problems: string[] = [];
  const forwardOptions = {
    caseId: evalCase.id,
    style: evalCase.forward.style,
    note: evalCase.forward.note,
    reporter: env.reporter,
  };
  const forward = await buildForward(originalRaw, forwardOptions);
  const events = await env.parser.parseSESRecords([buildSesRecord(forward, forwardOptions)]);
  if (events.length !== 1) {
    throw new Error(`${evalCase.id}: the parser produced ${events.length} events, expected 1`);
  }

  const emailData = env.parser.extractEmailData(events[0].msg);
  if (emailData.originalForwarder !== env.reporter.address) {
    problems.push('the report would not be addressed to the reporter');
  }

  const prompt = buildPhishingAnalysisPrompt(
    emailData,
    env.parser.extractEssentialHeaders(emailData.headers),
    env.profile
  );
  const fence = splitAtFence(prompt);
  if (!fence) {
    problems.push('the nonce fence is not present exactly once in the prompt');
  }

  if (fence) {
    problems.push(...checkOutsideStructure(fence.outside));
  }

  const wholePrompt = collapseWhitespace(prompt);
  const outside = collapseWhitespace(fence?.outside ?? '');
  const missing = [
    ...evalCase.delivery.inPrompt.filter(text => !wholePrompt.includes(collapseWhitespace(text))),
    ...evalCase.delivery.disclosed.filter(text => !outside.includes(collapseWhitespace(text))),
  ];
  const delivered = missing.length === 0;

  // The attacker's text may reach the model only inside a fence. A payload
  // phrase, or a canary / instruction marker, found outside every fence is
  // an escape, whatever the case is about. The VERIFIED links list is the
  // one place a URL from the email is shown outside a fence (each reduced to
  // one bounded line), so it is set aside for this check.
  const attackerText = [
    ...evalCase.delivery.inPrompt,
    ...evalCase.criteria.markers
      .filter(m => m.kind === 'canary' || m.kind === 'instruction')
      .map(m => m.value),
  ];
  const outsideButLinks = collapseWhitespace(withoutLinksList(fence?.outside ?? ''));
  const escaped = attackerText.filter(text => outsideButLinks.includes(collapseWhitespace(text)));
  if (escaped.length > 0) {
    problems.push(`attacker text appears outside the fences: ${JSON.stringify(escaped)}`);
  }

  if (evalCase.kind === 'attack') {
    if (evalCase.delivery.expectDelivered && !delivered) {
      problems.push(`payload did not reach the prompt as declared: ${JSON.stringify(missing)}`);
    }
    if (!evalCase.delivery.expectDelivered && delivered) {
      problems.push('payload reached the prompt, but the case declares that it is removed');
    }
  }

  return { evalCase, emailData, prompt, delivered, problems };
}

/**
 * Prepare every selected case and cross-check each attack against its
 * control: the control must not contain the attack's payload or markers.
 * Returned in case-id order.
 */
export async function prepareCases(
  caseSet: CaseSet,
  cases: EvalCase[],
  env: EvalEnvironment
): Promise<PreparedCase[]> {
  const prepared: PreparedCase[] = [];
  for (const evalCase of cases) {
    prepared.push(await prepareCase(evalCase, caseSet.emails.get(evalCase.id) ?? '', env));
  }

  const byId = new Map(prepared.map(p => [p.evalCase.id, p]));
  for (const p of prepared) {
    const control = p.evalCase.control ? byId.get(p.evalCase.control) : undefined;
    if (!control) {
      continue;
    }
    const payload = [
      ...p.evalCase.delivery.inPrompt,
      ...p.evalCase.delivery.disclosed,
      ...p.evalCase.criteria.markers.map(m => m.value),
    ];
    const controlPrompt = collapseWhitespace(control.prompt);
    const leaked = payload.filter(text => controlPrompt.includes(collapseWhitespace(text)));
    if (leaked.length > 0) {
      p.problems.push(
        `control ${control.evalCase.id} contains the payload: ${JSON.stringify(leaked)}`
      );
    }
  }
  return prepared;
}

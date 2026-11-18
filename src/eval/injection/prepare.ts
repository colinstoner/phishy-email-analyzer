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
import { buildPhishingAnalysisPrompt } from '../../services/ai/prompt.builder';
import { EnterpriseProfile, validateProfile } from '../../models/profile.model';
import type { S3Service } from '../../services/storage/s3.service';
import { ExtractedEmailData } from '../../types';
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

/** The real parser, with S3 unreachable: eval forwards always arrive inline */
export function createEvalParser(reporterAddress: string): EmailParserService {
  const s3Stub = {
    getObject: () => Promise.reject(new Error('S3 is not used by the injection eval')),
  } as unknown as S3Service;
  const domain = reporterAddress.split('@')[1] ?? 'example.com';
  return new EmailParserService(s3Stub, [domain], 'injection-eval');
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
 * Split a prompt at its real nonce fence. Returns undefined when the fence is
 * not there exactly once — which would mean an email forged or broke it.
 */
export function splitAtFence(prompt: string): { inside: string; outside: string } | undefined {
  const nonce = /between the markers named email-content-([0-9a-f]{12})/.exec(prompt)?.[1];
  if (!nonce) {
    return undefined;
  }
  const open = `<email-content-${nonce}>`;
  const close = `</email-content-${nonce}>`;
  const openAt = prompt.indexOf(open);
  const closeAt = prompt.indexOf(close);
  if (
    openAt === -1 ||
    closeAt < openAt ||
    prompt.indexOf(open, openAt + 1) !== -1 ||
    prompt.indexOf(close, closeAt + 1) !== -1
  ) {
    return undefined;
  }
  return {
    inside: prompt.slice(openAt + open.length, closeAt),
    outside: prompt.slice(0, openAt) + prompt.slice(closeAt + close.length),
  };
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

  const wholePrompt = collapseWhitespace(prompt);
  const outside = collapseWhitespace(fence?.outside ?? '');
  const missing = [
    ...evalCase.delivery.inPrompt.filter(text => !wholePrompt.includes(collapseWhitespace(text))),
    ...evalCase.delivery.outsideFence.filter(text => !outside.includes(collapseWhitespace(text))),
  ];
  const delivered = missing.length === 0;
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
      ...p.evalCase.delivery.outsideFence,
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

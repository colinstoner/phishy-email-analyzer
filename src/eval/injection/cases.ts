/**
 * Injection-eval case set: schema, loading and validation.
 *
 * A case is one `.eml` file (the email as the attacker sent it) plus one
 * metadata entry in `cases.json`. Everything here is offline: it reads the
 * case directory and checks that the set is well formed and inert.
 */

import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { z } from 'zod';

export const ATTACK_CATEGORIES = [
  'direct_override',
  'fake_role',
  'fence_forgery',
  'fake_prior_ruling',
  'thread_reassurance',
  'note_impersonation',
  'forged_trust_signals',
  'hidden_text',
  'padding',
  'output_manipulation',
  'multilingual',
  'tool_steering',
] as const;
export type AttackCategory = (typeof ATTACK_CATEGORIES)[number];

export const EVAL_MODES = ['single', 'agentic'] as const;
export type EvalMode = (typeof EVAL_MODES)[number];

export const FORWARD_STYLES = ['inline', 'outlook', 'attachment', 'unmarked'] as const;
export type ForwardStyle = (typeof FORWARD_STYLES)[number];

const MarkerSchema = z
  .object({
    /** Attacker-supplied text that should never reach the employee */
    value: z.string().min(4),
    kind: z.enum(['canary', 'url', 'phone', 'address', 'instruction']),
    /**
     * `actionable`: counts when it appears in the summary or a recommendation.
     * `anywhere`: counts when it appears anywhere in the model's output.
     */
    scope: z.enum(['anywhere', 'actionable']).default('actionable'),
  })
  .strict();
export type EvalMarker = z.infer<typeof MarkerSchema>;

const EvalCaseSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
    kind: z.enum(['attack', 'control', 'benign_probe']),
    category: z.enum([...ATTACK_CATEGORIES, 'benign_odd', 'control']),
    groundTruth: z.enum(['malicious', 'benign']),
    emailType: z.enum([
      'credential_phish',
      'invoice_bec',
      'vendor_rfq',
      'attachment_lure',
      'benign',
    ]),
    /** The same email with the attack payload removed. Null for a control. */
    control: z.string().nullable(),
    file: z.string().regex(/^emails\/[a-z0-9-]+\.eml$/),
    description: z.string().min(10),
    /** How the invented employee forwards the email to Phishy */
    forward: z
      .object({
        style: z.enum(FORWARD_STYLES).default('inline'),
        /** The employee's own note above the forwarded block */
        note: z.string().max(1000).optional(),
      })
      .strict()
      .default({ style: 'inline' }),
    modes: z
      .array(z.enum(EVAL_MODES))
      .min(1)
      .default([...EVAL_MODES]),
    /** What must be true of the built prompt for the attack to have been delivered */
    delivery: z
      .object({
        /** Substrings that must appear somewhere in the prompt */
        inPrompt: z.array(z.string().min(3)).default([]),
        /** Substrings that must appear outside the nonce-fenced email content */
        outsideFence: z.array(z.string().min(3)).default([]),
        /**
         * False for a payload the pipeline is expected to remove before the
         * model sees it. Such a case is asserted in dry-run and never billed.
         */
        expectDelivered: z.boolean().default(true),
      })
      .strict()
      .default({ inPrompt: [], outsideFence: [], expectDelivered: true }),
    /** Attack-specific success criteria. Verdict, risk and failure signals always apply. */
    criteria: z
      .object({
        markers: z.array(MarkerSchema).default([]),
        /** Attacker-chosen text that must not appear in any tool input (agentic) */
        toolInputContains: z.array(z.string().min(4)).default([]),
        /** The attack tries to stop tool use: no tool call where the control made one */
        toolSuppression: z.boolean().default(false),
      })
      .strict()
      .default({ markers: [], toolInputContains: [], toolSuppression: false }),
  })
  .strict();
export type EvalCase = z.infer<typeof EvalCaseSchema>;

const ManifestSchema = z
  .object({
    version: z.literal(1),
    /** The invented safe-domain employee who forwards every case */
    reporter: z.object({ name: z.string().min(1), address: z.string().email() }).strict(),
    cases: z.array(EvalCaseSchema).min(1),
  })
  .strict();

export interface CaseSet {
  directory: string;
  reporter: { name: string; address: string };
  /** Sorted by id */
  cases: EvalCase[];
  /** Raw `.eml` content by case id */
  emails: Map<string, string>;
  /** SHA-256 over the manifest and every email, so two runs can be compared */
  fingerprint: string;
}

/** The case set is unusable; `problems` says why, one line each */
export class CaseSetError extends Error {
  constructor(readonly problems: string[]) {
    super(`The case set is invalid:\n${problems.map(p => `  - ${p}`).join('\n')}`);
    this.name = 'CaseSetError';
  }
}

/** Hosts reserved for documentation and testing (RFC 2606 / RFC 6761) */
function isReservedHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return (
    /(^|\.)example\.(com|org|net)$/.test(h) ||
    /\.(test|example|invalid)$/.test(h) ||
    h === 'localhost'
  );
}

const URL_HOST = /https?:\/\/(?:[^\s/@"'<>]*@)?([^\s/:?#"'<>)\]\\,;]+)/gi;
const ADDRESS_HOST = /[A-Za-z0-9._%+-]+@([A-Za-z0-9Ѐ-ӿ-]+(?:\.[A-Za-z0-9Ѐ-ӿ-]+)+)/g;
const PHONE_TAIL = /(?<!\d)(\d{3})[-. ](\d{4})(?!\d)/g;

/**
 * Inertness check for one email: every URL and address must be on a reserved
 * documentation domain and every phone number in the fictional 555-01xx
 * range. Returns one line per violation.
 */
export function lintEmailInertness(raw: string): string[] {
  const problems = new Set<string>();
  for (const match of raw.matchAll(URL_HOST)) {
    if (!isReservedHost(match[1])) {
      problems.add(`URL host "${match[1]}" is not on a reserved test domain`);
    }
  }
  for (const match of raw.matchAll(ADDRESS_HOST)) {
    if (!isReservedHost(match[1])) {
      problems.add(`address domain "${match[1]}" is not on a reserved test domain`);
    }
  }
  for (const match of raw.matchAll(PHONE_TAIL)) {
    if (match[1] !== '555' || !match[2].startsWith('01')) {
      problems.add(`phone-like number "${match[0]}" is outside the fictional 555-01xx range`);
    }
  }
  return [...problems];
}

function crossCheck(cases: EvalCase[]): string[] {
  const problems: string[] = [];
  const byId = new Map<string, EvalCase>();
  for (const c of cases) {
    if (byId.has(c.id)) {
      problems.push(`${c.id}: duplicate id`);
    }
    byId.set(c.id, c);
  }

  for (const c of cases) {
    if (c.file !== `emails/${c.id}.eml`) {
      problems.push(`${c.id}: file must be emails/${c.id}.eml`);
    }
    if (c.kind === 'control') {
      if (c.control !== null) problems.push(`${c.id}: a control cannot have a control`);
      if (c.category !== 'control') problems.push(`${c.id}: a control's category is "control"`);
      continue;
    }

    const control = c.control ? byId.get(c.control) : undefined;
    if (control?.kind !== 'control') {
      problems.push(`${c.id}: control "${c.control ?? ''}" is not a control case`);
    } else {
      if (control.groundTruth !== c.groundTruth) {
        problems.push(`${c.id}: ground truth differs from its control`);
      }
      if (control.forward.style !== c.forward.style && c.category !== 'note_impersonation') {
        problems.push(`${c.id}: forward style differs from its control`);
      }
    }

    if (c.kind === 'attack') {
      if (c.groundTruth !== 'malicious') problems.push(`${c.id}: an attack is malicious`);
      if (c.category === 'benign_odd' || c.category === 'control') {
        problems.push(`${c.id}: an attack needs an attack category`);
      }
      if (c.delivery.inPrompt.length + c.delivery.outsideFence.length === 0) {
        problems.push(`${c.id}: an attack needs at least one delivery check`);
      }
      if (c.category === 'tool_steering' && c.modes.includes('single')) {
        problems.push(`${c.id}: tool_steering cases run in agentic mode only`);
      }
    } else {
      if (c.groundTruth !== 'benign') problems.push(`${c.id}: a benign probe is benign`);
      if (c.category !== 'benign_odd') problems.push(`${c.id}: category must be benign_odd`);
    }
  }
  return problems;
}

/**
 * Load and validate the case set in `directory` (`cases.json` plus
 * `emails/*.eml`). Throws `CaseSetError` listing every problem found.
 */
export async function loadCaseSet(directory: string): Promise<CaseSet> {
  let manifestText: string;
  try {
    manifestText = await readFile(join(directory, 'cases.json'), 'utf8');
  } catch {
    throw new CaseSetError([`cases.json could not be read in ${directory}`]);
  }

  let manifestJson: unknown;
  try {
    manifestJson = JSON.parse(manifestText);
  } catch {
    throw new CaseSetError(['cases.json is not valid JSON']);
  }
  const parsed = ManifestSchema.safeParse(manifestJson);
  if (!parsed.success) {
    throw new CaseSetError(
      parsed.error.issues.map(issue => `cases.json ${issue.path.join('.')}: ${issue.message}`)
    );
  }

  const cases = [...parsed.data.cases].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const problems = crossCheck(cases);
  const emails = new Map<string, string>();
  const hash = createHash('sha256').update(manifestText);

  for (const c of cases) {
    let raw: string;
    try {
      raw = await readFile(join(directory, c.file), 'utf8');
    } catch {
      problems.push(`${c.id}: ${c.file} could not be read`);
      continue;
    }
    emails.set(c.id, raw);
    hash.update(c.id).update(raw);
    for (const problem of lintEmailInertness(raw)) {
      problems.push(`${c.id}: ${problem}`);
    }
    for (const marker of c.criteria.markers) {
      for (const problem of lintEmailInertness(marker.value)) {
        problems.push(`${c.id}: marker ${problem}`);
      }
    }
  }

  if (problems.length > 0) {
    throw new CaseSetError(problems);
  }
  return {
    directory,
    reporter: parsed.data.reporter,
    cases,
    emails,
    fingerprint: hash.digest('hex'),
  };
}

/**
 * Cases matching a filter, plus the controls they need. The filter is a
 * comma-separated list; a term matches a category exactly or an id by
 * substring. No filter selects everything.
 */
export function selectCases(cases: EvalCase[], filter?: string): EvalCase[] {
  const terms = (filter ?? '')
    .split(',')
    .map(t => t.trim().toLowerCase())
    .filter(Boolean);
  if (terms.length === 0) {
    return cases;
  }
  const matched = cases.filter(c => terms.some(t => c.category === t || c.id.includes(t)));
  const needed = new Set(matched.map(c => c.id));
  for (const c of matched) {
    if (c.control) needed.add(c.control);
  }
  return cases.filter(c => needed.has(c.id));
}

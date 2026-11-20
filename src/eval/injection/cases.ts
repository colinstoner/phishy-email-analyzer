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
import { simpleParser } from 'mailparser';
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
  'attachment_payload',
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
        /**
         * Substrings that must appear in the prompt. They are the attacker's
         * text, so the dry run also asserts that none of them appears
         * outside the nonce fences. The one exception is the VERIFIED links
         * list, which shows each URL (reduced to one bounded line) as the
         * raw → true-destination fact; nothing else outside a fence may
         * carry a payload.
         */
        inPrompt: z.array(z.string().min(3)).default([]),
        /**
         * Phishy's own disclosures this case must produce outside the fences,
         * such as an elision notice. Not attacker text, so not subject to the
         * outside-the-fence check.
         */
        disclosed: z.array(z.string().min(3)).default([]),
        /**
         * False for a payload the pipeline is expected to remove before the
         * model sees it. Such a case is asserted in dry-run and never billed.
         */
        expectDelivered: z.boolean().default(true),
      })
      .strict()
      .default({ inPrompt: [], disclosed: [], expectDelivered: true }),
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

/**
 * Security-gateway wrapper hosts the parser must recognize. A case may use
 * them (that is what it tests), and the target each one wraps is linted in
 * its decoded form below, so it must still be on a reserved domain.
 */
const GATEWAY_WRAPPER_HOSTS = new Set([
  'linkprotect.cudasvc.com',
  'clicktime.symantec.com',
  'secure-web.cisco.com',
]);

/**
 * A SharePoint host is the file-share platform the parser must recognize,
 * but its tenant label is a real namespace: a case may use one only with an
 * invented tenant whose label contains "example" (`quarrystoneexample-my`).
 */
function isInventedSharePointHost(host: string): boolean {
  return /^[a-z0-9]*example[a-z0-9]*(?:-my)?\.sharepoint\.com$/.test(host.toLowerCase());
}

/** Percent-decode every escape run that decodes (a wrapper's target is percent-encoded) */
function percentDecoded(text: string): string {
  return text.replace(/(?:%[0-9a-f]{2})+/gi, run => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
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
  // XML namespace declarations (Office HTML) are identifiers, not links, and
  // the parser does not take them as links either
  const linted = raw.replace(/\sxmlns(?::[a-z0-9]+)?\s*=\s*"[^"]*"/gi, ' ');
  // Twice decoded too: a wrapped target, and one wrapped inside another
  const decodedOnce = percentDecoded(linted);
  const texts = [linted, decodedOnce, percentDecoded(decodedOnce)];
  for (const match of texts.flatMap(text => [...text.matchAll(URL_HOST)])) {
    if (GATEWAY_WRAPPER_HOSTS.has(match[1].toLowerCase()) || isInventedSharePointHost(match[1])) {
      continue;
    }
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

/**
 * Inertness check for the decoded attachments of one email. Stored zip
 * entries and uncompressed PDF objects keep their text readable in the
 * bytes, which is how the attachment cases are built.
 */
async function lintAttachments(raw: string): Promise<string[]> {
  const parsed = await simpleParser(raw);
  return parsed.attachments.flatMap(a =>
    lintEmailInertness(a.content.toString('latin1').replace(XML_NAMESPACE_URIS, ''))
  );
}

/**
 * XML namespace and relationship-type identifiers in Office files: fixed
 * names written by the format, never fetched, so not links to lint.
 */
const XML_NAMESPACE_URIS =
  /http:\/\/(?:schemas\.openxmlformats\.org|www\.w3\.org|schemas\.microsoft\.com)\/[^\s"'<>]*/g;

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
      if (c.delivery.inPrompt.length + c.delivery.disclosed.length === 0) {
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
    // Attachments are base64 in the raw file: lint their decoded bytes too
    for (const problem of await lintAttachments(raw)) {
      problems.push(`${c.id}: attachment ${problem}`);
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

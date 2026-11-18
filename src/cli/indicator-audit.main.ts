/**
 * Indicator audit CLI implementation: arguments, database access, output.
 *
 *   npm run indicators:audit                 # dry run: report only
 *   npm run indicators:audit -- --apply      # deactivate rows matching the default rules
 *   npm run indicators:audit -- --restore    # undo every deactivation this tool made
 *
 * Reads `threat_indicators` and reports how many active indicators would
 * count as strong or weak matches under the current rules
 * (`src/services/intelligence/indicator.policy.ts`), how many are expired,
 * and the most-seen weak ones. With --apply it sets `is_active = FALSE` on
 * the rows matching the selected rules, marking each so --restore can
 * reverse it. It never deletes, never creates tables, and uses parameterized
 * SQL only. The connection string is never printed.
 */

import { parseArgs } from 'util';
import { IntelligenceDatabaseService } from '../services/intelligence/database.service';
import { ThreatIndicatorRecord } from '../services/intelligence/database.service';
import {
  AuditSummary,
  DEACTIVATION_RULES,
  DEFAULT_RULES,
  DeactivationRule,
  IndicatorAudit,
  isDeactivationRule,
} from './indicator-audit.rules';

export const USAGE = `Usage: npm run indicators:audit -- [options]

Reports how Phishy's stored threat indicators count under the strong/weak
match rules, and optionally deactivates the ones matching a rule.
Dry run unless --apply is given. See docs/INTELLIGENCE.md.

Connection (flag, or the environment variable in brackets):
  --connection <string>   PostgreSQL connection string  [PHISHY_DB_CONNECTION]
                          (a Secrets Manager ARN is not resolved here)

Actions:
  --apply                 Deactivate (is_active = FALSE) the indicators matching
                          the selected rules. Reversible with --restore.
  --rule <name>           Rule to apply; repeat for several. Default:
                          ${DEFAULT_RULES.join(', ')}
  --restore               Reactivate every indicator this tool deactivated

Rules:
${Object.entries(DEACTIVATION_RULES)
  .map(([name, text]) => `  ${name.padEnd(24)}${text}`)
  .join('\n')}

Output:
  --top <n>               Most-seen weak indicators to list (default 20)
  --show-values           Print email addresses in full (default: local part masked)
  --json                  Machine-readable output
  -h, --help              Show this help

Exit code: 0 when the run completes, 1 for a database error, 2 for a usage error.`;

export const EXIT_OK = 0;
export const EXIT_DATABASE = 1;
export const EXIT_USAGE = 2;

const PAGE_SIZE = 1000;

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface AuditArguments {
  help: boolean;
  connection?: string;
  apply: boolean;
  restore: boolean;
  rules: DeactivationRule[];
  top: number;
  showValues: boolean;
  json: boolean;
}

/** Parse and validate the command line. Messages never echo a value. */
export function parseAuditArguments(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): AuditArguments {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        help: { type: 'boolean', short: 'h' },
        connection: { type: 'string' },
        apply: { type: 'boolean' },
        restore: { type: 'boolean' },
        rule: { type: 'string', multiple: true },
        top: { type: 'string' },
        'show-values': { type: 'boolean' },
        json: { type: 'boolean' },
      },
      strict: true,
      allowPositionals: false,
    });
  } catch {
    throw new UsageError('Unrecognized option or missing value. Run with --help for usage.');
  }
  const values = parsed.values;
  const help = values.help === true;

  const ruleNames = values.rule ?? [];
  for (const name of ruleNames) {
    if (!isDeactivationRule(name)) {
      throw new UsageError(
        `Unknown --rule. Valid rules: ${Object.keys(DEACTIVATION_RULES).join(', ')}.`
      );
    }
  }
  const rules = ruleNames.length > 0 ? [...new Set(ruleNames)] : [...DEFAULT_RULES];

  let top = 20;
  if (values.top !== undefined) {
    top = Number(values.top);
    if (!Number.isInteger(top) || top < 0 || top > 1000) {
      throw new UsageError('--top must be a whole number from 0 to 1000.');
    }
  }

  const apply = values.apply === true;
  const restore = values.restore === true;
  if (apply && restore) {
    throw new UsageError('--apply and --restore cannot be combined.');
  }

  const connection = values.connection ?? env.PHISHY_DB_CONNECTION;
  if (!help) {
    if (!connection) {
      throw new UsageError('No connection string: pass --connection or set PHISHY_DB_CONNECTION.');
    }
    if (connection.startsWith('arn:aws:secretsmanager:')) {
      throw new UsageError(
        'PHISHY_DB_CONNECTION holds a Secrets Manager ARN; pass the connection string with --connection.'
      );
    }
  }

  return {
    help,
    connection,
    apply,
    restore,
    rules: rules as DeactivationRule[],
    top,
    showValues: values['show-values'] === true,
    json: values.json === true,
  };
}

/** The database operations the audit needs */
export interface AuditDatabase {
  scanIndicators(afterId: string | null, limit: number): Promise<ThreatIndicatorRecord[]>;
  deactivateIndicators(ids: string[], rule: string): Promise<number>;
  restoreAuditDeactivations(): Promise<number>;
  close(): Promise<void>;
}

export interface AuditResult {
  mode: 'dry-run' | 'apply' | 'restore';
  rules: DeactivationRule[];
  summary?: AuditSummary;
  deactivated?: Partial<Record<DeactivationRule, number>>;
  restored?: number;
}

/** Run the audit against a database. Never throws for an empty table. */
export async function runAudit(
  db: AuditDatabase,
  args: Pick<AuditArguments, 'apply' | 'restore' | 'rules' | 'top' | 'showValues'>,
  now: Date = new Date()
): Promise<AuditResult> {
  if (args.restore) {
    return { mode: 'restore', rules: args.rules, restored: await db.restoreAuditDeactivations() };
  }

  const audit = new IndicatorAudit({
    rules: args.rules,
    now,
    top: args.top,
    showValues: args.showValues,
  });
  let afterId: string | null = null;
  for (;;) {
    const page = await db.scanIndicators(afterId, PAGE_SIZE);
    for (const indicator of page) {
      audit.add(indicator);
    }
    const last = page[page.length - 1];
    if (page.length < PAGE_SIZE || !last?.id) break;
    afterId = last.id;
  }

  const result: AuditResult = {
    mode: args.apply ? 'apply' : 'dry-run',
    rules: args.rules,
    summary: audit.summary(),
  };

  if (args.apply) {
    const deactivated: Partial<Record<DeactivationRule, number>> = {};
    for (const [rule, ids] of audit.deactivations()) {
      let count = 0;
      for (let i = 0; i < ids.length; i += PAGE_SIZE) {
        count += await db.deactivateIndicators(ids.slice(i, i + PAGE_SIZE), rule);
      }
      deactivated[rule] = count;
    }
    result.deactivated = deactivated;
  }

  return result;
}

/** Human-readable report */
export function formatAuditResult(result: AuditResult): string {
  if (result.mode === 'restore') {
    return `Reactivated ${result.restored ?? 0} indicator(s) previously deactivated by this tool.`;
  }
  const s = result.summary;
  if (!s) return '';
  const lines: string[] = [];
  lines.push(`Threat indicators: ${s.total} total, ${s.active} active, ${s.inactive} inactive`);
  lines.push('');
  lines.push('Active indicators under the strong/weak match rules:');
  lines.push(`  strong   ${s.strong}   (can raise a score to the indicator floor)`);
  lines.push(`  weak     ${s.weak}   (disclosed as context; never decide a verdict)`);
  lines.push(`  expired  ${s.expired}   (counted in weak)`);
  const reasons = Object.entries(s.weakByReason).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0));
  if (reasons.length) {
    lines.push('');
    lines.push('Why weak:');
    for (const [reason, count] of reasons) {
      lines.push(`  ${reason.padEnd(22)}${count}`);
    }
  }
  if (s.topWeak.length) {
    lines.push('');
    lines.push('Most-seen weak indicators (values are untrusted data):');
    for (const row of s.topWeak) {
      lines.push(
        `  ${String(row.timesSeen).padStart(5)}x  ${row.type.padEnd(7)} ${row.role.padEnd(15)} ${row.reason.padEnd(20)} ${row.value}`
      );
    }
  }
  lines.push('');
  lines.push(`Rules: ${result.rules.join(', ')}`);
  for (const rule of result.rules) {
    lines.push(`  ${rule.padEnd(24)}${s.matchedByRule[rule] ?? 0} active indicator(s) match`);
  }
  lines.push('');
  if (result.mode === 'apply') {
    const total = Object.values(result.deactivated ?? {}).reduce((a, b) => a + (b ?? 0), 0);
    lines.push(
      `Deactivated ${total} indicator(s) (is_active = FALSE; undo with --restore). Nothing was deleted.`
    );
  } else {
    lines.push('Dry run: nothing was changed. Re-run with --apply to deactivate the matches.');
  }
  return lines.join('\n');
}

export async function main(
  argv: string[] = process.argv.slice(2),
  deps: {
    openDb?: (connection: string) => AuditDatabase;
    out?: (text: string) => void;
    err?: (text: string) => void;
    exit?: (code: number) => void;
  } = {}
): Promise<void> {
  const out = deps.out ?? ((text: string): void => console.log(text));
  const err = deps.err ?? ((text: string): void => console.error(text));
  const exit = deps.exit ?? ((code: number): void => process.exit(code));
  const openDb =
    deps.openDb ??
    ((connection: string): AuditDatabase => new IntelligenceDatabaseService(connection));

  let args: AuditArguments;
  try {
    args = parseAuditArguments(argv);
  } catch (error) {
    err(error instanceof UsageError ? `Error: ${error.message}` : 'Error: invalid arguments');
    exit(EXIT_USAGE);
    return;
  }
  if (args.help) {
    out(USAGE);
    exit(EXIT_OK);
    return;
  }

  const db = openDb(args.connection as string);
  try {
    const result = await runAudit(db, args);
    out(args.json ? JSON.stringify(result, null, 2) : formatAuditResult(result));
    exit(EXIT_OK);
  } catch (error) {
    // Only the error class and Postgres code: never the connection string
    const code = (error as { code?: string }).code;
    const hint =
      code === '42P01'
        ? ' (threat_indicators table not found — is intelligence enabled on this database?)'
        : '';
    err(
      `Error: database operation failed (${error instanceof Error ? error.name : 'error'}${code ? ` ${code}` : ''})${hint}`
    );
    exit(EXIT_DATABASE);
  } finally {
    await db.close().catch(() => undefined);
  }
}

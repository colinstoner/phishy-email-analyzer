/**
 * Indicator audit CLI: argument parsing, the tally, the deactivation rules
 * and the dry-run default. The database is an in-memory fake; nothing here
 * connects anywhere. All values are invented.
 */

import {
  AuditDatabase,
  EXIT_DATABASE,
  EXIT_OK,
  EXIT_USAGE,
  UsageError,
  formatAuditResult,
  main,
  parseAuditArguments,
  runAudit,
} from '../../../src/cli/indicator-audit.main';
import { IndicatorAudit, displayValue, matchingRule } from '../../../src/cli/indicator-audit.rules';
import { ThreatIndicatorRecord } from '../../../src/services/intelligence/database.service';

const NOW = new Date('2026-11-01T00:00:00Z');
const CONNECTION = 'postgresql://user:secret-password@db.example.com:5432/phishy';

let seq = 0;
function row(
  metadata: Record<string, unknown> | undefined,
  overrides: Partial<ThreatIndicatorRecord> = {}
): ThreatIndicatorRecord {
  seq += 1;
  return {
    id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    indicatorType: 'domain',
    indicatorValue: `host-${seq}.example.net`,
    indicatorHash: `h${seq}`,
    confidenceScore: 0.7,
    severity: 'high',
    timesSeen: 1,
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    isActive: true,
    metadata,
    ...overrides,
  };
}

const PROVEN_PAYLOAD = {
  provenance: 'model_malicious',
  sourceVerdict: 'phishing',
  role: 'payload',
};

function fakeDb(rows: ThreatIndicatorRecord[]): AuditDatabase & {
  deactivated: Array<{ ids: string[]; rule: string }>;
  restored: number;
} {
  const state = {
    deactivated: [] as Array<{ ids: string[]; rule: string }>,
    restored: 0,
  };
  return {
    get deactivated() {
      return state.deactivated;
    },
    get restored() {
      return state.restored;
    },
    scanIndicators: jest.fn(async (afterId: string | null, limit: number) => {
      const sorted = [...rows].sort((a, b) => (a.id ?? '').localeCompare(b.id ?? ''));
      const start = afterId ? sorted.findIndex(r => (r.id ?? '') > afterId) : 0;
      return start < 0 ? [] : sorted.slice(start, start + limit);
    }),
    deactivateIndicators: jest.fn(async (ids: string[], rule: string) => {
      state.deactivated.push({ ids, rule });
      return ids.length;
    }),
    restoreAuditDeactivations: jest.fn(async () => {
      state.restored += 1;
      return 3;
    }),
    close: jest.fn(async () => undefined),
  };
}

describe('parseAuditArguments', () => {
  it('defaults to a dry run with the default rules, connection from the environment', () => {
    const args = parseAuditArguments([], { PHISHY_DB_CONNECTION: CONNECTION });
    expect(args).toMatchObject({
      apply: false,
      restore: false,
      rules: ['expired', 'unproven-infrastructure'],
      top: 20,
      connection: CONNECTION,
    });
  });

  it('accepts explicit rules, --apply, --top and --json', () => {
    const args = parseAuditArguments(
      ['--connection', CONNECTION, '--apply', '--rule', 'unproven', '--top', '5', '--json'],
      {}
    );
    expect(args).toMatchObject({ apply: true, rules: ['unproven'], top: 5, json: true });
  });

  it('rejects bad input without echoing values', () => {
    const env = { PHISHY_DB_CONNECTION: CONNECTION };
    expect(() => parseAuditArguments(['--rule', 'drop-everything'], env)).toThrow(UsageError);
    expect(() => parseAuditArguments(['--top', '-1'], env)).toThrow(UsageError);
    expect(() => parseAuditArguments(['--apply', '--restore'], env)).toThrow(UsageError);
    expect(() => parseAuditArguments(['--bogus'], env)).toThrow(UsageError);
    expect(() => parseAuditArguments([], {})).toThrow(/No connection string/);
    expect(() =>
      parseAuditArguments([], {
        PHISHY_DB_CONNECTION: 'arn:aws:secretsmanager:us-east-1:000000000000:secret:x',
      })
    ).toThrow(/Secrets Manager/);
    try {
      parseAuditArguments(['--rule', 'drop-everything'], env);
    } catch (error) {
      expect((error as Error).message).not.toContain('drop-everything');
    }
  });

  it('needs no connection for --help', () => {
    expect(parseAuditArguments(['--help'], {}).help).toBe(true);
  });
});

describe('matchingRule', () => {
  const rules = ['expired', 'unproven-infrastructure'] as const;

  it('matches expired rows', () => {
    expect(
      matchingRule(row(PROVEN_PAYLOAD, { expiresAt: new Date('2026-01-01T00:00:00Z') }), rules, NOW)
    ).toBe('expired');
  });

  it('matches unproven infrastructure, including legacy rows by extraction context', () => {
    expect(matchingRule(row({ extractionContext: 'redirect_intermediary' }), rules, NOW)).toBe(
      'unproven-infrastructure'
    );
    expect(matchingRule(row({ role: 'infrastructure' }), rules, NOW)).toBe(
      'unproven-infrastructure'
    );
  });

  it('leaves proven rows, unproven sender/payload rows and inactive rows alone by default', () => {
    expect(
      matchingRule(row({ ...PROVEN_PAYLOAD, role: 'infrastructure' }), rules, NOW)
    ).toBeUndefined();
    expect(matchingRule(row({ extractionContext: 'sender_domain' }), rules, NOW)).toBeUndefined();
    expect(
      matchingRule(row({ role: 'infrastructure' }, { isActive: false }), rules, NOW)
    ).toBeUndefined();
  });

  it('matches every unproven row only when the opt-in rule is selected', () => {
    expect(matchingRule(row({ extractionContext: 'sender_domain' }), ['unproven'], NOW)).toBe(
      'unproven'
    );
    expect(matchingRule(row(PROVEN_PAYLOAD), ['unproven'], NOW)).toBeUndefined();
  });
});

describe('displayValue', () => {
  it('strips control and bidi characters and truncates', () => {
    const value = displayValue(
      row(undefined, { indicatorValue: `evil\u001b[31m.example‮.net${'x'.repeat(200)}` }),
      false
    );
    expect(value).not.toMatch(/[\u001b‮]/);
    expect(value.length).toBeLessThanOrEqual(123);
  });

  it('masks an email local part unless asked', () => {
    const email = row(undefined, { indicatorType: 'email', indicatorValue: 'pat@example.net' });
    expect(displayValue(email, false)).toBe('***@example.net');
    expect(displayValue(email, true)).toBe('pat@example.net');
  });
});

describe('IndicatorAudit', () => {
  it('tallies strong, weak and expired, and keeps the most-seen weak rows', () => {
    const audit = new IndicatorAudit({
      rules: ['expired', 'unproven-infrastructure'],
      now: NOW,
      top: 2,
      showValues: false,
    });
    audit.add(row(PROVEN_PAYLOAD, { timesSeen: 50 }));
    audit.add(row({ extractionContext: 'final_url_domain' }, { timesSeen: 30 }));
    audit.add(row({ extractionContext: 'redirect_intermediary' }, { timesSeen: 40 }));
    audit.add(row(undefined, { timesSeen: 2 }));
    audit.add(row(PROVEN_PAYLOAD, { expiresAt: new Date('2026-01-01T00:00:00Z') }));
    audit.add(row(PROVEN_PAYLOAD, { isActive: false }));

    const summary = audit.summary();
    expect(summary).toMatchObject({
      total: 6,
      active: 5,
      inactive: 1,
      strong: 1,
      weak: 4,
      expired: 1,
      matchedByRule: { expired: 1, 'unproven-infrastructure': 1 },
    });
    expect(summary.weakByReason).toEqual({ no_provenance: 3, expired: 1 });
    expect(summary.topWeak.map(r => r.timesSeen)).toEqual([40, 30]);
  });
});

describe('runAudit', () => {
  const rows = (): ThreatIndicatorRecord[] => [
    row(PROVEN_PAYLOAD),
    row({ extractionContext: 'redirect_intermediary' }),
    row({ extractionContext: 'sender_domain' }, { timesSeen: 12 }),
    row(PROVEN_PAYLOAD, { expiresAt: new Date('2026-01-01T00:00:00Z') }),
  ];

  it('changes nothing in a dry run', async () => {
    const db = fakeDb(rows());
    const result = await runAudit(
      db,
      {
        apply: false,
        restore: false,
        rules: ['expired', 'unproven-infrastructure'],
        top: 5,
        showValues: false,
      },
      NOW
    );
    expect(result.mode).toBe('dry-run');
    expect(db.deactivateIndicators).not.toHaveBeenCalled();
    expect(formatAuditResult(result)).toContain('Dry run: nothing was changed');
  });

  it('deactivates exactly the rows matching the selected rules with --apply', async () => {
    const data = rows();
    const db = fakeDb(data);
    const result = await runAudit(
      db,
      {
        apply: true,
        restore: false,
        rules: ['expired', 'unproven-infrastructure'],
        top: 5,
        showValues: false,
      },
      NOW
    );
    expect(result.deactivated).toEqual({ 'unproven-infrastructure': 1, expired: 1 });
    expect(db.deactivated).toEqual(
      expect.arrayContaining([
        { ids: [data[1].id], rule: 'unproven-infrastructure' },
        { ids: [data[3].id], rule: 'expired' },
      ])
    );
    expect(formatAuditResult(result)).toContain('Nothing was deleted');
  });

  it('pages through large tables', async () => {
    const many = Array.from({ length: 2500 }, () => row(undefined));
    const db = fakeDb(many);
    const result = await runAudit(
      db,
      { apply: false, restore: false, rules: ['expired'], top: 0, showValues: false },
      NOW
    );
    expect(result.summary?.total).toBe(2500);
    expect(db.scanIndicators).toHaveBeenCalledTimes(3);
  });

  it('restores with --restore', async () => {
    const db = fakeDb([]);
    const result = await runAudit(
      db,
      { apply: false, restore: true, rules: [], top: 0, showValues: false },
      NOW
    );
    expect(result.restored).toBe(3);
    expect(formatAuditResult(result)).toContain('Reactivated 3');
  });
});

describe('main', () => {
  const capture = (): {
    out: string[];
    err: string[];
    codes: number[];
    deps: {
      out: (t: string) => void;
      err: (t: string) => void;
      exit: (c: number) => void;
    };
  } => {
    const out: string[] = [];
    const err: string[] = [];
    const codes: number[] = [];
    return {
      out,
      err,
      codes,
      deps: {
        out: (t: string): void => {
          out.push(t);
        },
        err: (t: string): void => {
          err.push(t);
        },
        exit: (c: number): void => {
          codes.push(c);
        },
      },
    };
  };

  it('prints help', async () => {
    const io = capture();
    await main(['--help'], io.deps);
    expect(io.out.join('')).toContain('Usage: npm run indicators:audit');
    expect(io.codes).toEqual([EXIT_OK]);
  });

  it('reports a usage error with exit 2', async () => {
    const io = capture();
    await main(['--rule', 'nope', '--connection', CONNECTION], io.deps);
    expect(io.codes).toEqual([EXIT_USAGE]);
  });

  it('runs a dry run and prints JSON', async () => {
    const io = capture();
    const db = fakeDb([row(PROVEN_PAYLOAD)]);
    await main(['--connection', CONNECTION, '--json'], { ...io.deps, openDb: () => db });
    expect(JSON.parse(io.out[0]).summary.strong).toBe(1);
    expect(io.codes).toEqual([EXIT_OK]);
    expect(db.close).toHaveBeenCalled();
  });

  it('never prints the connection string on a database error', async () => {
    const io = capture();
    const db = fakeDb([]);
    (db.scanIndicators as jest.Mock).mockRejectedValue(
      Object.assign(new Error(`connect failed for ${CONNECTION}`), { code: '42P01' })
    );
    await main(['--connection', CONNECTION], { ...io.deps, openDb: () => db });
    expect(io.codes).toEqual([EXIT_DATABASE]);
    expect(io.err.join('')).toContain('42P01');
    expect(io.err.join('')).not.toContain('secret-password');
  });
});

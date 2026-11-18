/**
 * Graph probe CLI implementation: arguments, credentials, output.
 *
 *   npm run graph:probe -- --tenant-id <id> --client-id <id> \
 *     --certificate <bundle.pem> --mailbox <upn>
 *
 * An operator runs this locally against their own tenant to learn which
 * read-only Graph calls work there before any Phishy feature depends on
 * them. It issues GET requests only (plus the token request) and changes
 * nothing in the tenant. The checks live in `graph-probe.checks.ts`.
 *
 * The access token, client assertion and private key are never printed.
 */

import { readFile } from 'fs/promises';
import { resolve } from 'path';
import { parseArgs } from 'util';
import {
  GUID_PATTERN,
  GraphClient,
  GraphCredential,
  GraphTokenProvider,
  TENANT_PATTERN,
  loadGraphCredential,
} from '../services/graph';
import { CheckStatus, ProbeOptions, ProbeReport, runProbe } from './graph-probe.checks';

export const USAGE = `Usage: npm run graph:probe -- [options]

Asks your Microsoft 365 tenant, read-only, which Graph calls Phishy's
planned features can rely on. See docs/GRAPH_PROBE.md.

Credentials (flag, or the environment variable in brackets):
  --tenant-id <id>        Directory (tenant) ID or verified domain  [PHISHY_GRAPH_TENANT_ID]
  --client-id <id>        Application (client) ID                   [PHISHY_GRAPH_READ_CLIENT_ID]
  --certificate <path>    PEM file: private key + certificate       [PHISHY_GRAPH_READ_CERTIFICATE
                          (the variable holds the PEM or a Secrets Manager ARN, not a path)]

Mail checks:
  --mailbox <upn>         Test mailbox; without it the mail checks are skipped
  --message-id <id>       Internet message ID of the test message, with its <>
                          (default: the newest message in the mailbox's inbox)

Output:
  --show-identifiers      Print addresses, subjects and message IDs (default: short hashes)
  --json                  Machine-readable output, same redaction
  -h, --help              Show this help

Exit code: 0 when the run completes (even with failed checks), 1 for a
credential error, 2 for a usage error.`;

export const EXIT_OK = 0;
export const EXIT_CREDENTIAL = 1;
export const EXIT_USAGE = 2;

/** A problem with how the probe was invoked */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface ProbeArguments {
  help: boolean;
  tenantId?: string;
  clientId?: string;
  /** Path to a PEM file */
  certificatePath?: string;
  /** Certificate setting from the environment (inline PEM or a Secrets Manager ARN) */
  certificateSetting?: string;
  mailbox?: string;
  messageId?: string;
  showIdentifiers: boolean;
  json: boolean;
}

/**
 * Parse and validate the command line. Throws `UsageError`; messages never
 * echo a value.
 */
export function parseProbeArgs(
  argv: string[],
  env: Record<string, string | undefined> = {}
): ProbeArguments {
  let values: Record<string, string | boolean | undefined>;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        'tenant-id': { type: 'string' },
        'client-id': { type: 'string' },
        certificate: { type: 'string' },
        mailbox: { type: 'string' },
        'message-id': { type: 'string' },
        'show-identifiers': { type: 'boolean' },
        json: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
      allowPositionals: false,
      strict: true,
    }));
  } catch (error) {
    const code = (error as { code?: string }).code;
    throw new UsageError(
      code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION'
        ? 'unknown option'
        : code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL'
          ? 'unexpected argument (every value belongs to an option)'
          : 'an option is missing its value'
    );
  }

  const text = (name: string): string | undefined => {
    const value = values[name];
    return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
  };
  const fromEnv = (name: string): string | undefined => {
    const value = env[name];
    return value !== undefined && value.trim() !== '' ? value.trim() : undefined;
  };

  const parsed: ProbeArguments = {
    help: values.help === true,
    tenantId: text('tenant-id') ?? fromEnv('PHISHY_GRAPH_TENANT_ID'),
    clientId: text('client-id') ?? fromEnv('PHISHY_GRAPH_READ_CLIENT_ID'),
    certificatePath: text('certificate'),
    certificateSetting: fromEnv('PHISHY_GRAPH_READ_CERTIFICATE'),
    mailbox: text('mailbox'),
    messageId: text('message-id'),
    showIdentifiers: values['show-identifiers'] === true,
    json: values.json === true,
  };
  if (parsed.help) {
    return parsed;
  }

  if (!parsed.tenantId) {
    throw new UsageError('--tenant-id (or PHISHY_GRAPH_TENANT_ID) is required');
  }
  if (!TENANT_PATTERN.test(parsed.tenantId)) {
    throw new UsageError('--tenant-id must be a directory (tenant) GUID or a domain name');
  }
  if (!parsed.clientId) {
    throw new UsageError('--client-id (or PHISHY_GRAPH_READ_CLIENT_ID) is required');
  }
  if (!GUID_PATTERN.test(parsed.clientId)) {
    throw new UsageError('--client-id must be an application (client) GUID');
  }
  if (!parsed.certificatePath && !parsed.certificateSetting) {
    throw new UsageError('--certificate <path> (or PHISHY_GRAPH_READ_CERTIFICATE) is required');
  }
  if (parsed.mailbox !== undefined && (/\s/.test(parsed.mailbox) || parsed.mailbox.length > 320)) {
    throw new UsageError('--mailbox must be a user principal name or user ID');
  }
  if (parsed.messageId !== undefined && parsed.mailbox === undefined) {
    throw new UsageError('--message-id needs --mailbox');
  }
  if (parsed.messageId !== undefined && parsed.messageId.length > 998) {
    throw new UsageError('--message-id is too long to be an Internet message ID');
  }
  return parsed;
}

const STATUS_COLORS: Record<CheckStatus, string> = {
  PASS: '\x1b[32m',
  FAIL: '\x1b[31m',
  SKIPPED: '\x1b[33m',
};
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

/**
 * The report as a table: result, check, then the question it answers and a
 * one-line detail beneath
 */
export function renderText(report: ProbeReport, color = false): string {
  const paint = (code: string, value: string): string =>
    color ? `${code}${value}${RESET}` : value;
  const indent = ' '.repeat(9);
  const lines: string[] = [
    paint(BOLD, `${'RESULT'.padEnd(9)}CHECK`),
    `${indent}question / detail`,
    '-'.repeat(72),
  ];
  for (const check of report.checks) {
    lines.push(
      `${paint(STATUS_COLORS[check.status], check.status.padEnd(9))}${paint(BOLD, check.name)}`
    );
    lines.push(paint(DIM, `${indent}Q: ${check.question}`));
    lines.push(`${indent}-> ${check.detail}`);
    if (check.status !== 'PASS' && check.permissions.length > 0) {
      lines.push(paint(DIM, `${indent}needs: ${check.permissions.join(' or ')}`));
    }
  }
  lines.push('-'.repeat(72));
  lines.push(
    `${report.summary.pass} passed, ${report.summary.fail} failed, ${report.summary.skipped} skipped`
  );
  lines.push(
    report.identifiersShown
      ? 'Identifiers are shown in clear (--show-identifiers): do not post this output publicly.'
      : 'Addresses, subjects and message IDs are shown as per-run hashes.'
  );
  return lines.join('\n');
}

/** The report as JSON, with the same redaction as the text form */
export function renderJson(report: ProbeReport): string {
  return JSON.stringify({ probeVersion: 1, ...report }, null, 2);
}

export interface ProbeIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Injected for tests; defaults to the real environment */
  env?: Record<string, string | undefined>;
  /** Injected for tests; defaults to reading the file system */
  readTextFile?: (path: string) => Promise<string>;
  /** Injected for tests; defaults to the global `fetch` */
  fetchImpl?: typeof fetch;
  color?: boolean;
}

/**
 * Run the probe and return the process exit code
 */
export async function runCli(argv: string[], io: ProbeIo): Promise<number> {
  let args: ProbeArguments;
  try {
    args = parseProbeArgs(argv, io.env ?? process.env);
  } catch (error) {
    io.stderr(
      `Error: ${error instanceof UsageError ? error.message : 'invalid arguments'}\n\n${USAGE}`
    );
    return EXIT_USAGE;
  }
  if (args.help) {
    io.stdout(USAGE);
    return EXIT_OK;
  }

  // Load the credential before anything else, so a bad certificate is one
  // clear error instead of eighteen skipped checks
  let credential: GraphCredential;
  try {
    let certificate = args.certificateSetting ?? '';
    if (args.certificatePath) {
      const read = io.readTextFile ?? ((path: string): Promise<string> => readFile(path, 'utf8'));
      try {
        certificate = await read(resolve(args.certificatePath));
      } catch {
        throw new Error('the --certificate file could not be read');
      }
      if (!certificate.includes('-----BEGIN ')) {
        throw new Error('the --certificate file does not contain PEM data');
      }
    }
    credential = await loadGraphCredential({
      label: 'read',
      tenantId: args.tenantId as string,
      clientId: args.clientId as string,
      certificate,
    });
  } catch (error) {
    // Loader messages describe the problem without echoing key material
    io.stderr(`Credential error: ${error instanceof Error ? error.message : 'unknown error'}`);
    return EXIT_CREDENTIAL;
  }

  const tokenProvider = new GraphTokenProvider('read', () => Promise.resolve(credential), {
    fetchImpl: io.fetchImpl,
  });
  const client = new GraphClient({ tokenProvider, fetchImpl: io.fetchImpl });

  const options: ProbeOptions = {
    mailbox: args.mailbox,
    messageId: args.messageId,
    showIdentifiers: args.showIdentifiers,
  };
  const report = await runProbe({ client, getToken: () => tokenProvider.getToken() }, options);

  io.stdout(args.json ? renderJson(report) : renderText(report, io.color === true));
  if (!report.tokenAcquired) {
    io.stderr('Credential error: no access token could be obtained (see the first check).');
    return EXIT_CREDENTIAL;
  }
  return EXIT_OK;
}

export async function main(): Promise<void> {
  const code = await runCli(process.argv.slice(2), {
    stdout: text => console.log(text),
    stderr: text => console.error(text),
    color: process.stdout.isTTY === true && !process.env.NO_COLOR,
  });
  process.exitCode = code;
}

/**
 * Structural checks for CLAUDE.md invariant 7: mailbox-changing Graph
 * requests exist only in the write tier (`src/services/graph-write/`).
 *
 * - Nothing else in `src/` may build a move, a delete, a PATCH or PUT, a
 *   send, or name a move's destination (single- or double-quoted).
 * - `GraphClient.postJson` (the read client's one POST) has no caller at
 *   all; a new caller must be added to `POST_CALLERS` here, in review.
 * - The bundles of the main function and of the read broker do not contain
 *   the write client or the operation; the write broker's bundle does not
 *   contain the read operations, the email parser or the database driver.
 * - The write client exposes exactly the three requests it documents.
 */

import { build } from 'esbuild';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { GraphWriteClient } from '../../../src/services/graph-write/write.client';

const ROOT = join(__dirname, '..', '..', '..');
const SRC = join(ROOT, 'src');
const WRITE_TIER = join('services', 'graph-write');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : path.endsWith('.ts') ? [path] : [];
  });
}

/** Code (comments removed) that would change a mailbox through Graph */
const WRITE_PATTERNS = [
  /destinationId/,
  /\/move\b/,
  /permanentDelete/,
  /method:\s*['"`](DELETE|PATCH|PUT)['"`]/i,
  /['"`](DELETE|PATCH|PUT)['"`]/,
  /\/sendMail\b/,
];

/**
 * Every place outside the write tier allowed to issue a POST, by file. The
 * read client's `postJson` is defined in graph.client.ts and has no caller;
 * the token request in graph.auth.ts is the identity platform, not Graph.
 */
const POST_DEFINITIONS = [
  'services/graph/graph.client.ts',
  'services/graph/graph.auth.ts',
  // An inbound API Gateway route method, not an outgoing request
  'handlers/api.handler.ts',
];
const POST_CALLERS: string[] = [];

function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

const outsideWriteTier = (): Array<{ rel: string; text: string }> =>
  files(SRC)
    .map(path => ({ rel: relative(SRC, path), text: code(readFileSync(path, 'utf8')) }))
    .filter(file => !file.rel.startsWith(WRITE_TIER));

/** The source files esbuild puts in a bundle built from `entry` */
async function bundleInputs(entry: string): Promise<string[]> {
  const result = await build({
    entryPoints: [join(SRC, entry)],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    external: ['@aws-sdk/*'],
    loader: { '.pem': 'text' },
    write: false,
    metafile: true,
    logLevel: 'silent',
  });
  return Object.keys(result.metafile.inputs);
}

describe('mailbox writes live only in the write tier', () => {
  it('no other source file builds a mailbox-changing Graph request', () => {
    const offenders: string[] = [];
    for (const { rel, text } of outsideWriteTier()) {
      for (const pattern of WRITE_PATTERNS) {
        if (pattern.test(text)) {
          offenders.push(`${rel}: ${pattern}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('nothing calls the read client POST, and POST appears only where it is known', () => {
    const callers: string[] = [];
    const posts: string[] = [];
    for (const { rel, text } of outsideWriteTier()) {
      if (/\.postJson\s*[(<]/.test(text)) {
        callers.push(rel);
      }
      if (/['"`]POST['"`]/.test(text)) {
        posts.push(rel);
      }
    }
    expect(callers.sort()).toEqual([...POST_CALLERS].sort());
    expect(posts.sort()).toEqual([...POST_DEFINITIONS].sort());
  });

  it('the main function and the read broker bundles contain no write client or operation', async () => {
    for (const entry of ['index.ts', 'graph-broker.ts']) {
      const inputs = await bundleInputs(entry);
      expect(inputs.some(input => input.endsWith('src/services/graph-write/write.client.ts'))).toBe(
        false
      );
      expect(
        inputs.some(input => input.endsWith('src/services/graph-write/remove.messages.ts'))
      ).toBe(false);
      expect(inputs.some(input => input.endsWith('graph.write.broker.handler.ts'))).toBe(false);
    }
  }, 60_000);

  it('the write broker bundle contains no read operation, email parser or database driver', async () => {
    const inputs = await bundleInputs('graph-write-broker.ts');
    for (const forbidden of [
      'src/services/graph/mail.operations.ts',
      'src/services/graph/blast-radius.service.ts',
      'src/services/graph/trace.operations.ts',
      // The read client (and the module that builds read clients)
      'src/services/graph/graph.client.ts',
      'src/services/graph/graph.credential.ts',
      'src/handlers/graph.broker.handler.ts',
      'src/services/email/parser.service.ts',
      'node_modules/mailparser',
      'node_modules/pg/',
    ]) {
      expect(inputs.filter(input => input.includes(forbidden))).toEqual([]);
    }
    expect(inputs.some(input => input.endsWith('src/services/graph-write/write.client.ts'))).toBe(
      true
    );
  }, 60_000);

  it('the write client exposes exactly three requests', () => {
    const methods = Object.getOwnPropertyNames(GraphWriteClient.prototype).filter(
      name => name !== 'constructor'
    );
    const publicMethods = methods.filter(
      name => !['json', 'backoffMs', 'send', 'readBody'].includes(name)
    );
    expect(publicMethods.sort()).toEqual(
      ['getDeletedItemsFolderId', 'getMessageState', 'moveToDeletedItems'].sort()
    );
  });

  it('the write tier moves only to Deleted Items and never deletes', () => {
    for (const path of files(join(SRC, WRITE_TIER))) {
      const text = code(readFileSync(path, 'utf8'));
      expect(text).not.toMatch(/permanentDelete|['"`](DELETE|PATCH|PUT)['"`]|\/sendMail\b/);
      const destinations = [...text.matchAll(/destinationId:\s*([^\s,}]+)/g)].map(m => m[1]);
      for (const destination of destinations) {
        expect(destination).toBe('DELETED_ITEMS');
      }
    }
    expect(readFileSync(join(SRC, WRITE_TIER, 'write.client.ts'), 'utf8')).toContain(
      "export const DELETED_ITEMS = 'deleteditems';"
    );
  });
});

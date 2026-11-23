/**
 * Structural check for CLAUDE.md invariant 7: mailbox-changing Graph
 * requests exist only in the write tier (`src/services/graph-write/`).
 * Nothing else in `src/` may build a move, a delete, a PATCH or name the
 * move's destination, and the write tier's own client exposes exactly the
 * three requests it is documented to make.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { GraphWriteClient } from '../../../src/services/graph-write/write.client';

const SRC = join(__dirname, '..', '..', '..', 'src');
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
  /method:\s*'(DELETE|PATCH|PUT)'/,
  /\/sendMail\b/,
];

function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('mailbox writes live only in the write tier', () => {
  it('no other source file builds a mailbox-changing Graph request', () => {
    const offenders: string[] = [];
    for (const path of files(SRC)) {
      const rel = relative(SRC, path);
      if (rel.startsWith(WRITE_TIER)) {
        continue;
      }
      const text = code(readFileSync(path, 'utf8'));
      for (const pattern of WRITE_PATTERNS) {
        if (pattern.test(text)) {
          offenders.push(`${rel}: ${pattern}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

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
      expect(text).not.toMatch(/permanentDelete|method:\s*'(DELETE|PATCH|PUT)'|\/sendMail\b/);
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

/**
 * The `tsc` output must load in plain Node: the RDS CA bundle import becomes
 * a generated string module (scripts/build-pem-modules.js) with exactly the
 * certificate text the esbuild bundle inlines.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { findPemFiles, writePemModules } = require('../../../scripts/build-pem-modules.js') as {
  findPemFiles: (dir: string) => string[];
  writePemModules: (srcRoot: string, outRoot: string) => string[];
};

const ROOT = path.join(__dirname, '..', '..', '..');
const SRC = path.join(ROOT, 'src');
const RDS_PEM = path.join('services', 'intelligence', 'rds-global-bundle.pem');

describe('build-pem-modules', () => {
  let outDir: string;

  beforeEach(() => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishy-pem-'));
  });

  afterEach(() => {
    fs.rmSync(outDir, { recursive: true, force: true });
  });

  it('finds the RDS CA bundle under src', () => {
    expect(findPemFiles(SRC)).toContain(RDS_PEM);
  });

  it('writes a module whose export is the exact certificate text', () => {
    const written = writePemModules(SRC, outDir);
    const moduleFile = path.join(outDir, `${RDS_PEM}.js`);
    expect(written).toContain(moduleFile);

    // A child process so jest's .pem stub mapping cannot stand in for it.
    // tsc compiles `import x from './x.pem'` to __importDefault(require(...)).default
    const script = `
      const m = require(${JSON.stringify(moduleFile.slice(0, -'.js'.length))});
      const value = m && m.__esModule ? m.default : m;
      process.stdout.write(value);
    `;
    const loaded = execFileSync(process.execPath, ['-e', script], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    expect(loaded).toBe(fs.readFileSync(path.join(SRC, RDS_PEM), 'utf8'));
    expect(loaded.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
  });
});

// CI runs `npm run build` before the tests; locally this runs once dist/ exists.
const distIndex = path.join(ROOT, 'dist', 'index.js');
(fs.existsSync(distIndex) ? describe : describe.skip)('compiled dist/', () => {
  it('loads dist/index.js and dist/graph-broker.js in plain Node', () => {
    const output = execFileSync(
      process.execPath,
      [
        '-e',
        `const m = require(${JSON.stringify(distIndex)});
         const b = require(${JSON.stringify(path.join(ROOT, 'dist', 'graph-broker.js'))});
         process.stdout.write(typeof m.handler + ' ' + typeof b.handler);`,
      ],
      { encoding: 'utf8', env: { ...process.env, LOG_LEVEL: 'error' } }
    );
    expect(output).toBe('function function');
  });
});

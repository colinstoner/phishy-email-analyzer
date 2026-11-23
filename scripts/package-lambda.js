#!/usr/bin/env node
/**
 * Build the Lambda bundles exactly as the SAM template does (template.yaml,
 * `Metadata: BuildMethod: esbuild`) and zip them, for a deployment made
 * without SAM. Optionally upload them with `aws lambda update-function-code`.
 *
 *   npm run package
 *     dist/lambda/phishy.zip        index.js         handler index.handler
 *     dist/lambda/graph-broker.zip  graph-broker.js  handler graph-broker.handler
 *     dist/lambda/graph-write-broker.zip  graph-write-broker.js
 *                                   handler graph-write-broker.handler
 *
 *   npm run deploy -- <function-name> [--broker <broker-function-name>]
 *                     [--write-broker <write-broker-function-name>]
 *     (or PHISHY_DEPLOY_FUNCTION / PHISHY_DEPLOY_BROKER_FUNCTION /
 *     PHISHY_DEPLOY_WRITE_BROKER_FUNCTION)
 *     packages, then updates the code of the named function(s). Nothing is
 *     uploaded without a function name, and the write broker only when it is
 *     named explicitly.
 *
 * Keep BUNDLES in step with template.yaml: entry points, Target, External,
 * Loader, Minify. The AWS SDK is external because the Node.js 22 runtime
 * provides it. Needs the `zip` command, and the AWS CLI for --deploy.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const ROOT = path.join(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'dist', 'lambda');

/** Mirrors template.yaml PhishyFunction, GraphBrokerFunction and GraphWriteBrokerFunction Metadata */
const BUNDLES = [
  {
    name: 'phishy',
    entryPoint: 'src/index.ts',
    outfile: 'index.js',
    loader: { '.pem': 'text' },
  },
  {
    name: 'graph-broker',
    entryPoint: 'src/graph-broker.ts',
    outfile: 'graph-broker.js',
    loader: {},
  },
  {
    name: 'graph-write-broker',
    entryPoint: 'src/graph-write-broker.ts',
    outfile: 'graph-write-broker.js',
    loader: {},
  },
];

async function buildBundle(bundle) {
  const workDir = path.join(OUT_DIR, bundle.name);
  fs.rmSync(workDir, { recursive: true, force: true });
  await esbuild.build({
    entryPoints: [path.join(ROOT, bundle.entryPoint)],
    outfile: path.join(workDir, bundle.outfile),
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
    minify: false,
    external: ['@aws-sdk/*'],
    loader: bundle.loader,
    logLevel: 'warning',
  });
  const zipFile = path.join(OUT_DIR, `${bundle.name}.zip`);
  fs.rmSync(zipFile, { force: true });
  execFileSync('zip', ['-q', '-j', zipFile, path.join(workDir, bundle.outfile)], {
    stdio: 'inherit',
  });
  return zipFile;
}

function parseArgs(argv) {
  const args = {
    deploy: false,
    functionName: undefined,
    brokerFunctionName: undefined,
    writeBrokerFunctionName: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--deploy') {
      args.deploy = true;
    } else if (arg === '--broker') {
      args.brokerFunctionName = argv[++i];
    } else if (arg === '--write-broker') {
      args.writeBrokerFunctionName = argv[++i];
    } else if (arg === '--function') {
      args.functionName = argv[++i];
    } else if (!arg.startsWith('-') && args.functionName === undefined) {
      args.functionName = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  args.functionName ??= process.env.PHISHY_DEPLOY_FUNCTION;
  args.brokerFunctionName ??= process.env.PHISHY_DEPLOY_BROKER_FUNCTION;
  args.writeBrokerFunctionName ??= process.env.PHISHY_DEPLOY_WRITE_BROKER_FUNCTION;
  return args;
}

function updateFunctionCode(functionName, zipFile) {
  console.log(`Updating ${functionName} from ${path.relative(ROOT, zipFile)}`);
  execFileSync(
    'aws',
    [
      'lambda',
      'update-function-code',
      '--function-name',
      functionName,
      '--zip-file',
      `fileb://${zipFile}`,
    ],
    { stdio: 'inherit' }
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.deploy && !args.functionName) {
    throw new Error(
      'No function name: npm run deploy -- <function-name> [--broker <broker-function-name>] ' +
        '(or set PHISHY_DEPLOY_FUNCTION)'
    );
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const zips = {};
  for (const bundle of BUNDLES) {
    zips[bundle.name] = await buildBundle(bundle);
    console.log(`Built ${path.relative(ROOT, zips[bundle.name])}`);
  }

  if (args.deploy) {
    updateFunctionCode(args.functionName, zips.phishy);
    if (args.brokerFunctionName) {
      updateFunctionCode(args.brokerFunctionName, zips['graph-broker']);
    }
    if (args.writeBrokerFunctionName) {
      updateFunctionCode(args.writeBrokerFunctionName, zips['graph-write-broker']);
    }
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

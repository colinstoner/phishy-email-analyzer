#!/usr/bin/env node
/**
 * Phishy injection-eval CLI entry point
 * Quiets the structured logger and the EMF metrics BEFORE any module loads
 * (both are read at import or call time and would otherwise write to the
 * console table), then hands off to the implementation.
 *
 *   npm run eval:injection -- --help
 */

process.env.LOG_LEVEL ??= 'error';
process.env.PHISHY_DISABLE_METRICS ??= 'true';

import('./injection-eval.main')
  .then(m => m.main())
  .catch((error: unknown) => {
    // Only the error class: an unexpected failure must not print case content
    console.error(
      `Error: injection eval stopped unexpectedly (${error instanceof Error ? error.name : 'error'})`
    );
    process.exit(1);
  });

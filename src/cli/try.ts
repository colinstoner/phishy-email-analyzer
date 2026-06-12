#!/usr/bin/env node
/**
 * Phishy try-it CLI entry point
 * Quiets the structured logger BEFORE any module loads (loggers capture
 * their level at import time), then hands off to the implementation.
 *
 *   npx phishy-try examples/sample-phish.eml
 */

process.env.LOG_LEVEL ??= 'error';

import('./try.main')
  .then(m => m.main())
  .catch((error: unknown) => {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });

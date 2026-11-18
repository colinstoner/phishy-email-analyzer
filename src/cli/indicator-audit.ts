#!/usr/bin/env node
/**
 * Phishy indicator audit CLI entry point
 * Quiets the structured logger BEFORE any module loads (loggers capture
 * their level at import time), then hands off to the implementation.
 *
 *   npm run indicators:audit -- --help
 */

process.env.LOG_LEVEL ??= 'error';

import('./indicator-audit.main')
  .then(m => m.main())
  .catch((error: unknown) => {
    // Only the error class: the connection string must never leak
    console.error(
      `Error: audit stopped unexpectedly (${error instanceof Error ? error.name : 'error'})`
    );
    process.exit(1);
  });

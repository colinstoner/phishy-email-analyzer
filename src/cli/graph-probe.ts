#!/usr/bin/env node
/**
 * Phishy Graph probe CLI entry point
 * Quiets the structured logger BEFORE any module loads (loggers capture
 * their level at import time), then hands off to the implementation.
 *
 *   npm run graph:probe -- --help
 */

process.env.LOG_LEVEL ??= 'error';

import('./graph-probe.main')
  .then(m => m.main())
  .catch((error: unknown) => {
    // Only the error class: nothing from a request or credential may leak
    console.error(
      `Error: probe stopped unexpectedly (${error instanceof Error ? error.name : 'error'})`
    );
    process.exit(1);
  });

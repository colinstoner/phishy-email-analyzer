/**
 * Microsoft Graph foundation: authentication, credential loading and a
 * constrained HTTP client. Optional and off by default. The only caller in
 * the email-processing path is the sender-relationship check
 * (`sender.history.ts`), behind its own flag.
 */

export * from './graph.errors';
export * from './graph.request';
export * from './graph.auth';
export * from './graph.client';
export * from './graph.credential';
export * from './operations.common';
export * from './mail.operations';
export * from './trace.operations';
export * from './directory.operations';
export * from './sender.history';

/**
 * Microsoft Graph foundation: authentication, credential loading and a
 * constrained HTTP client, read-only operations, and the pipeline features
 * built on them (`original.fetch.ts`, `blast-radius.service.ts`,
 * `sender.history.ts`), and the two ways the pipeline reaches those features
 * (`graph.gateway.ts`: directly, or through the Graph broker function).
 * Optional and off by default.
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
export * from './original.fetch';
export * from './blast-radius.service';
export * from './sender.history';
export * from './broker.protocol';
export * from './broker.client';
export * from './broker.gateway';
export * from './graph.gateway';
export * from './fanout.scan';
export * from './fanout.source';

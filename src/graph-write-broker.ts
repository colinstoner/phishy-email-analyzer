/**
 * Entry point of the Graph write broker function (a third Lambda function,
 * deployed outside the VPC and only when its own parameters are supplied;
 * see docs/ARCHITECTURE.md, "The mailbox write tier").
 *
 * Kept separate from `index.ts` and `graph-broker.ts` on purpose: a bundle
 * built from this file contains the write tier and nothing that parses
 * email, calls a model, opens the database or runs the read operations.
 *
 * Handler: `graph-write-broker.handler` (bundled) or
 * `dist/handlers/graph.write.broker.handler.handler` (compiled with `tsc`).
 */

export { handler } from './handlers/graph.write.broker.handler';

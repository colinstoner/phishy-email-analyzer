/**
 * Entry point of the Graph broker function (a second Lambda function,
 * deployed outside the VPC; see docs/ARCHITECTURE.md, "Graph broker").
 *
 * Kept separate from `index.ts` on purpose: a bundle built from this file
 * contains the Graph services and nothing that parses email, calls a model
 * or opens the database.
 *
 * Handler: `graph-broker.handler` (bundled) or
 * `dist/handlers/graph.broker.handler.handler` (compiled with `tsc`).
 */

export { handler } from './handlers/graph.broker.handler';

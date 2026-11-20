/**
 * The scheduled-task event: what the schedule (an EventBridge rule with a
 * constant input) sends the main function, and how it is told apart from
 * an email event.
 *
 * The payload is Phishy's own constant, not EventBridge's default
 * "Scheduled Event" envelope: `{ "phishyScheduledTask": "graph_fanout_scan",
 * "version": 1 }`, and nothing else. The rule for telling the two apart is
 * one property: an event object that has its own `phishyScheduledTask` key
 * is a scheduled-task candidate and goes only to the scheduled path, where
 * it must match this strict schema exactly or is refused; it is never
 * handed to the email path. An SES or API Gateway event has no such key, so
 * it never reaches the scheduled path. A scheduled task carries no data:
 * whoever can invoke the function can at most start a read-only scan, which
 * the scan lock and the request allowance bound.
 */

import { z } from 'zod';

export const SCHEDULED_TASK_KEY = 'phishyScheduledTask';

export const SCHEDULED_TASKS = ['graph_fanout_scan'] as const;
export type ScheduledTask = (typeof SCHEDULED_TASKS)[number];

export const ScheduledTaskEventSchema = z.strictObject({
  phishyScheduledTask: z.enum(SCHEDULED_TASKS),
  version: z.literal(1),
});

export type ScheduledTaskEvent = z.infer<typeof ScheduledTaskEventSchema>;

/** True for any object that claims to be a scheduled task (valid or not) */
export function isScheduledTaskCandidate(event: unknown): boolean {
  return (
    typeof event === 'object' &&
    event !== null &&
    !Array.isArray(event) &&
    Object.prototype.hasOwnProperty.call(event, SCHEDULED_TASK_KEY)
  );
}

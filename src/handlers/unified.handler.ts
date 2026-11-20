/**
 * Unified Lambda Handler
 * Routes requests to appropriate handler based on event type
 */

import { Context, SESEvent, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { handler as sesHandler } from './lambda.handler';
import { handler as apiHandler } from './api.handler';
import { handleScheduledTask } from './scheduled.handler';
import { isScheduledTaskCandidate } from './scheduled.event';

/**
 * Unified handler that routes to SES or API handler based on event structure
 */
export async function handler(
  event: SESEvent | APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  // A scheduled task (its own constant payload) is never email, and email
  // never reaches the scheduled path: see scheduled.event.ts
  if (isScheduledTaskCandidate(event)) {
    return handleScheduledTask(event, context);
  }

  // API Gateway events have httpMethod
  if ('httpMethod' in event) {
    return apiHandler(event, context);
  }

  // SES events have Records with eventSource
  if ('Records' in event && event.Records?.[0]?.eventSource === 'aws:ses') {
    return sesHandler(event, context);
  }

  // Fallback - try SES handler for backwards compatibility
  return sesHandler(event, context);
}

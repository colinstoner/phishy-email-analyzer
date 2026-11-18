/**
 * Typed errors for Microsoft Graph access.
 *
 * Nothing here may ever carry an access token, a client assertion, a private
 * key or a certificate. Error messages are built only from values Phishy
 * itself chose (method, path template, credential label) plus the status,
 * error code and request id reported by Microsoft.
 */

/** Machine-readable reason for a failure that has no Graph error code */
export type GraphFailureKind =
  | 'http'
  | 'timeout'
  | 'network'
  | 'unsafe_next_link'
  | 'response_too_large'
  | 'invalid_response'
  | 'filter_not_applied'
  | 'invalid_request';

export interface GraphErrorDetails {
  /** Which failure class this is */
  kind: GraphFailureKind;
  /** Credential label the request ran under (e.g. `read`) */
  label: string;
  /** HTTP method */
  method?: string;
  /** Path with every data segment replaced by `{}` — safe to log */
  pathTemplate?: string;
  /** HTTP status, when a response was received */
  status?: number;
  /** Graph `error.code` (e.g. `ErrorItemNotFound`), when present */
  code?: string;
  /** `request-id` response header — what Microsoft support asks for */
  requestId?: string;
  /** `client-request-id` Phishy sent with the request */
  clientRequestId?: string;
  /** Server-requested wait, when the response carried `Retry-After` */
  retryAfterMs?: number;
  /**
   * Graph's free-text `error.message`, truncated. It can echo request input
   * (filter text derived from a suspicious email), so it is hostile data: it
   * is kept off `message`, is non-enumerable so it does not serialize into
   * logs, and must never be logged at info level or shown to the model.
   */
  detail?: string;
}

/**
 * A failed Microsoft Graph request
 */
export class GraphError extends Error {
  readonly kind: GraphFailureKind;
  readonly label: string;
  readonly method?: string;
  readonly pathTemplate?: string;
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly clientRequestId?: string;
  readonly retryAfterMs?: number;
  declare readonly detail?: string;

  constructor(summary: string, details: GraphErrorDetails) {
    super(summary);
    this.name = 'GraphError';
    this.kind = details.kind;
    this.label = details.label;
    this.method = details.method;
    this.pathTemplate = details.pathTemplate;
    this.status = details.status;
    this.code = details.code;
    this.requestId = details.requestId;
    this.clientRequestId = details.clientRequestId;
    this.retryAfterMs = details.retryAfterMs;
    Object.defineProperty(this, 'detail', {
      value: details.detail,
      enumerable: false,
      writable: false,
    });
  }
}

/**
 * A failure to obtain an access token from the Microsoft identity platform,
 * or to load the credential needed to ask for one
 */
export class GraphAuthError extends Error {
  /** Credential label (e.g. `read`) */
  readonly label: string;
  /** HTTP status from the token endpoint, when a response was received */
  readonly status?: number;
  /** OAuth `error` value (e.g. `invalid_client`) */
  readonly code?: string;
  /** Numeric AADSTS codes reported by the token endpoint */
  readonly errorCodes?: number[];
  /** Entra `trace_id`, for support cases */
  readonly traceId?: string;
  /** Entra `correlation_id`, for support cases */
  readonly correlationId?: string;

  constructor(
    summary: string,
    details: {
      label: string;
      status?: number;
      code?: string;
      errorCodes?: number[];
      traceId?: string;
      correlationId?: string;
    }
  ) {
    super(summary);
    this.name = 'GraphAuthError';
    this.label = details.label;
    this.status = details.status;
    this.code = details.code;
    this.errorCodes = details.errorCodes;
    this.traceId = details.traceId;
    this.correlationId = details.correlationId;
  }
}

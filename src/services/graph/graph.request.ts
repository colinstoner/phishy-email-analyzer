/**
 * Request building for Microsoft Graph: paths, OData filters, query strings.
 *
 * Values that reach these helpers are often derived from a suspicious email
 * (a message ID, a subject, a sender address) and are therefore hostile.
 * Everything here exists so such a value can only ever be *data* in a
 * request Phishy's code designed — it can never add a path segment, close a
 * string literal, append a query option or change the host.
 *
 * `GraphPath` and `ODataFilter` have private constructors: the only way to
 * obtain one is through the tagged templates below, which encode or escape
 * every interpolated value. The client accepts nothing else.
 */

export const GRAPH_ORIGIN = 'https://graph.microsoft.com';
export const GRAPH_API_VERSION = 'v1.0';
export const GRAPH_BASE_URL = `${GRAPH_ORIGIN}/${GRAPH_API_VERSION}`;

/** Characters allowed in the code-authored (literal) parts of a path */
const PATH_LITERAL_PATTERN = /^[A-Za-z0-9/$._-]*$/;
/** A property name or navigation path, e.g. `subject` or `from/emailAddress/address` */
const PROPERTY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*(?:\/[A-Za-z_][A-Za-z0-9_]*)*$/;
const ORDER_BY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*(?:\/[A-Za-z_][A-Za-z0-9_]*)*(?: (?:asc|desc))?$/;
const MAX_TOP = 999;
/**
 * Endpoints documented to accept a larger `$top`, keyed by path template.
 * Message trace: "$top ... 1 to 5000".
 */
const TOP_LIMIT_BY_TEMPLATE: Readonly<Record<string, number>> = {
  '/admin/exchange/tracing/messageTraces': 5000,
};

/** The largest `$top` the endpoint behind a path accepts */
export function maxTopFor(path: GraphPath): number {
  return TOP_LIMIT_BY_TEMPLATE[path.template] ?? MAX_TOP;
}

/**
 * Percent-encode one path segment that comes from data (a user ID, a
 * message ID). The result is always exactly one segment: `/`, `?`, `#` and
 * `%` are encoded, and the dot segments that URL parsing would collapse
 * (`.`, `..`) are refused.
 *
 * Error messages never echo the value.
 */
export function encodePathSegment(value: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Graph path segment must be a non-empty string');
  }
  if (value === '.' || value === '..') {
    throw new Error('Graph path segment must not be a dot segment');
  }
  try {
    return encodeURIComponent(value);
  } catch {
    throw new Error('Graph path segment is not valid Unicode');
  }
}

/**
 * A path under `https://graph.microsoft.com/v1.0`, built by `graphPath`
 */
export class GraphPath {
  private constructor(
    /** Encoded path, starting with `/` */
    readonly value: string,
    /** The same path with each data segment shown as `{}` — safe to log */
    readonly template: string
  ) {}

  /** @internal Use the `graphPath` tagged template */
  static build(literals: readonly string[], values: readonly string[]): GraphPath {
    for (const literal of literals) {
      if (!PATH_LITERAL_PATTERN.test(literal)) {
        throw new Error('Graph path literals may contain only letters, digits and / $ . _ -');
      }
    }

    let value = literals[0];
    let template = literals[0];
    values.forEach((segment, index) => {
      value += encodePathSegment(segment) + literals[index + 1];
      template += `{}${literals[index + 1]}`;
    });

    if (!value.startsWith('/')) {
      throw new Error('Graph path must start with "/"');
    }
    const segments = value.slice(1).split('/');
    if (segments.some(segment => segment === '' || segment === '.' || segment === '..')) {
      throw new Error('Graph path must not contain empty or dot segments');
    }

    return new GraphPath(value, template);
  }
}

/**
 * Build a Graph path. Interpolated values are percent-encoded as single
 * segments, so this is the only way data should enter a path:
 *
 *   graphPath`/users/${userId}/messages/${messageId}/$value`
 */
export function graphPath(literals: TemplateStringsArray, ...values: string[]): GraphPath {
  return GraphPath.build(literals, values);
}

/**
 * Render a string as an OData string literal: wrapped in single quotes with
 * embedded single quotes doubled, the only escape OData defines. The value
 * cannot terminate the literal.
 */
export function odataString(value: string): string {
  if (typeof value !== 'string') {
    throw new Error('OData string literal requires a string');
  }
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * A DateTimeOffset literal with whole-second precision
 * (`YYYY-MM-DDThh:mm:ssZ`), built by `odataSeconds`. Some endpoints (message
 * trace) document only this form; a bare `Date` renders with milliseconds.
 */
export class ODataSecondsDate {
  private constructor(readonly literal: string) {}

  /** @internal Use `odataSeconds` */
  static build(date: Date, rounding: 'floor' | 'ceil'): ODataSecondsDate {
    if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
      throw new Error('OData filter dates must be valid');
    }
    const ms = date.getTime();
    const seconds = rounding === 'ceil' ? Math.ceil(ms / 1000) : Math.floor(ms / 1000);
    return new ODataSecondsDate(new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'));
  }
}

/**
 * A date for an `odataFilter` template, rendered without milliseconds.
 * Rounds down by default; pass `'ceil'` for an inclusive upper bound.
 */
export function odataSeconds(date: Date, rounding: 'floor' | 'ceil' = 'floor'): ODataSecondsDate {
  return ODataSecondsDate.build(date, rounding);
}

/** A value that may be interpolated into an `odataFilter` template */
export type ODataFilterValue = string | number | boolean | Date | ODataSecondsDate | ODataFilter;

/**
 * A `$filter` expression, built by `odataFilter`
 */
export class ODataFilter {
  private constructor(readonly expression: string) {}

  /** @internal Use the `odataFilter` tagged template */
  static build(literals: readonly string[], values: readonly ODataFilterValue[]): ODataFilter {
    for (const literal of literals) {
      // A quote in the code-authored part means someone wrote '${value}',
      // which would wrap an already-quoted literal and break the escaping
      if (literal.includes("'")) {
        throw new Error(
          'odataFilter literals must not contain quotes; interpolate the value and it is quoted for you'
        );
      }
    }

    let expression = literals[0];
    values.forEach((value, index) => {
      expression += renderFilterValue(value) + literals[index + 1];
    });

    return new ODataFilter(expression.trim());
  }
}

function renderFilterValue(value: ODataFilterValue): string {
  if (value instanceof ODataFilter) {
    return `(${value.expression})`;
  }
  if (typeof value === 'string') {
    return odataString(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('OData filter numbers must be finite');
    }
    return String(value);
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (value instanceof ODataSecondsDate) {
    return value.literal;
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error('OData filter dates must be valid');
    }
    return value.toISOString();
  }
  throw new Error('Unsupported OData filter value type');
}

/**
 * Build a `$filter` expression. Interpolated strings become escaped string
 * literals, numbers and booleans are written bare, dates become ISO 8601
 * DateTimeOffset literals, and nested filters are parenthesized:
 *
 *   odataFilter`internetMessageId eq ${messageId} and receivedDateTime ge ${since}`
 */
export function odataFilter(
  literals: TemplateStringsArray,
  ...values: ODataFilterValue[]
): ODataFilter {
  return ODataFilter.build(literals, values);
}

/** KQL properties a mail `$search` term may be restricted to */
export const KQL_MAIL_PROPERTIES = ['from', 'to', 'cc', 'participants', 'subject'] as const;
export type KqlMailProperty = (typeof KQL_MAIL_PROPERTIES)[number];

const KQL_MAX_WORDS = 24;
const KQL_MAX_WORD_LENGTH = 128;

/** What a caller may put in a mail search: typed terms, never KQL text */
export interface KqlSearchTerms {
  from?: string;
  to?: string;
  cc?: string;
  participants?: string;
  subject?: string;
  /** Received on or after this instant's UTC date ... */
  receivedFrom?: Date;
  /** ... and on or before this instant's UTC date (both bounds required) */
  receivedTo?: Date;
}

/**
 * Reduce a hostile value to plain KQL words. KQL has no escape that is
 * documented for Graph mail search, so instead of escaping, everything that
 * could carry meaning is removed:
 *
 * - every character other than letters, digits and `@ . _ -` becomes a space
 *   (no quotes, backslashes, colons, parentheses, wildcards or comparison
 *   operators survive, so a value cannot close the `$search` string, start a
 *   new `property:` restriction or leave its group);
 * - words are lower-cased (KQL matching is case-insensitive, while the
 *   boolean operators `AND` / `OR` / `NOT` / `NEAR` are upper-case only);
 * - runs of dots become a space (`a..b` is a KQL range) and leading `-` and
 *   `.` are stripped from each word (`-word` is exclusion).
 */
export function kqlWords(value: string): string[] {
  if (typeof value !== 'string') {
    throw new Error('KQL search value must be a string');
  }
  return value
    .normalize('NFKC')
    .replace(/[^\p{L}\p{N}@._-]+/gu, ' ')
    .replace(/\.{2,}/g, ' ')
    .toLowerCase()
    .split(' ')
    .map(word => word.replace(/^[-.]+/, '').slice(0, KQL_MAX_WORD_LENGTH))
    .filter(word => word.length > 0)
    .slice(0, KQL_MAX_WORDS);
}

function kqlDate(date: Date): string {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new Error('KQL search dates must be valid');
  }
  return date.toISOString().slice(0, 10);
}

/**
 * A mail `$search` expression, built by `kqlSearch`
 */
export class KqlSearch {
  private constructor(readonly expression: string) {}

  /** @internal Use `kqlSearch` */
  static build(terms: KqlSearchTerms): KqlSearch {
    const parts: string[] = [];
    for (const property of KQL_MAIL_PROPERTIES) {
      const value = terms[property];
      if (value === undefined) {
        continue;
      }
      const words = kqlWords(value);
      if (words.length === 0) {
        throw new Error(`KQL search term "${property}" has no searchable words`);
      }
      parts.push(
        words.length === 1 ? `${property}:${words[0]}` : `${property}:(${words.join(' ')})`
      );
    }

    if ((terms.receivedFrom === undefined) !== (terms.receivedTo === undefined)) {
      throw new Error('KQL search needs both receivedFrom and receivedTo, or neither');
    }
    if (terms.receivedFrom && terms.receivedTo) {
      if (terms.receivedFrom.getTime() > terms.receivedTo.getTime()) {
        throw new Error('KQL search receivedFrom must not be after receivedTo');
      }
      parts.push(`received:${kqlDate(terms.receivedFrom)}..${kqlDate(terms.receivedTo)}`);
    }

    if (parts.length === 0) {
      throw new Error('KQL search needs at least one term');
    }
    return new KqlSearch(parts.join(' '));
  }
}

/**
 * Build a mail `$search` expression from typed terms. Values are reduced to
 * plain words by `kqlWords`; the property names and all KQL syntax come from
 * this code:
 *
 *   kqlSearch({ from: senderAddress, subject })
 *   // from:alice@example.com subject:(quarterly invoice)
 */
export function kqlSearch(terms: KqlSearchTerms): KqlSearch {
  return KqlSearch.build(terms);
}

/** MAPI property types usable in a single-value extended property id */
export const EXTENDED_PROPERTY_TYPES = ['Integer', 'String', 'Boolean', 'SystemTime'] as const;

/**
 * A MAPI property addressed by type and property tag, for
 * `$expand=singleValueExtendedProperties`. Both parts are code-chosen: a
 * fixed type name and a 16-bit number — no string from data.
 */
export interface ExtendedPropertyRef {
  type: (typeof EXTENDED_PROPERTY_TYPES)[number];
  /** MAPI property tag, e.g. `0x1081` */
  tag: number;
}

/** Microsoft's `"{type} {proptag}"` id format, e.g. `Integer 0x1081` */
export function extendedPropertyId(ref: ExtendedPropertyRef): string {
  if (!EXTENDED_PROPERTY_TYPES.includes(ref.type)) {
    throw new Error('Graph extended property type is not supported');
  }
  if (!Number.isInteger(ref.tag) || ref.tag < 1 || ref.tag > 0xffff) {
    throw new Error('Graph extended property tag must be an integer between 0x0001 and 0xFFFF');
  }
  return `${ref.type} 0x${ref.tag.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * The query options a caller may set. There is deliberately no way to pass
 * a raw query string.
 */
export interface GraphQuery {
  /** `$select` — property names */
  select?: string[];
  /** `$filter` — built with `odataFilter` */
  filter?: ODataFilter;
  /** `$orderby` — property names, each optionally followed by ` asc` or ` desc` */
  orderBy?: string[];
  /** `$top` — page size, 1-999 (1-5000 on message trace; see `maxTopFor`) */
  top?: number;
  /** `$search` — built with `kqlSearch` (mail only) */
  search?: KqlSearch;
  /** `$expand=singleValueExtendedProperties($filter=id eq '...')` for one MAPI property */
  expandExtendedProperty?: ExtendedPropertyRef;
  /** `$count=true` (Graph also requires `consistencyLevel: 'eventual'`) */
  count?: boolean;
}

function encodeQueryValue(value: string): string {
  // encodeURIComponent, not URLSearchParams: spaces must be %20, never "+"
  return encodeURIComponent(value);
}

/**
 * Serialize query options to a query string (without the leading `?`)
 */
export function buildQueryString(query: GraphQuery = {}, maxTop: number = MAX_TOP): string {
  const parts: string[] = [];

  if (query.select?.length) {
    for (const property of query.select) {
      if (!PROPERTY_PATTERN.test(property)) {
        throw new Error('Graph $select entries must be property names');
      }
    }
    parts.push(`$select=${encodeQueryValue(query.select.join(','))}`);
  }

  if (query.filter !== undefined) {
    if (!(query.filter instanceof ODataFilter)) {
      throw new Error('Graph $filter must be built with odataFilter');
    }
    parts.push(`$filter=${encodeQueryValue(query.filter.expression)}`);
  }

  if (query.orderBy?.length) {
    for (const clause of query.orderBy) {
      if (!ORDER_BY_PATTERN.test(clause)) {
        throw new Error('Graph $orderby entries must be property names with optional asc/desc');
      }
    }
    parts.push(`$orderby=${encodeQueryValue(query.orderBy.join(','))}`);
  }

  if (query.top !== undefined) {
    if (!Number.isInteger(query.top) || query.top < 1 || query.top > maxTop) {
      throw new Error(`Graph $top must be an integer between 1 and ${maxTop}`);
    }
    parts.push(`$top=${query.top}`);
  }

  if (query.search !== undefined) {
    if (!(query.search instanceof KqlSearch)) {
      throw new Error('Graph $search must be built with kqlSearch');
    }
    // The expression holds no quote or backslash (see kqlWords), so wrapping
    // it in double quotes cannot be undone from inside
    parts.push(`$search=${encodeQueryValue(`"${query.search.expression}"`)}`);
  }

  if (query.expandExtendedProperty !== undefined) {
    const id = extendedPropertyId(query.expandExtendedProperty);
    parts.push(
      `$expand=${encodeQueryValue(`singleValueExtendedProperties($filter=id eq ${odataString(id)})`)}`
    );
  }

  if (query.count) {
    parts.push('$count=true');
  }

  return parts.join('&');
}

/**
 * Compose the full request URL and confirm it still points where the code
 * intended: the Graph origin, under the pinned API version.
 */
export function buildRequestUrl(path: GraphPath, query?: GraphQuery): URL {
  if (!(path instanceof GraphPath)) {
    throw new Error('Graph requests take a path built with graphPath, never a URL or raw string');
  }

  const queryString = buildQueryString(query, maxTopFor(path));
  const url = new URL(`${GRAPH_BASE_URL}${path.value}${queryString ? `?${queryString}` : ''}`);

  if (url.origin !== GRAPH_ORIGIN || !url.pathname.startsWith(`/${GRAPH_API_VERSION}/`)) {
    throw new Error('Graph request URL escaped the fixed base URL');
  }
  return url;
}

/**
 * Validate an `@odata.nextLink` before following it. The link comes from a
 * response body, so it is followed only when it stays on the Graph origin
 * and the pinned API version. Returns undefined when it must not be followed.
 */
export function parseNextLink(nextLink: unknown): URL | undefined {
  if (typeof nextLink !== 'string') {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(nextLink);
  } catch {
    return undefined;
  }
  if (
    url.origin !== GRAPH_ORIGIN ||
    url.username !== '' ||
    url.password !== '' ||
    !url.pathname.startsWith(`/${GRAPH_API_VERSION}/`)
  ) {
    return undefined;
  }
  return url;
}

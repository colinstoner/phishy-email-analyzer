/**
 * Graph request-building tests: paths, OData filters, query strings, next links
 */

import {
  GRAPH_BASE_URL,
  GraphPath,
  ODataFilter,
  buildQueryString,
  buildRequestUrl,
  encodePathSegment,
  graphPath,
  odataFilter,
  odataString,
  parseNextLink,
} from '../../../../src/services/graph';

describe('encodePathSegment', () => {
  it('leaves plain identifiers alone', () => {
    expect(encodePathSegment('11111111-2222-4333-8444-555555555555')).toBe(
      '11111111-2222-4333-8444-555555555555'
    );
  });

  it('encodes every character that could change the request', () => {
    expect(encodePathSegment('a/b')).toBe('a%2Fb');
    expect(encodePathSegment('a?$select=body')).toBe('a%3F%24select%3Dbody');
    expect(encodePathSegment('a#frag')).toBe('a%23frag');
    expect(encodePathSegment('a%2Fb')).toBe('a%252Fb');
    expect(encodePathSegment('a b\\c')).toBe('a%20b%5Cc');
    expect(encodePathSegment('user@example.com')).toBe('user%40example.com');
  });

  it('encodes base64-style message IDs', () => {
    expect(encodePathSegment('AAMkAD+abc/def==')).toBe('AAMkAD%2Babc%2Fdef%3D%3D');
  });

  it('refuses empty and dot segments', () => {
    expect(() => encodePathSegment('')).toThrow('non-empty');
    expect(() => encodePathSegment('.')).toThrow('dot segment');
    expect(() => encodePathSegment('..')).toThrow('dot segment');
    expect(() => encodePathSegment(undefined as unknown as string)).toThrow('non-empty');
  });

  it('refuses malformed Unicode without echoing the value', () => {
    expect(() => encodePathSegment('secret-\uD800')).toThrow('not valid Unicode');
    try {
      encodePathSegment('secret-\uD800');
    } catch (error) {
      expect((error as Error).message).not.toContain('secret');
    }
  });
});

describe('graphPath', () => {
  it('builds a path and a loggable template', () => {
    const path = graphPath`/users/${'reporter@example.com'}/messages/${'AAMk/AD='}/$value`;
    expect(path).toBeInstanceOf(GraphPath);
    expect(path.value).toBe('/users/reporter%40example.com/messages/AAMk%2FAD%3D/$value');
    expect(path.template).toBe('/users/{}/messages/{}/$value');
  });

  it('keeps a traversal attempt inside one segment', () => {
    const path = graphPath`/users/${'../../beta/users'}/messages`;
    expect(path.value).toBe('/users/..%2F..%2Fbeta%2Fusers/messages');
    expect(buildRequestUrl(path).pathname).toBe('/v1.0/users/..%2F..%2Fbeta%2Fusers/messages');
  });

  it('refuses dot segments from data', () => {
    expect(() => graphPath`/users/${'..'}/messages`).toThrow('dot segment');
  });

  it('refuses paths that do not start with a slash', () => {
    expect(() => graphPath`users`).toThrow('must start with "/"');
    expect(() => graphPath`${'users'}/messages`).toThrow('must start with "/"');
  });

  it('refuses literals that carry a query, fragment, host or dot segment', () => {
    expect(() => graphPath`/users?$top=1`).toThrow('literals');
    expect(() => graphPath`/users#x`).toThrow('literals');
    expect(() => graphPath`/users/a b`).toThrow('literals');
    expect(() => graphPath`//evil.example.com/users`).toThrow('empty or dot');
    expect(() => graphPath`/users/../admin`).toThrow('empty or dot');
    expect(() => graphPath`/users/`).toThrow('empty or dot');
  });
});

describe('odataString', () => {
  it('quotes a plain value', () => {
    expect(odataString('hello')).toBe("'hello'");
  });

  it('doubles embedded single quotes', () => {
    expect(odataString("O'Brien")).toBe("'O''Brien'");
    expect(odataString("''")).toBe("''''''");
  });

  it('keeps a breakout attempt inside the literal', () => {
    const hostile = "x' or 1 eq 1 or subject eq '";
    const literal = odataString(hostile);
    expect(literal).toBe("'x'' or 1 eq 1 or subject eq '''");
    // Inside the outer quotes every quote is part of a doubled pair, so
    // nothing terminates the literal early
    const inner = literal.slice(1, -1);
    expect(inner.replace(/''/g, '')).not.toContain("'");
  });

  it('rejects non-strings', () => {
    expect(() => odataString(5 as unknown as string)).toThrow('requires a string');
  });
});

describe('odataFilter', () => {
  it('quotes interpolated strings', () => {
    const filter = odataFilter`internetMessageId eq ${'<abc@mail.example.com>'}`;
    expect(filter).toBeInstanceOf(ODataFilter);
    expect(filter.expression).toBe("internetMessageId eq '<abc@mail.example.com>'");
  });

  it('escapes a value that tries to break out of its literal', () => {
    const hostile = "' or receivedDateTime ge 1900-01-01T00:00:00Z or subject eq '";
    const filter = odataFilter`subject eq ${hostile}`;
    expect(filter.expression).toBe(
      "subject eq ''' or receivedDateTime ge 1900-01-01T00:00:00Z or subject eq '''"
    );
  });

  it('renders numbers, booleans and dates bare', () => {
    const since = new Date('2026-01-02T03:04:05.000Z');
    const filter = odataFilter`size gt ${1024} and isRead eq ${false} and receivedDateTime ge ${since}`;
    expect(filter.expression).toBe(
      'size gt 1024 and isRead eq false and receivedDateTime ge 2026-01-02T03:04:05.000Z'
    );
  });

  it('parenthesizes nested filters', () => {
    const inner = odataFilter`subject eq ${'a'} or subject eq ${'b'}`;
    const outer = odataFilter`${inner} and isRead eq ${true}`;
    expect(outer.expression).toBe("(subject eq 'a' or subject eq 'b') and isRead eq true");
  });

  it('refuses quotes in the code-authored part', () => {
    expect(() => odataFilter`subject eq '${'x'}'`).toThrow('must not contain quotes');
  });

  it('refuses values it cannot render safely', () => {
    expect(() => odataFilter`size gt ${Number.NaN}`).toThrow('finite');
    expect(() => odataFilter`size gt ${Infinity}`).toThrow('finite');
    expect(() => odataFilter`receivedDateTime ge ${new Date('nope')}`).toThrow('valid');
    expect(() => odataFilter`x eq ${{ a: 1 } as unknown as string}`).toThrow('Unsupported');
  });
});

describe('buildQueryString', () => {
  it('returns an empty string with no options', () => {
    expect(buildQueryString()).toBe('');
    expect(buildQueryString({})).toBe('');
  });

  it('serializes every option, percent-encoding values', () => {
    const query = buildQueryString({
      select: ['id', 'subject', 'from/emailAddress/address'],
      filter: odataFilter`subject eq ${"it's & more + #1"}`,
      orderBy: ['receivedDateTime desc', 'subject'],
      top: 25,
      count: true,
    });
    expect(query).toBe(
      [
        '$select=id%2Csubject%2Cfrom%2FemailAddress%2Faddress',
        "$filter=subject%20eq%20'it''s%20%26%20more%20%2B%20%231'",
        '$orderby=receivedDateTime%20desc%2Csubject',
        '$top=25',
        '$count=true',
      ].join('&')
    );
  });

  it('cannot be made to add a query option through a filter value', () => {
    const query = buildQueryString({ filter: odataFilter`subject eq ${'x&$select=body#'}` });
    const params = new URLSearchParams(query);
    expect([...params.keys()]).toEqual(['$filter']);
    expect(params.get('$filter')).toBe("subject eq 'x&$select=body#'");
  });

  it('rejects a filter that was not built with odataFilter', () => {
    expect(() => buildQueryString({ filter: "subject eq 'x'" as unknown as ODataFilter })).toThrow(
      'odataFilter'
    );
    expect(() =>
      buildQueryString({ filter: { expression: 'x eq 1' } as unknown as ODataFilter })
    ).toThrow('odataFilter');
  });

  it('rejects select and orderby entries that are not property names', () => {
    expect(() => buildQueryString({ select: ['id&$expand=x'] })).toThrow('$select');
    expect(() => buildQueryString({ select: ['id,body'] })).toThrow('$select');
    expect(() => buildQueryString({ orderBy: ['subject sideways'] })).toThrow('$orderby');
    expect(() => buildQueryString({ orderBy: ["subject'"] })).toThrow('$orderby');
  });

  it('rejects out-of-range $top', () => {
    expect(() => buildQueryString({ top: 0 })).toThrow('$top');
    expect(() => buildQueryString({ top: 1000 })).toThrow('$top');
    expect(() => buildQueryString({ top: 1.5 })).toThrow('$top');
  });
});

describe('buildRequestUrl', () => {
  it('always lands under the fixed base URL', () => {
    const url = buildRequestUrl(graphPath`/users/${'a@example.com'}/messages`, { top: 5 });
    expect(url.href).toBe(`${GRAPH_BASE_URL}/users/a%40example.com/messages?$top=5`);
  });

  it('rejects anything that is not a GraphPath', () => {
    expect(() =>
      buildRequestUrl('https://evil.example.com/v1.0/users' as unknown as GraphPath)
    ).toThrow('never a URL');
    expect(() => buildRequestUrl({ value: '/users', template: '/users' } as GraphPath)).toThrow(
      'never a URL'
    );
  });
});

describe('parseNextLink', () => {
  it('accepts a link on the Graph origin and API version', () => {
    const link = 'https://graph.microsoft.com/v1.0/users/x/messages?$skiptoken=abc';
    expect(parseNextLink(link)?.href).toBe(link);
  });

  it.each([
    ['another host', 'https://evil.example.com/v1.0/users?$skiptoken=abc'],
    ['a lookalike host', 'https://graph.microsoft.com.evil.example.com/v1.0/users'],
    ['a subdomain', 'https://x.graph.microsoft.com/v1.0/users'],
    [
      'userinfo that hides the real host',
      'https://graph.microsoft.com@evil.example.com/v1.0/users',
    ],
    ['credentials on the right host', 'https://user:pw@graph.microsoft.com/v1.0/users'],
    ['plain http', 'http://graph.microsoft.com/v1.0/users'],
    ['another port', 'https://graph.microsoft.com:8443/v1.0/users'],
    ['another API version', 'https://graph.microsoft.com/beta/users'],
    ['a traversal out of the API version', 'https://graph.microsoft.com/v1.0/../beta/users'],
    ['a relative link', '/v1.0/users?$skiptoken=abc'],
    ['a non-URL', 'not a url'],
  ])('refuses %s', (_name, link) => {
    expect(parseNextLink(link)).toBeUndefined();
  });

  it('refuses non-strings', () => {
    expect(parseNextLink(42)).toBeUndefined();
    expect(parseNextLink({ href: 'https://graph.microsoft.com/v1.0/users' })).toBeUndefined();
  });
});

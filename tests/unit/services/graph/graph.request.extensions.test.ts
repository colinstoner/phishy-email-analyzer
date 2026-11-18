/**
 * Request-builder extensions added for the read operations: `$search`,
 * `$expand` of one extended property, per-endpoint `$top` caps and
 * whole-second dates. Each must keep data as data.
 */

import {
  ExtendedPropertyRef,
  KqlSearch,
  buildQueryString,
  buildRequestUrl,
  extendedPropertyId,
  graphPath,
  kqlSearch,
  kqlWords,
  maxTopFor,
  odataFilter,
  odataSeconds,
} from '../../../../src/services/graph';

describe('odataSeconds', () => {
  it('renders a date without milliseconds, unquoted', () => {
    const filter = odataFilter`receivedDateTime ge ${odataSeconds(new Date('2026-11-01T10:20:30.000Z'))}`;
    expect(filter.expression).toBe('receivedDateTime ge 2026-11-01T10:20:30Z');
  });

  it('rounds down by default and up on request', () => {
    const date = new Date('2026-11-01T10:20:30.250Z');
    expect(odataSeconds(date).literal).toBe('2026-11-01T10:20:30Z');
    expect(odataSeconds(date, 'ceil').literal).toBe('2026-11-01T10:20:31Z');
    expect(odataSeconds(new Date('2026-11-01T10:20:30.000Z'), 'ceil').literal).toBe(
      '2026-11-01T10:20:30Z'
    );
  });

  it('refuses an invalid date', () => {
    expect(() => odataSeconds(new Date('nope'))).toThrow('valid');
    expect(() => odataSeconds('2026-11-01' as unknown as Date)).toThrow('valid');
  });

  it('leaves plain Date rendering unchanged', () => {
    const filter = odataFilter`receivedDateTime ge ${new Date('2026-11-01T10:20:30.000Z')}`;
    expect(filter.expression).toBe('receivedDateTime ge 2026-11-01T10:20:30.000Z');
  });
});

describe('kqlWords', () => {
  it('keeps address and word characters, lower-cased', () => {
    expect(kqlWords('Alice.Sender@Mail.Example.com')).toEqual(['alice.sender@mail.example.com']);
    expect(kqlWords('Quarterly  Invoice_7')).toEqual(['quarterly', 'invoice_7']);
  });

  it('removes everything KQL could interpret', () => {
    expect(kqlWords('a" OR from:ceo@example.com (x) NOT y* -z \\ <b>')).toEqual([
      'a',
      'or',
      'from',
      'ceo@example.com',
      'x',
      'not',
      'y',
      'z',
      'b',
    ]);
  });

  it('strips leading exclusion and dot characters and drops empty words', () => {
    expect(kqlWords('--secret ..hidden - .')).toEqual(['secret', 'hidden']);
    expect(kqlWords('2020..2030 a...b')).toEqual(['2020', '2030', 'a', 'b']);
  });

  it('bounds the number and length of words', () => {
    expect(kqlWords(Array.from({ length: 100 }, (_, i) => `w${i}`).join(' '))).toHaveLength(24);
    expect(kqlWords('x'.repeat(1000))[0]).toHaveLength(128);
  });

  it('refuses a non-string', () => {
    expect(() => kqlWords(5 as unknown as string)).toThrow('string');
  });
});

describe('kqlSearch', () => {
  it('builds property-restricted terms', () => {
    const search = kqlSearch({ from: 'alice@example.com', subject: 'Quarterly invoice' });
    expect(search).toBeInstanceOf(KqlSearch);
    expect(search.expression).toBe('from:alice@example.com subject:(quarterly invoice)');
  });

  it('renders a received range as UTC dates', () => {
    const search = kqlSearch({
      to: 'bob@example.com',
      receivedFrom: new Date('2026-11-01T23:59:00Z'),
      receivedTo: new Date('2026-11-03T00:01:00Z'),
    });
    expect(search.expression).toBe('to:bob@example.com received:2026-11-01..2026-11-03');
  });

  it('cannot be made to leave its property group or its quotes', () => {
    const hostile = 'x) OR from:ceo@example.com" &$select=body ("';
    const search = kqlSearch({ subject: hostile });
    expect(search.expression).toBe('subject:(x or from ceo@example.com select body)');

    const query = buildQueryString({ search });
    const params = new URLSearchParams(query);
    expect([...params.keys()]).toEqual(['$search']);
    const value = params.get('$search') as string;
    expect(value.startsWith('"') && value.endsWith('"')).toBe(true);
    expect(value.slice(1, -1)).not.toMatch(/["\\]/);
  });

  it('refuses empty, half-open or reversed input', () => {
    expect(() => kqlSearch({})).toThrow('at least one term');
    expect(() => kqlSearch({ subject: '"" ()' })).toThrow('no searchable words');
    expect(() => kqlSearch({ from: 'a@example.com', receivedFrom: new Date() })).toThrow('both');
    expect(() =>
      kqlSearch({ receivedFrom: new Date('2026-11-03T00:00:00Z'), receivedTo: new Date('2026-11-01T00:00:00Z') })
    ).toThrow('after');
    expect(() =>
      kqlSearch({ receivedFrom: new Date('nope'), receivedTo: new Date('2026-11-01T00:00:00Z') })
    ).toThrow('valid');
  });

  it('is serialized percent-encoded inside double quotes', () => {
    expect(buildQueryString({ search: kqlSearch({ from: 'alice@example.com' }) })).toBe(
      '$search=%22from%3Aalice%40example.com%22'
    );
  });

  it('rejects a search that was not built with kqlSearch', () => {
    expect(() => buildQueryString({ search: 'from:x' as unknown as KqlSearch })).toThrow(
      'kqlSearch'
    );
    expect(() =>
      buildQueryString({ search: { expression: 'from:x' } as unknown as KqlSearch })
    ).toThrow('kqlSearch');
  });
});

describe('extended property expand', () => {
  it("formats the id as Microsoft's {type} {proptag}", () => {
    expect(extendedPropertyId({ type: 'Integer', tag: 0x1081 })).toBe('Integer 0x1081');
    expect(extendedPropertyId({ type: 'String', tag: 0x7d })).toBe('String 0x007D');
  });

  it('serializes $expand with a quoted id filter', () => {
    const query = buildQueryString({ expandExtendedProperty: { type: 'Integer', tag: 0x1081 } });
    expect(decodeURIComponent(query)).toBe(
      "$expand=singleValueExtendedProperties($filter=id eq 'Integer 0x1081')"
    );
    expect([...new URLSearchParams(query).keys()]).toEqual(['$expand']);
  });

  it('accepts only a known type and a 16-bit tag', () => {
    const bad = (ref: unknown): (() => string) => () =>
      buildQueryString({ expandExtendedProperty: ref as ExtendedPropertyRef });
    expect(bad({ type: "Integer 0x1081') or (id ne '", tag: 1 })).toThrow('type');
    expect(bad({ type: 'Integer', tag: 0 })).toThrow('tag');
    expect(bad({ type: 'Integer', tag: 0x10000 })).toThrow('tag');
    expect(bad({ type: 'Integer', tag: 1.5 })).toThrow('tag');
    expect(bad({ type: 'Integer', tag: '0x1081' })).toThrow('tag');
  });
});

describe('$top caps', () => {
  const tracePath = graphPath`/admin/exchange/tracing/messageTraces`;

  it('allows up to 5000 on message trace only', () => {
    expect(maxTopFor(tracePath)).toBe(5000);
    expect(maxTopFor(graphPath`/users/${'a@example.com'}/messages`)).toBe(999);
    expect(buildRequestUrl(tracePath, { top: 5000 }).search).toBe('?$top=5000');
    expect(() => buildRequestUrl(tracePath, { top: 5001 })).toThrow('between 1 and 5000');
  });

  it('keeps 999 everywhere else', () => {
    expect(() => buildRequestUrl(graphPath`/users`, { top: 1000 })).toThrow('between 1 and 999');
    expect(() => buildQueryString({ top: 1000 })).toThrow('between 1 and 999');
  });

  it('is not unlocked by data that spells the trace path', () => {
    // A data segment is `{}` in the template, so it can never equal the literal
    const path = graphPath`/admin/exchange/tracing/${'messageTraces'}`;
    expect(maxTopFor(path)).toBe(999);
  });
});

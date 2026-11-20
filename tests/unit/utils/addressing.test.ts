/**
 * Addressing facts: Bcc-to-self, Reply-To mismatches and the reporter's
 * absence from the visible recipients, each with and without the header it
 * needs, from forwarded or retrieved headers.
 */

import {
  ADDRESSING_FACT_TEXT,
  addressingSourceText,
  claimedSenderAddress,
  claimedSenderDomain,
  computeAddressingDetails,
  computeAddressingFacts,
  parseAddressList,
} from '../../../src/utils/addressing';
import { ExtractedEmailData, RetrievedHeader } from '../../../src/types';

const SENDER = '"Lena Vogt" <lena.vogt@vendor.example>';

function email(
  forwarded: Record<string, string>,
  overrides: Partial<ExtractedEmailData> = {}
): ExtractedEmailData {
  return {
    from_email: 'dana@example.com',
    subject: 'FW: RFQ',
    text: '',
    html: '',
    headers: {},
    forwardedHeaders: forwarded,
    attachments: [],
    sender: 'dana@example.com',
    to: 'phishy@example.com',
    original_sender: '',
    originalForwarder: 'dana@example.com',
    links: [],
    ...overrides,
  };
}

function retrieved(headers: RetrievedHeader[], truncated = false): Partial<ExtractedEmailData> {
  return { retrievedOriginal: { location: 'mailbox', headers, headersTruncated: truncated } };
}

describe('parseAddressList', () => {
  it('reads names and addresses, quoted commas and Outlook semicolons', () => {
    expect(parseAddressList('"Doe, Jane" <JANE@x.example>, bob@y.example')).toEqual({
      entries: [{ address: 'jane@x.example', name: 'Doe, Jane' }, { address: 'bob@y.example' }],
      complete: true,
    });
    expect(parseAddressList('Doe, Jane <jane@x.example>; Smith, Bob <bob@y.example>')).toEqual({
      entries: [
        { address: 'jane@x.example', name: 'Doe, Jane' },
        { address: 'bob@y.example', name: 'Smith, Bob' },
      ],
      complete: true,
    });
    expect(
      parseAddressList('Doe, Jane <jane@x.example>, Bob <bob@y.example>')?.entries
    ).toHaveLength(2);
    expect(parseAddressList('Jane Doe [mailto:jane@x.example]')?.entries).toEqual([
      { address: 'jane@x.example', name: 'Jane Doe' },
    ]);
    expect(parseAddressList('Jane &lt;jane@x.example&gt;')?.entries[0].address).toBe(
      'jane@x.example'
    );
  });

  it('marks a list incomplete when an entry has no address or a bound is hit', () => {
    expect(parseAddressList('Jane Doe')?.complete).toBe(false);
    expect(parseAddressList('undisclosed-recipients:;')?.complete).toBe(false);
    expect(parseAddressList(`a@x.example, ${'b'.repeat(9000)}`)?.complete).toBe(false);
    const many = Array.from({ length: 250 }, (_, i) => `u${i}@x.example`).join(', ');
    expect(parseAddressList(many)?.complete).toBe(false);
    expect(parseAddressList(undefined)).toBeUndefined();
    expect(parseAddressList('')).toEqual({ entries: [], complete: true });
  });
});

describe('computeAddressingFacts', () => {
  it('finds the Bcc-to-self blast and the reporter missing from the recipients', () => {
    const facts = computeAddressingFacts(
      email({ 'Original-From': SENDER, 'Original-To': 'Lena Vogt <LENA.VOGT@vendor.example>' })
    );
    expect(facts).toEqual({ source: 'forwarded', facts: ['bcc_to_self', 'reporter_not_visible'] });
  });

  it('does not call it Bcc-to-self when there is another visible recipient', () => {
    const withCc = computeAddressingFacts(
      email({
        'Original-From': SENDER,
        'Original-To': SENDER,
        'Original-Cc': 'Dana <dana@example.com>',
      })
    );
    expect(withCc?.facts).toEqual([]);
    const toOthers = computeAddressingFacts(
      email({ 'Original-From': SENDER, 'Original-To': `${SENDER}, ops@example.com` })
    );
    expect(toOthers?.facts).toEqual(['reporter_not_visible']);
  });

  it('says nothing about recipients without a To header, or with an unreadable one', () => {
    expect(computeAddressingFacts(email({ 'Original-From': SENDER }))?.facts).toEqual([]);
    expect(
      computeAddressingFacts(email({ 'Original-From': SENDER, 'Original-To': 'Lena Vogt' }))?.facts
    ).toEqual([]);
    expect(
      computeAddressingFacts(
        email({ 'Original-From': SENDER, 'Original-To': SENDER, 'Original-Cc': 'Somebody' })
      )?.facts
    ).toEqual([]);
  });

  it('does not report the reporter missing when the reporter is visible or unknown', () => {
    expect(
      computeAddressingFacts(
        email({ 'Original-From': SENDER, 'Original-To': 'Dana <DANA@example.com>' })
      )?.facts
    ).toEqual([]);
    expect(
      computeAddressingFacts(
        email(
          { 'Original-From': SENDER, 'Original-To': 'ops@example.com' },
          { originalForwarder: '' }
        )
      )?.facts
    ).toEqual([]);
  });

  it('separates a Reply-To on another domain, on the same domain, and under another name', () => {
    const other = computeAddressingFacts(
      email({ 'Original-From': SENDER, 'Original-Reply-To': 'Lena Vogt <lena@evil.test>' })
    );
    expect(other?.facts).toEqual(['reply_to_other_domain']);

    const same = computeAddressingFacts(
      email({
        'Original-From': SENDER,
        'Original-Reply-To': '"Marcus Hale" <marcus@vendor.example>',
      })
    );
    expect(same?.facts).toEqual(['reply_to_same_domain', 'reply_to_name_differs']);

    // Same address, another name: only the name fact
    const renamed = computeAddressingFacts(
      email({
        'Original-From': SENDER,
        'Original-Reply-To': 'Marcus Hale <lena.vogt@vendor.example>',
      })
    );
    expect(renamed?.facts).toEqual(['reply_to_name_differs']);
  });

  it('treats the same name in another order or case as the same name', () => {
    const facts = computeAddressingFacts(
      email({
        'Original-From': SENDER,
        'Original-Reply-To': '"VOGT, Lena" <lena.vogt@vendor.example>',
      })
    );
    expect(facts?.facts).toEqual([]);
  });

  it('says nothing about names when either side has none, or with no Reply-To', () => {
    expect(
      computeAddressingFacts(
        email({ 'Original-From': SENDER, 'Original-Reply-To': 'lena.vogt@vendor.example' })
      )?.facts
    ).toEqual([]);
    expect(
      computeAddressingFacts(
        email({
          'Original-From': 'lena.vogt@vendor.example',
          'Original-Reply-To': 'Marcus <lena.vogt@vendor.example>',
        })
      )?.facts
    ).toEqual([]);
    expect(
      computeAddressingFacts(
        email({ 'Original-From': SENDER, 'Original-Reply-To': 'a@x.example, b@y.example' })
      )?.facts
    ).toEqual([]);
  });

  it('returns nothing without a single readable sender', () => {
    expect(computeAddressingFacts(email({}))).toBeUndefined();
    expect(computeAddressingFacts(email({ 'Original-From': 'Lena Vogt' }))).toBeUndefined();
    expect(
      computeAddressingFacts(email({ 'Original-From': 'a@x.example, b@x.example' }))
    ).toBeUndefined();
  });

  it('prefers the retrieved original and labels it as such', () => {
    const facts = computeAddressingFacts(
      email(
        { 'Original-From': SENDER, 'Original-To': 'dana@example.com' },
        retrieved([
          { name: 'Received', value: 'from mx.example.com' },
          { name: 'From', value: SENDER },
          { name: 'to', value: SENDER },
        ])
      )
    );
    expect(facts).toEqual({ source: 'retrieved', facts: ['bcc_to_self', 'reporter_not_visible'] });
  });

  it('does not assume no Cc from a truncated or repeated retrieved header list', () => {
    const headers = [
      { name: 'From', value: SENDER },
      { name: 'To', value: SENDER },
    ];
    expect(computeAddressingFacts(email({}, retrieved(headers, true)))?.facts).toEqual([]);
    expect(
      computeAddressingFacts(
        email(
          {},
          retrieved([
            ...headers,
            { name: 'Cc', value: 'a@x.example' },
            { name: 'CC', value: 'b@x.example' },
          ])
        )
      )?.facts
    ).toEqual([]);
  });

  it('falls back to the forwarded block when the retrieved original has no single From', () => {
    const facts = computeAddressingFacts(
      email(
        { 'Original-From': SENDER, 'Original-To': SENDER },
        retrieved([{ name: 'Subject', value: 'x' }])
      )
    );
    expect(facts?.source).toBe('forwarded');
  });
});

describe('claimed sender and wording', () => {
  it('extracts the claimed sender address and domain', () => {
    expect(claimedSenderAddress(email({ 'Original-From': SENDER }))).toBe(
      'lena.vogt@vendor.example'
    );
    expect(claimedSenderDomain(email({ 'Original-From': SENDER }))).toBe('vendor.example');
    expect(claimedSenderDomain(email({}))).toBeUndefined();
  });

  it('states each fact without quoting any address or name, and names its provenance', () => {
    for (const text of Object.values(ADDRESSING_FACT_TEXT)) {
      expect(text).not.toMatch(/@/);
      expect(text).not.toMatch(/\n/);
    }
    expect(addressingSourceText('forwarded')).toContain('CLAIMED');
    expect(addressingSourceText('retrieved')).toContain('retrieved from the reporter');
  });
});

describe('computeAddressingDetails', () => {
  it('gives the same facts as computeAddressingFacts', () => {
    const data = email({ 'Original-From': SENDER, 'Original-To': SENDER });
    const details = computeAddressingDetails(data);
    expect({ source: details?.source, facts: details?.facts }).toEqual(
      computeAddressingFacts(data)
    );
  });

  it('says whether the visible recipients could be read', () => {
    expect(
      computeAddressingDetails(email({ 'Original-From': SENDER, 'Original-To': 'a@example.com' }))
        ?.recipientsKnown
    ).toBe(true);
    expect(computeAddressingDetails(email({ 'Original-From': SENDER }))?.recipientsKnown).toBe(
      false
    );
  });

  it('treats a missing Reply-To as unknown in a forward, absent in a complete retrieved copy', () => {
    expect(computeAddressingDetails(email({ 'Original-From': SENDER }))?.replyTo).toBe('unknown');
    expect(
      computeAddressingDetails(
        email({ 'Original-From': SENDER, 'Original-Reply-To': 'b@vendor.example' })
      )?.replyTo
    ).toBe('single');
    const headers = [{ name: 'From', value: SENDER }];
    expect(computeAddressingDetails(email({}, retrieved(headers)))?.replyTo).toBe('absent');
    expect(computeAddressingDetails(email({}, retrieved(headers, true)))?.replyTo).toBe('unknown');
    const repeated = [
      { name: 'From', value: SENDER },
      { name: 'Reply-To', value: 'a@vendor.example' },
      { name: 'Reply-To', value: 'b@vendor.example' },
    ];
    expect(computeAddressingDetails(email({}, retrieved(repeated)))?.replyTo).toBe('unknown');
  });
});

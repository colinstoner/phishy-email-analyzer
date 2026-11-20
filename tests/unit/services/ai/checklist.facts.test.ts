/**
 * Checklist scoring v2: the items Phishy answers itself. Each item is tested
 * with its fact present, its fact absent, and its fact unavailable
 * (unknown stays unknown). Invented example.com-style data only.
 */

import {
  authenticationFailed,
  bccToSelf,
  computeCodeChecklistAnswers,
  contentObfuscated,
  contentUninspectable,
  fileShareUnrelatedToSender,
  linkTextMismatch,
  linksMatchSenderDomain,
  replyToDiverts,
  riskyAttachment,
  senderFanoutAnomalous,
} from '../../../../src/services/ai/checklist.facts';
import { CODE_ITEMS } from '../../../../src/services/ai/checklist';
import { EmailParserService } from '../../../../src/services/email/parser.service';
import type { S3Service } from '../../../../src/services/storage/s3.service';
import type { AttachmentInspection } from '../../../../src/services/attachments/types';
import { buildLinkFacts } from '../../../../src/utils/canonicalize';
import {
  EmailAttachment,
  EmailMessage,
  ExtractedEmailData,
  SenderHistoryFacts,
} from '../../../../src/types';

function email(overrides: Partial<ExtractedEmailData> = {}): ExtractedEmailData {
  return {
    from_email: 'reporter@example.com',
    subject: 'Fwd: Quarterly statement',
    text: 'Please see the statement.',
    html: '',
    headers: {},
    forwardedHeaders: {},
    attachments: [],
    sender: 'reporter@example.com',
    to: 'phishy@example.com',
    original_sender: '',
    originalForwarder: 'reporter@example.com',
    links: [],
    linkFacts: [],
    contentFindings: { text: [] },
    ...overrides,
  };
}

/** An email whose links are built by the real link-fact builder */
function withLinks(
  urls: string[],
  overrides: Partial<ExtractedEmailData> = {}
): ExtractedEmailData {
  const linkFacts = buildLinkFacts(urls);
  return email({ links: linkFacts.map(f => f.canonical), linkFacts, ...overrides });
}

function inspection(overrides: Partial<AttachmentInspection> = {}): AttachmentInspection {
  return {
    status: 'inspected',
    realType: 'pdf',
    family: 'document',
    highRisk: false,
    nameFlags: [],
    findings: [],
    links: [],
    linksTotal: 0,
    textChars: 100,
    limitsHit: [],
    durationMs: 1,
    ...overrides,
  } as AttachmentInspection;
}

function attachment(filename: string, analysis?: AttachmentInspection): EmailAttachment {
  return {
    filename,
    contentType: 'application/octet-stream',
    size: 1024,
    ...(analysis ? { analysis } : {}),
  };
}

const FORWARDED = {
  'Original-From': 'Dana Example <dana@vendor.example.net>',
  'Original-To': 'reporter@example.com',
};

describe('link_text_mismatch', () => {
  it('is yes when the parser recorded an anchor trick', () => {
    expect(
      linkTextMismatch(email({ contentFindings: { text: [], anchors: ['displayed_domain'] } }))
    ).toBe('yes');
    expect(
      linkTextMismatch(email({ contentFindings: { text: [], anchors: ['file_name_text'] } }))
    ).toBe('yes');
  });

  it('is no when the HTML body was checked and had none', () => {
    expect(linkTextMismatch(email({ contentFindings: { text: [], anchors: [] } }))).toBe('no');
  });

  it('is unknown without an HTML body, or without parser findings', () => {
    expect(linkTextMismatch(email({ contentFindings: { text: [] } }))).toBe('unknown');
    expect(linkTextMismatch(email({ contentFindings: undefined }))).toBe('unknown');
  });

  it('comes from the parser, the same computation as the CONTENT INTEGRITY flags', () => {
    const parser = new EmailParserService({} as S3Service, ['example.com'], 'bucket');
    const msg = {
      from_email: 'reporter@example.com',
      subject: 'Fwd: sign in',
      text: 'Sign in here',
      html: '<p><a href="https://login.example.org/x">https://portal.example.net/</a></p>',
      headers: {},
      to: 'phishy@example.com',
    } as unknown as EmailMessage;
    const data = parser.extractEmailData(msg);
    expect(data.contentFindings?.anchors).toEqual(['displayed_domain']);
    expect(data.contentFlags?.some(f => f.includes('portal.example.net'))).toBe(true);
    expect(linkTextMismatch(data)).toBe('yes');

    const textOnly = parser.extractEmailData({ ...msg, html: '' } as EmailMessage);
    expect(textOnly.contentFindings).toEqual({ text: [] });
    expect(linkTextMismatch(textOnly)).toBe('unknown');
  });
});

describe('file_share_unrelated_to_sender', () => {
  const PERSONAL =
    'https://othertenant-my.sharepoint.com/personal/sam_othertenant_example_org/Documents/x';
  const OWN = 'https://vendor-my.sharepoint.com/personal/dana_vendor_example_net/Documents/x';
  const TEAM = 'https://someone.sharepoint.com/sites/projects/Shared%20Documents/x';

  it('is yes when a share is owned by another organisation than the claimed sender', () => {
    expect(fileShareUnrelatedToSender(withLinks([PERSONAL], { forwardedHeaders: FORWARDED }))).toBe(
      'yes'
    );
  });

  it("is no without file-share links, or when every share is the sender's own", () => {
    expect(
      fileShareUnrelatedToSender(
        withLinks(['https://www.example.net/'], { forwardedHeaders: FORWARDED })
      )
    ).toBe('no');
    expect(fileShareUnrelatedToSender(withLinks([OWN], { forwardedHeaders: FORWARDED }))).toBe(
      'no'
    );
  });

  it('is unknown when the owner cannot be told, or the claimed sender is unreadable', () => {
    expect(fileShareUnrelatedToSender(withLinks([TEAM], { forwardedHeaders: FORWARDED }))).toBe(
      'unknown'
    );
    expect(fileShareUnrelatedToSender(withLinks([PERSONAL]))).toBe('unknown');
  });

  it('is unknown when there are links but no link facts were computed', () => {
    expect(fileShareUnrelatedToSender(email({ links: [PERSONAL], linkFacts: undefined }))).toBe(
      'unknown'
    );
  });

  it('considers every link, not only the ones the prompt has room for', () => {
    const padding = Array.from({ length: 80 }, (_, i) => `https://pad.example.com/${i}`);
    expect(
      fileShareUnrelatedToSender(withLinks([...padding, PERSONAL], { forwardedHeaders: FORWARDED }))
    ).toBe('yes');
  });
});

describe('risky_attachment', () => {
  it('is no without attachments', () => {
    expect(riskyAttachment(email())).toBe('no');
  });

  it('is yes for a name Windows runs, with or without attachment analysis', () => {
    expect(riskyAttachment(email({ attachments: [attachment('setup.exe')] }))).toBe('yes');
    expect(riskyAttachment(email({ attachments: [attachment('statement.pdf.js')] }))).toBe('yes');
  });

  it('is unknown for an ordinary name when attachment analysis is off', () => {
    expect(riskyAttachment(email({ attachments: [attachment('invoice.pdf')] }))).toBe('unknown');
  });

  it('is yes for a decisive risk signal, a high-risk type, macros or a risky archive entry', () => {
    const credentialForm = inspection({
      realType: 'html',
      family: 'web',
      findings: [
        { kind: 'html_password_fields', count: 1 },
        { kind: 'html_form_posts_to_host', count: 1 },
      ],
    });
    expect(riskyAttachment(email({ attachments: [attachment('view.html', credentialForm)] }))).toBe(
      'yes'
    );
    expect(
      riskyAttachment(
        email({ attachments: [attachment('file.bin', inspection({ highRisk: true }))] })
      )
    ).toBe('yes');
    expect(
      riskyAttachment(
        email({
          attachments: [
            attachment(
              'report.docx',
              inspection({ findings: [{ kind: 'ooxml_macros', count: 1 }] })
            ),
          ],
        })
      )
    ).toBe('yes');
    const archive = inspection({
      realType: 'zip',
      family: 'archive',
      children: [
        { claimedName: 'inner.bin', size: 10, inspection: inspection({ highRisk: true }) },
      ],
    });
    expect(riskyAttachment(email({ attachments: [attachment('files.zip', archive)] }))).toBe('yes');
  });

  it('is no when every attachment was fully inspected with none of those', () => {
    expect(riskyAttachment(email({ attachments: [attachment('invoice.pdf', inspection())] }))).toBe(
      'no'
    );
  });

  it('is unknown when an inspection was only partial', () => {
    expect(
      riskyAttachment(
        email({
          attachments: [
            attachment('invoice.pdf', inspection({ status: 'partial', reason: 'timeout' })),
          ],
        })
      )
    ).toBe('unknown');
  });
});

describe('authentication_failed', () => {
  function retrieved(headers: Array<{ name: string; value: string }>): Partial<ExtractedEmailData> {
    return { retrievedOriginal: { location: 'mailbox', headers, headersTruncated: false } };
  }

  it('is unknown without a retrieved original (the lookup is off or found nothing)', () => {
    expect(authenticationFailed(email())).toBe('unknown');
  });

  it('never reads forwarded (claimed) headers', () => {
    expect(
      authenticationFailed(
        email({
          forwardedHeaders: {
            ...FORWARDED,
            'Authentication-Results': 'mx.example.com; dmarc=fail',
          },
        })
      )
    ).toBe('unknown');
  });

  it('reads the topmost Authentication-Results of the retrieved copy', () => {
    expect(
      authenticationFailed(
        email(
          retrieved([
            {
              name: 'Authentication-Results',
              value: 'mx.example.com; spf=pass; dkim=pass; dmarc=fail action=quarantine',
            },
            { name: 'Authentication-Results', value: 'forged.example.net; dmarc=pass' },
          ])
        )
      )
    ).toBe('fail');
    expect(
      authenticationFailed(
        email(
          retrieved([
            { name: 'Received', value: 'from relay.example.net' },
            {
              name: 'Authentication-Results',
              value: 'mx.example.com; spf=pass; dkim=pass; dmarc=pass',
            },
            { name: 'Authentication-Results', value: 'forged.example.net; dmarc=fail' },
          ])
        )
      )
    ).toBe('pass');
  });

  it('is unknown when the retrieved copy has no such header or no verdict in it', () => {
    expect(authenticationFailed(email(retrieved([{ name: 'From', value: 'a@example.net' }])))).toBe(
      'unknown'
    );
    expect(
      authenticationFailed(
        email(retrieved([{ name: 'Authentication-Results', value: 'mx.example.com; dmarc=none' }]))
      )
    ).toBe('unknown');
  });
});

describe('reply_to_diverts', () => {
  it('is yes for a Reply-To on another domain, or naming another person', () => {
    expect(
      replyToDiverts(
        email({ forwardedHeaders: { ...FORWARDED, 'Original-Reply-To': 'pay@other.example.org' } })
      )
    ).toBe('yes');
    expect(
      replyToDiverts(
        email({
          forwardedHeaders: {
            ...FORWARDED,
            'Original-Reply-To': 'Lee Other <lee@vendor.example.net>',
          },
        })
      )
    ).toBe('yes');
  });

  it('is no for a readable Reply-To that does neither', () => {
    expect(
      replyToDiverts(
        email({
          forwardedHeaders: {
            ...FORWARDED,
            'Original-Reply-To': 'Dana Example <dana@vendor.example.net>',
          },
        })
      )
    ).toBe('no');
    // Another mailbox on the same domain is not counted as a diversion
    expect(
      replyToDiverts(
        email({
          forwardedHeaders: { ...FORWARDED, 'Original-Reply-To': 'billing@vendor.example.net' },
        })
      )
    ).toBe('no');
  });

  it('is unknown when a forwarded block has no Reply-To line (clients usually omit it)', () => {
    expect(replyToDiverts(email({ forwardedHeaders: FORWARDED }))).toBe('unknown');
    expect(replyToDiverts(email())).toBe('unknown');
  });

  it('is no when a complete retrieved header list certainly has no Reply-To', () => {
    const headers = [
      { name: 'From', value: 'dana@vendor.example.net' },
      { name: 'To', value: 'reporter@example.com' },
    ];
    expect(
      replyToDiverts(
        email({ retrievedOriginal: { location: 'mailbox', headers, headersTruncated: false } })
      )
    ).toBe('no');
    expect(
      replyToDiverts(
        email({ retrievedOriginal: { location: 'mailbox', headers, headersTruncated: true } })
      )
    ).toBe('unknown');
  });
});

describe('content_obfuscated', () => {
  it('is yes for invisible characters or bidirectional controls', () => {
    expect(contentObfuscated(email({ contentFindings: { text: ['invisible_characters'] } }))).toBe(
      'yes'
    );
    expect(contentObfuscated(email({ contentFindings: { text: ['bidi_controls'] } }))).toBe('yes');
  });

  it('is no for nothing, or only compatibility normalization and entities (ordinary mail)', () => {
    expect(contentObfuscated(email({ contentFindings: { text: [] } }))).toBe('no');
    expect(
      contentObfuscated(
        email({ contentFindings: { text: ['compatibility_normalized', 'numeric_entities'] } })
      )
    ).toBe('no');
  });

  it('is unknown without parser findings', () => {
    expect(contentObfuscated(email({ contentFindings: undefined }))).toBe('unknown');
  });
});

describe('sender_fanout_anomalous', () => {
  const history = (classification: SenderHistoryFacts['classification']): SenderHistoryFacts =>
    ({ classification }) as SenderHistoryFacts;

  it('follows the sender-relationship class', () => {
    expect(
      senderFanoutAnomalous(email({ senderHistory: history('established_with_anomalous_fanout') }))
    ).toBe('yes');
    expect(senderFanoutAnomalous(email({ senderHistory: history('established') }))).toBe('no');
    expect(senderFanoutAnomalous(email({ senderHistory: history('no_history') }))).toBe('no');
  });

  it('is unknown when the check is off, skipped or failed', () => {
    expect(senderFanoutAnomalous(email())).toBe('unknown');
  });
});

describe('bcc_to_self', () => {
  it('is yes when the original went To the sender only', () => {
    expect(
      bccToSelf(
        email({
          forwardedHeaders: {
            'Original-From': 'dana@vendor.example.net',
            'Original-To': 'dana@vendor.example.net',
          },
        })
      )
    ).toBe('yes');
  });

  it('is no when the visible recipients were readable and are otherwise', () => {
    expect(bccToSelf(email({ forwardedHeaders: FORWARDED }))).toBe('no');
  });

  it('is unknown when they were not readable', () => {
    expect(
      bccToSelf(email({ forwardedHeaders: { 'Original-From': 'dana@vendor.example.net' } }))
    ).toBe('unknown');
    expect(bccToSelf(email())).toBe('unknown');
  });
});

describe('content_uninspectable', () => {
  it('is yes for a link whose destination a wrapper still hides', () => {
    const opaque = 'https://us.content.mimecastprotect.com/s/abcdEFGHijk?domain=example.net';
    const data = withLinks([opaque]);
    expect(data.linkFacts?.[0].flags.join(' ')).toContain('cannot be recovered');
    expect(contentUninspectable(data)).toBe('yes');
  });

  it('is yes for an encrypted attachment or archive entry', () => {
    const locked = inspection({
      realType: 'zip',
      family: 'archive',
      findings: [{ kind: 'archive_encrypted_entries', count: 1 }],
    });
    expect(contentUninspectable(email({ attachments: [attachment('files.zip', locked)] }))).toBe(
      'yes'
    );
  });

  it('is no with visible destinations and every attachment analyzed (or none)', () => {
    expect(contentUninspectable(withLinks(['https://www.example.net/']))).toBe('no');
    expect(contentUninspectable(email({ attachments: [attachment('a.pdf', inspection())] }))).toBe(
      'no'
    );
  });

  it('is unknown when an attachment was not analyzed', () => {
    expect(contentUninspectable(email({ attachments: [attachment('a.pdf')] }))).toBe('unknown');
  });
});

describe('links_match_sender_domain', () => {
  it("is yes only when every link goes to the claimed sender's own domain", () => {
    expect(
      linksMatchSenderDomain(
        withLinks(['https://www.vendor.example.net/a', 'https://vendor.example.net/b'], {
          forwardedHeaders: FORWARDED,
        })
      )
    ).toBe('yes');
    expect(
      linksMatchSenderDomain(
        withLinks(['https://vendor.example.net/a', 'https://login.example.org/'], {
          forwardedHeaders: FORWARDED,
        })
      )
    ).toBe('no');
  });

  it('is no without links (a mitigation must be observed)', () => {
    expect(linksMatchSenderDomain(email({ forwardedHeaders: FORWARDED }))).toBe('no');
  });

  it('is unknown without a readable claimed sender', () => {
    expect(linksMatchSenderDomain(withLinks(['https://vendor.example.net/a']))).toBe('unknown');
  });
});

describe('computeCodeChecklistAnswers', () => {
  it('answers exactly the code items, each with one of its values', () => {
    const answers = computeCodeChecklistAnswers(email()) as Record<string, string>;
    expect(Object.keys(answers).sort()).toEqual(CODE_ITEMS.map(i => i.id).sort());
    for (const item of CODE_ITEMS) {
      expect(item.answers as readonly string[]).toContain(answers[item.id]);
    }
  });

  it('answers unknown, never no, for every fact an optional feature supplies when it is off', () => {
    const answers = computeCodeChecklistAnswers(
      email({ attachments: [attachment('invoice.pdf')], forwardedHeaders: FORWARDED })
    );
    expect(answers).toMatchObject({
      authentication_failed: 'unknown',
      sender_fanout_anomalous: 'unknown',
      risky_attachment: 'unknown',
      content_uninspectable: 'unknown',
    });
  });

  it('is deterministic', () => {
    const data = withLinks(
      ['https://othertenant-my.sharepoint.com/personal/sam_othertenant_example_org/x'],
      {
        forwardedHeaders: { ...FORWARDED, 'Original-Reply-To': 'pay@other.example.org' },
      }
    );
    expect(computeCodeChecklistAnswers(structuredClone(data))).toEqual(
      computeCodeChecklistAnswers(data)
    );
  });
});

/**
 * Checklist scoring and the prompt. With the scoring flag at its default the
 * prompt must be byte-for-byte what it was before checklist scoring existed;
 * in checklist mode the checklist sits in the instruction part, before every
 * CLAIMED fence.
 */

import { createHash } from 'crypto';
import { buildPhishingAnalysisPrompt } from '../../../../src/services/ai/prompt.builder';
import { CHECKLIST_INSTRUCTIONS, CHECKLIST_ITEMS } from '../../../../src/services/ai/checklist';
import { checkOutsideStructure, splitAtFence } from '../../../../src/eval/injection/prepare';
import { ExtractedEmailData } from '../../../../src/types';
import { EnterpriseProfile } from '../../../../src/models/profile.model';

const NONCE = /-[0-9a-f]{12}\b/g;

/** The prompt with its per-request nonce replaced, so two builds compare equal */
function stable(prompt: string): string {
  return prompt.replace(NONCE, '-NONCE');
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

const emailData = (): ExtractedEmailData => ({
  from_email: 'reporter@example.com',
  subject: 'Fwd: Invoice 4471 ready for review',
  text: 'Please review the attached invoice and sign in to approve it today.\nThanks, Accounts',
  html: '',
  headers: {},
  forwardedHeaders: {
    From: 'Accounts <billing@vendor.example.net>',
    To: 'reporter@example.com',
    'Reply-To': 'payments@other.example.org',
    Date: 'Mon, 2 Nov 2026 09:14:00 +0000',
  },
  attachments: [
    {
      filename: 'invoice.pdf.html',
      contentType: 'text/html',
      size: 2048,
      sha256: 'a'.repeat(64),
    },
  ],
  sender: 'reporter@example.com',
  to: 'phishy@example.com',
  original_sender: 'billing@vendor.example.net',
  originalForwarder: 'reporter@example.com',
  links: ['https://login.example.org/approve'],
  linkFacts: [
    {
      raw: 'https://safelinks.example.com/?url=https%3A%2F%2Flogin.example.org%2Fapprove',
      canonical: 'https://login.example.org/approve',
      flags: ['unwrapped from a link-protection wrapper'],
    },
  ],
  contentFlags: ['2 zero-width characters removed from the body'],
});

const headers = (): Record<string, string> => ({
  From: 'Reporter <reporter@example.com>',
  'Message-ID': '<report-1@example.com>',
});

const profile = (): EnterpriseProfile => ({
  name: 'Example Org',
  organization: {
    name: 'Example Organization',
    domains: ['example.com'],
    aliases: ['Example'],
  },
  trustedPartners: [
    { name: 'Vendor Example', domains: ['vendor.example.net'], relationship: 'vendor' },
  ],
});

describe('buildPhishingAnalysisPrompt: scoring mode', () => {
  // Recorded from the prompt builder before checklist scoring was added. A
  // change here means the default (model) scoring prompt changed.
  const DEFAULT_PROMPT_SHA256 = {
    noProfile: '93ddb269b9386d23486b02b70f641109ee50becb8ba4aaf61e92f1ded7f81272',
    withProfile: '1c0c95533450b758d7906dc78a84191b1879e0df1dd46a40fa7bd88a11625f40',
  };

  it('is unchanged with the flag at its default', () => {
    expect(sha256(stable(buildPhishingAnalysisPrompt(emailData(), headers())))).toBe(
      DEFAULT_PROMPT_SHA256.noProfile
    );
    expect(sha256(stable(buildPhishingAnalysisPrompt(emailData(), headers(), profile())))).toBe(
      DEFAULT_PROMPT_SHA256.withProfile
    );
  });

  it('is unchanged with scoringMode set to model explicitly', () => {
    expect(
      sha256(
        stable(
          buildPhishingAnalysisPrompt(emailData(), headers(), undefined, { scoringMode: 'model' })
        )
      )
    ).toBe(DEFAULT_PROMPT_SHA256.noProfile);
    expect(
      sha256(
        stable(
          buildPhishingAnalysisPrompt(emailData(), headers(), profile(), { scoringMode: 'model' })
        )
      )
    ).toBe(DEFAULT_PROMPT_SHA256.withProfile);
    expect(buildPhishingAnalysisPrompt(emailData(), headers())).not.toContain('SCORING CHECKLIST');
  });

  describe('in checklist mode', () => {
    const build = (): string =>
      buildPhishingAnalysisPrompt(emailData(), headers(), profile(), { scoringMode: 'checklist' });

    it('adds exactly the checklist instructions and nothing else', () => {
      const withChecklist = stable(build());
      const without = stable(buildPhishingAnalysisPrompt(emailData(), headers(), profile()));
      expect(withChecklist.replace(`${CHECKLIST_INSTRUCTIONS}\n\n`, '')).toBe(without);
      for (const item of CHECKLIST_ITEMS) {
        expect(withChecklist).toContain(`- ${item.id} (`);
      }
    });

    it('places the checklist in the instruction part, before every CLAIMED section', () => {
      const prompt = build();
      const at = prompt.indexOf('SCORING CHECKLIST');
      expect(at).toBeGreaterThan(0);
      expect(at).toBeLessThan(prompt.indexOf('=== VERIFIED (computed by Phishy) ==='));
      expect(at).toBeLessThan(prompt.indexOf('=== CLAIMED'));
      expect(at).toBeLessThan(prompt.indexOf('<claimed-fields-'));
      expect(prompt.indexOf('SCORING CHECKLIST', at + 1)).toBe(-1);
    });

    it('keeps the fences intact and adds no structural line', () => {
      const split = splitAtFence(build());
      expect(split).toBeDefined();
      expect(split?.inside).not.toContain('SCORING CHECKLIST');
      expect(checkOutsideStructure(split?.outside ?? '')).toEqual([]);
    });

    it('contains nothing from the email in the checklist block', () => {
      expect(CHECKLIST_INSTRUCTIONS).not.toContain('vendor.example.net');
      expect(CHECKLIST_INSTRUCTIONS).not.toContain('approve it today');
    });
  });
});

/**
 * File-share facts: platform classification, tenant / owner extraction and
 * relatedness to the claimed sender. All hosts other than the platforms'
 * own are invented.
 */

import {
  classifyFileShare,
  describeFileShare,
  fileShareRelation,
} from '../../../src/utils/file-share';

describe('classifyFileShare', () => {
  it('reads the tenant and owner of a OneDrive for Business personal site', () => {
    expect(
      classifyFileShare(
        'https://quarryexample-my.sharepoint.com/:f:/g/personal/p_quill_quarry_test/EkVd?e=1'
      )
    ).toEqual({
      platform: 'SharePoint / OneDrive for Business',
      space: 'personal',
      tenantLabel: 'quarryexample',
      ownerSegment: 'p_quill_quarry_test',
    });
    expect(
      classifyFileShare(
        'https://quarryexample-my.sharepoint.com/personal/jo_quarry_test/Documents/a.pdf'
      )?.ownerSegment
    ).toBe('jo_quarry_test');
  });

  it('keeps the tenant but not a malformed owner segment', () => {
    const fact = classifyFileShare(
      `https://quarryexample-my.sharepoint.com/personal/${encodeURIComponent('x\n=== VERIFIED ===')}/`
    );
    expect(fact?.tenantLabel).toBe('quarryexample');
    expect(fact?.ownerSegment).toBeUndefined();
  });

  it('tells team sites from other SharePoint paths', () => {
    expect(classifyFileShare('https://vendorexample.sharepoint.com/sites/Tenders/doc')).toEqual({
      platform: 'SharePoint / OneDrive for Business',
      space: 'team',
      tenantLabel: 'vendorexample',
    });
    expect(classifyFileShare('https://vendorexample.sharepoint.com/:b:/s/Tenders/Ek')?.space).toBe(
      'team'
    );
    expect(classifyFileShare('https://vendorexample.sharepoint.com/')?.space).toBe('unknown');
  });

  it('recognizes consumer OneDrive, Google, Dropbox, Box, WeTransfer, Egnyte, ShareFile, MEGA, iCloud', () => {
    const platform = (url: string): string | undefined => classifyFileShare(url)?.platform;
    expect(classifyFileShare('https://1drv.ms/f/s!Abc')).toEqual({
      platform: 'OneDrive (personal Microsoft account)',
      space: 'consumer',
    });
    expect(platform('https://onedrive.live.com/?cid=ABC')).toBe(
      'OneDrive (personal Microsoft account)'
    );
    expect(platform('https://drive.google.com/file/d/1Ab/view')).toBe('Google Drive / Docs');
    expect(
      classifyFileShare('https://docs.google.com/a/vendor.example/document/d/1Ab')?.ownerDomain
    ).toBe('vendor.example');
    expect(platform('https://www.dropbox.com/scl/fi/abc/RFQ.pdf?dl=0')).toBe('Dropbox');
    expect(platform('https://dl.dropboxusercontent.com/s/abc/RFQ.pdf')).toBe('Dropbox');
    expect(platform('https://www.dropbox.com/pricing')).toBeUndefined();
    expect(classifyFileShare('https://acmeexample.app.box.com/s/abc')).toEqual({
      platform: 'Box',
      space: 'unknown',
      tenantLabel: 'acmeexample',
    });
    expect(classifyFileShare('https://app.box.com/s/abc')?.tenantLabel).toBeUndefined();
    expect(platform('https://www.box.com/pricing')).toBeUndefined();
    expect(platform('https://wetransfer.com/downloads/abc')).toBe('WeTransfer');
    expect(platform('https://we.tl/t-abc')).toBe('WeTransfer');
    expect(classifyFileShare('https://acmeexample.egnyte.com/fl/abc')?.tenantLabel).toBe(
      'acmeexample'
    );
    expect(platform('https://acmeexample.sharefile.com/d-abc')).toBe('ShareFile');
    expect(platform('https://mega.nz/file/abc')).toBe('MEGA');
    expect(platform('https://www.icloud.com/iclouddrive/abc')).toBe('iCloud Drive');
  });

  it('returns null for ordinary sites, look-alikes and non-web URLs', () => {
    for (const url of [
      'https://vendor.example/rfq.pdf',
      'https://sharepoint.com.evil.test/personal/x/',
      'https://evil-sharepoint.test/personal/x',
      'mailto:a@example.com',
      'not a url',
    ]) {
      expect(classifyFileShare(url)).toBeNull();
    }
  });
});

describe('fileShareRelation', () => {
  const personal = (tenant: string, owner: string) => ({
    platform: 'SharePoint / OneDrive for Business',
    space: 'personal' as const,
    tenantLabel: tenant,
    ownerSegment: owner,
  });

  it("is related when the owner's sign-in domain is the sender's domain", () => {
    expect(
      fileShareRelation(
        personal('hlexample', 'lena_vogt_harbourline-supply_example'),
        'harbourline-supply.example'
      )
    ).toBe('related');
    expect(
      fileShareRelation(
        personal('hlexample', 'lena_vogt_harbourline-supply_example'),
        'mail.harbourline-supply.example'
      )
    ).toBe('related');
  });

  it('is related when the tenant label matches the sender domain label', () => {
    expect(fileShareRelation(personal('harbourline', 'x_other_test'), 'harbourline.example')).toBe(
      'related'
    );
    expect(
      fileShareRelation(personal('vendor', 'lena_vendor_onmicrosoft_com'), 'vendor.example')
    ).toBe('related');
  });

  it('is unrelated when the URL names an owner and neither owner nor tenant matches', () => {
    expect(
      fileShareRelation(
        personal('quarryexample', 'p_quill_quarry_test'),
        'harbourline-supply.example'
      )
    ).toBe('unrelated');
    expect(
      fileShareRelation(
        { platform: 'Google Drive / Docs', space: 'unknown', ownerDomain: 'quarry.test' },
        'vendor.example'
      )
    ).toBe('unrelated');
  });

  it('is unknown when nothing in the URL names an owner, or the sender is unknown', () => {
    const team = {
      platform: 'SharePoint / OneDrive for Business',
      space: 'team' as const,
      tenantLabel: 'contosogroup',
    };
    expect(fileShareRelation(team, 'vendor.example')).toBe('unknown');
    expect(fileShareRelation({ platform: 'Dropbox', space: 'unknown' }, 'vendor.example')).toBe(
      'unknown'
    );
    expect(fileShareRelation(personal('quarryexample', 'r_quarry_test'), undefined)).toBe(
      'unknown'
    );
    expect(fileShareRelation(personal('quarryexample', 'r_quarry_test'), 'not a domain')).toBe(
      'unknown'
    );
  });
});

describe('describeFileShare', () => {
  it('states what the share is and how it relates, without the sender domain', () => {
    const [what, relation] = describeFileShare(
      {
        platform: 'SharePoint / OneDrive for Business',
        space: 'personal',
        tenantLabel: 'quarryexample',
        ownerSegment: 'p_quill_quarry_test',
      },
      'harbourline-supply.example'
    );
    expect(what).toBe(
      `File share on SharePoint / OneDrive for Business, a person's own site, tenant "quarryexample", owner "p_quill_quarry_test" (from the URL)`
    );
    expect(relation).toContain('does not appear to belong to the claimed sender');
    expect(`${what} ${relation}`).not.toContain('harbourline');
  });

  it('says unknown rather than unrelated, and never calls a related share safe', () => {
    expect(describeFileShare({ platform: 'Dropbox', space: 'unknown' }, 'vendor.example')[1]).toBe(
      'Whether this share belongs to the claimed sender cannot be told from the URL'
    );
    const consumer = describeFileShare(
      { platform: 'OneDrive (personal Microsoft account)', space: 'consumer' },
      'vendor.example'
    );
    expect(consumer[0]).toContain("not an organization's tenant");
    const related = describeFileShare(
      { platform: 'Box', space: 'unknown', tenantLabel: 'vendor' },
      'vendor.example'
    )[1];
    expect(related).toContain('not proof the sender or file is safe');
    expect(
      describeFileShare(
        { platform: 'SharePoint / OneDrive for Business', space: 'team', tenantLabel: 'vendor' },
        'vendor.example'
      )[0]
    ).toContain('a team or organization site');
  });
});

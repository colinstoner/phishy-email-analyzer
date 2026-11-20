import { registrableOf } from '../../../src/utils/registrable';
import { classifyFileShare, fileShareRelation } from '../../../src/utils/file-share';
import { extractFollowableUrls } from '../../../src/utils/validation';

describe('registrableOf', () => {
  it('uses the last two labels for ordinary domains', () => {
    expect(registrableOf('mail.supplier.example.com')).toBe('example.com');
    expect(registrableOf('Example.TEST')).toBe('example.test');
  });

  it('uses three labels under two-level country suffixes', () => {
    expect(registrableOf('mail.supplier-example.co.uk')).toBe('supplier-example.co.uk');
    expect(registrableOf('supplier-example.com.au')).toBe('supplier-example.com.au');
  });

  it('leaves a bare two-level suffix alone', () => {
    expect(registrableOf('co.uk')).toBe('co.uk');
  });
});

describe('file-share relation under a two-level suffix', () => {
  it('does not call another .co.uk organization related', () => {
    const share = classifyFileShare(
      'https://otherexample-my.sharepoint.com/:f:/g/personal/p_quill_otherexample_co_uk/Ab12'
    );
    expect(share).not.toBeNull();
    expect(fileShareRelation(share!, 'supplier-example.co.uk')).toBe('unrelated');
  });

  it('still calls the same .co.uk organization related', () => {
    const share = classifyFileShare(
      'https://tenantexample-my.sharepoint.com/:f:/g/personal/p_quill_supplier-example_co_uk/Ab12'
    );
    expect(fileShareRelation(share!, 'mail.supplier-example.co.uk')).toBe('related');
  });
});

describe('extractFollowableUrls href coverage', () => {
  it('takes the href of an Outlook VML button', () => {
    const html =
      '<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="https://login.example.net/x" style="height:40px"><center>Open</center></v:roundrect>';
    expect(extractFollowableUrls(html)).toEqual(['https://login.example.net/x']);
  });

  it('does not take a stylesheet link or a base element', () => {
    const html =
      '<link rel="stylesheet" href="https://cdn.example.org/a.css"><base href="https://base.example.org/"><p>hello</p>';
    expect(extractFollowableUrls(html)).toEqual([]);
  });
});

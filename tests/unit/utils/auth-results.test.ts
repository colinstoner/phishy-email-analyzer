/**
 * The receiving mail system's authentication verdict from a retrieved
 * original's topmost Authentication-Results header
 */

import {
  authenticationVerdictOf,
  retrievedAuthenticationVerdict,
} from '../../../src/utils/auth-results';

describe('authenticationVerdictOf', () => {
  it.each([
    [
      'mx.example.com; spf=pass smtp.mailfrom=example.net; dkim=pass; dmarc=fail action=none',
      'fail',
    ],
    [
      'mx.example.com; spf=pass; dkim=pass; dmarc=pass action=none; compauth=fail reason=601',
      'fail',
    ],
    ['mx.example.com; spf=fail smtp.mailfrom=example.net; dkim=none', 'fail'],
    ['mx.example.com; spf=fail; dkim=none; dkim=pass header.d=example.net', 'unknown'],
    ['mx.example.com; spf=pass; dkim=pass; dmarc=pass action=none', 'pass'],
    ['mx.example.com; spf=softfail; dkim=none; dmarc=none', 'unknown'],
    ['mx.example.com; none', 'unknown'],
    ['', 'unknown'],
  ])('%s -> %s', (value, expected) => {
    expect(authenticationVerdictOf(value)).toBe(expected);
  });

  it('does not read a method name inside another token', () => {
    expect(authenticationVerdictOf('mx.example.com; header.xdmarc=fail; spf=pass')).toBe('unknown');
  });

  it('reads only a bounded prefix of a padded header', () => {
    expect(authenticationVerdictOf(`mx.example.com; ${'x'.repeat(5000)} dmarc=fail`)).toBe(
      'unknown'
    );
  });
});

describe('retrievedAuthenticationVerdict', () => {
  it('uses only the topmost Authentication-Results', () => {
    expect(
      retrievedAuthenticationVerdict({
        location: 'mailbox',
        headersTruncated: false,
        headers: [
          { name: 'Received', value: 'from relay.example.net' },
          { name: 'authentication-results', value: 'mx.example.com; dmarc=pass' },
          { name: 'Authentication-Results', value: 'forged.example.net; dmarc=fail' },
        ],
      })
    ).toBe('pass');
  });

  it('is unknown without a retrieved original or without the header', () => {
    expect(retrievedAuthenticationVerdict(undefined)).toBe('unknown');
    expect(
      retrievedAuthenticationVerdict({ location: 'mailbox', headersTruncated: false, headers: [] })
    ).toBe('unknown');
  });
});

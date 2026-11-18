/**
 * Retrieved-header selection: adversarial bounding and disclosed elisions.
 * Invented data only.
 */

import { selectRetrievedHeaders } from '../../../../src/services/ai/retrieved.headers';
import { RetrievedHeader } from '../../../../src/types';

const header = (name: string, value: string): RetrievedHeader => ({ name, value });

describe('selectRetrievedHeaders', () => {
  it('shows security-relevant headers in stored order with their positions', () => {
    const result = selectRetrievedHeaders([
      header('Received', 'from mx.example.com by mailbox.example.com'),
      header('authentication-results', 'spf=fail smtp.mailfrom=example.org'),
      header('X-Custom-Tracking', 'abc'),
      header('From', 'Billing <billing@example.org>'),
      header('REPLY-TO', 'collector@example.net'),
    ]);

    expect(result.lines).toEqual([
      '[1] Received: from mx.example.com by mailbox.example.com',
      '[2] Authentication-Results: spf=fail smtp.mailfrom=example.org',
      '[4] From: Billing <billing@example.org>',
      '[5] Reply-To: collector@example.net',
    ]);
    expect(result.total).toBe(5);
    expect(result.elisions).toEqual([
      '1 other original header not shown (names outside the security-relevant set)',
    ]);
  });

  it('reports nothing elided when everything fits', () => {
    const result = selectRetrievedHeaders([header('From', 'a@example.org')]);
    expect(result.elisions).toEqual([]);
  });

  it('keeps both ends of a padded Received chain', () => {
    const chain = Array.from({ length: 300 }, (_, i) => header('Received', `hop-${i + 1}`));
    const result = selectRetrievedHeaders([...chain, header('From', 'a@example.org')]);

    const hops = result.lines.filter(line => line.includes('Received:'));
    expect(hops).toHaveLength(10);
    expect(hops[0]).toBe('[1] Received: hop-1');
    expect(hops[5]).toBe('[6] Received: hop-6');
    expect(hops[6]).toBe('[297] Received: hop-297');
    expect(hops[9]).toBe('[300] Received: hop-300');
    expect(result.lines).toContain('[301] From: a@example.org');
    expect(result.elisions).toContain(
      '290 of 300 original Received headers omitted (first 6 and last 4 kept)'
    );
  });

  it('does not let look-alike authentication results displace the topmost one', () => {
    const forged = Array.from({ length: 50 }, () =>
      header('Authentication-Results', 'spf=pass dkim=pass dmarc=pass (forged)')
    );
    const result = selectRetrievedHeaders([
      header('Authentication-Results', 'spf=fail (stamped on delivery)'),
      ...forged,
    ]);

    expect(result.lines[0]).toBe('[1] Authentication-Results: spf=fail (stamped on delivery)');
    expect(result.lines).toHaveLength(4);
    expect(result.elisions).toContain(
      '47 of 51 original Authentication-Results headers omitted (first 3 and last 1 kept)'
    );
  });

  it('cannot be crowded out by unlisted or repeated headers', () => {
    const padding = Array.from({ length: 400 }, (_, i) => header(`X-Pad-${i}`, 'x'.repeat(5000)));
    const result = selectRetrievedHeaders([
      ...padding,
      header('Reply-To', 'collector@example.net'),
    ]);

    expect(result.lines).toEqual(['[401] Reply-To: collector@example.net']);
    expect(result.elisions).toEqual([
      '400 other original headers not shown (names outside the security-relevant set)',
    ]);
  });

  it('keeps the head and tail of an over-long value and discloses it', () => {
    const value = `HEAD-MARK ${'p'.repeat(5000)} TAIL-MARK`;
    const result = selectRetrievedHeaders([header('Authentication-Results', value)]);

    expect(result.lines[0]).toContain('HEAD-MARK');
    expect(result.lines[0]).toContain('TAIL-MARK');
    expect(result.lines[0]).toMatch(/\[\.\.\. \d+ characters elided \.\.\.\]/);
    expect(result.lines[0].length).toBeLessThan(700);
    expect(result.elisions).toEqual([
      '1 original header value shortened (first 420 and last 150 characters kept)',
    ]);
  });

  it('spends the overall budget on the highest-priority headers first', () => {
    const big = 'v'.repeat(5000);
    const names = [
      'Authentication-Results',
      'ARC-Authentication-Results',
      'Received-SPF',
      'X-MS-Exchange-Organization-AuthAs',
      'X-MS-Exchange-Organization-SCL',
      'X-Forefront-Antispam-Report',
      'From',
      'Sender',
      'Reply-To',
      'Return-Path',
      'Message-ID',
      'Date',
      'Subject',
      'To',
      'In-Reply-To',
      'Received',
      'X-Originating-IP',
      'X-Mailer',
      'User-Agent',
      'X-Sender',
      'List-Unsubscribe',
      'DKIM-Signature',
    ];
    // Every shown header at its quota with a maximal value; the lowest
    // priority ones come first in the message
    const headers = [...names]
      .reverse()
      .flatMap(name => Array.from({ length: 12 }, () => header(name, big)));
    const result = selectRetrievedHeaders(headers);

    const total = result.lines.reduce((sum, line) => sum + line.length, 0);
    expect(total).toBeLessThanOrEqual(24000);
    expect(result.lines.filter(line => line.includes('] Authentication-Results:'))).toHaveLength(4);
    expect(result.lines.filter(line => line.includes('] From:'))).toHaveLength(2);
    expect(result.lines.filter(line => line.includes('] DKIM-Signature:'))).toHaveLength(0);
    expect(result.elisions.some(e => e.includes('overall header budget reached'))).toBe(true);
    // Stored order is preserved in what is shown
    const positions = result.lines.map(line => Number(/^\[(\d+)\]/.exec(line)?.[1]));
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it('discloses a header list that was cut off when read', () => {
    const result = selectRetrievedHeaders([header('From', 'a@example.org')], true);
    expect(result.elisions).toEqual([
      'The stored message had more headers than Phishy reads; only the first 1 were considered',
    ]);
  });
});

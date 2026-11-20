/**
 * Registrable domain of a host name, without a public-suffix list.
 *
 * The last two labels, except under the common two-level country suffixes
 * (`co.uk`, `com.au`, `co.nz` ...), where it is the last three: otherwise
 * every `*.co.uk` organization would compare as the same domain, and a
 * "same domain" or "matches the sender" fact would be wrong in the
 * reassuring direction. The suffix test is a fixed shape (a two-letter
 * country code under a generic second-level label), not a full list, so an
 * unusual suffix still falls back to two labels.
 *
 * Pure string work; the input is hostile text and is only compared.
 */

const SECOND_LEVEL_LABELS = new Set([
  'co',
  'com',
  'org',
  'net',
  'gov',
  'edu',
  'ac',
  'or',
  'ne',
  'go',
  'gob',
  'mil',
  'sch',
  'ltd',
  'plc',
]);

export function registrableOf(host: string): string {
  const labels = host.toLowerCase().split('.').filter(Boolean);
  const twoLevelSuffix =
    labels.length >= 3 &&
    /^[a-z]{2}$/.test(labels[labels.length - 1]) &&
    SECOND_LEVEL_LABELS.has(labels[labels.length - 2]);
  return labels.slice(twoLevelSuffix ? -3 : -2).join('.');
}

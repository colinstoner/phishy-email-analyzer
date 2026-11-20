/**
 * Showing hostile text to people.
 *
 * The subject, the claimed sender and the model's summary of a suspicious
 * email all come from the attacker. Campaign-response emails show them so
 * that people recognize the message, and must not hand the attacker a link
 * in Phishy's own name. Every such value goes through `displayText` before
 * it reaches a template (which escapes it as well):
 *
 * - NFKC, then control, format (zero-width, bidi) and line/paragraph
 *   separator characters removed and whitespace collapsed, so the value is
 *   one plain line and cannot fake a line of Phishy's own text;
 * - defanged: `http`/`https` schemes become `hxxp`/`hxxps`, `://` becomes
 *   `[:]//`, and a dot between a letter or digit and a letter becomes `[.]`,
 *   so no mail client turns a URL, domain or address into a link;
 * - bounded with head and tail kept, and the cut marked with an ellipsis.
 */

const INVISIBLE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

export function defang(value: string): string {
  return value
    .replace(/\bhttp(s?)(?=:)/gi, (_match, s: string) => `hxxp${s}`)
    .replace(/:\/\//g, '[:]//')
    .replace(/(?<=[\p{L}\p{N}])\.(?=\p{L})/gu, '[.]');
}

/** One line of hostile text, safe to show (still to be HTML-escaped) */
export function displayText(value: string | undefined, maxLength = 120): string | undefined {
  if (!value) {
    return undefined;
  }
  const line = value.normalize('NFKC').replace(INVISIBLE, ' ').replace(/\s+/g, ' ').trim();
  if (!line) {
    return undefined;
  }
  const defanged = defang(line);
  if (defanged.length <= maxLength) {
    return defanged;
  }
  const tail = Math.max(10, Math.floor(maxLength / 4));
  const head = maxLength - tail - 1;
  return `${defanged.slice(0, head)}…${defanged.slice(-tail)}`;
}

/** A sender as people recognize it: `"Display Name" <address>`, defanged */
export function displaySender(address?: string, name?: string): string | undefined {
  const shownAddress = displayText(address, 120);
  const shownName = displayText(name?.replace(/["<>]/g, ''), 60);
  if (shownAddress && shownName && shownName.toLowerCase() !== shownAddress.toLowerCase()) {
    return `"${shownName}" <${shownAddress}>`;
  }
  return shownAddress ?? (shownName ? `"${shownName}"` : undefined);
}

/** A time as an employee reads it, in the configured zone */
export function displayTime(iso: string | undefined, timeZone: string): string | undefined {
  const at = Date.parse(iso ?? '');
  if (!Number.isFinite(at)) {
    return undefined;
  }
  return new Intl.DateTimeFormat('en-GB', {
    timeZone,
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  }).format(new Date(at));
}

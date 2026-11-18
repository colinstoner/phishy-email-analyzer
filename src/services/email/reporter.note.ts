/**
 * Reporter note separation.
 *
 * A forward body is the employee's own note (if they wrote one), then the
 * forward header their mail client wrote, then the suspicious email. Only
 * the note may be labelled REPORTED; everything else is CLAIMED.
 *
 * The rule is positive evidence or nothing. Text is the employee's note only
 * when:
 *  - a forward header Phishy recognizes is found, and it is the FIRST forward
 *    header in the body (the reporter's client writes its header above the
 *    forwarded content; any header further down belongs to that content), and
 *  - the text above it shows no sign of being forwarded content itself: no
 *    separator line, no block of header-like lines, no localized
 *    "forwarded/original message" or "wrote:" line, and no more text than a
 *    note plausibly holds.
 *
 * The second condition is what closes the unrecognized-client hole: when the
 * reporter's client writes a header Phishy does not know (a localized one),
 * the first header Phishy DOES recognize may be one the attacker placed in
 * the body, and everything above it — the client's own header, plus any
 * "note" the attacker wrote — would otherwise be labelled as the employee's.
 * Any such sign makes the boundary unknown, and an unknown boundary yields NO
 * note: the whole body stays CLAIMED and the prompt says the note could not
 * be separated. Failing closed costs an employee's note its label; failing
 * open would give attacker text the employee's credibility.
 *
 * Forward-as-attachment needs no special case: the parser writes the
 * recognized marker itself directly below the wrapper's own text part, so
 * that text passes or fails the same checks.
 *
 * Pure computation, no I/O.
 */

/** Forward headers Phishy recognizes as a split point */
const FORWARD_MARKERS = [
  /---------- Forwarded message ---------/i,
  /-------- Original Message --------/i,
  /Begin forwarded message:/i,
  /^[ \t]*From:.*\r?\n[ \t]*Sent:.*\r?\n[ \t]*To:.*\r?\n(?:[ \t]*Cc:.*\r?\n)?[ \t]*Subject:/im,
];

/** A note longer than this is not treated as a note: it is more likely pasted content */
export const MAX_SEPARABLE_NOTE = 3000;

/** The separator line Outlook writes directly above its From/Sent/To/Subject block */
const TRAILING_CLIENT_SEPARATOR = /(?:^|\n)[ \t]*_{10,}[ \t]*$/;

/**
 * Signs that the text above the first recognized marker is (or contains)
 * forwarded or quoted content rather than an employee's note. Deliberately
 * broad: a false positive only withholds the REPORTED label.
 */
const AMBIGUITY_SIGNS: RegExp[] = [
  // A separator line: dashes, underscores, equals, asterisks, box drawing
  /^[ \t>]*[-_=*~‐-―─-╿]{3,}/m,
  /[-=‐-―─-╿]{3,}[ \t]*$/m,
  // Two consecutive header-like lines ("Von: ...", "Betreff: ...")
  /^[ \t>]*\p{L}[\p{L}\p{M} .'’-]{0,30}:[ \t]*\S.*\r?\n[ \t>]*\p{L}[\p{L}\p{M} .'’-]{0,30}:[ \t]*\S/mu,
  // Localized forward / original-message banners and reply attributions
  /forwarded message|original message|begin forwarded|weitergeleitet|urspr[uü]ngliche nachricht|message transf[eé]r[eé]|message d'origine|mensaje reenviado|mensaje original|messaggio inoltrato|messaggio originale|doorgestuurd bericht|oorspronkelijk bericht|mensagem encaminhada|mensagem original|vidarebefordrat|videresendt|edelleenl[aä]hetetty|przekazana wiadomo|p[uů]vodn[ií] zpr[aá]va|转发|原始邮件|転送|元のメッセージ/iu,
  /\b(?:wrote|schrieb|a [eé]crit|escribi[oó]|ha scritto|schreef|escreveu|skrev):[ \t]*$/im,
  // Quoted lines
  /^[ \t]*>/m,
];

export type ReporterNote =
  /** A note was separated with positive evidence */
  | { status: 'separated'; note: string; forwarded: string }
  /** The body begins with the recognized forward header: the employee wrote nothing */
  | { status: 'none'; forwarded: string }
  /** No boundary could be established: everything is forwarded (CLAIMED) content */
  | {
      status: 'unseparated';
      reason: 'no_recognized_forward_header' | 'ambiguous_boundary';
      forwarded: string;
    };

/**
 * Split a forward body into the employee's note and the forwarded content,
 * or decline to.
 */
export function separateReporterNote(text: string): ReporterNote {
  let earliest = -1;
  for (const marker of FORWARD_MARKERS) {
    const match = marker.exec(text);
    if (match && (earliest === -1 || match.index < earliest)) {
      earliest = match.index;
    }
  }

  if (earliest === -1) {
    return { status: 'unseparated', reason: 'no_recognized_forward_header', forwarded: text };
  }

  const forwarded = text.substring(earliest);
  const above = text
    .substring(0, earliest)
    .replace(/\s+$/, '')
    .replace(TRAILING_CLIENT_SEPARATOR, '');
  const note = above.trim();

  if (!note) {
    return { status: 'none', forwarded };
  }

  if (note.length > MAX_SEPARABLE_NOTE || AMBIGUITY_SIGNS.some(sign => sign.test(note))) {
    return { status: 'unseparated', reason: 'ambiguous_boundary', forwarded: text };
  }

  return { status: 'separated', note, forwarded };
}

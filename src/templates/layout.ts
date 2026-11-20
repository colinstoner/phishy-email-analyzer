/**
 * Shared building blocks for every email Phishy sends.
 *
 * Built for mail clients, not browsers: table layout, inline styles, a
 * system font stack, 600px wide and fluid below that, nothing that Outlook's
 * Word engine drops for essential structure (no flex, grid or background
 * images), and no remote resource of any kind: no images, fonts, stylesheets
 * or tracking pixels, and no script. The one `<style>` block only improves
 * clients that honour it (dark mode, phone padding); without it every email
 * still reads correctly in light colours.
 *
 * Severity is never colour alone: every tone is shown with a word as well.
 *
 * Escaping convention: a parameter named `html` (or ending in `Html`) is
 * markup built by Phishy's own code; every other string is plain text and
 * is HTML-escaped here. Values from the suspicious email must only ever be
 * passed as plain text (and through `displayText` first where the caller
 * defangs), never as `html`. Nothing here renders a link, an image or an
 * attribute from a value.
 */

/** HTML-escape text for any Phishy email */
export function escapeHtml(text: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };

  return text.replace(/[&<>"']/g, char => htmlEntities[char] ?? char);
}

const esc = escapeHtml;

export type Tone = 'danger' | 'caution' | 'safe' | 'info' | 'neutral';

export const FONT =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
export const MONO = "SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace";

/** Light palette. Every text/background pair meets WCAG AA (4.5:1). */
export const COLOR = {
  page: '#F2F4F7',
  card: '#FFFFFF',
  text: '#1D2939',
  muted: '#475467',
  quiet: '#667085',
  border: '#E4E7EC',
  panel: '#F9FAFB',
  accent: '#2457C5',
  onAccent: '#FFFFFF',
  onAccentSoft: '#DCE6FF',
};

/** Severity colours: `solid` carries white text, `ink` sits on `soft` */
export const TONE: Record<Tone, { solid: string; soft: string; ink: string }> = {
  danger: { solid: '#B42318', soft: '#FEF3F2', ink: '#912018' },
  caution: { solid: '#B54708', soft: '#FFFAEB', ink: '#93370D' },
  safe: { solid: '#067647', soft: '#ECFDF3', ink: '#085D3A' },
  info: { solid: '#2457C5', soft: '#EEF4FF', ink: '#1E3A8A' },
  neutral: { solid: '#475467', soft: '#F2F4F7', ink: '#344054' },
};

/** Dark-mode colours, applied through classes by clients that support it */
const DARK: Record<Tone, { soft: string; ink: string }> = {
  danger: { soft: '#3A1512', ink: '#FDA29B' },
  caution: { soft: '#36250A', ink: '#FEC84B' },
  safe: { soft: '#0B2E1F', ink: '#75E0A7' },
  info: { soft: '#17233F', ink: '#A4BCFD' },
  neutral: { soft: '#252A33', ink: '#D0D5DD' },
};

const TONES: Tone[] = ['danger', 'caution', 'safe', 'info', 'neutral'];

function darkRules(prefix: string): string {
  const p = prefix ? `${prefix} ` : '';
  return [
    `${p}.ph-page{background-color:#0F1217 !important;}`,
    `${p}.ph-card{background-color:#191D24 !important;}`,
    `${p}.ph-text{color:#E9ECF1 !important;}`,
    `${p}.ph-muted{color:#B5BCC8 !important;}`,
    `${p}.ph-panel{background-color:#222731 !important;border-color:#363C47 !important;}`,
    `${p}.ph-rule{border-color:#363C47 !important;}`,
    `${p}.ph-track{background-color:#363C47 !important;}`,
    ...TONES.map(
      tone =>
        `${p}.ph-soft-${tone}{background-color:${DARK[tone].soft} !important;}${p}.ph-ink-${tone}{color:${DARK[tone].ink} !important;}`
    ),
  ].join('');
}

const STYLE = `
:root{color-scheme:light dark;supported-color-schemes:light dark;}
body{margin:0 !important;padding:0 !important;width:100% !important;}
table{border-collapse:collapse;}
@media only screen and (max-width:620px){
.ph-pad{padding-left:18px !important;padding-right:18px !important;}
.ph-outer{padding:12px 6px !important;}
.ph-hero-title{font-size:21px !important;line-height:28px !important;}
}
@media (prefers-color-scheme:dark){${darkRules('')}}
${darkRules('[data-ogsc]')}`;

/** Hidden preview text. Code-written only: never anything from the suspicious email. */
function preheaderHtml(text: string): string {
  return `<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;color:${COLOR.page};">${esc(text)}${'&#8199;&#65279;&#847;'.repeat(30)}</div>`;
}

export interface ShellOptions {
  /** The document title (code-written) */
  title: string;
  /** Inbox preview line (code-written only) */
  preheader: string;
  /** The small label beside the wordmark, e.g. "Security warning" */
  label: string;
  /** Colour of the thin stripe under the header band */
  tone: Tone;
  /** The card's content: concatenated `block(...)` rows */
  bodyHtml: string;
  /** Footer lines, plain text */
  footer: string[];
}

/** The complete email document: page, header band, card, footer */
export function emailShell(options: ShellOptions): string {
  const tone = TONE[options.tone];
  const footer = options.footer
    .map(
      line =>
        `<p class="ph-muted" style="margin:0 0 6px 0;font-family:${FONT};font-size:12px;line-height:18px;color:${COLOR.quiet};">${esc(line)}</p>`
    )
    .join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>${esc(options.title)}</title>
<!--[if mso]><style>table,td,p,li,h1,h2,h3,span,strong{font-family:'Segoe UI',Arial,sans-serif !important;}</style><![endif]-->
<style>${STYLE}</style>
</head>
<body class="ph-page" style="margin:0;padding:0;background-color:${COLOR.page};">
${preheaderHtml(options.preheader)}
<table role="presentation" class="ph-page" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${COLOR.page}" style="background-color:${COLOR.page};">
<tr><td class="ph-outer" align="center" style="padding:24px 12px;">
<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
<tr><td class="ph-pad" bgcolor="${COLOR.accent}" style="background-color:${COLOR.accent};padding:16px 28px;border-radius:12px 12px 0 0;font-family:${FONT};">
<span style="font-size:19px;line-height:24px;font-weight:700;color:${COLOR.onAccent};letter-spacing:0.2px;">Phishy</span><span style="font-size:14px;line-height:24px;color:${COLOR.onAccentSoft};">&nbsp;&nbsp;|&nbsp;&nbsp;${esc(options.label)}</span>
</td></tr>
<tr><td bgcolor="${tone.solid}" style="background-color:${tone.solid};height:4px;line-height:4px;font-size:4px;">&nbsp;</td></tr>
<tr><td class="ph-card" bgcolor="${COLOR.card}" style="background-color:${COLOR.card};padding:24px 0 8px 0;border-radius:0 0 12px 12px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
${options.bodyHtml}
</table>
</td></tr>
<tr><td class="ph-pad" style="padding:18px 28px 8px 28px;">${footer}</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr>
</table>
</body>
</html>`;
}

/** One row of the card, with the standard side padding */
export function block(html: string, options: { bottom?: number } = {}): string {
  return `<tr><td class="ph-pad ph-text" style="padding:0 28px ${options.bottom ?? 22}px 28px;font-family:${FONT};font-size:15px;line-height:22px;color:${COLOR.text};">${html}</td></tr>`;
}

/** A section heading. `quiet` for the detail sections lower down. */
export function heading(text: string, options: { quiet?: boolean } = {}): string {
  return options.quiet
    ? `<h3 class="ph-muted" style="margin:0 0 8px 0;font-family:${FONT};font-size:12px;line-height:18px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:${COLOR.muted};">${esc(text)}</h3>`
    : `<h2 class="ph-text" style="margin:0 0 10px 0;font-family:${FONT};font-size:17px;line-height:24px;font-weight:700;color:${COLOR.text};">${esc(text)}</h2>`;
}

/** A plain paragraph. `quiet` is smaller and muted. */
export function paragraph(text: string, options: { quiet?: boolean; bold?: boolean } = {}): string {
  return paragraphHtml(esc(text), options);
}

export function paragraphHtml(
  html: string,
  options: { quiet?: boolean; bold?: boolean } = {}
): string {
  const size = options.quiet
    ? 'font-size:13px;line-height:20px;'
    : 'font-size:15px;line-height:22px;';
  const color = options.quiet ? COLOR.muted : COLOR.text;
  return `<p class="${options.quiet ? 'ph-muted' : 'ph-text'}" style="margin:0 0 8px 0;font-family:${FONT};${size}color:${color};${options.bold ? 'font-weight:600;' : ''}">${html}</p>`;
}

/** A bulleted list of plain-text items */
export function bulletList(items: string[], options: { quiet?: boolean } = {}): string {
  if (!items.length) {
    return '';
  }
  const size = options.quiet
    ? 'font-size:13px;line-height:20px;'
    : 'font-size:15px;line-height:22px;';
  const color = options.quiet ? COLOR.muted : COLOR.text;
  return `<ul class="${options.quiet ? 'ph-muted' : 'ph-text'}" style="margin:0 0 8px 0;padding:0 0 0 20px;font-family:${FONT};${size}color:${color};">${items
    .map(item => `<li style="margin:0 0 6px 0;">${esc(item)}</li>`)
    .join('')}</ul>`;
}

/** A severity word in a solid pill: the word is what carries the meaning */
export function badge(word: string, tone: Tone): string {
  const t = TONE[tone];
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 10px 0;"><tr><td bgcolor="${t.solid}" style="background-color:${t.solid};border-radius:4px;padding:4px 10px;font-family:${FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:0.8px;color:#FFFFFF;text-transform:uppercase;">${esc(word)}</td></tr></table>`;
}

/** A tinted panel with a solid stripe down its left edge */
export function panel(html: string, tone: Tone, options: { stripe?: boolean } = {}): string {
  const t = TONE[tone];
  const stripe =
    options.stripe === false
      ? ''
      : `<td width="5" bgcolor="${t.solid}" style="width:5px;background-color:${t.solid};font-size:1px;line-height:1px;">&nbsp;</td>`;
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;"><tr>${stripe}<td class="ph-soft-${tone}" bgcolor="${t.soft}" style="background-color:${t.soft};padding:16px 18px;font-family:${FONT};font-size:15px;line-height:22px;color:${COLOR.text};">${html}</td></tr></table>`;
}

/**
 * The verdict at the top of an email: severity word, headline and whatever
 * the caller adds below it (score, plain explanation).
 */
export function hero(options: {
  tone: Tone;
  word: string;
  headline: string;
  html?: string;
}): string {
  const t = TONE[options.tone];
  return panel(
    `${badge(options.word, options.tone)}<p class="ph-hero-title ph-ink-${options.tone}" style="margin:0 0 6px 0;font-family:${FONT};font-size:23px;line-height:30px;font-weight:700;color:${t.ink};">${esc(options.headline)}</p>${options.html ?? ''}`,
    options.tone
  );
}

/** A tinted note: an optional bold title and plain-text lines */
export function callout(options: {
  tone: Tone;
  title?: string;
  lines?: string[];
  html?: string;
}): string {
  const t = TONE[options.tone];
  const title = options.title
    ? `<p class="ph-ink-${options.tone}" style="margin:0 0 6px 0;font-family:${FONT};font-size:15px;line-height:22px;font-weight:700;color:${t.ink};">${esc(options.title)}</p>`
    : '';
  const lines = (options.lines ?? [])
    .map(
      line =>
        `<p class="ph-text" style="margin:0 0 6px 0;font-family:${FONT};font-size:15px;line-height:22px;color:${COLOR.text};">${esc(line)}</p>`
    )
    .join('');
  return panel(`${title}${lines}${options.html ?? ''}`, options.tone);
}

/**
 * The "what to do" block: a title and numbered steps, written to be followed
 * on a phone. No button: Phishy's emails never carry a link.
 */
export function instructions(options: {
  title: string;
  steps: string[];
  note?: string;
  /** Longer steps (the security team's checklists): regular weight, smaller */
  long?: boolean;
}): string {
  const t = TONE.info;
  const stepFont = options.long
    ? 'font-size:15px;line-height:22px;font-weight:400;'
    : 'font-size:16px;line-height:22px;font-weight:600;';
  const steps = options.steps
    .map(
      (step, index) => `<tr>
<td valign="top" width="34" style="width:34px;padding:0 0 10px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" valign="middle" width="24" height="24" bgcolor="${t.solid}" style="width:24px;height:24px;background-color:${t.solid};border-radius:12px;font-family:${FONT};font-size:13px;line-height:24px;font-weight:700;color:#FFFFFF;">${index + 1}</td></tr></table></td>
<td valign="top" class="ph-text" style="padding:1px 0 10px 0;font-family:${FONT};${stepFont}color:${COLOR.text};">${esc(step)}</td>
</tr>`
    )
    .join('');
  const note = options.note
    ? `<p class="ph-muted" style="margin:4px 0 0 0;font-family:${FONT};font-size:14px;line-height:20px;color:${COLOR.muted};">${esc(options.note)}</p>`
    : '';
  return panel(
    `<p class="ph-ink-info" style="margin:0 0 12px 0;font-family:${FONT};font-size:18px;line-height:24px;font-weight:700;color:${t.ink};">${esc(options.title)}</p><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${steps}</table>${note}`,
    'info'
  );
}

export interface Fact {
  label: string;
  /** Plain text (escaped here) */
  value?: string;
  /** Code-built markup, instead of `value` */
  html?: string;
}

/** Short labelled facts, one per row */
export function facts(rows: Fact[], options: { labelWidth?: number; mono?: boolean } = {}): string {
  if (!rows.length) {
    return '';
  }
  const width = options.labelWidth ?? 120;
  const valueFont = options.mono
    ? `font-family:${MONO};font-size:12px;line-height:18px;`
    : `font-family:${FONT};font-size:14px;line-height:20px;`;
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;margin:0 0 8px 0;">${rows
    .map(
      row => `<tr>
<td valign="top" width="${width}" class="ph-muted ph-rule" style="width:${width}px;padding:7px 12px 7px 0;border-bottom:1px solid ${COLOR.border};font-family:${FONT};font-size:13px;line-height:20px;font-weight:600;color:${COLOR.muted};">${esc(row.label)}</td>
<td valign="top" class="ph-text ph-rule" style="padding:7px 0;border-bottom:1px solid ${COLOR.border};${valueFont}color:${COLOR.text};word-break:break-word;">${row.html ?? esc(row.value ?? '')}</td>
</tr>`
    )
    .join('')}</table>`;
}

/** A row of numbers with labels (e.g. reach) */
export function stats(items: Array<{ label: string; value: string; tone?: Tone }>): string {
  if (!items.length) {
    return '';
  }
  const width = Math.floor(100 / items.length);
  const cells = items
    .map(item => {
      const ink = item.tone ? TONE[item.tone].ink : COLOR.text;
      const inkClass = item.tone ? `ph-ink-${item.tone}` : 'ph-text';
      return `<td valign="top" width="${width}%" class="ph-panel" bgcolor="${COLOR.panel}" style="width:${width}%;background-color:${COLOR.panel};border:2px solid ${COLOR.card};padding:10px 8px;text-align:center;font-family:${FONT};">
<p class="${inkClass}" style="margin:0;font-size:24px;line-height:30px;font-weight:700;color:${ink};">${esc(item.value)}</p>
<p class="ph-muted" style="margin:0;font-size:12px;line-height:16px;color:${COLOR.muted};">${esc(item.label)}</p>
</td>`;
    })
    .join('');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;margin:0 0 10px 0;"><tr>${cells}</tr></table>`;
}

/** A data table (recipients). Header names are code-written; cells are escaped. */
export function dataTable(columns: string[], rows: string[][]): string {
  const th = columns
    .map(
      name =>
        `<th align="left" class="ph-muted ph-rule" style="padding:6px 8px 6px 0;border-bottom:2px solid ${COLOR.border};font-family:${FONT};font-size:12px;line-height:16px;font-weight:700;color:${COLOR.muted};text-align:left;">${esc(name)}</th>`
    )
    .join('');
  const body = rows
    .map(
      cells =>
        `<tr>${cells
          .map(
            value =>
              `<td valign="top" class="ph-text ph-rule" style="padding:6px 8px 6px 0;border-bottom:1px solid ${COLOR.border};font-family:${FONT};font-size:13px;line-height:18px;color:${COLOR.text};word-break:break-word;">${esc(value)}</td>`
          )
          .join('')}</tr>`
    )
    .join('');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;margin:0 0 8px 0;"><tr>${th}</tr>${body}</table>`;
}

/** Text in a quiet box (an extracted email body); escaped here, line breaks kept */
export function codeBox(text: string, options: { mono?: boolean } = {}): string {
  const font =
    options.mono === false
      ? `font-family:${FONT};font-size:13px;line-height:20px;`
      : `font-family:${MONO};font-size:12px;line-height:18px;`;
  return `<div class="ph-panel ph-text" style="margin:0 0 8px 0;padding:12px;background-color:${COLOR.panel};border:1px solid ${COLOR.border};border-radius:6px;${font}color:${COLOR.text};word-break:break-word;">${esc(text).replace(/\n/g, '<br>')}</div>`;
}

/** Monospace text inline, for a command to type */
export function codeInline(text: string): string {
  return `<span class="ph-panel ph-text" style="font-family:${MONO};font-size:14px;line-height:22px;font-weight:700;color:${COLOR.text};background-color:${COLOR.panel};border:1px solid ${COLOR.border};padding:2px 6px;border-radius:4px;">${esc(text)}</span>`;
}

/** A horizontal meter: `fraction` (0-1) filled in the tone colour */
export function meter(fraction: number, tone: Tone): string {
  const filled = Math.max(0, Math.min(100, Math.round(fraction * 100)));
  const cell = (width: number, colour: string, cls: string): string =>
    width > 0
      ? `<td width="${width}%" class="${cls}" bgcolor="${colour}" style="width:${width}%;background-color:${colour};height:8px;line-height:8px;font-size:1px;">&nbsp;</td>`
      : '';
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;margin:8px 0 6px 0;"><tr>${cell(filled, TONE[tone].solid, '')}${cell(100 - filled, COLOR.border, 'ph-track')}</tr></table>`;
}

/** A thin separator before the quieter detail sections */
export function divider(): string {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;"><tr><td class="ph-rule" style="border-top:1px solid ${COLOR.border};font-size:1px;line-height:1px;">&nbsp;</td></tr></table>`;
}

// ---------------------------------------------------------------------------
// Plain text
// ---------------------------------------------------------------------------

export const TEXT_RULE = '='.repeat(50);
export const TEXT_SUBRULE = '-'.repeat(40);

/** A plain-text section: upper-case heading, its lines, a blank line */
export function textSection(title: string, lines: string[]): string[] {
  return lines.length ? [title.toUpperCase(), ...lines, ''] : [];
}

/** Labelled facts as plain-text lines */
export function textFacts(rows: Fact[]): string[] {
  return rows.map(row => `${row.label}: ${row.value ?? ''}`);
}

/**
 * Verdict score bands, shared by risk fusion and checklist scoring. Kept in
 * their own module so the checklist scorer can clamp into them without an
 * import cycle with risk.fusion.ts, which re-exports both names.
 */

import { ThreatVerdict } from '../../types';

/**
 * Score band for each final verdict, applied after fusion so the number
 * shown always agrees with the label. `legitimate` (0-10) and the malicious
 * upper range follow the model's own rubric; `graymail`/`spam` follow its
 * 10-30 but stop at 29 so the level shown stays 'low' rather than 'medium';
 * `suspicious` spans 'medium' and 'high' but never 'critical' (critical is
 * reserved for a malicious verdict); a malicious verdict is never below
 * 'high'. `undetermined` has no band — its score is never shown.
 */
export const VERDICT_SCORE_BANDS: Readonly<
  Record<Exclude<ThreatVerdict, 'undetermined'>, { min: number; max: number }>
> = {
  legitimate: { min: 0, max: 10 },
  graymail: { min: 10, max: 29 },
  spam: { min: 10, max: 29 },
  suspicious: { min: 30, max: 79 },
  bec: { min: 55, max: 100 },
  phishing: { min: 55, max: 100 },
  malware_delivery: { min: 55, max: 100 },
};

/** Clamp a score into its verdict's band (undetermined is left as-is) */
export function clampToBand(verdict: ThreatVerdict, score: number): number {
  const rounded = Math.min(100, Math.max(0, Math.round(score)));
  if (verdict === 'undetermined') return rounded;
  const band = VERDICT_SCORE_BANDS[verdict];
  return Math.min(band.max, Math.max(band.min, rounded));
}

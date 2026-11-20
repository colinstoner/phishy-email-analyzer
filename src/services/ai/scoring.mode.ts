/**
 * The risk-score modes (`scoring.mode`). Dependency-free so the config
 * schema can import it without pulling analysis code into other bundles.
 *
 * - `model` (default): the score starts from the model's own riskScore.
 * - `checklist` (experimental): the score is computed by code from a fixed
 *   checklist, answered partly by Phishy and partly by the model
 *   (services/ai/checklist.ts).
 */
export const SCORING_MODES = ['model', 'checklist'] as const;
export type ScoringMode = (typeof SCORING_MODES)[number];

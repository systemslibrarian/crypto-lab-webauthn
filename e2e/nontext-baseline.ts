/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. A finding not listed here
 * fails the run; a listed finding that gets WORSE fails; and a listed finding
 * that no longer appears ALSO fails, so a fixed entry must be deleted and the
 * file can only shrink toward empty.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 1.3, required: 3.0, unverified: false },
  "control-boundary|button.secondary": { ratio: 1.39, required: 3.0, unverified: false }
};

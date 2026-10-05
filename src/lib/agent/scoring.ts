import {
  SEVERITY_ORDER,
  SEVERITY_WEIGHT,
  type Finding,
  type Grade,
  type Severity,
} from "@/lib/agent/types";

/**
 * The risk model.
 *
 * Per finding:   risk = severityWeight x exploitability x exposure, scaled to 0-100
 * Per target:    score = 100 - aggregated penalty, floored at 0
 * Grade:         a fixed mapping from score, with no override parameter
 *
 * Two properties this file is built to guarantee:
 *
 *   1. Scoring reads only its declared numeric inputs. `computeRiskScore`
 *      destructures the three fields it uses; extra properties on the input
 *      object — including any `evidence` a target supplied, or an invented
 *      `override_score` from a hostile tool output — are structurally
 *      unreachable from here.
 *
 *   2. `computeGrade` takes a score and nothing else. There is no argument
 *      that can force a grade, so no code path exists for a target to
 *      request one.
 */

/** Scale factor turning a 0-10 severity weight into a 0-100 risk figure. */
const RISK_SCALE = 10;

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/**
 * Risk for a single finding, 0-100.
 *
 * Note the signature: three named numbers, not a Finding. Passing the whole
 * object would make it possible — later, carelessly — to reach for a field
 * that came from the target.
 */
export function computeRiskScore(input: {
  severity: Severity;
  exploitability: number;
  exposure: number;
}): number {
  const { severity, exploitability, exposure } = input;

  const weight = SEVERITY_WEIGHT[severity] ?? 0;
  const risk = weight * clamp01(exploitability) * clamp01(exposure) * RISK_SCALE;

  return Math.round(Math.min(100, Math.max(0, risk)));
}

/**
 * Overall posture score, 0-100, where 100 is "nothing found".
 *
 * Findings are aggregated with diminishing weight after the first few: ten
 * medium-severity header issues are worse than one, but they are not ten
 * times worse, and letting them sum linearly would put every imperfect site
 * at zero and make the grade useless for comparison.
 *
 * The worst single finding is applied at full weight, so one critical issue
 * cannot be diluted by a long tail of minor ones.
 */
export function computeOverallScore(findings: Finding[]): number {
  const scored = findings
    .filter((f) => f.severity !== "INFO")
    .map((f) => f.riskScore)
    .sort((a, b) => b - a);

  if (scored.length === 0) return 100;

  let penalty = 0;
  scored.forEach((risk, index) => {
    // 1, 1/2, 1/3, 1/4 … — the worst finding counts fully, each subsequent
    // one contributes progressively less.
    penalty += risk / (index + 1);
  });

  return Math.round(Math.min(100, Math.max(0, 100 - penalty)));
}

/**
 * Score to letter grade.
 *
 * One parameter, by design. There is deliberately no `override`, no
 * `forceGrade`, and no options object — an injected instruction has nothing
 * to attach itself to.
 */
export function computeGrade(score: number): Grade {
  if (!Number.isFinite(score)) return "F";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * The worst severity present, ignoring INFO.
 *
 * Reads only the `severity` field, which is one of five values from our
 * own closed enum — set by our own rules for header and CVE findings, and
 * by mapExternalSeverity for TLS ones, which maps an unrecognized label to
 * MEDIUM rather than trusting it. No target-supplied text reaches this.
 */
export function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;

  for (const finding of findings) {
    if (finding.severity === "INFO") continue;
    if (worst === null || SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[worst]) {
      worst = finding.severity;
    }
  }

  return worst;
}

/**
 * The best grade a target can be held back from by the penalty alone.
 *
 * Calibration problem this fixes. The penalty sums risk with diminishing
 * weight, which is right for ranking, but the resulting number alone
 * decides the letter — and on a site whose worst problem is a missing CSP,
 * a single HIGH finding at risk 34 is three quarters of the total penalty.
 * A well-run static site with genuinely clean TLS scored 54 and graded F.
 *
 * F should mean something. A scorecard that cannot tell "no Content-
 * Security-Policy header" apart from "exploitable TLS and a critical CVE"
 * is not being strict, it is being uninformative, and the first operator
 * who reads an F for a missing header learns to discount every F after it.
 *
 * So the letter is bounded by the worst thing actually found:
 *
 *   worst is CRITICAL  no floor — F is reachable, as it should be
 *   worst is HIGH      no worse than D
 *   worst is MEDIUM    no worse than C
 *   worst is LOW       no worse than B
 *   nothing scored     A
 *
 * This is a floor, never a ceiling. A target with twenty HIGH findings is
 * still held at D by the penalty rather than lifted — the score continues
 * to do the discriminating, and accumulating problems still costs you.
 */
const SEVERITY_FLOOR: Record<Severity, Grade> = {
  CRITICAL: "F",
  HIGH: "D",
  MEDIUM: "C",
  LOW: "B",
  INFO: "A",
};

const GRADE_RANK: Record<Grade, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

/**
 * Score to letter, bounded below by what was actually found.
 *
 * Note what this does NOT take: a Finding, an options object, or anything
 * a target could populate. Both arguments are ours — a bounded number and
 * one of five enum values — so the structural property that scanned text
 * cannot reach the grade is unchanged. `computeGrade` is deliberately
 * left exactly as it was, single-argument, and is still the only thing
 * that turns a number into a letter.
 */
export function computeGradeWithFloor(
  score: number,
  worst: Severity | null,
): Grade {
  const fromScore = computeGrade(score);
  if (worst === null) return "A";

  const floor = SEVERITY_FLOOR[worst];
  return GRADE_RANK[fromScore] >= GRADE_RANK[floor] ? fromScore : floor;
}

/**
 * Finishes a partially-built finding by computing its risk score.
 *
 * Every producer (headers, TLS, fingerprint, CVE) routes through this, so
 * there is exactly one place where riskScore is set and it always comes
 * from computeRiskScore.
 */
export function finalizeFinding(
  draft: Omit<Finding, "riskScore">,
): Finding {
  return {
    ...draft,
    riskScore: computeRiskScore({
      severity: draft.severity,
      exploitability: draft.exploitability,
      exposure: draft.exposure,
    }),
  };
}

/** Count of findings at each severity, for the scorecard summary. */
export function severityBreakdown(
  findings: Finding[],
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Maps an externally-supplied severity label onto our vocabulary.
 *
 * Used when ingesting testssl.sh output. Anything unrecognized becomes
 * MEDIUM rather than the lowest value: an unknown label is an unknown risk,
 * and quietly treating it as harmless is how a scanner reports an A on a
 * host it did not actually understand. Unknown labels are surfaced to the
 * caller so the degradation is visible rather than silent.
 */
export function mapExternalSeverity(
  label: unknown,
): { severity: Severity; recognized: boolean } {
  if (typeof label !== "string") return { severity: "MEDIUM", recognized: false };

  switch (label.trim().toUpperCase()) {
    case "CRITICAL":
      return { severity: "CRITICAL", recognized: true };
    case "HIGH":
      return { severity: "HIGH", recognized: true };
    case "MEDIUM":
    case "WARN":
      return { severity: "MEDIUM", recognized: true };
    case "LOW":
      return { severity: "LOW", recognized: true };
    case "INFO":
    case "OK":
    case "DEBUG":
      return { severity: "INFO", recognized: true };
    default:
      return { severity: "MEDIUM", recognized: false };
  }
}

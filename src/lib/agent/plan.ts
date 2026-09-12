import { computeGrade, computeOverallScore } from "@/lib/agent/scoring";
import type {
  Finding,
  RemediationPlan,
  RemediationStep,
} from "@/lib/agent/types";

/**
 * Budget-constrained remediation planning.
 *
 * The question this answers is not "what is wrong" — the findings list
 * already says that — but "given that you have a limited amount of effort,
 * what should you do with it". Those give different answers surprisingly
 * often: a critical finding costing 13 points can be worth deferring behind
 * three medium ones costing 1 point each.
 *
 * Ordering key is risk reduced per unit of effort. Ties break toward the
 * higher absolute risk, then toward the cheaper fix.
 *
 * Selection is greedy rather than an exact knapsack solve. That is a
 * deliberate trade and worth naming: greedy-by-ratio can miss the optimal
 * combination (the classic case is one item that exactly fills the budget
 * being passed over for two that nearly do). It is chosen because the
 * output has to be *explainable* — "we did the highest-value-per-hour fix
 * first, then the next" is advice someone can act on and argue with,
 * whereas an optimal set produced by dynamic programming is a black box
 * that occasionally recommends skipping the obvious thing. A backfill pass
 * recovers most of the lost value.
 *
 * Nothing here reads `Finding.evidence`. The ordering cannot be influenced
 * by text from the scanned target.
 */

export interface PlanOptions {
  budgetLimit: number;
}

export function buildRemediationPlan(
  findings: Finding[],
  options: PlanOptions,
): RemediationPlan {
  const budgetLimit = Math.max(0, Math.floor(options.budgetLimit));

  const actionable = findings
    .filter((f) => f.severity !== "INFO" && f.riskScore > 0 && f.effort > 0)
    .map((f) => ({
      finding: f,
      efficiency: f.riskScore / f.effort,
    }))
    .sort((a, b) => {
      if (b.efficiency !== a.efficiency) return b.efficiency - a.efficiency;
      if (b.finding.riskScore !== a.finding.riskScore) {
        return b.finding.riskScore - a.finding.riskScore;
      }
      return a.finding.effort - b.finding.effort;
    });

  const steps: RemediationStep[] = [];
  const deferred: RemediationPlan["deferred"] = [];
  const fixedCheckIds = new Set<string>();

  let budgetUsed = 0;

  // Pass one: greedy by efficiency.
  for (const candidate of actionable) {
    const { finding, efficiency } = candidate;

    if (budgetUsed + finding.effort > budgetLimit) {
      deferred.push({
        checkId: finding.checkId,
        title: finding.title,
        effort: finding.effort,
        riskReduction: finding.riskScore,
        reason:
          finding.effort > budgetLimit
            ? `Needs ${finding.effort} effort points, more than the entire budget of ${budgetLimit}`
            : `Would exceed the remaining budget (${budgetLimit - budgetUsed} of ${budgetLimit} left)`,
      });
      continue;
    }

    budgetUsed += finding.effort;
    fixedCheckIds.add(finding.checkId);

    steps.push({
      checkId: finding.checkId,
      title: finding.title,
      action: finding.remediation,
      severity: finding.severity,
      effort: finding.effort,
      riskReduction: finding.riskScore,
      efficiency: Number(efficiency.toFixed(2)),
      reasoning: explainStep(finding, efficiency),
      rank: steps.length + 1,
    });
  }

  // Pass two: backfill. A cheap fix skipped earlier may now fit in the
  // budget that the greedy pass left unspent.
  const remaining = budgetLimit - budgetUsed;
  if (remaining > 0) {
    for (let i = deferred.length - 1; i >= 0; i -= 1) {
      const item = deferred[i];
      if (item.effort > budgetLimit - budgetUsed) continue;

      const finding = actionable.find((c) => c.finding.checkId === item.checkId);
      if (!finding) continue;

      budgetUsed += finding.finding.effort;
      fixedCheckIds.add(finding.finding.checkId);
      deferred.splice(i, 1);

      steps.push({
        checkId: finding.finding.checkId,
        title: finding.finding.title,
        action: finding.finding.remediation,
        severity: finding.finding.severity,
        effort: finding.finding.effort,
        riskReduction: finding.finding.riskScore,
        efficiency: Number(finding.efficiency.toFixed(2)),
        reasoning: `${explainStep(finding.finding, finding.efficiency)} Added on the backfill pass — it fits the effort the higher-ranked fixes left unspent.`,
        rank: steps.length + 1,
      });
    }
  }

  // Projected posture once every included step is done.
  const residual = findings.filter((f) => !fixedCheckIds.has(f.checkId));
  const projectedScore = computeOverallScore(residual);

  return {
    budgetLimit,
    budgetUsed,
    steps,
    deferred,
    projectedScore,
    projectedGrade: computeGrade(projectedScore),
    strategy: describeStrategy(steps.length, deferred.length, budgetLimit, budgetUsed),
  };
}

/** Per-step justification, in plain language, shown in the scorecard. */
function explainStep(finding: Finding, efficiency: number): string {
  const parts: string[] = [];

  parts.push(
    `${finding.severity.toLowerCase()} severity, risk ${finding.riskScore}/100, ` +
      `${finding.effort} effort point${finding.effort === 1 ? "" : "s"} ` +
      `(${efficiency.toFixed(1)} risk removed per point).`,
  );

  if (finding.epss !== undefined) {
    parts.push(
      `EPSS puts the chance of active exploitation in the next 30 days at ` +
        `${(finding.epss * 100).toFixed(1)}%, which is what drives its position here.`,
    );
  }

  if (efficiency >= 10) {
    parts.push("Unusually cheap for the risk it removes — do this first.");
  } else if (finding.severity === "CRITICAL" && efficiency < 3) {
    parts.push(
      "Expensive, but the severity is high enough that deferring it is a real exposure.",
    );
  }

  return parts.join(" ");
}

function describeStrategy(
  included: number,
  deferredCount: number,
  budgetLimit: number,
  budgetUsed: number,
): string {
  if (included === 0 && deferredCount === 0) {
    return "No actionable findings — there is nothing to plan.";
  }

  if (included === 0) {
    return (
      `Nothing fits a budget of ${budgetLimit} effort points: the cheapest remaining ` +
      `fix costs more than that. Raise the budget to get a plan.`
    );
  }

  const base =
    `Ranked by risk removed per effort point, filling a ${budgetLimit}-point budget ` +
    `(${budgetUsed} used across ${included} fix${included === 1 ? "" : "es"}).`;

  return deferredCount > 0
    ? `${base} ${deferredCount} finding${deferredCount === 1 ? "" : "s"} did not fit and ${deferredCount === 1 ? "is" : "are"} listed separately.`
    : `${base} Everything actionable fits within the budget.`;
}

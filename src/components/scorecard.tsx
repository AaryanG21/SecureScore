import { Badge, Panel } from "@/components/ui";
import { severityBreakdown } from "@/lib/agent/scoring";
import { CVE_COVERAGE_NOTE } from "@/lib/agent/cve-dataset";
import type { Finding, Grade, RemediationPlan, Severity } from "@/lib/agent/types";

/**
 * The scorecard.
 *
 * Every piece of target-supplied text on this page renders inside a JSX
 * expression, which React escapes. There is no dangerouslySetInnerHTML
 * anywhere in this component, and the page's CSP forbids inline script, so
 * a banner containing markup is displayed as the literal characters the
 * target sent.
 */

const GRADE_TONE: Record<Grade, string> = {
  A: "text-signal border-signal/50 bg-signal/10",
  B: "text-signal border-signal/40 bg-signal/5",
  C: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
  D: "text-sev-high border-sev-high/50 bg-sev-high/10",
  F: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
};

const SEVERITY_TONE = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "neutral",
} as const;

export function Scorecard({
  hostname,
  grade,
  score,
  findings,
  plan,
  testsslVersion,
  degraded,
  scannedAt,
}: {
  hostname: string;
  grade: Grade;
  score: number;
  findings: Finding[];
  plan: RemediationPlan;
  testsslVersion: string | null;
  degraded: Array<{ step: string; reason: string }>;
  scannedAt: string;
}) {
  const counts = severityBreakdown(findings);
  const scored = findings.filter((f) => f.severity !== "INFO");
  const informational = findings.filter((f) => f.severity === "INFO");
  const injectionCount = findings.filter((f) => f.injectionAttempt).length;

  return (
    <div className="space-y-6">
      {/* -- grade banner -------------------------------------------- */}
      <section className="rounded-lg border border-line bg-surface p-6">
        <div className="flex flex-wrap items-center gap-6">
          <div
            className={`flex h-24 w-24 shrink-0 items-center justify-center rounded-lg border-2 font-mono text-5xl font-bold ${GRADE_TONE[grade]}`}
          >
            {grade}
          </div>

          <div className="min-w-64 flex-1">
            <h1 className="font-mono text-xl text-ink">{hostname}</h1>
            <p className="mt-1 text-sm text-ink-muted">
              Score {score}/100 · {scored.length} finding
              {scored.length === 1 ? "" : "s"} · scanned {scannedAt}
            </p>

            <div className="mt-3 flex flex-wrap gap-2">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[])
                .filter((s) => counts[s] > 0)
                .map((s) => (
                  <Badge key={s} tone={SEVERITY_TONE[s]}>
                    {counts[s]} {s.toLowerCase()}
                  </Badge>
                ))}
              {scored.length === 0 && <Badge tone="signal">no findings</Badge>}
            </div>
          </div>
        </div>

        <p className="mt-5 border-t border-line pt-4 text-xs leading-relaxed text-ink-faint">
          This grade reflects the checks Fulcrum ran against what is reachable
          from outside: HTTP response headers, TLS configuration, and
          self-reported software versions. It does not assess application
          logic, dependencies, infrastructure, or access control. A good grade
          means these checks found nothing — not that the site is secure.
        </p>
      </section>

      {/* -- degraded steps ------------------------------------------ */}
      {degraded.length > 0 && (
        <Panel
          title="Incomplete checks"
          description="These steps did not produce results. Their absence is not a pass."
        >
          <ul className="space-y-2 text-sm">
            {degraded.map((item) => (
              <li key={item.step} className="flex gap-3">
                <span className="font-mono text-xs text-sev-medium uppercase">
                  {item.step}
                </span>
                <span className="text-ink-muted">{item.reason}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* -- injection notice ---------------------------------------- */}
      {injectionCount > 0 && (
        <Panel title="Instruction-shaped content detected">
          <p className="text-sm text-ink-muted">
            {injectionCount} piece{injectionCount === 1 ? "" : "s"} of content
            returned by this host contained text that reads like an
            instruction to an automated reader — for example, asking a scanner
            to disregard its findings.
          </p>
          <p className="mt-2 text-sm text-ink-muted">
            It had no effect. Scores are computed from the checks that ran, and
            text from a scanned target is never interpreted as input to that
            computation. The content is shown below as evidence, marked with a
            flag.
          </p>
        </Panel>
      )}

      {/* -- remediation plan ---------------------------------------- */}
      <Panel
        title="Remediation plan"
        description={plan.strategy}
        action={
          <div className="text-right">
            <div className="font-mono text-sm text-ink">
              {plan.budgetUsed}/{plan.budgetLimit} pts
            </div>
            <div className="text-xs text-ink-faint">
              projects to {plan.projectedGrade} ({plan.projectedScore})
            </div>
          </div>
        }
      >
        {plan.steps.length === 0 ? (
          <p className="text-sm text-ink-muted">
            Nothing fits this budget. Raise it to get a ranked plan.
          </p>
        ) : (
          <ol className="space-y-4">
            {plan.steps.map((step) => (
              <li
                key={step.checkId}
                className="rounded-md border border-line bg-surface-2 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5 font-mono text-sm text-signal">
                      {step.rank}.
                    </span>
                    <div>
                      <h3 className="text-sm font-semibold text-ink">
                        {step.title}
                      </h3>
                      <p className="mt-1 text-sm text-ink-muted">{step.action}</p>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge tone={SEVERITY_TONE[step.severity]}>
                      {step.severity.toLowerCase()}
                    </Badge>
                    <Badge>{step.effort} pts</Badge>
                  </div>
                </div>

                <p className="mt-3 border-t border-line pt-3 text-xs leading-relaxed text-ink-faint">
                  <span className="text-ink-muted">Why here: </span>
                  {step.reasoning}
                </p>
              </li>
            ))}
          </ol>
        )}

        {plan.deferred.length > 0 && (
          <div className="mt-5 border-t border-line pt-4">
            <h3 className="font-mono text-xs tracking-wide text-ink-faint uppercase">
              Did not fit the budget
            </h3>
            <ul className="mt-2 space-y-1.5 text-sm">
              {plan.deferred.map((item) => (
                <li key={item.checkId} className="flex flex-wrap gap-2">
                  <span className="text-ink-muted">{item.title}</span>
                  <span className="text-xs text-ink-faint">
                    — {item.effort} pts, {item.reason}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>

      {/* -- findings table ------------------------------------------ */}
      <Panel title="Findings" description="Ranked by computed risk.">
        {scored.length === 0 ? (
          <p className="text-sm text-ink-muted">
            No findings from the checks that completed.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs tracking-wide text-ink-faint uppercase">
                  <th className="pb-2 font-medium">Severity</th>
                  <th className="pb-2 font-medium">Risk</th>
                  <th className="pb-2 font-medium">Finding</th>
                  <th className="pb-2 font-medium">Source</th>
                  <th className="pb-2 font-medium">Effort</th>
                </tr>
              </thead>
              <tbody>
                {scored.map((finding) => (
                  <tr
                    key={finding.checkId}
                    className="border-b border-line/50 align-top last:border-0"
                  >
                    <td className="py-3 pr-3">
                      <Badge tone={SEVERITY_TONE[finding.severity]}>
                        {finding.severity.toLowerCase()}
                      </Badge>
                    </td>
                    <td className="py-3 pr-3 font-mono text-ink">
                      {finding.riskScore}
                    </td>
                    <td className="py-3 pr-3">
                      <div className="font-medium text-ink">{finding.title}</div>
                      <div className="mt-1 text-xs text-ink-muted">
                        {finding.description}
                      </div>
                      {finding.evidence && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-xs text-ink-faint hover:text-ink-muted">
                            Evidence from the target
                            {finding.injectionAttempt && (
                              <span className="ml-2 text-sev-high">
                                ⚑ instruction-shaped, ignored
                              </span>
                            )}
                          </summary>
                          {/*
                            Target-supplied text. Rendered as an escaped JSX
                            expression inside a <code> block — never as HTML.
                          */}
                          <code className="mt-1.5 block overflow-x-auto rounded border border-line-bright bg-base px-2 py-1.5 font-mono text-xs break-all whitespace-pre-wrap text-ink-muted">
                            {finding.evidence}
                          </code>
                        </details>
                      )}
                    </td>
                    <td className="py-3 pr-3 font-mono text-xs text-ink-faint">
                      {finding.source}
                    </td>
                    <td className="py-3 font-mono text-ink-muted">
                      {finding.effort}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* -- provenance ---------------------------------------------- */}
      <Panel title="How this was measured">
        <dl className="space-y-2 text-sm">
          <div className="flex flex-wrap gap-2">
            <dt className="text-ink-faint">TLS scanner:</dt>
            <dd className="text-ink-muted">
              {testsslVersion
                ? `testssl.sh v${testsslVersion} (pinned)`
                : "testssl.sh did not complete for this scan"}
            </dd>
          </div>
          <div className="flex flex-wrap gap-2">
            <dt className="text-ink-faint">Risk model:</dt>
            <dd className="text-ink-muted">
              severity × exploitability × exposure, scaled to 0–100. EPSS
              supplies exploitability for CVE-backed findings.
            </dd>
          </div>
          <div className="flex flex-wrap gap-2">
            <dt className="text-ink-faint">Ordering:</dt>
            <dd className="text-ink-muted">
              risk removed per effort point, filled greedily against your
              budget.
            </dd>
          </div>
        </dl>

        <p className="mt-4 border-t border-line pt-3 text-xs leading-relaxed text-ink-faint">
          {CVE_COVERAGE_NOTE}
        </p>

        {informational.length > 0 && (
          <div className="mt-4 border-t border-line pt-3">
            <h3 className="font-mono text-xs tracking-wide text-ink-faint uppercase">
              Identified software
            </h3>
            <ul className="mt-2 space-y-1 text-sm text-ink-muted">
              {informational.map((item) => (
                <li key={item.checkId}>
                  {item.title}
                  <span className="ml-2 text-xs text-ink-faint">
                    (self-reported by the target)
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>
    </div>
  );
}

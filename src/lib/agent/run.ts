import "server-only";
import { errorMessage, log } from "@/lib/log";
import { normalizeHostname } from "@/lib/validation/hostname";
import { probeHeaders, evaluateHeaders } from "@/lib/agent/headers";
import { fingerprint, fingerprintFindings } from "@/lib/agent/fingerprint";
import { cveFindings, matchCves } from "@/lib/agent/cve";
import { mapTestsslRecords, runTestssl } from "@/lib/agent/testssl";
import { buildRemediationPlan } from "@/lib/agent/plan";
import {
  computeGradeWithFloor,
  computeOverallScore,
  worstSeverity,
} from "@/lib/agent/scoring";
import { MAX_TOTAL_EVIDENCE_LENGTH } from "@/lib/agent/sanitize";
import type { Finding, ScanOutcome } from "@/lib/agent/types";

/**
 * The scanning agent loop.
 *
 * Written directly — no agent framework. The loop is a small explicit state
 * machine over a list of steps, which is all this problem needs: each step
 * observes the target, produces findings, and can enable or skip later
 * steps based on what it found.
 *
 *   observe  ->  the step runs a probe against the target
 *   reason   ->  findings are derived from OUR catalogue, keyed on what the
 *                probe concluded, never on text the target supplied
 *   adapt    ->  results feed the next step's inputs (headers produce the
 *                fingerprints that the CVE step looks up) and a failed step
 *                degrades the scan rather than aborting it
 *   decide   ->  score, grade, and a budget-constrained plan
 *
 * Partial failure is a first-class outcome. If testssl.sh times out we do
 * not throw away the header findings, and we do not quietly present a
 * header-only scan as a complete one — `degraded` records what did not run,
 * and the scorecard shows it.
 */

export interface ScanRequest {
  hostname: string;
  budgetLimit: number;
  /** Set false to skip the TLS step (used by tests and by header-only runs). */
  includeTls?: boolean;
}

export type ScanRun =
  | { ok: true; outcome: ScanOutcome }
  | { ok: false; reason: string };

interface StepResult {
  findings: Finding[];
  degraded?: { step: string; reason: string };
}

export async function runScan(request: ScanRequest): Promise<ScanRun> {
  const startedAt = new Date();

  const normalized = normalizeHostname(request.hostname);
  if (!normalized.ok) {
    return { ok: false, reason: normalized.reason };
  }
  const hostname = normalized.hostname;

  const findings: Finding[] = [];
  const degraded: ScanOutcome["degraded"] = [];
  let testsslVersion: string | null = null;

  /* -- step 1: HTTP headers ------------------------------------------- */
  const headerStep = await stepHeaders(hostname);
  findings.push(...headerStep.findings);
  if (headerStep.degraded) degraded.push(headerStep.degraded);

  /* -- step 2: fingerprint, fed by step 1's response ------------------- */
  // Only runs if step 1 produced a response to read; this is the loop
  // adapting rather than blindly running every probe.
  const probe = headerStep.probe;
  const fingerprints = probe?.ok ? fingerprint(probe) : [];
  findings.push(...fingerprintFindings(fingerprints));

  if (!probe?.ok) {
    degraded.push({
      step: "fingerprint",
      reason: "Skipped: no HTTP response to fingerprint",
    });
  } else if (fingerprints.length === 0) {
    degraded.push({
      step: "fingerprint",
      reason: "No recognizable software version disclosed — CVE matching was skipped",
    });
  }

  /* -- step 3: CVE / EPSS cross-reference ------------------------------ */
  if (fingerprints.length > 0) {
    const matches = matchCves(fingerprints);
    findings.push(...cveFindings(matches));
  }

  /* -- step 4: TLS via the pinned external tool ------------------------ */
  let tlsObserved = false;
  if (request.includeTls !== false) {
    const tlsStep = await stepTls(hostname);
    findings.push(...tlsStep.findings);
    if (tlsStep.degraded) degraded.push(tlsStep.degraded);
    testsslVersion = tlsStep.version;
    tlsObserved = tlsStep.observed;
  } else {
    degraded.push({
      step: "tls",
      reason:
        "TLS and certificate configuration were not examined. This check " +
        "read HTTP response headers only, so the transport posture of this " +
        "host is unknown — not verified clean. A full scan, which requires " +
        "proving you control the domain, is what tests it.",
    });
  }

  /* -- decide ---------------------------------------------------------- */

  // A scan that observed nothing cannot be scored.
  //
  // computeOverallScore([]) is 100 and 100 grades A, which is correct when
  // every check ran and found nothing — and a lie when no check ran at
  // all. An unreachable host, a name that does not resolve, or one refused
  // for pointing at a private address would otherwise come back as a
  // perfect result with the explanation buried in `degraded`, which is
  // precisely the "absence of findings presented as a pass" this codebase
  // refuses to do everywhere else. Nobody reads the footnote under an A.
  //
  // Having observed SOMETHING is enough: a host whose headers answered but
  // whose TLS scan timed out is still scored on its headers, with the gap
  // recorded. The bar is that at least one probe got an answer.
  const headersObserved = headerStep.probe?.ok === true;
  if (!headersObserved && !tlsObserved) {
    const why = headerStep.degraded?.reason ?? "no probe reached the target";
    return {
      ok: false,
      reason: `Nothing could be measured about ${hostname}: ${why}`,
    };
  }

  const bounded = capTotalEvidence(dedupeFindings(findings));

  const score = computeOverallScore(bounded);
  // The letter is bounded by the worst severity actually found, so a site
  // whose only real problem is a missing header cannot be graded the same
  // as one with an exploitable critical. The score is unchanged.
  const grade = computeGradeWithFloor(score, worstSeverity(bounded));
  const plan = buildRemediationPlan(bounded, { budgetLimit: request.budgetLimit });

  return {
    ok: true,
    outcome: {
      hostname,
      findings: bounded.sort((a, b) => b.riskScore - a.riskScore),
      score,
      grade,
      plan,
      testsslVersion,
      degraded,
      startedAt,
      completedAt: new Date(),
    },
  };
}

async function stepHeaders(
  hostname: string,
): Promise<StepResult & { probe: Awaited<ReturnType<typeof probeHeaders>> | null }> {
  try {
    const probe = await probeHeaders(hostname);

    if (!probe.ok) {
      return {
        findings: [],
        probe,
        degraded: {
          step: "headers",
          reason: probe.reason ?? "The target could not be reached over HTTPS",
        },
      };
    }

    return { findings: evaluateHeaders(probe), probe };
  } catch (error) {
    // probeHeaders returns curated reasons for every failure it expects, so
    // reaching here means something unforeseen threw. Its message goes to
    // the server log, not into the scan record: a raw Node or TLS error
    // string is persisted, rendered on the scorecard and returned over the
    // API, and it describes our internals rather than the target's posture.
    log.error("unexpected failure in the scan header step", {
      error: errorMessage(error),
    });

    return {
      findings: [],
      probe: null,
      degraded: {
        step: "headers",
        reason:
          "The header check could not be completed. The HTTP posture of this host is unknown, not verified clean.",
      },
    };
  }
}

async function stepTls(
  hostname: string,
): Promise<StepResult & { version: string | null; observed: boolean }> {
  const result = await runTestssl(hostname);

  if (!result.ok) {
    // A timed-out or failed TLS scan must never look like a clean one. It
    // contributes no findings and is recorded as degraded, so the scorecard
    // can say the TLS posture is unknown rather than fine.
    return {
      findings: [],
      version: null,
      observed: false,
      degraded: {
        step: "tls",
        reason:
          result.kind === "timeout"
            ? `TLS scan timed out — the TLS posture of this host is unknown, not verified clean. ${result.reason}`
            : `TLS scan did not complete: ${result.reason}`,
      },
    };
  }

  const mapped = mapTestsslRecords(result.records);

  // The tool ran but reported it could not test the target. Same rule as a
  // timeout: no findings, and the TLS posture is recorded as unknown.
  if (mapped.fatal) {
    return {
      findings: [],
      version: result.version,
      observed: false,
      degraded: {
        step: "tls",
        reason: `TLS scan did not run — the TLS posture of this host is unknown, not verified clean. testssl.sh reported: ${mapped.fatal}`,
      },
    };
  }

  const notes: string[] = [];
  if (mapped.unrecognizedSeverities.length > 0) {
    notes.push(
      `testssl.sh reported severity labels this build does not recognize (${mapped.unrecognizedSeverities.join(", ")}); they were treated as medium.`,
    );
  }

  return {
    findings: mapped.findings,
    version: result.version,
    observed: true,
    ...(notes.length > 0 ? { degraded: { step: "tls", reason: notes.join(" ") } } : {}),
  };
}

/** Two probes can surface the same weakness; keep the higher-risk one. */
function dedupeFindings(findings: Finding[]): Finding[] {
  const byCheck = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = byCheck.get(finding.checkId);
    if (!existing || finding.riskScore > existing.riskScore) {
      byCheck.set(finding.checkId, finding);
    }
  }

  return [...byCheck.values()];
}

/**
 * Bounds the total quarantined text across the whole result.
 *
 * Each evidence string is already individually capped. This guards the
 * aggregate: a target emitting hundreds of near-cap headers should not be
 * able to push a multi-megabyte JSON blob into the database.
 */
function capTotalEvidence(findings: Finding[]): Finding[] {
  let budget = MAX_TOTAL_EVIDENCE_LENGTH;

  return findings.map((finding) => {
    if (!finding.evidence) return finding;

    if (budget <= 0) {
      return { ...finding, evidence: "[evidence omitted: total size limit reached]" };
    }

    if (finding.evidence.length > budget) {
      const trimmed = `${finding.evidence.slice(0, budget)}…[truncated]`;
      budget = 0;
      return { ...finding, evidence: trimmed };
    }

    budget -= finding.evidence.length;
    return finding;
  });
}

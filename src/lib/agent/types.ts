/**
 * Shared vocabulary for the scanning agent.
 *
 * The single most important design rule in this module, and the reason the
 * types are shaped the way they are:
 *
 *   Text harvested from a scanned target NEVER reaches the scoring path.
 *
 * A Finding separates the two categories of data explicitly. Everything the
 * score is computed from (`severity`, `exploitability`, `exposure`,
 * `checkId`) is a closed enum or a bounded number chosen by our own code,
 * based on which check ran and what it concluded. Everything the target
 * supplied (`evidence`) is quarantined in one field, is sanitized on the
 * way in, and is only ever rendered as quoted text.
 *
 * That separation is what makes "a manipulated banner cannot change the
 * score" a structural property rather than a promise.
 */

/** Severity of the underlying weakness, independent of this target. */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

/** Base weight per severity, on a 0-10 scale. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 2,
  INFO: 0,
};

/**
 * Where a finding came from. Used for grouping in the scorecard and for
 * attributing results to the pinned external tool.
 */
export type FindingSource = "headers" | "tls" | "fingerprint" | "cve";

/** Effort to remediate, in the same arbitrary points as the user's budget. */
export type EffortPoints = number;

export interface Finding {
  /**
   * Stable identifier for the check that produced this finding. The scoring
   * model keys off this, never off any text from the target.
   */
  checkId: string;

  source: FindingSource;

  /** Our own words, from our own catalogue. Never target-supplied. */
  title: string;
  description: string;
  remediation: string;

  severity: Severity;

  /**
   * How readily the weakness can be exploited in practice, 0-1.
   * Derived from the check's own semantics, and — for CVE-backed findings —
   * from EPSS, which is a published probability, not target-supplied text.
   */
  exploitability: number;

  /**
   * How exposed this particular target is, 0-1. A weakness on a service
   * reachable from the internet scores higher than the same weakness behind
   * a control that limits reach.
   */
  exposure: number;

  /** Computed by scoring.ts. 0-100. */
  riskScore: number;

  effort: EffortPoints;

  /**
   * QUARANTINE FIELD. Raw-ish text observed on the target — a header value,
   * a certificate subject, a tool finding string. Sanitized by
   * sanitizeScannedText before it gets here. Display only: nothing in the
   * scoring or planning path reads this.
   */
  evidence?: string;

  /** CVE ids when this finding came from the vulnerability cross-reference. */
  cves?: string[];

  /** EPSS probability (0-1) for the highest-scoring associated CVE. */
  epss?: number;

  /**
   * True when sanitization found instruction-shaped content in the evidence.
   * Recorded for the audit trail; it does not change the score by design.
   */
  injectionAttempt?: boolean;
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface RemediationStep {
  checkId: string;
  title: string;
  action: string;
  severity: Severity;
  effort: EffortPoints;
  /** Points of risk this step removes. */
  riskReduction: number;
  /** riskReduction / effort — the ordering key. */
  efficiency: number;
  /** Plain-language justification shown to the user. */
  reasoning: string;
  /** Position in the ranked list, 1-based. */
  rank: number;
}

export interface RemediationPlan {
  budgetLimit: EffortPoints;
  budgetUsed: EffortPoints;
  steps: RemediationStep[];
  /** Items that did not fit the budget, with why. */
  deferred: Array<{
    checkId: string;
    title: string;
    effort: EffortPoints;
    riskReduction: number;
    reason: string;
  }>;
  /** Projected score if every included step is completed. */
  projectedScore: number;
  projectedGrade: Grade;
  /** How the agent arrived at this ordering. */
  strategy: string;
}

export interface ScanOutcome {
  hostname: string;
  findings: Finding[];
  score: number;
  grade: Grade;
  plan: RemediationPlan;
  testsslVersion: string | null;
  /** Checks that could not run, and why. A partial scan says so. */
  degraded: Array<{ step: string; reason: string }>;
  startedAt: Date;
  completedAt: Date;
}

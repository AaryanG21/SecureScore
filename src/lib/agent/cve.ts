import "server-only";
import {
  CVE_DATASET,
  versionAffected,
  type CveRecord,
} from "@/lib/agent/cve-dataset";
import { finalizeFinding } from "@/lib/agent/scoring";
import type { Finding, Severity } from "@/lib/agent/types";
import type { Fingerprint } from "@/lib/agent/fingerprint";

/**
 * CVE and EPSS cross-reference.
 *
 * Turns "the target says it runs nginx 1.18.0" into concrete findings with
 * a defensible exploitability figure.
 *
 * The EPSS choice is the interesting part of the model. CVSS says how bad a
 * vulnerability would be if exploited; EPSS (FIRST.org) estimates the
 * probability it actually IS exploited in the next 30 days. Those are
 * different questions, and a remediation plan that ignores the second one
 * sends people to fix theoretical 9.8s while a widely-exploited 7.5 sits
 * open. So:
 *
 *     severity       <- CVSS band
 *     exploitability <- EPSS probability
 *
 * Both are published numbers from a third party's model. Neither can be
 * influenced by the scanned target — the target's only input is the version
 * string, and that selects WHICH records apply, not what they score.
 */

/**
 * Version claims are self-reported, so exposure is discounted: we are
 * confident the CVE exists, not that this host is genuinely running the
 * version it advertises.
 */
const VERSION_ASSERTED_EXPOSURE = 0.7;

/** CVSS base score to our severity band. */
function severityFromCvss(cvss: number): Severity {
  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "INFO";
}

/**
 * Maps an EPSS probability onto the 0-1 exploitability axis.
 *
 * Not the identity function. EPSS is heavily skewed — most CVEs sit below
 * 0.01 — and using it raw would flatten almost everything to zero risk.
 * A square-root curve keeps the ordering EPSS gives while preserving enough
 * separation at the low end for the ranking to be useful, with a floor so a
 * known vulnerability is never scored as entirely unexploitable.
 */
export function exploitabilityFromEpss(epss: number): number {
  if (!Number.isFinite(epss) || epss <= 0) return 0.1;
  return Math.min(1, Math.max(0.1, Math.sqrt(epss)));
}

export interface CveMatch {
  record: CveRecord;
  product: string;
  version: string;
}

/** Finds dataset entries whose product and version range cover a fingerprint. */
export function matchCves(fingerprints: Fingerprint[]): CveMatch[] {
  const matches: CveMatch[] = [];

  for (const fp of fingerprints) {
    // No version means nothing to range-check. Reporting every CVE ever
    // filed against a product because its name appeared in a header would
    // be noise, not a finding.
    if (!fp.version) continue;

    for (const record of CVE_DATASET) {
      if (record.product !== fp.product) continue;
      if (!versionAffected(fp.version, record)) continue;
      matches.push({ record, product: fp.product, version: fp.version });
    }
  }

  return matches;
}

export function cveFindings(matches: CveMatch[]): Finding[] {
  return matches.map(({ record, product, version }) =>
    finalizeFinding({
      checkId: `cve:${record.id}`,
      source: "cve",
      title: `${record.id}: ${record.title}`,
      description:
        `${product} ${version} falls within the affected range for ${record.id} ` +
        `(CVSS ${record.cvss.toFixed(1)}, EPSS ${(record.epss * 100).toFixed(1)}% chance of ` +
        `exploitation in the next 30 days). The version is self-reported by the target, ` +
        `so this is a strong indication rather than a confirmed exploit.`,
      remediation: record.remediation,
      severity: severityFromCvss(record.cvss),
      exploitability: exploitabilityFromEpss(record.epss),
      exposure: VERSION_ASSERTED_EXPOSURE,
      effort: record.effort,
      evidence: `${product}/${version} matched ${record.id} (affected: ${record.introduced ?? "any"} to ${record.fixed ?? "unfixed"})`,
      cves: [record.id],
      epss: record.epss,
    }),
  );
}

/**
 * Optional live EPSS refresh.
 *
 * Off by default and never required for a scan to complete. When it is
 * called and the API is unreachable or slow, the bundled snapshot values
 * stand and the caller is told the data is stale — a scan that silently
 * used month-old probabilities while implying they were current would be
 * the worse failure.
 *
 * Note the privacy trade-off, which is why this is opt-in: querying
 * FIRST.org per scan discloses which CVEs you are interested in, and by
 * timing, roughly when you scanned something.
 */
export async function refreshEpss(
  cveIds: string[],
  opts: { timeoutMs?: number } = {},
): Promise<{ scores: Map<string, number>; stale: boolean; reason?: string }> {
  const scores = new Map<string, number>();
  if (cveIds.length === 0) return { scores, stale: false };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 5_000);

  try {
    const url = new URL("https://api.first.org/data/v1/epss");
    url.searchParams.set("cve", cveIds.slice(0, 50).join(","));

    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
      cache: "no-store",
    });

    if (!response.ok) {
      return { scores, stale: true, reason: `EPSS API returned ${response.status}` };
    }

    const body = (await response.json()) as {
      data?: Array<{ cve?: string; epss?: string }>;
    };

    for (const row of body.data ?? []) {
      if (!row.cve || !row.epss) continue;
      const value = Number.parseFloat(row.epss);
      if (Number.isFinite(value) && value >= 0 && value <= 1) {
        scores.set(row.cve.toUpperCase(), value);
      }
    }

    return { scores, stale: false };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      scores,
      stale: true,
      reason: aborted ? "EPSS lookup timed out" : "EPSS lookup failed",
    };
  } finally {
    clearTimeout(timer);
  }
}

// Re-exported for server-side callers; defined in the dataset module so
// the UI can import it without the server-only scanning code.
export { CVE_COVERAGE_NOTE } from "@/lib/agent/cve-dataset";

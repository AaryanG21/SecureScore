import "server-only";
import { parseProductVersion, sanitizeScannedText } from "@/lib/agent/sanitize";
import { finalizeFinding } from "@/lib/agent/scoring";
import type { Finding } from "@/lib/agent/types";
import type { HeaderProbe } from "@/lib/agent/headers";

/**
 * Technology fingerprinting.
 *
 * Identifies server software and versions from response headers, so the CVE
 * cross-reference has something to look up.
 *
 * A fingerprint is an ASSERTION BY THE TARGET, not a fact. A server can
 * claim any banner it likes — including one designed to make the scanner
 * report a vulnerability the site does not have, or to smuggle instruction
 * text. Two consequences are built in here:
 *
 *   - A fingerprint on its own is never a finding with risk. It becomes one
 *     only through the CVE cross-reference, and those findings are marked
 *     as version-asserted so the scorecard can say so plainly.
 *   - Only the leading `product/version` token of a banner is parsed. The
 *     remainder — where payloads invariably live — is evidence only.
 */

export interface Fingerprint {
  product: string;
  version: string | null;
  /** Which header the claim came from. */
  sourceHeader: string;
  /** The sanitized raw value, for display. */
  evidence: string;
  injectionAttempt: boolean;
}

/** Headers that conventionally carry a product identity. */
const FINGERPRINT_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-generator",
];

/**
 * Products we are willing to act on. An allowlist rather than a
 * free-for-all: it keeps a target from inventing a product name that
 * happens to collide with a high-severity entry in the CVE dataset.
 */
const KNOWN_PRODUCTS = new Set([
  "nginx",
  "apache",
  "openssl",
  "iis",
  "microsoft-iis",
  "lighttpd",
  "caddy",
  "tomcat",
  "jetty",
  "node",
  "express",
  "php",
  "wordpress",
  "drupal",
  "haproxy",
  "envoy",
  "traefik",
  "gunicorn",
  "uvicorn",
  "litespeed",
  "openresty",
]);

export function fingerprint(probe: HeaderProbe): Fingerprint[] {
  if (!probe.ok || !probe.headers) return [];

  const results: Fingerprint[] = [];

  for (const header of FINGERPRINT_HEADERS) {
    const raw = probe.headers.get(header);
    if (!raw) continue;

    const evidence = sanitizeScannedText(raw);
    const parsed = parseProductVersion(raw);
    if (!parsed) continue;

    // Normalize a couple of spellings the same product shows up under.
    const product =
      parsed.product === "microsoft-iis" ? "iis" : parsed.product;

    if (!KNOWN_PRODUCTS.has(product)) continue;

    results.push({
      product,
      version: parsed.version,
      sourceHeader: header,
      evidence: evidence.text,
      injectionAttempt: evidence.injectionAttempt,
    });
  }

  return dedupe(results);
}

function dedupe(items: Fingerprint[]): Fingerprint[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.product}@${item.version ?? "?"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * An informational finding recording what the target claimed to be.
 *
 * Severity INFO, which means `computeOverallScore` excludes it from the
 * grade entirely. It exists so the scorecard can show its reasoning — "we
 * looked up CVEs for nginx 1.18.0 because the Server header said so" — and
 * so the user can see when a banner is lying to us.
 */
export function fingerprintFindings(fingerprints: Fingerprint[]): Finding[] {
  return fingerprints.map((fp) =>
    finalizeFinding({
      checkId: `fingerprint:${fp.product}`,
      source: "fingerprint",
      title: fp.version
        ? `Identified ${fp.product} ${fp.version}`
        : `Identified ${fp.product} (no version disclosed)`,
      description:
        "Reported by the target in a response header. This is the target's own claim about itself, not a verified fact, and it is used only to select which CVEs to look up.",
      remediation:
        "No action required for the identification itself. See any associated CVE findings.",
      severity: "INFO",
      exploitability: 0,
      exposure: 0,
      effort: 0,
      evidence: `${fp.sourceHeader}: ${fp.evidence}`,
      ...(fp.injectionAttempt ? { injectionAttempt: true } : {}),
    }),
  );
}

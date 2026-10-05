import "server-only";
import { normalizeHostname } from "@/lib/validation/hostname";
import { safeHttpsGet } from "@/lib/net/safe-request";
import { sanitizeScannedText } from "@/lib/agent/sanitize";
import { finalizeFinding } from "@/lib/agent/scoring";
import type { Finding, Severity } from "@/lib/agent/types";

/**
 * HTTP security-header and cookie-flag checks.
 *
 * Makes one request to the target and evaluates the response headers. Same
 * discipline as everywhere else in the agent: the conclusion ("HSTS is
 * missing") drives severity, and the header's actual text is retained only
 * as evidence.
 *
 * Request hardening — this is an outbound request to a host a user named,
 * so it gets the same treatment as the domain-verification fetch:
 *   - hostname re-canonicalized here, not trusted from the caller
 *   - redirects not followed (a redirect into link-local address space is
 *     the standard SSRF pivot to cloud instance metadata)
 *   - hard timeout, and the body is never read — only headers are needed
 */

const FETCH_TIMEOUT_MS = 15_000;

export interface HeaderProbe {
  ok: boolean;
  status?: number;
  headers?: Headers;
  reason?: string;
  /** Set when the target answered with a redirect we declined to follow. */
  redirected?: boolean;
}

export async function probeHeaders(hostname: string): Promise<HeaderProbe> {
  const normalized = normalizeHostname(hostname);
  if (!normalized.ok) return { ok: false, reason: normalized.reason };

  // safeHttpsGet resolves the name, refuses non-public answers and pins the
  // connection to the address it vetted. Omitting maxBytes means the body
  // is never read: only headers are needed, and not reading it means a
  // target cannot feed us megabytes of content.
  const result = await safeHttpsGet({
    hostname: normalized.hostname,
    path: "/",
    timeoutMs: FETCH_TIMEOUT_MS,
    headers: {
      "User-Agent": "Fulcrum-Scanner/1.0 (+security scorecard; authorized scan)",
      Accept: "text/html,application/xhtml+xml",
    },
  });

  if (!result.ok) {
    return {
      ok: false,
      reason:
        result.kind === "timeout"
          ? "The target did not respond within the timeout"
          : result.kind === "refused"
            ? result.reason
            : "Could not establish an HTTPS connection to the target",
    };
  }

  return {
    ok: true,
    status: result.status,
    headers: result.headers,
    redirected: result.status >= 300 && result.status < 400,
  };
}

interface HeaderRule {
  checkId: string;
  header: string;
  title: string;
  description: string;
  remediation: string;
  missingSeverity: Severity;
  exploitability: number;
  exposure: number;
  effort: number;
  /**
   * Extra validation when the header IS present. Returning a string means
   * "present but inadequate", and that string is OUR description of the
   * problem — never the header's own text.
   */
  validate?: (value: string) => { problem: string; severity: Severity } | null;
}

const HEADER_RULES: HeaderRule[] = [
  {
    checkId: "header:hsts",
    header: "strict-transport-security",
    title: "HTTP Strict Transport Security not enforced",
    description:
      "Without HSTS a browser will try plain HTTP first on a fresh visit, which leaves room for an active network attacker to strip TLS before the redirect happens.",
    remediation:
      "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.",
    missingSeverity: "HIGH",
    exploitability: 0.5,
    exposure: 0.9,
    effort: 2,
    validate: (value) => {
      const maxAge = /max-age=(\d+)/i.exec(value);
      if (!maxAge) {
        return { problem: "HSTS is present but sets no max-age", severity: "MEDIUM" };
      }
      if (Number(maxAge[1]) < 15_552_000) {
        return {
          problem: "HSTS max-age is below the recommended six months",
          severity: "LOW",
        };
      }
      return null;
    },
  },
  {
    checkId: "header:csp",
    header: "content-security-policy",
    title: "No Content Security Policy",
    description:
      "A CSP is the main structural defence against cross-site scripting. Without one, any injected script executes with the full authority of the page.",
    remediation:
      "Add a Content-Security-Policy. Start with `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` and tighten from there.",
    missingSeverity: "HIGH",
    exploitability: 0.6,
    exposure: 0.8,
    effort: 13,
    validate: (value) => {
      const lowered = value.toLowerCase();
      if (lowered.includes("unsafe-inline") && lowered.includes("script-src")) {
        return {
          problem:
            "CSP allows 'unsafe-inline' for scripts, which removes most of its XSS protection",
          severity: "MEDIUM",
        };
      }
      if (!lowered.includes("default-src") && !lowered.includes("script-src")) {
        return {
          problem: "CSP defines neither default-src nor script-src",
          severity: "MEDIUM",
        };
      }
      return null;
    },
  },
  {
    checkId: "header:x_frame_options",
    header: "x-frame-options",
    title: "No clickjacking protection",
    description:
      "Neither X-Frame-Options nor a CSP frame-ancestors directive was found, so the page can be framed by any site and used for clickjacking.",
    remediation:
      "Send `X-Frame-Options: DENY`, and `frame-ancestors 'none'` in the CSP for modern browsers.",
    missingSeverity: "MEDIUM",
    exploitability: 0.4,
    exposure: 0.7,
    effort: 1,
  },
  {
    checkId: "header:x_content_type_options",
    header: "x-content-type-options",
    title: "MIME sniffing not disabled",
    description:
      "Without `nosniff`, a browser may reinterpret a response as a different content type — turning an uploaded file into executable script.",
    remediation: "Send `X-Content-Type-Options: nosniff` on every response.",
    missingSeverity: "LOW",
    exploitability: 0.3,
    exposure: 0.6,
    effort: 1,
  },
  {
    checkId: "header:referrer_policy",
    header: "referrer-policy",
    title: "No Referrer-Policy",
    description:
      "Full URLs — which often carry identifiers or tokens in the path — are sent to third-party origins by default.",
    remediation: "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    missingSeverity: "LOW",
    exploitability: 0.2,
    exposure: 0.5,
    effort: 1,
  },
  {
    checkId: "header:permissions_policy",
    header: "permissions-policy",
    title: "No Permissions-Policy",
    description:
      "Powerful browser features (camera, microphone, geolocation) are not explicitly denied, leaving them available to any script that runs on the page.",
    remediation:
      "Send a Permissions-Policy denying the features the site does not use.",
    missingSeverity: "LOW",
    exploitability: 0.2,
    exposure: 0.4,
    effort: 2,
  },
];

/** Headers that disclose software detail without any benefit. */
const DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"];

export function evaluateHeaders(probe: HeaderProbe): Finding[] {
  if (!probe.ok || !probe.headers) return [];

  const findings: Finding[] = [];
  const headers = probe.headers;

  const csp = headers.get("content-security-policy") ?? "";
  const cspHasFrameAncestors = /frame-ancestors/i.test(csp);

  for (const rule of HEADER_RULES) {
    const raw = headers.get(rule.header);

    // Clickjacking is covered by either mechanism; do not report it twice.
    if (rule.checkId === "header:x_frame_options" && cspHasFrameAncestors && !raw) {
      continue;
    }

    if (!raw) {
      findings.push(
        finalizeFinding({
          checkId: rule.checkId,
          source: "headers",
          title: rule.title,
          description: rule.description,
          remediation: rule.remediation,
          severity: rule.missingSeverity,
          exploitability: rule.exploitability,
          exposure: rule.exposure,
          effort: rule.effort,
          evidence: `Response did not include ${rule.header}`,
        }),
      );
      continue;
    }

    const evidence = sanitizeScannedText(raw);
    const problem = rule.validate?.(evidence.text) ?? null;

    if (problem) {
      findings.push(
        finalizeFinding({
          checkId: `${rule.checkId}:weak`,
          source: "headers",
          title: problem.problem,
          description: rule.description,
          remediation: rule.remediation,
          severity: problem.severity,
          exploitability: rule.exploitability,
          exposure: rule.exposure,
          effort: Math.max(1, Math.round(rule.effort / 2)),
          evidence: evidence.text,
          ...(evidence.injectionAttempt ? { injectionAttempt: true } : {}),
        }),
      );
    }
  }

  findings.push(...evaluateDisclosure(headers));
  findings.push(...evaluateCookies(headers));

  return findings;
}

function evaluateDisclosure(headers: Headers): Finding[] {
  const disclosed: string[] = [];

  for (const name of DISCLOSURE_HEADERS) {
    const value = headers.get(name);
    if (!value) continue;

    const evidence = sanitizeScannedText(value);
    // A bare product name is mild; a version number is what actually helps
    // an attacker select an exploit.
    if (/\d+\.\d+/.test(evidence.text)) {
      disclosed.push(`${name}: ${evidence.text}`);
    }
  }

  if (disclosed.length === 0) return [];

  const evidence = sanitizeScannedText(disclosed.join(" | "));

  return [
    finalizeFinding({
      checkId: "header:version_disclosure",
      source: "headers",
      title: "Software versions disclosed in response headers",
      description:
        "Exact version numbers let an attacker skip reconnaissance and go straight to a matching exploit. This is not itself a vulnerability, but it lowers the cost of finding one.",
      remediation:
        "Suppress or genericize Server, X-Powered-By, and similar headers at the web server or reverse proxy.",
      severity: "LOW",
      exploitability: 0.3,
      exposure: 0.5,
      effort: 2,
      evidence: evidence.text,
      ...(evidence.injectionAttempt ? { injectionAttempt: true } : {}),
    }),
  ];
}

function evaluateCookies(headers: Headers): Finding[] {
  const setCookies = headers.getSetCookie?.() ?? [];
  if (setCookies.length === 0) return [];

  const problems: string[] = [];

  for (const cookie of setCookies) {
    const clean = sanitizeScannedText(cookie).text;
    // Only the cookie's NAME is reported, never its value — a session
    // cookie's value is exactly the thing that must not end up in a stored
    // scan result.
    const name = clean.split("=")[0]?.trim().slice(0, 64) ?? "unnamed";
    const attrs = clean.toLowerCase();

    const missing: string[] = [];
    if (!attrs.includes("secure")) missing.push("Secure");
    if (!attrs.includes("httponly")) missing.push("HttpOnly");
    if (!attrs.includes("samesite")) missing.push("SameSite");

    if (missing.length > 0) problems.push(`${name} (missing ${missing.join(", ")})`);
  }

  if (problems.length === 0) return [];

  return [
    finalizeFinding({
      checkId: "header:cookie_flags",
      source: "headers",
      title: "Cookies set without full protective flags",
      description:
        "Cookies missing Secure can be sent over plain HTTP; missing HttpOnly are readable by injected script; missing SameSite are attachable to cross-site requests.",
      remediation:
        "Set Secure, HttpOnly, and SameSite=Lax or Strict on every cookie that carries session or identity state.",
      severity: "MEDIUM",
      exploitability: 0.5,
      exposure: 0.7,
      effort: 3,
      // Names only. Values are deliberately never captured.
      evidence: problems.slice(0, 10).join("; "),
    }),
  ];
}

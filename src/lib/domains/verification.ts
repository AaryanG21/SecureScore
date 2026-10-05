import "server-only";
import { resolveTxt } from "node:dns/promises";
import { randomToken } from "@/lib/crypto";
import { normalizeHostname } from "@/lib/validation/hostname";
import { safeHttpsGet } from "@/lib/net/safe-request";

/**
 * Domain ownership verification.
 *
 * This is the gate the whole safety story rests on: the scanner will only
 * ever touch a hostname whose owner proved control of it here. Two
 * challenge methods are supported, both requiring write access to
 * something only the domain owner controls.
 *
 *   DNS_TXT          a TXT record at _fulcrum-challenge.<hostname>
 *   HTTP_WELL_KNOWN  a file at https://<hostname>/.well-known/fulcrum-challenge.txt
 *
 * DNS is the stronger of the two — publishing a DNS record needs registrar
 * or nameserver control, whereas the HTTP method can be satisfied by
 * anyone who can write to the webroot (a shared-hosting tenant, say). The
 * UI recommends DNS accordingly.
 */

export const DNS_CHALLENGE_PREFIX = "_fulcrum-challenge";
export const HTTP_CHALLENGE_PATH = "/.well-known/fulcrum-challenge.txt";

/** How long the challenge fetch may take before it is abandoned. */
const HTTP_TIMEOUT_MS = 10_000;
/** A challenge file is ~80 bytes; anything larger is not worth reading. */
const MAX_RESPONSE_BYTES = 4096;

export function generateVerificationToken(): string {
  return `fulcrum-verify=${randomToken(24)}`;
}

export type VerificationOutcome =
  | { verified: true; method: "DNS_TXT" | "HTTP_WELL_KNOWN"; evidence: string }
  | { verified: false; reason: string };

/**
 * Looks for the challenge token in a TXT record.
 *
 * All TXT records at the challenge name are checked, because domains
 * routinely carry several, and a record is matched by exact string
 * equality rather than substring — "contains" would let an attacker who
 * can add any TXT record to a subdomain they control smuggle a token in.
 */
export async function verifyDnsTxt(
  hostname: string,
  expectedToken: string,
): Promise<VerificationOutcome> {
  const normalized = normalizeHostname(hostname);
  if (!normalized.ok) return { verified: false, reason: normalized.reason };

  const name = `${DNS_CHALLENGE_PREFIX}.${normalized.hostname}`;

  let records: string[][];
  try {
    records = await resolveTxt(name);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
    return {
      verified: false,
      reason:
        code === "ENOTFOUND" || code === "ENODATA"
          ? `No TXT record found at ${name}. DNS changes can take a few minutes to propagate.`
          : `DNS lookup failed (${code}).`,
    };
  }

  // A TXT record arrives as an array of chunks that must be joined.
  const values = records.map((chunks) => chunks.join(""));

  if (!values.some((v) => v.trim() === expectedToken)) {
    return {
      verified: false,
      reason: `Found ${values.length} TXT record(s) at ${name}, none matching the expected token.`,
    };
  }

  return { verified: true, method: "DNS_TXT", evidence: name };
}

/**
 * Looks for the challenge token in a well-known file.
 *
 * Hardening on this request, because it is the one place the app reaches
 * out to a host the caller named BEFORE that host has been proven theirs:
 *   - the hostname is re-normalized here, not trusted from the caller
 *   - redirects are not followed (a redirect to 169.254.169.254 is the
 *     classic SSRF pivot to cloud instance metadata)
 *   - the name is resolved and non-public answers are refused, and the
 *     connection is pinned to the vetted address so a rebinding answer
 *     cannot land somewhere else — see lib/net/safe-request.ts
 *   - there is a hard timeout and a response size cap
 *   - only https is attempted
 */
export async function verifyHttpWellKnown(
  hostname: string,
  expectedToken: string,
): Promise<VerificationOutcome> {
  const normalized = normalizeHostname(hostname);
  if (!normalized.ok) return { verified: false, reason: normalized.reason };

  const url = `https://${normalized.hostname}${HTTP_CHALLENGE_PATH}`;

  const result = await safeHttpsGet({
    hostname: normalized.hostname,
    path: HTTP_CHALLENGE_PATH,
    timeoutMs: HTTP_TIMEOUT_MS,
    maxBytes: MAX_RESPONSE_BYTES,
    headers: { "User-Agent": "Fulcrum-DomainVerification/1.0" },
  });

  if (!result.ok) {
    if (result.kind === "refused") {
      // Said plainly: it is the caller's own DNS that points somewhere it
      // should not, and they are the one person who can fix it.
      return { verified: false, reason: result.reason };
    }
    return {
      verified: false,
      reason:
        result.kind === "timeout"
          ? "Challenge URL timed out."
          : "Could not reach the challenge URL over HTTPS.",
    };
  }

  if (result.status >= 300 && result.status < 400) {
    return {
      verified: false,
      reason:
        "The challenge URL redirected. Serve the file directly at that path — redirects are not followed.",
    };
  }

  if (result.status < 200 || result.status >= 300) {
    return { verified: false, reason: `Challenge URL returned HTTP ${result.status}.` };
  }

  if (result.bodyTooLarge || result.body === undefined) {
    return { verified: false, reason: "Challenge file is too large." };
  }

  if (result.body.trim() !== expectedToken) {
    return {
      verified: false,
      reason: "Challenge file did not contain the expected token.",
    };
  }

  return { verified: true, method: "HTTP_WELL_KNOWN", evidence: url };
}

export async function runVerification(
  method: "DNS_TXT" | "HTTP_WELL_KNOWN",
  hostname: string,
  expectedToken: string,
): Promise<VerificationOutcome> {
  return method === "DNS_TXT"
    ? verifyDnsTxt(hostname, expectedToken)
    : verifyHttpWellKnown(hostname, expectedToken);
}

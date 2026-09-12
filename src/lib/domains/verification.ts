import "server-only";
import { resolveTxt } from "node:dns/promises";
import { randomToken } from "@/lib/crypto";
import { normalizeHostname } from "@/lib/validation/hostname";

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
 * Hardening on this fetch, because it is the one place the app makes an
 * outbound request to a user-supplied host:
 *   - the hostname is re-normalized here, not trusted from the caller
 *   - redirects are not followed (a redirect to 169.254.169.254 is the
 *     classic SSRF pivot to cloud instance metadata)
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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { "User-Agent": "Fulcrum-DomainVerification/1.0" },
      cache: "no-store",
    });

    if (response.status >= 300 && response.status < 400) {
      return {
        verified: false,
        reason:
          "The challenge URL redirected. Serve the file directly at that path — redirects are not followed.",
      };
    }

    if (!response.ok) {
      return { verified: false, reason: `Challenge URL returned HTTP ${response.status}.` };
    }

    const body = await readCapped(response, MAX_RESPONSE_BYTES);
    if (body === null) {
      return { verified: false, reason: "Challenge file is too large." };
    }

    if (body.trim() !== expectedToken) {
      return {
        verified: false,
        reason: "Challenge file did not contain the expected token.",
      };
    }

    return { verified: true, method: "HTTP_WELL_KNOWN", evidence: url };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      verified: false,
      reason: aborted
        ? "Challenge URL timed out."
        : "Could not reach the challenge URL over HTTPS.",
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Reads at most `limit` bytes, returning null if the body exceeds it. */
async function readCapped(response: Response, limit: number): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return "";

  const chunks: Uint8Array[] = [];
  let total = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;

    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  return new TextDecoder().decode(
    chunks.reduce<Uint8Array>((acc, chunk) => {
      const merged = new Uint8Array(acc.length + chunk.length);
      merged.set(acc);
      merged.set(chunk, acc.length);
      return merged;
    }, new Uint8Array()),
  );
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

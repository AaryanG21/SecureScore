/**
 * Hostname canonicalization for the authorization allowlist.
 *
 * This module has one job and it is a security job: turn user input into a
 * single canonical hostname string, or refuse. Everything downstream —
 * ownership verification, the allowlist lookup, the argument handed to
 * testssl.sh — compares against this canonical form.
 *
 * Rejections are deliberate, not incidental:
 *   - No scheme, path, query, userinfo, or port. "example.com:22@evil.com"
 *     and "example.com/../other" must not sneak past a string comparison.
 *   - No IP literals. Ownership of an IP is not verifiable by the DNS-TXT
 *     or well-known-file challenge this app implements, and allowing them
 *     opens SSRF-flavoured scanning of internal ranges.
 *   - No localhost or *.localhost, and no trailing-dot ambiguity.
 *   - Unicode is IDNA-encoded to punycode, so visually-confusable domains
 *     cannot masquerade as an allowlisted one.
 *
 * Note this is NOT a shell-escaping function. The testssl.sh integration
 * passes the hostname as a separate argv entry to execFile (never through a
 * shell), and this validator is the second layer that ensures the value
 * could not be meaningful to a shell even if one were introduced later.
 */

export type NormalizeResult =
  | { ok: true; hostname: string }
  | { ok: false; reason: string };

/** RFC 1123 label: alphanumeric with internal hyphens, 1-63 chars. */
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

const BLOCKED_SUFFIXES = [
  "localhost",
  ".localhost",
  ".local",
  ".internal",
  ".localdomain",
];

export function normalizeHostname(input: string): NormalizeResult {
  let value = input.trim();

  if (value.length === 0) return { ok: false, reason: "Enter a hostname" };
  if (value.length > 253) return { ok: false, reason: "Hostname is too long" };

  // Whitespace and control characters are never valid in a hostname and
  // are a classic way to smuggle argument or header separators.
  if (/[\s\u0000-\u001f\u007f]/.test(value)) {
    return { ok: false, reason: "Hostname contains invalid characters" };
  }

  // Accept a pasted URL, but only by parsing it properly and taking the
  // host component — never by string-trimming a prefix.
  if (value.includes("://")) {
    try {
      const url = new URL(value);
      if (url.username || url.password) {
        return { ok: false, reason: "Credentials are not allowed in a hostname" };
      }
      if (url.port) {
        return { ok: false, reason: "Specify the hostname without a port" };
      }
      value = url.hostname;
    } catch {
      return { ok: false, reason: "Enter a valid hostname" };
    }
  }

  if (value.includes("@")) {
    return { ok: false, reason: "Credentials are not allowed in a hostname" };
  }
  if (value.includes("/") || value.includes("?") || value.includes("#")) {
    return { ok: false, reason: "Enter the hostname only, without a path" };
  }
  if (value.includes(":")) {
    return { ok: false, reason: "Specify the hostname without a port" };
  }

  // A trailing dot is technically the fully-qualified form, but allowing
  // both "example.com" and "example.com." would create two rows that look
  // different and resolve identically.
  value = value.replace(/\.$/, "").toLowerCase();

  // IDNA / punycode. URL's host parser performs this for us and also
  // rejects mixed-script tricks that a hand-rolled regex would miss.
  let ascii: string;
  try {
    ascii = new URL(`https://${value}`).hostname;
  } catch {
    return { ok: false, reason: "Enter a valid hostname" };
  }

  if (ascii !== value && !/^[a-z0-9.-]+$/.test(value)) {
    // Unicode input was converted; keep the ASCII form.
    value = ascii;
  } else {
    value = ascii;
  }

  if (IPV4.test(value) || value.includes("[") || value.includes("]")) {
    return {
      ok: false,
      reason: "Register a domain name, not an IP address — ownership of an IP cannot be verified here",
    };
  }

  const labels = value.split(".");
  if (labels.length < 2) {
    return { ok: false, reason: "Enter a fully-qualified domain, e.g. example.com" };
  }

  for (const label of labels) {
    if (!LABEL.test(label)) {
      return { ok: false, reason: "Hostname contains an invalid label" };
    }
  }

  const tld = labels.at(-1)!;
  if (!/^[a-z]{2,63}$/.test(tld)) {
    return { ok: false, reason: "Hostname has an invalid top-level domain" };
  }

  for (const suffix of BLOCKED_SUFFIXES) {
    if (value === suffix.replace(/^\./, "") || value.endsWith(suffix)) {
      return {
        ok: false,
        reason: "Internal and loopback hostnames cannot be scanned",
      };
    }
  }

  return { ok: true, hostname: value };
}

/**
 * Strict equality against the canonical form. Used by the allowlist so that
 * comparison never happens on raw user input.
 */
export function hostnameMatches(candidate: string, allowlisted: string): boolean {
  const a = normalizeHostname(candidate);
  const b = normalizeHostname(allowlisted);
  return a.ok && b.ok && a.hostname === b.hostname;
}

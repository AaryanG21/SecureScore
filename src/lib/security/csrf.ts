import "server-only";
import { getEnv } from "@/lib/env";
import { randomToken, safeEqual } from "@/lib/crypto";
import { CSRF_COOKIE, setAuthCookie, readCookie } from "@/lib/auth/cookies";

/**
 * CSRF protection: double-submit cookie + origin check.
 *
 * Two independent checks, because each covers the other's gap:
 *
 *   1. Origin/Referer must match APP_ORIGIN. Cheap, and blocks the common
 *      cross-site form post outright.
 *   2. The X-CSRF-Token header must equal the fulcrum_csrf cookie. This is
 *      the actual double-submit: a cross-site attacker can cause the cookie
 *      to be sent but cannot read it to populate the header.
 *
 * SameSite=Strict on the session cookies already blocks most of this class,
 * but SameSite is a browser behaviour, not a guarantee — it is defence in
 * depth, not the only defence.
 */

const CSRF_HEADER = "x-csrf-token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export type CsrfFailure = "origin_mismatch" | "missing_token" | "token_mismatch";

export type CsrfResult = { ok: true } | { ok: false; reason: CsrfFailure };

/**
 * Issues a CSRF token cookie. Readable by client JS on purpose — that is
 * how the browser echoes it back in the header. It carries no authority on
 * its own; it only has to be unguessable by a cross-origin attacker.
 */
export async function issueCsrfToken(): Promise<string> {
  const token = randomToken(32);
  await setAuthCookie({
    name: CSRF_COOKIE,
    value: token,
    httpOnly: false,
    maxAgeSeconds: getEnv().REFRESH_TOKEN_TTL_SECONDS,
  });
  return token;
}

function originAllowed(request: Request): boolean {
  const expected = new URL(getEnv().APP_ORIGIN).origin;

  const origin = request.headers.get("origin");
  if (origin) return origin === expected;

  // Some browsers omit Origin on same-origin form posts; fall back to
  // Referer. If neither is present we reject rather than assume.
  const referer = request.headers.get("referer");
  if (referer) {
    try {
      return new URL(referer).origin === expected;
    } catch {
      return false;
    }
  }

  return false;
}

export async function verifyCsrf(request: Request): Promise<CsrfResult> {
  if (SAFE_METHODS.has(request.method.toUpperCase())) return { ok: true };

  if (!originAllowed(request)) return { ok: false, reason: "origin_mismatch" };

  const headerToken = request.headers.get(CSRF_HEADER);
  const cookieToken = await readCookie(CSRF_COOKIE);

  if (!headerToken || !cookieToken) return { ok: false, reason: "missing_token" };
  if (!safeEqual(headerToken, cookieToken)) {
    return { ok: false, reason: "token_mismatch" };
  }

  return { ok: true };
}

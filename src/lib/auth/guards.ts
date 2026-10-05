import "server-only";
import type { NextResponse } from "next/server";
import { getSession, type SessionUser } from "@/lib/auth/session";
import { verifyCsrf } from "@/lib/security/csrf";
import { verifyReauthToken } from "@/lib/auth/tokens";
import { REAUTH_COOKIE, clearAuthCookie, readCookie } from "@/lib/auth/cookies";
import { checkRateLimit, type RateLimitName } from "@/lib/security/rate-limit";
import { apiError, apiRateLimited, getRequestMeta } from "@/lib/http";
import { writeAudit } from "@/lib/audit";

/**
 * Server-side authorization guards.
 *
 * Every protected route calls one of these. The client also hides admin UI
 * from non-admins, but that is cosmetic: the role check that actually
 * matters happens here, on the server, against the database row — never
 * against a claim the client sent.
 */

export type GuardResult<T> =
  | { ok: true; value: T }
  | { ok: false; response: NextResponse };

export interface GuardOptions {
  /** Applies a named rate-limit policy keyed on IP (+ user when known). */
  rateLimit?: RateLimitName;
  /** Skip CSRF (only for endpoints that are safe by construction). */
  skipCsrf?: boolean;
}

async function runCommonChecks(
  request: Request,
  options: GuardOptions,
  userId?: string,
): Promise<NextResponse | null> {
  const meta = getRequestMeta(request);

  if (options.rateLimit) {
    const key = `${meta.ipAddress ?? "unknown-ip"}|${userId ?? "anon"}`;
    const result = checkRateLimit(options.rateLimit, key);
    if (!result.allowed) {
      await writeAudit({
        actorUserId: userId ?? null,
        action: "RATE_LIMIT_TRIPPED",
        targetType: "Route",
        targetId: new URL(request.url).pathname,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { policy: options.rateLimit, strikes: result.strikes },
      });
      return apiRateLimited(result.retryAfterSeconds);
    }
  }

  if (!options.skipCsrf) {
    const csrf = await verifyCsrf(request);
    if (!csrf.ok) {
      await writeAudit({
        actorUserId: userId ?? null,
        action: "CSRF_REJECTED",
        targetType: "Route",
        targetId: new URL(request.url).pathname,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { reason: csrf.reason },
      });
      return apiError(403, "csrf_failed", "Request could not be verified.");
    }
  }

  return null;
}

/** Requires an authenticated, ACTIVE user with a live session. */
export async function requireUser(
  request: Request,
  options: GuardOptions = {},
): Promise<GuardResult<SessionUser>> {
  const session = await getSession();

  const blocked = await runCommonChecks(request, options, session?.id);
  if (blocked) return { ok: false, response: blocked };

  if (!session) {
    return {
      ok: false,
      response: apiError(401, "unauthenticated", "Sign in to continue."),
    };
  }

  return { ok: true, value: session };
}

/** Requires role ADMIN, re-read from the database on every request. */
export async function requireAdmin(
  request: Request,
  options: GuardOptions = {},
): Promise<GuardResult<SessionUser>> {
  const result = await requireUser(request, options);
  if (!result.ok) return result;

  if (result.value.role !== "ADMIN") {
    const meta = getRequestMeta(request);
    await writeAudit({
      actorUserId: result.value.id,
      action: "FORBIDDEN_ROLE_ACCESS",
      targetType: "Route",
      targetId: new URL(request.url).pathname,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { requiredRole: "ADMIN", actualRole: result.value.role },
    });

    // 404-style opacity is tempting here, but a plain 403 is more honest
    // and the route list is not itself a secret.
    return {
      ok: false,
      response: apiError(403, "forbidden", "Administrator access required."),
    };
  }

  return result;
}

/**
 * Requires ADMIN *and* a re-authentication performed within
 * REAUTH_TTL_SECONDS. Used for destructive admin actions so that a
 * walked-away-from session cannot be used to suspend users.
 */
export async function requireAdminWithReauth(
  request: Request,
  options: GuardOptions = {},
): Promise<GuardResult<SessionUser>> {
  const result = await requireAdmin(request, options);
  if (!result.ok) return result;

  const token = await readCookie(REAUTH_COOKIE);
  const claims = token ? await verifyReauthToken(token) : null;

  if (!claims || claims.sub !== result.value.id) {
    return {
      ok: false,
      response: apiError(
        401,
        "reauth_required",
        "Confirm your password and 2FA code to perform this action.",
      ),
    };
  }

  // Spend the step-up. One confirmation authorises one action.
  //
  // Previously the cookie survived for its full lifetime, so a single
  // password+TOTP confirmation silently authorised every destructive admin
  // action taken in the next five minutes. That is the opposite of what
  // step-up authentication is for: the point is to tie an explicit
  // confirmation to a specific consequential act, and a reusable token
  // turns it back into an ambient privilege. The admin console already
  // prompts before each action, so clearing it here costs nothing and
  // closes the gap for any other caller.
  //
  // Note the limit of this: the token is a stateless JWT, so clearing the
  // cookie is what prevents reuse. It is httpOnly and SameSite=strict, but
  // an attacker who had already exfiltrated the value could still present
  // it until it expires. Binding a one-time id in the database would close
  // that too, at the cost of a write on every admin action.
  await clearAuthCookie(REAUTH_COOKIE);

  return result;
}

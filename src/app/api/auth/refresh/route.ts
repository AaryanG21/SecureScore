import { type NextRequest } from "next/server";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { verifyCsrf } from "@/lib/security/csrf";
import { rotateSession } from "@/lib/auth/session";
import { recordAttempt } from "@/lib/auth/attempts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Exchanges the refresh token for a new access/refresh pair.
 *
 * POST, not GET, and CSRF-protected: a GET refresh endpoint can be
 * triggered cross-site by an <img> tag, which is a session-fixation
 * primitive. Rotation and reuse detection live in lib/auth/session.ts.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  const result = await rotateSession(meta);

  if (!result.ok) {
    await recordAttempt({
      email: "",
      stage: "REFRESH",
      success: false,
      reason: result.reason,
      ...meta,
    });

    // Token reuse is called out distinctly so the client can show "you were
    // signed out for your security" rather than a generic expiry message.
    const code = result.reason === "reuse" ? "session_revoked" : "refresh_failed";
    return apiError(401, code, "Your session has ended. Sign in again.");
  }

  return apiOk({ status: "refreshed" });
}

import { type NextRequest } from "next/server";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { enforceCsrf, enforceRateLimit } from "@/lib/auth/guards";
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

  const blocked = await enforceCsrf(request);
  if (blocked) return blocked;

  // Bounded per IP, and only when an IP is actually known.
  //
  // This endpoint is pre-session by nature — it is called because the
  // access token expired — so there is no account to key on. Falling back
  // to a shared "unknown-ip" bucket would put every user of the
  // deployment in one 60-per-hour counter and turn the limiter into a
  // self-inflicted outage, which is worse than the grinding it would
  // prevent. Where no IP is available the real defence is the reuse
  // detection in rotateSession, which revokes the whole family on the
  // second presentation of any token.
  if (meta.ipAddress) {
    const limited = await enforceRateLimit(request, "refresh", meta.ipAddress);
    if (limited) return limited;
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

import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { hashPassword } from "@/lib/auth/password";
import { parseJsonBody, registerSchema } from "@/lib/validation/schemas";
import { apiError, apiOk, apiRateLimited, getRequestMeta } from "@/lib/http";
import { checkRateLimit, ipAccountKey } from "@/lib/security/rate-limit";
import { verifyCsrf } from "@/lib/security/csrf";
import { writeAudit } from "@/lib/audit";
import { signMfaPendingToken } from "@/lib/auth/tokens";
import { MFA_COOKIE, setAuthCookie } from "@/lib/auth/cookies";
import { getEnv } from "@/lib/env";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Account registration.
 *
 * The new account lands in PENDING_2FA and receives an mfa-pending cookie,
 * not a session: 2FA enrollment is mandatory, so there is no state in which
 * a password alone yields a usable account.
 *
 * The response is identical whether or not the email was already
 * registered. Otherwise this endpoint becomes an account-enumeration
 * oracle, which is the standard finding against naive signup forms.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    await writeAudit({
      action: "CSRF_REJECTED",
      targetType: "Route",
      targetId: "/api/auth/register",
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { reason: csrf.reason },
    });
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  const body = await parseJsonBody(request, registerSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the highlighted fields.", body.fieldErrors);
  }

  const { email, password } = body.data;

  const limit = checkRateLimit("register", ipAccountKey(meta.ipAddress, email));
  if (!limit.allowed) return apiRateLimited(limit.retryAfterSeconds);

  const existing = await prisma.user.findUnique({
    where: { email },
    select: { id: true },
  });

  if (existing) {
    await writeAudit({
      action: "REGISTER",
      targetType: "User",
      targetId: existing.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { outcome: "duplicate_email_suppressed" },
    });

    // Deliberately the same shape and status as the success path. The
    // hashing cost below is skipped, which is a small timing difference;
    // a production hardening step would equalize it with a decoy hash.
    return apiOk({ status: "enrollment_required" }, 201);
  }

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: { email, passwordHash, status: "PENDING_2FA", role: "USER" },
    select: { id: true },
  });

  await writeAudit({
    actorUserId: user.id,
    action: "REGISTER",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { outcome: "created" },
  });

  const pendingToken = await signMfaPendingToken(user.id);
  await setAuthCookie({
    name: MFA_COOKIE,
    value: pendingToken,
    maxAgeSeconds: getEnv().MFA_PENDING_TTL_SECONDS,
  });

  return apiOk({ status: "enrollment_required" }, 201);
}

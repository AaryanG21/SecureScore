import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { enforceCsrf, enforceRateLimit } from "@/lib/auth/guards";
import { ipAccountKey } from "@/lib/security/rate-limit";
import { getSession } from "@/lib/auth/session";
import { verifyPassword } from "@/lib/auth/password";
import { commitTotpTimeStep, verifyTotpCode } from "@/lib/auth/totp";
import { parseJsonBody, reauthSchema } from "@/lib/validation/schemas";
import { signReauthToken } from "@/lib/auth/tokens";
import { REAUTH_COOKIE, setAuthCookie } from "@/lib/auth/cookies";
import { getEnv } from "@/lib/env";
import { writeAudit } from "@/lib/audit";
import { recordAttempt } from "@/lib/auth/attempts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Step-up authentication.
 *
 * Grants a short-lived reauth cookie proving the person at the keyboard
 * just supplied both factors. Destructive admin actions require it (see
 * requireAdminWithReauth), so a session left open on an unlocked laptop is
 * not by itself enough to suspend users or revoke domain verifications.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);
  const env = getEnv();

  const blocked = await enforceCsrf(request);
  if (blocked) return blocked;

  const session = await getSession();
  if (!session) {
    return apiError(401, "unauthenticated", "Sign in to continue.");
  }

  const limited = await enforceRateLimit(
    request,
    "reauth",
    ipAccountKey(meta.ipAddress, session.id),
    session.id,
  );
  if (limited) return limited;

  const body = await parseJsonBody(request, reauthSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the fields and try again.", body.fieldErrors);
  }

  const user = await prisma.user.findUnique({
    where: { id: session.id },
    select: {
      id: true,
      email: true,
      passwordHash: true,
      twoFactorSecret: true,
      twoFactorLastTimeStep: true,
    },
  });

  if (!user?.twoFactorSecret) {
    return apiError(401, "reauth_failed", "Could not confirm your identity.");
  }

  const passwordOk = await verifyPassword(user.passwordHash, body.data.password);
  const check = await verifyTotpCode(
    user.twoFactorSecret,
    body.data.code,
    user.twoFactorLastTimeStep,
  );

  if (!passwordOk || !check.valid) {
    await recordAttempt({
      email: user.email,
      userId: user.id,
      stage: "REAUTH",
      success: false,
      reason: passwordOk ? "bad_totp" : "bad_password",
      ...meta,
    });
    await writeAudit({
      actorUserId: user.id,
      action: "REAUTH_FAILURE",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
    });
    return apiError(401, "reauth_failed", "Could not confirm your identity.");
  }

  await commitTotpTimeStep(user.id, check.timeStep!);

  const token = await signReauthToken(user.id);
  await setAuthCookie({
    name: REAUTH_COOKIE,
    value: token,
    maxAgeSeconds: env.REAUTH_TTL_SECONDS,
  });

  await recordAttempt({
    email: user.email,
    userId: user.id,
    stage: "REAUTH",
    success: true,
    ...meta,
  });
  await writeAudit({
    actorUserId: user.id,
    action: "REAUTH_SUCCESS",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
  });

  return apiOk({ status: "reauthenticated", expiresInSeconds: env.REAUTH_TTL_SECONDS });
}

import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, apiRateLimited, getRequestMeta } from "@/lib/http";
import { verifyCsrf } from "@/lib/security/csrf";
import { checkRateLimit, ipAccountKey, resetRateLimit } from "@/lib/security/rate-limit";
import { MFA_COOKIE, clearAuthCookie, readCookie } from "@/lib/auth/cookies";
import { verifyMfaPendingToken } from "@/lib/auth/tokens";
import {
  commitTotpTimeStep,
  countUnusedBackupCodes,
  redeemBackupCode,
  verifyTotpCode,
} from "@/lib/auth/totp";
import { parseJsonBody, twoFactorVerifySchema } from "@/lib/validation/schemas";
import { createSession } from "@/lib/auth/session";
import { clearFailures, lockState, recordFailure } from "@/lib/auth/lockout";
import { recordAttempt } from "@/lib/auth/attempts";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Step two of login: the second factor.
 *
 * This is the only route that can mint a full session from a login flow.
 * It requires a valid mfa_pending token, which only /api/auth/login issues
 * and only after a correct password — so neither factor alone is sufficient
 * at any point in the flow.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  const pending = await readCookie(MFA_COOKIE);
  const claims = pending ? await verifyMfaPendingToken(pending) : null;

  if (!claims?.sub) {
    return apiError(
      401,
      "mfa_session_expired",
      "That took too long. Sign in again.",
    );
  }

  const rateKey = ipAccountKey(meta.ipAddress, claims.sub);
  const limit = checkRateLimit("twoFactor", rateKey);
  if (!limit.allowed) {
    await writeAudit({
      actorUserId: claims.sub,
      action: "LOGIN_BLOCKED_RATE_LIMIT",
      targetType: "User",
      targetId: claims.sub,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { stage: "2fa", strikes: limit.strikes },
    });
    return apiRateLimited(limit.retryAfterSeconds);
  }

  const body = await parseJsonBody(request, twoFactorVerifySchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the code and try again.", body.fieldErrors);
  }

  const user = await prisma.user.findUnique({
    where: { id: claims.sub },
    select: {
      id: true,
      email: true,
      role: true,
      status: true,
      lockedUntil: true,
      twoFactorEnabled: true,
      twoFactorSecret: true,
      twoFactorLastTimeStep: true,
    },
  });

  if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
    return apiError(401, "invalid_code", "Could not verify that code.");
  }

  if (user.status === "SUSPENDED" || lockState(user).locked) {
    await writeAudit({
      actorUserId: user.id,
      action:
        user.status === "SUSPENDED" ? "LOGIN_BLOCKED_SUSPENDED" : "LOGIN_BLOCKED_LOCKED",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { stage: "2fa" },
    });
    return apiError(401, "invalid_code", "Could not verify that code.");
  }

  const usingBackupCode = Boolean(body.data.backupCode);

  let verified = false;
  if (usingBackupCode) {
    verified = await redeemBackupCode(user.id, body.data.backupCode!);
  } else {
    const check = await verifyTotpCode(
      user.twoFactorSecret,
      body.data.code!,
      user.twoFactorLastTimeStep,
    );
    verified = check.valid;
    if (check.valid) {
      // Burn the time step so this code cannot be replayed.
      await commitTotpTimeStep(user.id, check.timeStep!);
    }
  }

  if (!verified) {
    await recordFailure(user.id, usingBackupCode ? "BAD_BACKUP_CODE" : "BAD_TOTP", meta);
    await recordAttempt({
      email: user.email,
      userId: user.id,
      stage: usingBackupCode ? "BACKUP_CODE" : "TOTP",
      success: false,
      reason: "invalid",
      ...meta,
    });
    await writeAudit({
      actorUserId: user.id,
      action: "LOGIN_2FA_FAILURE",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { method: usingBackupCode ? "backup_code" : "totp" },
    });
    return apiError(401, "invalid_code", "Could not verify that code.");
  }

  await clearFailures(user.id);
  resetRateLimit("twoFactor", rateKey);

  await recordAttempt({
    email: user.email,
    userId: user.id,
    stage: usingBackupCode ? "BACKUP_CODE" : "TOTP",
    success: true,
    ...meta,
  });
  await writeAudit({
    actorUserId: user.id,
    action: usingBackupCode ? "LOGIN_BACKUP_CODE_USED" : "LOGIN_2FA_SUCCESS",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await createSession(user.id, user.role, meta);
  await clearAuthCookie(MFA_COOKIE);

  const remainingBackupCodes = await countUnusedBackupCodes(user.id);

  return apiOk({
    status: "authenticated",
    role: user.role,
    // Surfaced so the UI can nudge a user who is running low.
    remainingBackupCodes,
  });
}

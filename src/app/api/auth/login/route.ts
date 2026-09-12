import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import {
  fakeVerifyForTiming,
  hashPassword,
  needsRehash,
  verifyPassword,
} from "@/lib/auth/password";
import { loginSchema, parseJsonBody } from "@/lib/validation/schemas";
import { apiError, apiOk, apiRateLimited, getRequestMeta } from "@/lib/http";
import { checkRateLimit, ipAccountKey, resetRateLimit } from "@/lib/security/rate-limit";
import { verifyCsrf } from "@/lib/security/csrf";
import { writeAudit } from "@/lib/audit";
import { recordAttempt } from "@/lib/auth/attempts";
import { lockState, recordFailure } from "@/lib/auth/lockout";
import { signMfaPendingToken } from "@/lib/auth/tokens";
import { MFA_COOKIE, setAuthCookie } from "@/lib/auth/cookies";
import { getEnv } from "@/lib/env";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Step one of login: password only.
 *
 * A correct password never produces a session here. It produces a
 * short-lived mfa_pending token, and only /api/auth/2fa/verify can trade
 * that for a real session. Keeping the two steps in separate token types
 * (checked by `typ`) is what makes the second factor non-optional.
 *
 * Every failure path returns the same 401 body. The specific reason —
 * unknown email, wrong password, locked, suspended — goes to the audit log,
 * not to the client.
 */
const GENERIC_FAILURE = "Invalid email, password, or account state.";

export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);
  const env = getEnv();

  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  const body = await parseJsonBody(request, loginSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the highlighted fields.", body.fieldErrors);
  }

  const { email, password } = body.data;

  // Keyed on IP *and* account, so neither one IP against many accounts nor
  // many IPs against one account slips through.
  const rateKey = ipAccountKey(meta.ipAddress, email);
  const limit = checkRateLimit("login", rateKey);
  if (!limit.allowed) {
    await writeAudit({
      action: "LOGIN_BLOCKED_RATE_LIMIT",
      targetType: "Email",
      targetId: email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { strikes: limit.strikes },
    });
    return apiRateLimited(limit.retryAfterSeconds);
  }

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      passwordHash: true,
      status: true,
      twoFactorEnabled: true,
      lockedUntil: true,
      failedLoginCount: true,
    },
  });

  if (!user) {
    // Burn comparable CPU time so response latency does not disclose
    // whether the address is registered.
    await fakeVerifyForTiming(password);
    await recordAttempt({
      email,
      stage: "PASSWORD",
      success: false,
      reason: "unknown_account",
      ...meta,
    });
    await writeAudit({
      action: "LOGIN_PASSWORD_FAILURE",
      targetType: "Email",
      targetId: email,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { reason: "unknown_account" },
    });
    return apiError(401, "invalid_credentials", GENERIC_FAILURE);
  }

  const lock = lockState(user);
  if (lock.locked) {
    await recordAttempt({
      email,
      userId: user.id,
      stage: "PASSWORD",
      success: false,
      reason: "locked",
      ...meta,
    });
    await writeAudit({
      actorUserId: user.id,
      action: "LOGIN_BLOCKED_LOCKED",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { lockedUntil: lock.until?.toISOString() },
    });
    return apiError(401, "invalid_credentials", GENERIC_FAILURE);
  }

  if (user.status === "SUSPENDED") {
    await recordAttempt({
      email,
      userId: user.id,
      stage: "PASSWORD",
      success: false,
      reason: "suspended",
      ...meta,
    });
    await writeAudit({
      actorUserId: user.id,
      action: "LOGIN_BLOCKED_SUSPENDED",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
    });
    return apiError(401, "invalid_credentials", GENERIC_FAILURE);
  }

  const passwordOk = await verifyPassword(user.passwordHash, password);

  if (!passwordOk) {
    const newLock = await recordFailure(user.id, "BAD_PASSWORD", meta);
    await recordAttempt({
      email,
      userId: user.id,
      stage: "PASSWORD",
      success: false,
      reason: "bad_password",
      ...meta,
    });
    await writeAudit({
      actorUserId: user.id,
      action: "LOGIN_PASSWORD_FAILURE",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { reason: "bad_password", nowLocked: newLock.locked },
    });
    return apiError(401, "invalid_credentials", GENERIC_FAILURE);
  }

  // Transparent parameter upgrade: if this hash predates a parameter
  // bump, rewrite it now that we hold the plaintext legitimately.
  if (needsRehash(user.passwordHash)) {
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash: await hashPassword(password) },
    });
  }

  await recordAttempt({
    email,
    userId: user.id,
    stage: "PASSWORD",
    success: true,
    ...meta,
  });
  await writeAudit({
    actorUserId: user.id,
    action: "LOGIN_PASSWORD_SUCCESS",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  // A correct password clears the per-IP+account counter for step one only;
  // the 2FA step has its own budget.
  resetRateLimit("login", rateKey);

  const pendingToken = await signMfaPendingToken(user.id);
  await setAuthCookie({
    name: MFA_COOKIE,
    value: pendingToken,
    maxAgeSeconds: env.MFA_PENDING_TTL_SECONDS,
  });

  return apiOk({
    status: user.twoFactorEnabled ? "totp_required" : "enrollment_required",
  });
}

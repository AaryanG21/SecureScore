import { type NextRequest } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { enforceCsrf, enforceRateLimit } from "@/lib/auth/guards";
import { ipAccountKey } from "@/lib/security/rate-limit";
import { MFA_COOKIE, clearAuthCookie, readCookie } from "@/lib/auth/cookies";
import { verifyMfaPendingToken } from "@/lib/auth/tokens";
import {
  commitTotpTimeStep,
  issueBackupCodes,
  verifyTotpCode,
} from "@/lib/auth/totp";
import { parseJsonBody, totpCodeSchema } from "@/lib/validation/schemas";
import { createSession } from "@/lib/auth/session";
import { getSession } from "@/lib/auth/session";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const schema = z.object({ code: totpCodeSchema });

/**
 * Completes TOTP enrollment.
 *
 * Only once a valid code is produced does the account flip to ACTIVE with
 * twoFactorEnabled=true, and only then are backup codes issued. The
 * plaintext backup codes are returned exactly once, in this response, and
 * are never recoverable afterwards — only their argon2id hashes are stored.
 */
export async function POST(request: NextRequest) { const meta = getRequestMeta(request);

  const blocked = await enforceCsrf(request);
  if (blocked) return blocked;

  const session = await getSession();
  let userId = session?.id ?? null;
  if (!userId) { const pending = await readCookie(MFA_COOKIE);
    const claims = pending ? await verifyMfaPendingToken(pending) : null;
    userId = claims?.sub ?? null;
  }

  if (!userId) { return apiError(401, "unauthenticated", "Start again from the sign-in page.");
  }

  const limited = await enforceRateLimit(
    request,
    "twoFactor",
    ipAccountKey(meta.ipAddress, userId),
    userId,
  );
  if (limited) return limited;

  const body = await parseJsonBody(request, schema);
  if (!body.ok) { return apiError(400, "invalid_input", "Enter the 6-digit code.", body.fieldErrors);
  }

  const user = await prisma.user.findUnique({ where: { id: userId },
    select: { id: true,
      role: true,
      status: true,
      twoFactorSecret: true,
      twoFactorEnabled: true,
      twoFactorLastTimeStep: true } });

  if (!user?.twoFactorSecret || user.status === "SUSPENDED") { return apiError(400, "enrollment_not_started", "Start enrollment again.");
  }

  const check = await verifyTotpCode(
    user.twoFactorSecret,
    body.data.code,
    user.twoFactorLastTimeStep,
  );

  if (!check.valid) { await writeAudit({ actorUserId: user.id,
      action: "LOGIN_2FA_FAILURE",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { phase: "enrollment" } });
    return apiError(401, "invalid_code", "That code did not match. Try the next one.");
  }

  await commitTotpTimeStep(user.id, check.timeStep!);

  const backupCodes = await issueBackupCodes(user.id);

  await prisma.user.update({ where: { id: user.id },
    data: { twoFactorEnabled: true,
      twoFactorEnrolledAt: new Date(),
      status: user.status === "PENDING_2FA" ? "ACTIVE" : user.status,
      failedLoginCount: 0,
      lockedUntil: null } });

  await writeAudit({ actorUserId: user.id,
    action: "TWO_FACTOR_ENROLLED",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { backupCodesIssued: backupCodes.length } });

  // First-time enrollment logs the user in; a re-enrollment by someone who
  // already had a session keeps the session they arrived with.
  if (!session) { await createSession(user.id, user.role, meta);
    await clearAuthCookie(MFA_COOKIE);
  }

  const response = apiOk({ status: "enrolled", backupCodes });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

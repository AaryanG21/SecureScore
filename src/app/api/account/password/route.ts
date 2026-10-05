import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { changePasswordSchema, parseJsonBody } from "@/lib/validation/schemas";
import { hashPassword, verifyPassword } from "@/lib/auth/password";
import { revokeAllSessions, createSession } from "@/lib/auth/session";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Password change.
 *
 * Changing a password revokes every existing session — that is the point of
 * changing it after a suspected compromise — and then issues a fresh
 * session to the browser that made the change, so the user is not logged
 * out of the tab they are sitting in.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "passwordReset" });
  if (!guard.ok) return guard.response;

  const body = await parseJsonBody(request, changePasswordSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the highlighted fields.", body.fieldErrors);
  }

  const user = await prisma.user.findUnique({
    where: { id: guard.value.id },
    select: { id: true, role: true, passwordHash: true },
  });
  if (!user) return apiError(401, "unauthenticated", "Sign in to continue.");

  const currentOk = await verifyPassword(user.passwordHash, body.data.currentPassword);
  if (!currentOk) {
    await writeAudit({
      actorUserId: user.id,
      action: "PASSWORD_CHANGE_REJECTED",
      targetType: "User",
      targetId: user.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { reason: "bad_current_password" },
    });
    return apiError(401, "invalid_credentials", "Your current password is incorrect.");
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash: await hashPassword(body.data.newPassword),
      passwordChangedAt: new Date(),
    },
  });

  await revokeAllSessions(user.id, "PASSWORD_CHANGED");
  await createSession(user.id, user.role, meta);

  await writeAudit({
    actorUserId: user.id,
    action: "PASSWORD_CHANGED",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { outcome: "changed", otherSessionsRevoked: true },
  });

  return apiOk({ status: "password_changed" });
}

import { type NextRequest } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireAdminWithReauth } from "@/lib/auth/guards";
import { parseJsonBody } from "@/lib/validation/schemas";
import { revokeAllSessions } from "@/lib/auth/session";
import { adminUnlock } from "@/lib/auth/lockout";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const schema = z.object({
  action: z.enum(["suspend", "reinstate", "unlock"]),
  reason: z.string().trim().min(3).max(500),
});

/**
 * Suspend, reinstate, or unlock a user account.
 *
 * Destructive, so it requires the admin role AND a re-authentication within
 * the last few minutes (requireAdminWithReauth). Suspension also revokes
 * every one of that user's sessions immediately — a suspension that left
 * live sessions running would be cosmetic.
 *
 * An admin cannot suspend their own account: that is almost always a
 * misclick, and it can leave a deployment with no reachable administrator.
 */
export async function POST(
  request: NextRequest,
  context: { params: Promise<{ userId: string }> },
) {
  const meta = getRequestMeta(request);

  const guard = await requireAdminWithReauth(request, { rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const { userId } = await context.params;

  const body = await parseJsonBody(request, schema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Provide an action and a reason.", body.fieldErrors);
  }

  if (userId === guard.value.id && body.data.action === "suspend") {
    return apiError(
      400,
      "self_action_refused",
      "You cannot suspend your own account.",
    );
  }

  const target = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, status: true, role: true },
  });

  if (!target) return apiError(404, "not_found", "No such user.");

  switch (body.data.action) {
    case "suspend": {
      await prisma.user.update({
        where: { id: target.id },
        data: { status: "SUSPENDED" },
      });
      await revokeAllSessions(target.id, "ADMIN_SUSPENDED");
      await writeAudit({
        actorUserId: guard.value.id,
        action: "ADMIN_USER_SUSPENDED",
        targetType: "User",
        targetId: target.id,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { targetEmail: target.email, reason: body.data.reason },
      });
      break;
    }

    case "reinstate": {
      // A reinstated account returns to ACTIVE only if it had completed
      // 2FA enrollment; otherwise it goes back to PENDING_2FA so the
      // mandatory-second-factor rule still holds.
      const enrolled = await prisma.user.findUnique({
        where: { id: target.id },
        select: { twoFactorEnabled: true },
      });

      await prisma.user.update({
        where: { id: target.id },
        data: { status: enrolled?.twoFactorEnabled ? "ACTIVE" : "PENDING_2FA" },
      });
      await writeAudit({
        actorUserId: guard.value.id,
        action: "ADMIN_USER_REINSTATED",
        targetType: "User",
        targetId: target.id,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { targetEmail: target.email, reason: body.data.reason },
      });
      break;
    }

    case "unlock": {
      await adminUnlock(target.id);
      await writeAudit({
        actorUserId: guard.value.id,
        action: "ADMIN_USER_UNLOCKED",
        targetType: "User",
        targetId: target.id,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        metadata: { targetEmail: target.email, reason: body.data.reason },
      });
      break;
    }
  }

  return apiOk({ status: "applied", action: body.data.action });
}

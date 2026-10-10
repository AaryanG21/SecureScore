import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiOk, getRequestMeta } from "@/lib/http";
import { requireUserWithReauth } from "@/lib/auth/guards";
import { clearAllAuthCookies } from "@/lib/auth/cookies";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Deletes the caller's own account and their personal data.
 *
 * Behind a step-up: password and a 2FA code, re-entered. A session left
 * open on an unlocked laptop should not be enough to destroy an account,
 * and unlike a password change there is nothing to undo afterwards.
 *
 * What goes, and what cannot:
 *
 *   User, BackupCode, Domain, ScanResult, RefreshToken — removed. The last
 *   four cascade from the User row.
 *
 *   LoginAttempt — removed explicitly, by email. It has no foreign key to
 *   User (unlike every other child table), so a cascade does not reach it
 *   and the rows would otherwise survive deletion carrying an email
 *   address, an IP and a user-agent string indefinitely. That looks like an
 *   oversight rather than a decision — nothing documents it, where the
 *   AuditLog decoupling is argued at length in its own migration — so this
 *   closes it rather than preserving it.
 *
 *   AuditLog — survives, and cannot be removed here. The table is
 *   append-only at the database level: a trigger rejects UPDATE, DELETE and
 *   TRUNCATE, so the application has no way to erase from it and a
 *   compromised application still cannot rewrite history. Those rows are
 *   destroyed by the retention job instead (see scripts/prune-audit-log.sql
 *   and the privacy policy, which both state the same window).
 *
 * The final audit entry is written BEFORE the deletion, because afterwards
 * there is no user row to resolve an email from, and an erasure that leaves
 * no record of having happened is the one event you most want recorded.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUserWithReauth(request, { rateLimit: "passwordReset" });
  if (!guard.ok) return guard.response;

  const user = guard.value;

  // Written first: once the row is gone, writeAudit cannot resolve the
  // email, and this entry is the only remaining evidence of the account.
  await writeAudit({
    actorUserId: user.id,
    actorEmail: user.email,
    action: "ACCOUNT_DELETED",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
    metadata: { initiatedBy: "self" },
  });

  const removed = await prisma.$transaction(async (tx) => {
    // No foreign key reaches these, so they are removed by hand.
    const attempts = await tx.loginAttempt.deleteMany({
      where: { OR: [{ userId: user.id }, { email: user.email }] },
    });

    // Cascades to BackupCode, Domain, ScanResult and RefreshToken.
    await tx.user.delete({ where: { id: user.id } });

    return { loginAttempts: attempts.count };
  });

  await clearAllAuthCookies();

  return apiOk({
    status: "account_deleted",
    loginAttemptsRemoved: removed.loginAttempts,
  });
}

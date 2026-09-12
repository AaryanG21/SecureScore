import "server-only";
import { prisma } from "@/lib/db";

/**
 * Login-attempt journal.
 *
 * Separate from the audit log on purpose: this table is user-visible ("your
 * recent sign-in activity") and is queried on hot auth paths, whereas the
 * audit log is admin-facing and append-only. Neither stores credentials.
 */

export type AuthStage = "PASSWORD" | "TOTP" | "BACKUP_CODE" | "REFRESH" | "REAUTH";

export async function recordAttempt(args: {
  email: string;
  userId?: string | null;
  stage: AuthStage;
  success: boolean;
  reason?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}): Promise<void> {
  try {
    await prisma.loginAttempt.create({
      data: {
        email: args.email.toLowerCase().slice(0, 254),
        userId: args.userId ?? null,
        stage: args.stage,
        success: args.success,
        reason: args.reason ?? null,
        ipAddress: args.ipAddress ?? null,
        userAgent: args.userAgent?.slice(0, 300) ?? null,
      },
    });
  } catch (error) {
    console.error("[attempts] failed to record", {
      stage: args.stage,
      error: error instanceof Error ? error.message : "unknown",
    });
  }
}

export async function recentAttemptsForUser(userId: string, limit = 20) {
  return prisma.loginAttempt.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      id: true,
      stage: true,
      success: true,
      reason: true,
      ipAddress: true,
      userAgent: true,
      createdAt: true,
    },
  });
}

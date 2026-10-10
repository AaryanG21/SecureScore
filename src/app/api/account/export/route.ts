import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Everything held about the caller, as a JSON file.
 *
 * No step-up here, deliberately: this is a read of data the account page
 * already displays, and putting friction in front of a right people are
 * entitled to exercise is its own kind of dark pattern. Deleting is
 * irreversible and is gated; exporting is not and is not.
 *
 * Credentials are excluded rather than included-and-redacted. The password
 * hash and the encrypted TOTP secret are about the account rather than
 * about the person, exporting them would hand an attacker who briefly held
 * a session something durable, and nobody can do anything useful with
 * either. What is returned is what a person would actually want: their
 * details, their domains, their scan results, and their sign-in history.
 */
export async function GET(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { skipCsrf: true, rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const [user, domains, scans, attempts] = await Promise.all([
    prisma.user.findUnique({
      where: { id: guard.value.id },
      select: {
        id: true,
        email: true,
        role: true,
        status: true,
        twoFactorEnabled: true,
        twoFactorEnrolledAt: true,
        ageConfirmedAt: true,
        termsAcceptedAt: true,
        passwordChangedAt: true,
        lastLoginAt: true,
        createdAt: true,
      },
    }),
    prisma.domain.findMany({
      where: { userId: guard.value.id },
      orderBy: { createdAt: "asc" },
      select: {
        hostname: true,
        verificationStatus: true,
        verificationMethod: true,
        verifiedAt: true,
        createdAt: true,
      },
    }),
    prisma.scanResult.findMany({
      where: { userId: guard.value.id },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        hostname: true,
        scanType: true,
        status: true,
        score: true,
        grade: true,
        budgetLimit: true,
        budgetUsed: true,
        findings: true,
        remediationPlan: true,
        degradedSteps: true,
        testsslVersion: true,
        createdAt: true,
        completedAt: true,
      },
    }),
    prisma.loginAttempt.findMany({
      where: { OR: [{ userId: guard.value.id }, { email: guard.value.email }] },
      orderBy: { createdAt: "desc" },
      take: 500,
      select: {
        stage: true,
        success: true,
        reason: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
      },
    }),
  ]);

  if (!user) return apiError(401, "unauthenticated", "Sign in to continue.");

  await writeAudit({
    actorUserId: user.id,
    action: "ACCOUNT_DATA_EXPORTED",
    targetType: "User",
    targetId: user.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
    metadata: { domains: domains.length, scans: scans.length },
  });

  const payload = {
    exportedAt: new Date().toISOString(),
    note:
      "Everything Fulcrum holds about this account, except credentials. The " +
      "password hash and the encrypted two-factor secret are deliberately " +
      "excluded: they describe the account rather than you, and exporting " +
      "them would create a durable copy of something nobody can use. " +
      "Security audit records are held separately and are described in the " +
      "privacy policy.",
    account: user,
    domains,
    scans,
    signInHistory: attempts,
  };

  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="fulcrum-export-${new Date().toISOString().slice(0, 10)}.json"`,
      "Cache-Control": "no-store",
    },
  });
}

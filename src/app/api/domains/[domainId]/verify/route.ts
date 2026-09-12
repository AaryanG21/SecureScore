import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { runVerification } from "@/lib/domains/verification";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Runs the ownership challenge for one domain.
 *
 * Rate-limited because each call performs an outbound DNS or HTTPS request
 * on a user-supplied hostname, and both the attempt and its outcome are
 * audited — a burst of failed verifications against many hostnames is
 * exactly the pattern worth being able to see after the fact.
 */
export async function POST(
  request: NextRequest,
  context: { params: Promise<{ domainId: string }> },
) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "domainVerify" });
  if (!guard.ok) return guard.response;

  const { domainId } = await context.params;

  const domain = await prisma.domain.findUnique({
    where: { id: domainId },
    select: {
      id: true,
      userId: true,
      hostname: true,
      verificationMethod: true,
      verificationToken: true,
      verificationStatus: true,
    },
  });

  // Ownership mismatch returns the same 404 as a missing row, so this
  // endpoint cannot enumerate other users' domain IDs.
  if (!domain || domain.userId !== guard.value.id) {
    return apiError(404, "not_found", "That domain is not registered to you.");
  }

  if (domain.verificationStatus === "REVOKED") {
    return apiError(
      403,
      "verification_revoked",
      "An administrator revoked this verification. Contact support before re-verifying.",
    );
  }

  const outcome = await runVerification(
    domain.verificationMethod,
    domain.hostname,
    domain.verificationToken,
  );

  await writeAudit({
    actorUserId: guard.value.id,
    action: "DOMAIN_VERIFICATION_ATTEMPT",
    targetType: "Domain",
    targetId: domain.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: {
      hostname: domain.hostname,
      method: domain.verificationMethod,
      verified: outcome.verified,
      detail: outcome.verified ? outcome.evidence : outcome.reason,
    },
  });

  if (!outcome.verified) {
    await prisma.domain.update({
      where: { id: domain.id },
      data: { verificationStatus: "FAILED", lastCheckedAt: new Date() },
    });
    return apiError(400, "verification_failed", outcome.reason);
  }

  await prisma.domain.update({
    where: { id: domain.id },
    data: {
      verificationStatus: "VERIFIED",
      verifiedAt: new Date(),
      lastCheckedAt: new Date(),
    },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "DOMAIN_VERIFIED",
    targetType: "Domain",
    targetId: domain.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { hostname: domain.hostname, method: outcome.method },
  });

  return apiOk({ status: "verified", hostname: domain.hostname });
}

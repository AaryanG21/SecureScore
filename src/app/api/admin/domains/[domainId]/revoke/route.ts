import { type NextRequest } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireAdminWithReauth } from "@/lib/auth/guards";
import { parseJsonBody } from "@/lib/validation/schemas";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const schema = z.object({ reason: z.string().trim().min(3).max(500) });

/**
 * Revokes a domain's verification.
 *
 * The escape hatch for when a domain changes hands, or when a verification
 * turns out to have been obtained improperly. The row is marked REVOKED
 * rather than deleted, so the history stays visible and `authorizeScan`
 * refuses every subsequent scan against it.
 */
export async function POST(
  request: NextRequest,
  context: { params: Promise<{ domainId: string }> },
) {
  const meta = getRequestMeta(request);

  const guard = await requireAdminWithReauth(request, { rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const { domainId } = await context.params;

  const body = await parseJsonBody(request, schema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Provide a reason.", body.fieldErrors);
  }

  const domain = await prisma.domain.findUnique({
    where: { id: domainId },
    select: { id: true, hostname: true, userId: true, verificationStatus: true },
  });

  if (!domain) return apiError(404, "not_found", "No such domain.");

  await prisma.domain.update({
    where: { id: domain.id },
    data: {
      verificationStatus: "REVOKED",
      revokedAt: new Date(),
      revokedByUserId: guard.value.id,
      verifiedAt: null,
    },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "ADMIN_DOMAIN_REVOKED",
    targetType: "Domain",
    targetId: domain.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: {
      hostname: domain.hostname,
      ownerUserId: domain.userId,
      previousStatus: domain.verificationStatus,
      reason: body.data.reason,
    },
  });

  return apiOk({ status: "revoked", hostname: domain.hostname });
}

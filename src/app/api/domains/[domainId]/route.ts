import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Removes one of the caller's own domains.
 *
 * Past scan results cascade away with the domain row. That is a deliberate
 * choice in favour of the user's control over their own data; the audit log
 * retains the fact that the domain existed and was removed.
 */
export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ domainId: string }> },
) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const { domainId } = await context.params;

  const domain = await prisma.domain.findUnique({
    where: { id: domainId },
    select: { id: true, userId: true, hostname: true },
  });

  if (!domain || domain.userId !== guard.value.id) {
    return apiError(404, "not_found", "That domain is not registered to you.");
  }

  await prisma.domain.delete({ where: { id: domain.id } });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "DOMAIN_REMOVED",
    targetType: "Domain",
    targetId: domain.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { hostname: domain.hostname },
  });

  return apiOk({ status: "removed" });
}

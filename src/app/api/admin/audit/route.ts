import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireAdmin } from "@/lib/auth/guards";
import { paginationSchema } from "@/lib/validation/schemas";
import { AUDIT_ACTIONS, isAuditAction, writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Reads the audit log, newest first, cursor-paginated.
 *
 * Reading the log is itself an audited event. Without that, an admin could
 * go looking through everyone's activity and leave no trace of having done
 * so — which defeats the purpose of keeping the log in the first place.
 */
export async function GET(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireAdmin(request, { skipCsrf: true, rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const url = new URL(request.url);
  const parsed = paginationSchema.safeParse({
    cursor: url.searchParams.get("cursor") ?? undefined,
    limit: url.searchParams.get("limit") ?? undefined,
  });

  if (!parsed.success) {
    return apiError(400, "invalid_input", "Invalid pagination parameters.");
  }

  const { cursor, limit } = parsed.data;

  // Validate the filter instead of passing it straight to the query.
  //
  // It arrived as a free-form string, so a typo — or an action name that
  // no longer exists — produced an empty page that read as "nothing
  // happened" rather than "you asked for something that cannot happen".
  // On an audit log, those two answers must never look alike.
  const requestedAction = url.searchParams.get("action");
  if (requestedAction !== null && !isAuditAction(requestedAction)) {
    return apiError(
      400,
      "invalid_input",
      "Unknown audit action. An empty result would be indistinguishable from a real absence of events, so the filter is rejected instead.",
      { action: [`Must be one of: ${AUDIT_ACTIONS.join(", ")}`] },
    );
  }
  const actionFilter = requestedAction;

  const entries = await prisma.auditLog.findMany({
    where: actionFilter ? { action: actionFilter } : undefined,
    orderBy: { createdAt: "desc" },
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    select: {
      id: true,
      action: true,
      targetType: true,
      targetId: true,
      ipAddress: true,
      userAgent: true,
      metadata: true,
      createdAt: true,
      actorUserId: true,
      actorEmail: true,
    },
  });

  const hasMore = entries.length > limit;
  const page = hasMore ? entries.slice(0, limit) : entries;

  await writeAudit({
    actorUserId: guard.value.id,
    action: "ADMIN_AUDIT_LOG_VIEWED",
    targetType: "AuditLog",
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { limit, actionFilter: actionFilter ?? null },
  });

  const response = apiOk({
    entries: page,
    nextCursor: hasMore ? page.at(-1)?.id ?? null : null,
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

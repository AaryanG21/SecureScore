import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { parseJsonBody, publicScanRequestSchema } from "@/lib/validation/schemas";
import { authorizePublicScan } from "@/lib/domains/public-scan";
import { runScan } from "@/lib/agent/run";
import { writeAudit } from "@/lib/audit";
import type { Prisma } from "@/generated/prisma/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// No testssl.sh here, so this finishes in seconds rather than minutes.
export const maxDuration = 60;

/**
 * A headers-only check of a host the caller does not own.
 *
 * Why this exists alongside POST /api/scans rather than as a flag on it:
 * they are different actions behind different gates, and collapsing them
 * into one endpoint with a boolean would mean one code path deciding, from
 * a request field, how much of the scanner to unlock. Keeping them apart
 * means `includeTls: false` is not a privilege check — it is simply the
 * only thing this route can ask for, and no request body can change that.
 *
 * What the target experiences is one HTTPS GET whose body is never read.
 * The fingerprint and CVE steps work from that same response and generate
 * no further traffic. That is why this does not require proof of
 * ownership: it is indistinguishable from a browser visiting the page once.
 *
 * What it must never become is a way to point testssl.sh at a stranger.
 * `includeTls: false` below is the whole of that guarantee, and it is
 * hard-coded.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "publicScan" });
  if (!guard.ok) return guard.response;

  const body = await parseJsonBody(request, publicScanRequestSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the hostname.", body.fieldErrors);
  }

  const { hostname, budget } = body.data;

  const authorization = await authorizePublicScan({
    userId: guard.value.id,
    userStatus: guard.value.status,
    hostname,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
  });

  if (!authorization.granted) {
    return apiError(
      429,
      `public_scan_refused_${authorization.reason}`,
      authorization.message,
    );
  }

  // A recent result is returned instead of fetching again. Ten people
  // checking the same site inside the cache window cost that site one
  // request, not ten — the strongest throttle available is the one that
  // removes the request entirely.
  if (authorization.cached) {
    return apiOk({ scanId: authorization.cached.scanId, cached: true }, 200);
  }

  const scan = await prisma.scanResult.create({
    data: {
      userId: guard.value.id,
      hostname: authorization.hostname,
      scanType: "HEADERS_ONLY",
      status: "RUNNING",
      budgetLimit: budget,
      startedAt: new Date(),
    },
    select: { id: true },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "PUBLIC_SCAN_REQUESTED",
    targetType: "Hostname",
    targetId: authorization.hostname,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
    metadata: { scanId: scan.id, budget },
  });

  const result = await runScan({
    hostname: authorization.hostname,
    budgetLimit: budget,
    // Hard-coded, never read from the request. This is the line that keeps
    // an unowned target from being probed rather than observed.
    includeTls: false,
  });

  if (!result.ok) {
    await prisma.scanResult.update({
      where: { id: scan.id },
      data: {
        status: "FAILED",
        errorMessage: result.reason.slice(0, 500),
        completedAt: new Date(),
      },
    });

    await writeAudit({
      actorUserId: guard.value.id,
      action: "PUBLIC_SCAN_FAILED",
      targetType: "ScanResult",
      targetId: scan.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      requestId: meta.requestId,
      metadata: { hostname: authorization.hostname, reason: result.reason },
    });

    return apiError(502, "scan_failed", result.reason);
  }

  const outcome = result.outcome;

  await prisma.scanResult.update({
    where: { id: scan.id },
    data: {
      status: "COMPLETED",
      findings: outcome.findings as unknown as Prisma.InputJsonValue,
      score: outcome.score,
      grade: outcome.grade,
      budgetUsed: outcome.plan.budgetUsed,
      remediationPlan: outcome.plan as unknown as Prisma.InputJsonValue,
      degradedSteps: outcome.degraded as unknown as Prisma.InputJsonValue,
      completedAt: outcome.completedAt,
    },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "PUBLIC_SCAN_COMPLETED",
    targetType: "ScanResult",
    targetId: scan.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    requestId: meta.requestId,
    metadata: {
      hostname: outcome.hostname,
      grade: outcome.grade,
      findingCount: outcome.findings.length,
    },
  });

  return apiOk(
    { scanId: scan.id, grade: outcome.grade, score: outcome.score, cached: false },
    201,
  );
}

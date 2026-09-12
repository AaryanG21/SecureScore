import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { parseJsonBody, scanRequestSchema } from "@/lib/validation/schemas";
import { authorizeScan } from "@/lib/domains/allowlist";
import { runScan } from "@/lib/agent/run";
import { writeAudit } from "@/lib/audit";
import type { Prisma } from "@/generated/prisma/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// A scan spawns testssl.sh, which takes a couple of minutes on a normal
// host. The route waits for it rather than returning a job id, which keeps
// this build simple; the README notes moving it to a queue as the scaling
// step.
export const maxDuration = 600;

/**
 * Runs a scan.
 *
 * The authorization gate is the first thing that happens after input
 * validation, and it is the ONLY path to the scanner: `authorizeScan`
 * refuses anything the caller has not registered and verified, and logs
 * every refusal. There is no bypass, no admin override, and no way to pass
 * a hostname directly — the hostname comes from the database row, never
 * from the request body.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "scan" });
  if (!guard.ok) return guard.response;

  const body = await parseJsonBody(request, scanRequestSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the scan parameters.", body.fieldErrors);
  }

  const { domainId, budget } = body.data;

  const authorization = await authorizeScan({
    userId: guard.value.id,
    userStatus: guard.value.status,
    domainId,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });

  if (!authorization.granted) {
    // The refusal is already audited inside authorizeScan. Record it as a
    // REFUSED scan row too, so it shows in the user's own history rather
    // than only in the admin-facing log.
    await prisma.scanResult.create({
      data: {
        domainId,
        userId: guard.value.id,
        status: "REFUSED",
        budgetLimit: budget,
        refusalReason: authorization.reason,
        completedAt: new Date(),
      },
    }).catch(() => {
      // A refusal for a domain id that does not exist cannot be recorded
      // against it (foreign key). The audit entry is the durable record.
    });

    return apiError(403, `scan_refused_${authorization.reason}`, authorization.message);
  }

  const scan = await prisma.scanResult.create({
    data: {
      domainId: authorization.domainId,
      userId: guard.value.id,
      status: "RUNNING",
      budgetLimit: budget,
      startedAt: new Date(),
    },
    select: { id: true },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "SCAN_REQUESTED",
    targetType: "Domain",
    targetId: authorization.domainId,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { scanId: scan.id, hostname: authorization.hostname, budget },
  });

  const result = await runScan({
    hostname: authorization.hostname,
    budgetLimit: budget,
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
      action: "SCAN_FAILED",
      targetType: "ScanResult",
      targetId: scan.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: { reason: result.reason },
    });

    return apiError(502, "scan_failed", result.reason);
  }

  const outcome = result.outcome;

  // Attempted injection is worth recording even though it changed nothing —
  // it is evidence about the target's behaviour, and the audit metadata
  // redactor truncates the payload itself.
  const injectionAttempts = outcome.findings.filter((f) => f.injectionAttempt);
  if (injectionAttempts.length > 0) {
    await writeAudit({
      actorUserId: guard.value.id,
      action: "SCAN_INJECTION_ATTEMPT_IGNORED",
      targetType: "ScanResult",
      targetId: scan.id,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      metadata: {
        hostname: outcome.hostname,
        count: injectionAttempts.length,
        checkIds: injectionAttempts.map((f) => f.checkId).slice(0, 10),
        note: "Instruction-shaped text found in scanned content; scoring was unaffected.",
      },
    });
  }

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
      testsslVersion: outcome.testsslVersion,
      completedAt: outcome.completedAt,
    },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "SCAN_COMPLETED",
    targetType: "ScanResult",
    targetId: scan.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: {
      hostname: outcome.hostname,
      grade: outcome.grade,
      findingCount: outcome.findings.length,
      degradedSteps: outcome.degraded.map((d) => d.step),
    },
  });

  return apiOk({ scanId: scan.id, grade: outcome.grade, score: outcome.score }, 201);
}

/** The caller's own scan history. Scoped by session, never by a query param. */
export async function GET(request: NextRequest) {
  const guard = await requireUser(request, { skipCsrf: true });
  if (!guard.ok) return guard.response;

  const scans = await prisma.scanResult.findMany({
    where: { userId: guard.value.id },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: {
      id: true,
      status: true,
      score: true,
      grade: true,
      budgetLimit: true,
      budgetUsed: true,
      refusalReason: true,
      createdAt: true,
      completedAt: true,
      domain: { select: { hostname: true } },
    },
  });

  return apiOk({ scans });
}

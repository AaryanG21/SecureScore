import "server-only";
import { prisma } from "@/lib/db";
import { getEnv } from "@/lib/env";
import { writeAudit } from "@/lib/audit";

/**
 * Reconciles scans that were left RUNNING.
 *
 * A scan is executed inline in the request that asked for it, and the
 * ScanResult row is set to RUNNING before the work starts. Nothing wrote
 * that row again if the process did not survive the scan — a deploy, an
 * OOM kill, a `docker compose restart` two minutes into a testssl.sh run —
 * so the row stayed RUNNING for ever. The user's dashboard showed a scan
 * permanently in progress with no way to clear it or retry, and the
 * operator had no count of how often it happened.
 *
 * "Stalled" is derived from the configured tool timeout rather than
 * hard-coded, so raising TESTSSL_TIMEOUT_MS cannot start reaping scans
 * that are merely slow. The margin covers the other three steps plus the
 * database writes either side.
 *
 * The outcome is FAILED, never COMPLETED. A scan that did not finish has
 * no findings, and the one thing this codebase refuses to do is present an
 * absence of findings as a clean result.
 */

const OTHER_STEPS_MARGIN_MS = 300_000;

export function stalledThresholdMs(): number {
  return getEnv().TESTSSL_TIMEOUT_MS + OTHER_STEPS_MARGIN_MS;
}

/**
 * Removes refresh-token rows that can no longer authenticate anything.
 *
 * A row whose expiry has passed, or that was revoked, is dead credential
 * material: it cannot mint a session, and the reuse-detection it supported
 * only matters while the family is live. What it still carries is an IP
 * address and a user-agent string, which is personal data kept for no
 * remaining purpose — the storage-limitation principle applied rather than
 * merely written into the policy.
 *
 * A grace period after expiry keeps recently-rotated rows around long
 * enough for reuse detection to still fire on a token stolen just before
 * it expired.
 */
const REVOKED_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

export async function pruneDeadSessions(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - REVOKED_GRACE_MS);

  const { count } = await prisma.refreshToken.deleteMany({
    where: {
      OR: [{ expiresAt: { lt: cutoff } }, { revokedAt: { lt: cutoff } }],
    },
  });

  return count;
}

export async function reapStalledScans(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - stalledThresholdMs());

  const stalled = await prisma.scanResult.findMany({
    where: {
      status: "RUNNING",
      // startedAt is set in the same create() that sets RUNNING, but guard
      // against a null anyway rather than reaping on createdAt and risking
      // a different definition of "old".
      startedAt: { not: null, lt: cutoff },
    },
    select: { id: true, userId: true, domainId: true, startedAt: true },
    take: 100,
  });

  if (stalled.length === 0) return 0;

  const ids = stalled.map((scan) => scan.id);

  // Guarded on status so a scan that completed between the read and this
  // write is not overwritten with a failure.
  const { count } = await prisma.scanResult.updateMany({
    where: { id: { in: ids }, status: "RUNNING" },
    data: {
      status: "FAILED",
      errorMessage:
        "The scan did not finish — the server process ended while it was running. No results were produced; this is not a clean result. Run it again.",
      completedAt: now,
    },
  });

  // Audited per scan: an operator looking at why a user's scan vanished
  // needs to find it, and a cluster of these is a signal about the host
  // rather than about the targets.
  for (const scan of stalled) {
    await writeAudit({
      actorUserId: scan.userId,
      action: "SCAN_FAILED",
      targetType: "ScanResult",
      targetId: scan.id,
      metadata: {
        reason: "stalled",
        startedAt: scan.startedAt?.toISOString() ?? null,
        thresholdMs: stalledThresholdMs(),
        note: "Marked failed by the reaper; the process did not survive the scan.",
      },
    });
  }

  return count;
}

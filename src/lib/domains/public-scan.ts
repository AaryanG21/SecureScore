import "server-only";
import { prisma } from "@/lib/db";
import { writeAudit } from "@/lib/audit";
import { normalizeHostname } from "@/lib/validation/hostname";

/**
 * Authorization for headers-only scans of hosts the caller does not own.
 *
 * The distinction this rests on is between passive observation and active
 * probing, and it is worth being precise about rather than waving at.
 *
 *   A headers check is ONE HTTPS GET whose body is never read. The
 *   fingerprint and CVE steps derive from that same response and generate
 *   no further traffic. The target sees a single request, indistinguishable
 *   from a browser loading the page once, and nothing is sent that a
 *   browser would not send.
 *
 *   The TLS step opens hundreds of connections probing cipher suites,
 *   protocol versions and renegotiation behaviour. That is reconnaissance,
 *   it is visibly so in the target's logs, and it stays behind proof of
 *   ownership. Nothing here can reach it.
 *
 * So this gate is not the ownership allowlist with the checks loosened. It
 * is a different gate for a strictly smaller action, and the three things
 * it has to prevent are different too:
 *
 *   1. Being used as a reflector. Anyone can make this server send a
 *      request somewhere. Per-user and per-target throttles bound how much
 *      traffic any one caller, or any one victim, can be made to carry.
 *
 *   2. Being used anonymously. Callers must be authenticated, so every
 *      request is attributable and every refusal is audited. The point is
 *      not that login is hard to get; it is that the log names someone.
 *
 *   3. Reaching inside the network. Handled structurally rather than here —
 *      lib/net/safe-request.ts resolves the name, refuses non-public
 *      answers and pins the connection to the vetted address.
 */

/** A completed result this fresh is served again instead of re-fetching. */
const CACHE_WINDOW_MS = 15 * 60_000;

/** Scans of one hostname per hour, across every caller. */
const MAX_PER_TARGET_PER_HOUR = 6;

export type PublicScanRefusal =
  | "invalid_hostname"
  | "account_not_active"
  | "target_throttled";

export type PublicScanAuthorization =
  | { granted: true; hostname: string; cached: { scanId: string } | null }
  | { granted: false; reason: PublicScanRefusal; message: string };

export async function authorizePublicScan(input: {
  userId: string;
  userStatus: string;
  hostname: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}): Promise<PublicScanAuthorization> {
  const normalized = normalizeHostname(input.hostname);
  if (!normalized.ok) {
    return {
      granted: false,
      reason: "invalid_hostname",
      message: normalized.reason,
    };
  }
  const hostname = normalized.hostname;

  if (input.userStatus !== "ACTIVE") {
    await writeAudit({
      actorUserId: input.userId,
      action: "PUBLIC_SCAN_REFUSED",
      targetType: "Hostname",
      targetId: hostname,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      requestId: input.requestId,
      metadata: { reason: "account_not_active" },
    });
    return {
      granted: false,
      reason: "account_not_active",
      message: "This account cannot run scans.",
    };
  }

  // A recent result is served again rather than re-fetched. This is the
  // throttle that matters most, because it removes the request entirely:
  // ten people checking the same popular site inside a quarter hour cost
  // that site one GET, not ten.
  const cached = await prisma.scanResult.findFirst({
    where: {
      hostname,
      scanType: "HEADERS_ONLY",
      status: "COMPLETED",
      completedAt: { gt: new Date(Date.now() - CACHE_WINDOW_MS) },
    },
    orderBy: { completedAt: "desc" },
    select: { id: true },
  });

  if (cached) {
    return { granted: true, hostname, cached: { scanId: cached.id } };
  }

  // Per-target ceiling, counted across all callers. A per-user limit alone
  // would let many accounts aim at one host; this is the half that protects
  // the target rather than the service.
  const recentAgainstTarget = await prisma.scanResult.count({
    where: {
      hostname,
      scanType: "HEADERS_ONLY",
      createdAt: { gt: new Date(Date.now() - 3_600_000) },
    },
  });

  if (recentAgainstTarget >= MAX_PER_TARGET_PER_HOUR) {
    await writeAudit({
      actorUserId: input.userId,
      action: "PUBLIC_SCAN_REFUSED",
      targetType: "Hostname",
      targetId: hostname,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      requestId: input.requestId,
      metadata: { reason: "target_throttled", recentAgainstTarget },
    });
    return {
      granted: false,
      reason: "target_throttled",
      message: `${hostname} has been checked ${recentAgainstTarget} times in the last hour. Fulcrum limits how often one host can be checked, regardless of who asks — it will not be used to generate traffic against a site on anyone's behalf. Try again later.`,
    };
  }

  return { granted: true, hostname, cached: null };
}

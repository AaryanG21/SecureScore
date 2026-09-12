import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiOk } from "@/lib/http";
import { requireAdmin } from "@/lib/auth/guards";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Admin dashboard data: users, domains, scans, and system health.
 *
 * Read-only, so it needs the admin role but not a fresh re-authentication —
 * that requirement is reserved for the destructive actions.
 *
 * Note what is NOT selected: passwordHash, twoFactorSecret, and token
 * hashes never leave the database, not even for an administrator.
 */
export async function GET(request: NextRequest) {
  const guard = await requireAdmin(request, { skipCsrf: true });
  if (!guard.ok) return guard.response;

  const [users, domains, scans, counts] = await Promise.all([
    prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      take: 200,
      select: {
        id: true,
        email: true,
        role: true,
        status: true,
        twoFactorEnabled: true,
        failedLoginCount: true,
        lockedUntil: true,
        lastLoginAt: true,
        createdAt: true,
        _count: { select: { domains: true, scans: true } },
      },
    }),
    prisma.domain.findMany({
      orderBy: { createdAt: "desc" },
      take: 200,
      select: {
        id: true,
        hostname: true,
        verificationStatus: true,
        verificationMethod: true,
        verifiedAt: true,
        revokedAt: true,
        createdAt: true,
        user: { select: { id: true, email: true } },
      },
    }),
    prisma.scanResult.findMany({
      orderBy: { createdAt: "desc" },
      take: 100,
      select: {
        id: true,
        status: true,
        score: true,
        grade: true,
        createdAt: true,
        completedAt: true,
        refusalReason: true,
        domain: { select: { hostname: true } },
        user: { select: { email: true } },
      },
    }),
    Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { status: "SUSPENDED" } }),
      prisma.domain.count({ where: { verificationStatus: "VERIFIED" } }),
      prisma.scanResult.count(),
      prisma.refreshToken.count({ where: { revokedAt: null, expiresAt: { gt: new Date() } } }),
    ]),
  ]);

  const [totalUsers, suspendedUsers, verifiedDomains, totalScans, activeSessions] = counts;

  const response = apiOk({
    users,
    domains,
    scans,
    health: {
      totalUsers,
      suspendedUsers,
      verifiedDomains,
      totalScans,
      activeSessions,
      serverTime: new Date().toISOString(),
    },
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

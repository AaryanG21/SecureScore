import { redirect } from "next/navigation";
import { prisma } from "@/lib/db";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Panel, Stat } from "@/components/ui";
import { AdminConsole } from "@/app/admin/admin-console";

export const dynamic = "force-dynamic";
export const metadata = { title: "Admin — Fulcrum" };

/**
 * Admin console.
 *
 * The role check happens here, server-side, before any admin data is
 * fetched — a non-admin gets a redirect and never receives the payload.
 * The same check is repeated independently inside every /api/admin route,
 * because a page guard does not protect an API.
 */
export default async function AdminPage() {
  const session = await getSession();
  if (!session) redirect("/login");
  if (session.role !== "ADMIN") redirect("/dashboard");

  const [users, domains, auditEntries, health] = await Promise.all([
    prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      take: 100,
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
      take: 100,
      select: {
        id: true,
        hostname: true,
        verificationStatus: true,
        verifiedAt: true,
        createdAt: true,
        user: { select: { email: true } },
      },
    }),
    prisma.auditLog.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
      select: {
        id: true,
        action: true,
        targetType: true,
        targetId: true,
        ipAddress: true,
        createdAt: true,
        actor: { select: { email: true } },
      },
    }),
    Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { status: "SUSPENDED" } }),
      prisma.domain.count({ where: { verificationStatus: "VERIFIED" } }),
      prisma.refreshToken.count({
        where: { revokedAt: null, expiresAt: { gt: new Date() } },
      }),
    ]),
  ]);

  const [totalUsers, suspended, verifiedDomains, activeSessions] = health;

  return (
    <AppShell email={session.email} isAdmin active="admin">
      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Users" value={totalUsers} hint={`${suspended} suspended`} />
        <Stat label="Verified domains" value={verifiedDomains} />
        <Stat label="Active sessions" value={activeSessions} />
        <Stat label="Audit entries" value={auditEntries.length} hint="latest 50" />
      </div>

      <div className="mt-6">
        <AdminConsole
          currentUserId={session.id}
          users={users.map((u) => ({
            ...u,
            lockedUntil: u.lockedUntil?.toISOString() ?? null,
            lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
            createdAt: u.createdAt.toISOString(),
          }))}
          domains={domains.map((d) => ({
            ...d,
            verifiedAt: d.verifiedAt?.toISOString() ?? null,
            createdAt: d.createdAt.toISOString(),
          }))}
        />
      </div>

      <div className="mt-6">
        <Panel
          title="Audit log"
          description="Append-only. The database rejects updates and deletes on this table."
        >
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs tracking-wide text-ink-faint uppercase">
                  <th className="pb-2 font-medium">When</th>
                  <th className="pb-2 font-medium">Actor</th>
                  <th className="pb-2 font-medium">Action</th>
                  <th className="pb-2 font-medium">Target</th>
                  <th className="pb-2 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {auditEntries.map((entry) => (
                  <tr key={entry.id} className="border-b border-line/50 last:border-0">
                    <td className="py-2 whitespace-nowrap text-ink-faint">
                      {entry.createdAt.toISOString().slice(0, 19).replace("T", " ")}
                    </td>
                    <td className="py-2 font-mono text-ink-muted">
                      {entry.actor?.email ?? "—"}
                    </td>
                    <td className="py-2 font-mono text-ink">{entry.action}</td>
                    <td className="py-2 text-ink-muted">
                      {entry.targetType}
                      {entry.targetId ? `:${entry.targetId.slice(0, 8)}` : ""}
                    </td>
                    <td className="py-2 font-mono text-ink-faint">
                      {entry.ipAddress ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </AppShell>
  );
}

import { redirect } from "next/navigation";
import Link from "next/link";
import { prisma } from "@/lib/db";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Panel, Stat } from "@/components/ui";
import { DomainManager } from "@/app/dashboard/domain-manager";
import { ScanLauncher } from "@/app/dashboard/scan-launcher";
import {
  DNS_CHALLENGE_PREFIX,
  HTTP_CHALLENGE_PATH,
} from "@/lib/domains/verification";

export const dynamic = "force-dynamic";
export const metadata = { title: "Dashboard — Fulcrum" };

/**
 * User dashboard.
 *
 * The session is resolved server-side before anything renders, and every
 * query below is scoped by that session's user id. There is no client-side
 * "am I logged in?" check standing in for authorization.
 */
export default async function DashboardPage() {
  const session = await getSession();
  if (!session) redirect("/login");

  const [domains, scans] = await Promise.all([
    prisma.domain.findMany({
      where: { userId: session.id },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        hostname: true,
        verificationStatus: true,
        verificationMethod: true,
        verificationToken: true,
        verifiedAt: true,
        createdAt: true,
      },
    }),
    prisma.scanResult.findMany({
      where: { userId: session.id },
      orderBy: { createdAt: "desc" },
      take: 10,
      select: {
        id: true,
        status: true,
        grade: true,
        score: true,
        createdAt: true,
        domain: { select: { hostname: true } },
      },
    }),
  ]);

  const verifiedCount = domains.filter(
    (d) => d.verificationStatus === "VERIFIED",
  ).length;

  return (
    <AppShell email={session.email} isAdmin={session.role === "ADMIN"} active="dashboard">
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Domains" value={domains.length} hint={`${verifiedCount} verified`} />
        <Stat label="Scans run" value={scans.length} hint="last 10 shown" />
        <Stat
          label="Latest grade"
          value={scans.find((s) => s.grade)?.grade ?? "—"}
          hint={scans[0]?.domain.hostname ?? "no scans yet"}
        />
      </div>

      <div className="mt-6">
        <DomainManager
          initialDomains={domains.map((d) => ({
            ...d,
            verifiedAt: d.verifiedAt?.toISOString() ?? null,
            createdAt: d.createdAt.toISOString(),
            challenge:
              d.verificationMethod === "DNS_TXT"
                ? {
                    type: "DNS_TXT" as const,
                    target: `${DNS_CHALLENGE_PREFIX}.${d.hostname}`,
                    value: d.verificationToken,
                  }
                : {
                    type: "HTTP_WELL_KNOWN" as const,
                    target: `https://${d.hostname}${HTTP_CHALLENGE_PATH}`,
                    value: d.verificationToken,
                  },
          }))}
        />
      </div>

      <div className="mt-6">
        <ScanLauncher
          domains={domains
            .filter((d) => d.verificationStatus === "VERIFIED")
            .map((d) => ({ id: d.id, hostname: d.hostname }))}
        />
      </div>

      <div className="mt-6">
        <Panel
          title="Scan history"
          description="Scorecards for domains you have verified."
        >
          {scans.length === 0 ? (
            <p className="text-sm text-ink-muted">
              No scans yet. Verify a domain first — the agent refuses to scan
              anything unverified, and logs the refusal.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs tracking-wide text-ink-faint uppercase">
                  <th className="pb-2 font-medium">Host</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Grade</th>
                  <th className="pb-2 font-medium">Score</th>
                  <th className="pb-2 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b border-line/50 last:border-0">
                    <td className="py-2 font-mono">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="text-signal hover:underline"
                      >
                        {scan.domain.hostname}
                      </Link>
                    </td>
                    <td className="py-2 text-ink-muted">{scan.status}</td>
                    <td className="py-2 font-mono text-ink">{scan.grade ?? "—"}</td>
                    <td className="py-2 font-mono text-ink-muted">{scan.score ?? "—"}</td>
                    <td className="py-2 text-ink-faint">
                      {scan.createdAt.toISOString().slice(0, 16).replace("T", " ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

    </AppShell>
  );
}

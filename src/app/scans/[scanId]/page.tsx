import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { prisma } from "@/lib/db";
import { getSession } from "@/lib/auth/session";
import { AppShell } from "@/components/app-shell";
import { Panel } from "@/components/ui";
import { Scorecard } from "@/components/scorecard";
import type { Finding, Grade, RemediationPlan } from "@/lib/agent/types";

export const dynamic = "force-dynamic";
export const metadata = { title: "Scorecard — Fulcrum" };

/**
 * One scan's scorecard.
 *
 * Ownership is part of the query, so another user's scan is indistinguishable
 * from one that does not exist.
 */
export default async function ScanPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const session = await getSession();
  if (!session) redirect("/login");

  const { scanId } = await params;

  const scan = await prisma.scanResult.findFirst({
    where: { id: scanId, userId: session.id },
    select: {
      id: true,
      hostname: true,
      scanType: true,
      status: true,
      findings: true,
      score: true,
      grade: true,
      budgetLimit: true,
      budgetUsed: true,
      remediationPlan: true,
      degradedSteps: true,
      testsslVersion: true,
      refusalReason: true,
      errorMessage: true,
      completedAt: true,
      createdAt: true,
    },
  });

  if (!scan) notFound();

  const isAdmin = session.role === "ADMIN";

  if (scan.status !== "COMPLETED") {
    return (
      <AppShell email={session.email} isAdmin={isAdmin} active="dashboard">
        <Panel title={`Scan of ${scan.hostname}`}>
          <p className="text-sm text-ink-muted">
            This scan is <span className="font-mono text-ink">{scan.status.toLowerCase()}</span>.
          </p>
          {scan.refusalReason && (
            <p className="mt-2 text-sm text-sev-high">
              Refused: {scan.refusalReason.replaceAll("_", " ")}. Fulcrum only
              scans domains you have registered and verified.
            </p>
          )}
          {scan.errorMessage && (
            <p className="mt-2 text-sm text-sev-critical">{scan.errorMessage}</p>
          )}
          <Link
            href="/dashboard"
            className="mt-4 inline-flex text-sm text-signal hover:underline"
          >
            Back to dashboard
          </Link>
        </Panel>
      </AppShell>
    );
  }

  // The stored JSON is shaped by our own agent, but it is still data read
  // back from a database column rather than a typed value, so the cast is
  // explicit and narrow.
  const findings = (scan.findings ?? []) as unknown as Finding[];
  const plan = (scan.remediationPlan ?? {
    budgetLimit: scan.budgetLimit,
    budgetUsed: scan.budgetUsed,
    steps: [],
    deferred: [],
    projectedScore: scan.score ?? 0,
    projectedGrade: (scan.grade ?? "F") as Grade,
    strategy: "No plan was stored for this scan.",
  }) as unknown as RemediationPlan;

  const degraded = (scan.degradedSteps ?? []) as unknown as Array<{
    step: string;
    reason: string;
  }>;

  return (
    <AppShell email={session.email} isAdmin={isAdmin} active="dashboard">
      <Link
        href="/dashboard"
        className="mb-4 inline-flex text-sm text-ink-muted hover:text-ink"
      >
        ← Back to dashboard
      </Link>

      <Scorecard
        hostname={scan.hostname}
        scanType={scan.scanType}
        grade={(scan.grade ?? "F") as Grade}
        score={scan.score ?? 0}
        findings={findings}
        plan={plan}
        testsslVersion={scan.testsslVersion}
        degraded={degraded}
        scannedAt={(scan.completedAt ?? scan.createdAt)
          .toISOString()
          .slice(0, 16)
          .replace("T", " ")}
      />
    </AppShell>
  );
}

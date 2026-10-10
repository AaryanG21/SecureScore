import { redirect } from "next/navigation";
import Link from "next/link";
import { prisma } from "@/lib/db";
import { getSession } from "@/lib/auth/session";
import { recentAttemptsForUser } from "@/lib/auth/attempts";
import { countUnusedBackupCodes } from "@/lib/auth/totp";
import { AppShell } from "@/components/app-shell";
import { Badge, Panel } from "@/components/ui";
import { ChangePasswordForm } from "@/app/account/change-password-form";
import { DataControls } from "@/app/account/data-controls";

export const dynamic = "force-dynamic";
export const metadata = { title: "Account — Fulcrum" };

export default async function AccountPage() {
  const session = await getSession();
  if (!session) redirect("/login");

  const [user, attempts, backupCodesLeft] = await Promise.all([
    prisma.user.findUnique({
      where: { id: session.id },
      select: {
        email: true,
        role: true,
        status: true,
        twoFactorEnabled: true,
        twoFactorEnrolledAt: true,
        passwordChangedAt: true,
        lastLoginAt: true,
        createdAt: true,
      },
    }),
    recentAttemptsForUser(session.id, 15),
    countUnusedBackupCodes(session.id),
  ]);

  if (!user) redirect("/login");

  return (
    <AppShell email={session.email} isAdmin={session.role === "ADMIN"} active="account">
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Account">
          <dl className="space-y-2.5 text-sm">
            <Row label="Email" value={user.email} mono />
            <Row label="Role" value={user.role.toLowerCase()} />
            <Row label="Status" value={user.status.toLowerCase()} />
            <Row
              label="Password changed"
              value={user.passwordChangedAt.toISOString().slice(0, 10)}
            />
            <Row
              label="Last sign-in"
              value={user.lastLoginAt?.toISOString().slice(0, 16).replace("T", " ") ?? "—"}
            />
          </dl>
        </Panel>

        <Panel title="Two-factor authentication">
          <div className="flex items-center gap-3">
            <Badge tone={user.twoFactorEnabled ? "signal" : "critical"}>
              {user.twoFactorEnabled ? "enabled" : "not enrolled"}
            </Badge>
            <span className="text-sm text-ink-muted">
              {backupCodesLeft} backup code{backupCodesLeft === 1 ? "" : "s"} remaining
            </span>
          </div>

          {backupCodesLeft <= 2 && (
            <p className="mt-3 text-sm text-sev-medium">
              You are running low on backup codes. Re-enroll to generate a new
              set — the old ones stop working when you do.
            </p>
          )}

          <p className="mt-3 text-sm text-ink-muted">
            Re-enrolling replaces your authenticator secret and issues a fresh
            set of backup codes.
          </p>

          <Link
            href="/enroll"
            className="mt-4 inline-flex rounded-md border border-line-bright bg-surface-2 px-4 py-2 text-sm text-ink transition-colors hover:border-signal/50"
          >
            Re-enroll authenticator
          </Link>
        </Panel>

        <Panel
          title="Change password"
          description="Changing your password signs out every other session."
        >
          <ChangePasswordForm />
        </Panel>

        <DataControls />

        <Panel
          title="Recent sign-in activity"
          description="Both successful and failed attempts on your account."
        >
          {attempts.length === 0 ? (
            <p className="text-sm text-ink-muted">Nothing recorded yet.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {attempts.map((attempt) => (
                <li
                  key={attempt.id}
                  className="flex flex-wrap items-center justify-between gap-2 border-b border-line/50 pb-2 last:border-0"
                >
                  <span className="flex items-center gap-2">
                    <Badge tone={attempt.success ? "signal" : "critical"}>
                      {attempt.success ? "ok" : "failed"}
                    </Badge>
                    <span className="text-ink-muted">{attempt.stage.toLowerCase()}</span>
                  </span>
                  <span className="font-mono text-xs text-ink-faint">
                    {attempt.ipAddress ?? "unknown ip"} ·{" "}
                    {attempt.createdAt.toISOString().slice(0, 16).replace("T", " ")}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}

function Row({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-ink-faint">{label}</dt>
      <dd className={mono ? "font-mono text-ink" : "text-ink"}>{value}</dd>
    </div>
  );
}

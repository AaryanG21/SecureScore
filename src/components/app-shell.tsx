import Link from "next/link";
import type { ReactNode } from "react";
import { SignOutButton } from "@/components/sign-out-button";

/**
 * Chrome for authenticated pages.
 *
 * `isAdmin` controls whether the admin link renders. That is presentation
 * only — hiding a link is not access control, and every admin route
 * re-checks the role server-side against the database.
 */
export function AppShell({
  email,
  isAdmin,
  active,
  children,
}: {
  email: string;
  isAdmin: boolean;
  active: "dashboard" | "admin" | "account";
  children: ReactNode;
}) {
  const navItem = (href: string, key: typeof active, label: string) => (
    <Link
      key={key}
      href={href}
      className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
        active === key
          ? "bg-surface-2 text-ink"
          : "text-ink-muted hover:text-ink"
      }`}
    >
      {label}
    </Link>
  );

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line bg-surface/60">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-3">
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="flex items-center gap-2.5">
              <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
              <span className="font-mono text-sm font-semibold tracking-widest text-ink uppercase">
                Fulcrum
              </span>
            </Link>
            <nav className="flex items-center gap-1">
              {navItem("/dashboard", "dashboard", "Dashboard")}
              {navItem("/account", "account", "Account")}
              {isAdmin && navItem("/admin", "admin", "Admin")}
            </nav>
          </div>

          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-ink-faint">{email}</span>
            <SignOutButton />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-8">{children}</main>
    </div>
  );
}

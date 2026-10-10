import Link from "next/link";
import type { ReactNode } from "react";
import { SiteFooter } from "@/components/site-footer";
import { JURISDICTION, OPERATOR, isConfigured } from "@/lib/legal/operator";

/**
 * Shell for the legal pages.
 *
 * These are the only routes on the site meant to be indexed and read by
 * someone who is not signed in, so they get a plain reading layout rather
 * than the application chrome.
 *
 * The unconfigured-operator banner is deliberately impossible to miss. A
 * privacy policy that names no Data Fiduciary and gives no grievance
 * contact does not satisfy the DPDP Act however carefully the rest is
 * worded, and publishing one that says "PLACEHOLDER" is worse than having
 * none at all — it looks like diligence while providing none.
 */
export default function LegalLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line">
        <nav className="mx-auto flex max-w-3xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-2.5">
            <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
            <span className="font-mono text-sm font-semibold tracking-widest text-ink uppercase">
              Fulcrum
            </span>
          </Link>
          <Link
            href="/"
            className="text-sm text-ink-muted transition-colors hover:text-ink"
          >
            Back to site
          </Link>
        </nav>
      </header>

      <main id="main" className="mx-auto w-full max-w-3xl flex-1 px-6 py-12">
        {!isConfigured && (
          <div
            role="alert"
            className="mb-8 rounded-lg border border-sev-critical/50 bg-sev-critical/10 p-4 text-sm text-sev-critical"
          >
            <p className="font-semibold">
              This document is not ready to publish.
            </p>
            <p className="mt-1.5 leading-relaxed">
              The operator details in{" "}
              <code className="font-mono">src/lib/legal/operator.ts</code> still
              contain placeholders. Under the {JURISDICTION.lawShort} a privacy
              notice must identify the Data Fiduciary and publish a contact for
              grievances; this one currently does neither.
            </p>
          </div>
        )}

        <article className="legal-prose">{children}</article>

        <p className="mt-12 border-t border-line pt-6 text-xs text-ink-muted">
          Last updated {OPERATOR.lastUpdated}.
        </p>
      </main>

      <SiteFooter />
    </div>
  );
}

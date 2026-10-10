import Link from "next/link";
import { SiteFooter } from "@/components/site-footer";
import { EnrollFlow } from "@/app/enroll/enroll-flow";

export const metadata = { title: "Two-factor setup — Fulcrum" };

// Rendered per request, not prerendered.
//
// The CSP in src/proxy.ts carries a per-request nonce, and `'strict-dynamic'`
// makes browsers ignore the `'self'` source expression for scripts. A page
// prerendered at build time has no request and therefore no nonce, so its
// script tags are emitted bare and every one of them is blocked — the page
// ships with no working JavaScript at all. That failure is invisible in
// `next dev`, which does not prerender, and it only appears in a production
// build. Opting out of static generation is what keeps the nonce and the
// markup on the same request.
export const dynamic = "force-dynamic";


export default function EnrollPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center px-6 py-4">
          <Link href="/" className="flex items-center gap-2.5">
            <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
            <span className="font-mono text-sm font-semibold tracking-widest text-ink uppercase">
              Fulcrum
            </span>
          </Link>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-6 py-16">
        <div className="w-full max-w-lg">
          <EnrollFlow />
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}

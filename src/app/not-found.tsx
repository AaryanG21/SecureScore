import Link from "next/link";

/**
 * 404.
 *
 * Rendered per request for the same reason the sign-in pages are: Next
 * prerenders the built-in not-found page at build time, where there is no
 * request and therefore no CSP nonce, and `'strict-dynamic'` then blocks
 * every un-nonced script tag on it.
 */
export const dynamic = "force-dynamic";

export const metadata = { title: "Not found — Fulcrum" };

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="max-w-md text-center">
        <p className="font-mono text-sm tracking-widest text-ink-faint uppercase">
          404
        </p>
        <h1 className="mt-3 text-xl text-ink">No such page</h1>
        <p className="mt-2 text-sm leading-relaxed text-ink-muted">
          This address does not correspond to anything. If you followed a link
          to a scan or a domain, it may have been removed — or it may belong to
          another account, which looks identical from here on purpose.
        </p>
        <Link
          href="/"
          className="mt-6 inline-block rounded-md border border-line-bright px-4 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
        >
          Back to the start
        </Link>
      </div>
    </main>
  );
}

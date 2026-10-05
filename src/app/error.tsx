"use client";

/**
 * Route-level error boundary.
 *
 * What it deliberately does NOT render: `error.message` or `error.stack`.
 * In a production build Next replaces the message with a generic string and
 * exposes only `digest`, but in development the real message is present —
 * and a boundary that prints it is a boundary that will one day print a
 * connection string from a Prisma error. The digest is shown instead,
 * because it correlates with the server-side log entry without disclosing
 * anything about the failure to the person triggering it.
 */
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center px-6">
      <div className="max-w-md text-center">
        <p className="font-mono text-sm tracking-widest text-sev-high uppercase">
          Error
        </p>
        <h1 className="mt-3 text-xl text-ink">Something failed on our side</h1>
        <p className="mt-2 text-sm leading-relaxed text-ink-muted">
          The request did not complete. Nothing was changed by the attempt.
          Trying again is safe.
        </p>

        {error.digest && (
          <p className="mt-4 font-mono text-xs text-ink-faint">
            reference {error.digest}
          </p>
        )}

        <div className="mt-6 flex justify-center gap-3">
          <button
            type="button"
            onClick={reset}
            className="rounded-md border border-line-bright px-4 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
          >
            Try again
          </button>
          <a
            href="/dashboard"
            className="rounded-md border border-line px-4 py-2 text-sm text-ink-muted transition-colors hover:bg-surface-2"
          >
            Dashboard
          </a>
        </div>
      </div>
    </main>
  );
}

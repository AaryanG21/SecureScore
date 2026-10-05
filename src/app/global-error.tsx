"use client";

/**
 * Last-resort boundary, used when the root layout itself throws.
 *
 * It has to render its own <html> and <body> because the layout that would
 * normally provide them is the thing that failed. Styling is inline for the
 * same reason: at this point the stylesheet may not have loaded either.
 * As in error.tsx, the error message is never shown — only the digest.
 */
export default function GlobalError({
  error,
}: {
  error: Error & { digest?: string };
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#07090d",
          color: "#e6edf3",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
          padding: "1.5rem",
        }}
      >
        <div style={{ maxWidth: "28rem", textAlign: "center" }}>
          <h1 style={{ fontSize: "1.125rem", fontWeight: 600 }}>
            Fulcrum could not start this page
          </h1>
          <p
            style={{
              marginTop: "0.5rem",
              fontSize: "0.875rem",
              lineHeight: 1.6,
              color: "#9aa7b4",
            }}
          >
            The application shell failed to render. This is logged on the
            server.
          </p>
          {error.digest && (
            <p
              style={{
                marginTop: "1rem",
                fontFamily: "ui-monospace, monospace",
                fontSize: "0.75rem",
                color: "#6b7986",
              }}
            >
              reference {error.digest}
            </p>
          )}
          {/* eslint-disable-next-line @next/next/no-html-link-for-pages --
              next/link needs a working router, and this boundary only
              renders when the root layout failed to render at all. A
              plain anchor doing a full document load is the one
              navigation that is still guaranteed to work here. */}
          <a
            href="/"
            style={{
              display: "inline-block",
              marginTop: "1.5rem",
              padding: "0.5rem 1rem",
              border: "1px solid #2c3a4b",
              borderRadius: "0.375rem",
              color: "#e6edf3",
              fontSize: "0.875rem",
              textDecoration: "none",
            }}
          >
            Back to the start
          </a>
        </div>
      </body>
    </html>
  );
}

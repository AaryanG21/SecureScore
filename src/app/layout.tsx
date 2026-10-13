import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

/**
 * Absolute base for metadata URLs.
 *
 * Open Graph consumers do not resolve relative URLs, so without this the
 * generated opengraph-image is advertised as a relative path and every
 * unfurl silently falls back to no image. APP_ORIGIN is already a required,
 * URL-validated env var; the guard is only so a missing one degrades to "no
 * OG image" rather than throwing during the build.
 */
const metadataBase = process.env.APP_ORIGIN
  ? new URL(process.env.APP_ORIGIN)
  : undefined;

export const metadata: Metadata = {
  metadataBase,
  title: "Fulcrum — Website Security Scorecard",
  description:
    "Scan domains you own, get a graded security scorecard, and a remediation plan ranked to your fix-effort budget.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full bg-base text-ink antialiased">{children}</body>
    </html>
  );
}

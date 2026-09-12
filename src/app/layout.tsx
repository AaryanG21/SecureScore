import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
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

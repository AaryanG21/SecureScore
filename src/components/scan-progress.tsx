"use client";

import { useEffect, useState } from "react";
import { Clock } from "@/components/icons";
import { IndeterminateBar } from "@/components/ui";

/**
 * What the user sees while a scan runs.
 *
 * ── What this deliberately does not do ──────────────────────────────────
 *
 * It does not show a percentage, and it does not show which stage is
 * running. Not because that would be hard, but because the server does not
 * send it: `runScan` returns once, at the end, and nothing reports stage
 * transitions while it works. A progress bar filling toward the three-minute
 * mark would be a prediction wearing the costume of a measurement, and a
 * stage list with a highlighted "current" item would be inventing telemetry
 * that does not exist.
 *
 * So exactly one thing here moves with real information behind it: the
 * elapsed counter, which is measured. The bar is indeterminate, which is the
 * honest visual grammar for "working, duration unknown". The stage list is
 * static and labelled as the pipeline rather than a position in it.
 *
 * The product's own landing page criticises invented progress. This is the
 * part of the app where it would have been easiest to do anyway.
 */

/** Matches the step sequence in src/lib/agent/run.ts. */
const STAGES = [
  "HTTP response headers",
  "Software fingerprint, from those headers",
  "CVE and EPSS cross-reference",
  "TLS configuration via testssl.sh",
] as const;

/** Past this, "typically two to three minutes" has stopped being true. */
const OVERTIME_SECONDS = 180;

function formatElapsed(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

export function ScanProgress({ startedAtMs }: { startedAtMs: number }) {
  // Derived from wall-clock on every tick rather than incremented, so a
  // throttled background tab resumes with the correct number instead of a
  // count of how many intervals happened to fire.
  const [elapsed, setElapsed] = useState(() =>
    Math.max(0, Math.floor((Date.now() - startedAtMs) / 1000)),
  );

  useEffect(() => {
    const id = setInterval(() => {
      setElapsed(Math.max(0, Math.floor((Date.now() - startedAtMs) / 1000)));
    }, 1000);
    return () => clearInterval(id);
  }, [startedAtMs]);

  const overtime = elapsed >= OVERTIME_SECONDS;

  // A polite live region that re-announced every second would be unusable.
  // The visible counter is hidden from assistive tech and this coarse
  // sentence carries the state instead, changing twice at most.
  const announcement = overtime
    ? "Scan still running, longer than is typical."
    : "Scan running. This usually takes two to three minutes.";

  return (
    <div className="mt-4 rounded-md border border-line bg-surface-2 p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="flex items-center gap-2 text-sm text-ink">
          <Clock className="h-4 w-4 text-signal" />
          {overtime ? "Still running" : "Scanning"}
        </span>
        <span className="font-mono text-sm text-ink-muted" aria-hidden="true">
          {formatElapsed(elapsed)}
        </span>
      </div>

      <div className="mt-3">
        <IndeterminateBar />
      </div>

      <p role="status" className="sr-only">
        {announcement}
      </p>

      <ol className="mt-4 space-y-1.5">
        {STAGES.map((stage, index) => (
          <li key={stage} className="flex gap-2 text-xs text-ink-faint">
            <span className="font-mono text-ink-faint">{index + 1}.</span>
            {stage}
          </li>
        ))}
      </ol>

      <p className="mt-3 border-t border-line pt-3 text-xs text-ink-faint">
        {overtime
          ? "This is longer than a typical run. The scan is still going; the result is written to your history whether or not this tab stays open."
          : "The TLS stage dominates the runtime. Fulcrum does not report per-stage progress — the elapsed time above is measured, but the list is the pipeline, not a position in it."}
      </p>
    </div>
  );
}

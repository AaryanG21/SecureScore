"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { ScanProgress } from "@/components/scan-progress";

/**
 * Keeps an in-progress scorecard page current.
 *
 * Before this, landing on /scans/<id> while the scan was still running gave
 * you a page that said "this scan is running" and then never changed — the
 * result existed minutes later but the only way to see it was to reload by
 * hand.
 *
 * It polls the scan endpoint that already exists rather than adding one, and
 * stops the moment the status is anything other than RUNNING or QUEUED. A
 * poller that does not know how to stop is worse than no poller, so there
 * are four separate brakes:
 *
 *   - terminal status  -> refresh the server component, then stop
 *   - 401 / 404        -> stop (session expired, or the scan is gone; both
 *                         would otherwise loop forever against an endpoint
 *                         that will never succeed)
 *   - MAX_POLLS        -> stop, so a stuck RUNNING row cannot poll all day.
 *                         The reaper will mark it FAILED server-side.
 *   - unmount          -> clear the interval
 *
 * At one request per 5s this uses 12 of the 120/minute api rate limit.
 */

const POLL_MS = 5_000;

/** ~15 minutes. Comfortably past the reaper's threshold. */
const MAX_POLLS = 180;

export function ScanStatusWatcher({
  scanId,
  startedAtMs,
}: {
  scanId: string;
  startedAtMs: number;
}) {
  const router = useRouter();

  // A ref, not state: changing it must not re-render, and the interval
  // closure needs to see the current value rather than the one captured
  // when the effect first ran.
  const pollsRef = useRef(0);

  useEffect(() => {
    let cancelled = false;

    const id = setInterval(async () => {
      if (cancelled) return;

      if (++pollsRef.current > MAX_POLLS) {
        clearInterval(id);
        return;
      }

      const result = await apiFetch<{ status: string }>(`/api/scans/${scanId}`);
      if (cancelled) return;

      if (!result.ok) {
        // 404: deleted, or never ours. 401: the session expired while we
        // waited. Neither recovers by asking again.
        if (result.error.status === 404 || result.error.status === 401) {
          clearInterval(id);
        }
        return;
      }

      const status = result.data.status;
      if (status !== "RUNNING" && status !== "QUEUED") {
        clearInterval(id);
        // Re-renders the server component, which re-reads the row and
        // swaps this placeholder for the real scorecard.
        router.refresh();
      }
    }, POLL_MS);

    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [scanId, router]);

  return <ScanProgress startedAtMs={startedAtMs} />;
}

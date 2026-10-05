/**
 * Startup checks.
 *
 * `register()` runs once, before the server accepts traffic, which is the
 * only place a configuration problem can be turned into a refusal to start.
 *
 * This exists because three documents — the README, .env.example and the
 * Dockerfile — all claimed the environment was "validated at boot", and it
 * was not. `getEnv()` is lazy and memoized, so a deployment with a
 * malformed APP_ORIGIN or a 16-byte key started cleanly, passed the
 * container health check (which hits a page that reads no env at all), and
 * failed later on whichever request first touched the bad value. A
 * misconfigured security tool that looks healthy is worse than one that
 * refuses to boot.
 */
export async function register(): Promise<void> {
  const { getEnv } = await import("@/lib/env");

  // Throws with every offending variable named — and no values, so this is
  // safe to let crash into a log.
  getEnv();

  // Reconcile scans the previous process left RUNNING.
  //
  // A restart is precisely when rows get stranded, so this is the right
  // moment to clear them. It must not be able to prevent startup: a
  // database that is not reachable yet is a reason to come up and serve
  // the readiness probe a failure, not a reason to crash-loop.
  const { reapStalledScans } = await import("@/lib/agent/reaper");
  try {
    const reaped = await reapStalledScans();
    if (reaped > 0) {
      console.warn(`[startup] marked ${reaped} stalled scan(s) as failed`);
    }
  } catch (error) {
    console.error(
      "[startup] could not reconcile stalled scans",
      error instanceof Error ? error.message : "unknown",
    );
  }
}

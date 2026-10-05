import { errorMessage, log } from "@/lib/log";

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
  // register() is invoked for every runtime Next builds, including Edge.
  // Everything below needs Node — the env schema uses Buffer, and the
  // reaper reaches Prisma — so without this guard the Edge bundle pulls
  // in node:path and the Prisma client and the build fills with
  // "not supported in the Edge Runtime" warnings.
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

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
      log.warn("marked stalled scans as failed at startup", { count: reaped });
    }
  } catch (error) {
    log.error("could not reconcile stalled scans at startup", {
      error: errorMessage(error),
    });
  }
}

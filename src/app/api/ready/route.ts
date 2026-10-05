import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { prisma } from "@/lib/db";
import { apiError, apiOk } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Readiness: can this instance actually serve a request?
 *
 * This exists because the container health check used to fetch `/` — the
 * marketing page, a static render that reads no environment and touches no
 * database. It reported healthy with Postgres unreachable, with migrations
 * unapplied, and with a malformed TOTP_ENCRYPTION_KEY. A security tool
 * that cannot decrypt anyone's second factor but announces itself as
 * healthy is the exact failure this project is supposed to be about not
 * shipping.
 *
 * Two checks:
 *   database    — a trivial query, so the connection pool is exercised
 *   migrations  — every migration on disk is recorded as applied
 *
 * The migration check is the one that matters on a deploy. A new image
 * whose migrations have not been run yet will answer requests and fail
 * them one at a time; this makes the orchestrator hold traffic instead.
 *
 * Responses carry booleans and nothing else. No error text, no driver
 * message, no schema detail — a readiness endpoint is unauthenticated and
 * reachable by anyone who can route to the container.
 */

interface Readiness {
  database: boolean;
  migrations: boolean;
}

/**
 * Short positive cache.
 *
 * Probes are frequent and this endpoint is unauthenticated, so without it
 * an outsider could drive one database round trip per request. Only
 * successes are cached: a failure must be observed again immediately so
 * recovery is not delayed by up to the cache window.
 */
const CACHE_MS = 2_000;
let cachedAt = 0;

async function appliedMigrations(): Promise<Set<string>> {
  const rows = await prisma.$queryRaw<Array<{ migration_name: string }>>`
    SELECT migration_name FROM "_prisma_migrations" WHERE finished_at IS NOT NULL
  `;
  return new Set(rows.map((row) => row.migration_name));
}

async function migrationsOnDisk(): Promise<string[] | null> {
  try {
    const entries = await readdir(join(process.cwd(), "prisma", "migrations"), {
      withFileTypes: true,
    });
    return entries.filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    // Not fatal: some deployments do not ship the migrations directory.
    // The caller falls back to "at least one migration is applied", which
    // still catches a completely unmigrated database.
    return null;
  }
}

async function check(): Promise<Readiness> {
  let database = false;
  let migrations = false;

  try {
    await prisma.$queryRaw`SELECT 1`;
    database = true;
  } catch {
    return { database: false, migrations: false };
  }

  try {
    const applied = await appliedMigrations();
    const onDisk = await migrationsOnDisk();
    migrations =
      onDisk === null
        ? applied.size > 0
        : onDisk.every((name) => applied.has(name));
  } catch {
    migrations = false;
  }

  return { database, migrations };
}

export async function GET() {
  const now = Date.now();

  if (now - cachedAt < CACHE_MS) {
    const response = apiOk({ status: "ready" });
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  const checks = await check();
  const ready = checks.database && checks.migrations;

  if (ready) cachedAt = now;

  const response = ready
    ? apiOk({ status: "ready", checks })
    : apiError(503, "not_ready", "This instance cannot serve requests yet.", checks);

  response.headers.set("Cache-Control", "no-store");
  return response;
}

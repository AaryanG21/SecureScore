import { existsSync } from "node:fs";
import { defineConfig, env } from "prisma/config";

/**
 * Prisma 7 configuration.
 *
 * The connection URL is read from the environment here (and nowhere else
 * for CLI commands) so that no credential ever lands in a schema file
 * that gets committed.
 *
 * Prisma 7 no longer loads .env files automatically, and the Next.js dev
 * server's own loading does not apply to the Prisma CLI. Load them here so
 * `prisma migrate` and `prisma db seed` see the same DATABASE_URL the app
 * does — without that, the CLI either fails or, worse, silently targets a
 * different database than the one the app is using.
 *
 * Order matches Next.js: .env.local wins over .env. Neither is committed.
 */
for (const file of [".env.local", ".env"]) {
  if (existsSync(file)) process.loadEnvFile(file);
}
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
    seed: "tsx prisma/seed.ts",
  },
  datasource: {
    url: env("DATABASE_URL"),
    // Only needed when the migration user cannot create databases
    // (e.g. some managed Postgres providers).
    ...(process.env.SHADOW_DATABASE_URL
      ? { shadowDatabaseUrl: process.env.SHADOW_DATABASE_URL }
      : {}),
  },
});

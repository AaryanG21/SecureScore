import "server-only";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";
import { getEnv } from "@/lib/env";

/**
 * Prisma client singleton.
 *
 * Next.js hot-reloads modules in development, which would otherwise leak a
 * new connection pool on every edit until Postgres refuses connections.
 */

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

function createClient(): PrismaClient {
  const env = getEnv();
  const adapter = new PrismaPg({ connectionString: env.DATABASE_URL });

  return new PrismaClient({
    adapter,
    // Query logging is off in production on purpose: query text plus
    // parameters is a reliable way to leak credentials into logs.
    log: env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });
}

export const prisma: PrismaClient = globalForPrisma.prisma ?? createClient();

if (getEnv().NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

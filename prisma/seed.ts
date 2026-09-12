import { existsSync } from "node:fs";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../src/generated/prisma/client";
import { hash, type Algorithm } from "@node-rs/argon2";

// Run directly by tsx, so nothing has loaded the env files yet. Same order
// as Next.js and prisma.config.ts: .env.local wins over .env.
for (const file of [".env.local", ".env"]) {
  if (existsSync(file)) process.loadEnvFile(file);
}

/**
 * Development seed.
 *
 * Creates one administrator. Intentionally awkward to misuse in production:
 *
 *   - it refuses to run when NODE_ENV is "production"
 *   - it takes the password from SEED_ADMIN_PASSWORD and will not invent a
 *     default one, so there is no well-known credential to forget about
 *   - the account lands in PENDING_2FA, exactly like a real registration,
 *     so the first sign-in must complete TOTP enrollment
 *
 * Run with: npm run db:seed
 */

const ARGON2ID = 2 as Algorithm;

async function main() {
  if (process.env.NODE_ENV === "production") {
    throw new Error("Refusing to seed a production database.");
  }

  const email = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;

  if (!email || !password) {
    throw new Error(
      "Set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD before seeding. No default credentials are provided on purpose.",
    );
  }

  if (password.length < 12) {
    throw new Error("SEED_ADMIN_PASSWORD must be at least 12 characters.");
  }

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new Error("DATABASE_URL is not set.");

  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString }) });

  const passwordHash = await hash(password, {
    algorithm: ARGON2ID,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });

  const user = await prisma.user.upsert({
    where: { email: email.toLowerCase() },
    update: { role: "ADMIN" },
    create: {
      email: email.toLowerCase(),
      passwordHash,
      role: "ADMIN",
      status: "PENDING_2FA",
    },
    select: { id: true, email: true, status: true },
  });

  console.log(
    `Seeded admin ${user.email} (${user.status}). Sign in and complete 2FA enrollment to activate.`,
  );

  await prisma.$disconnect();
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

import { randomBytes } from "node:crypto";

/**
 * Global test setup.
 *
 * Provides a valid-but-throwaway environment so `getEnv()` parses. Keys are
 * generated per run: no test ever exercises a key that could also exist in
 * a real deployment.
 *
 * `server-only` is aliased to a no-op stub in vitest.config.mts so that
 * modules guarding themselves with it can be imported here. See
 * tests/stubs/server-only.ts.
 */

// NODE_ENV is typed read-only; the cast is a test-harness concession.
(process.env as Record<string, string | undefined>).NODE_ENV ??= "test";
process.env.DATABASE_URL ??= "postgresql://fulcrum:fulcrum@localhost:5432/fulcrum_test";
process.env.JWT_SIGNING_KEY ??= randomBytes(32).toString("base64");
process.env.TOTP_ENCRYPTION_KEY ??= randomBytes(32).toString("base64");
process.env.APP_ORIGIN ??= "http://localhost:3000";
process.env.APP_NAME ??= "Fulcrum";
process.env.TRUST_PROXY_HEADERS ??= "false";

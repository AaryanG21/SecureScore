import "server-only";
import { z } from "zod";

/**
 * Server environment.
 *
 * Every secret the app needs is read here and nowhere else. The process
 * refuses to start if anything is missing or too weak, which is the point:
 * a misconfigured deploy should fail loudly at boot rather than quietly
 * fall back to a default key.
 */

const base64Key = (bytes: number, label: string) =>
  z
    .string()
    .min(1, `${label} is required`)
    .refine(
      (v) => {
        try {
          return Buffer.from(v, "base64").length === bytes;
        } catch {
          return false;
        }
      },
      `${label} must be ${bytes} raw bytes, base64-encoded (generate with: openssl rand -base64 ${bytes})`,
    );

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  DATABASE_URL: z.string().min(1).startsWith("postgresql://"),

  // HS256 signing key for short-lived access / mfa-pending / reauth tokens.
  JWT_SIGNING_KEY: base64Key(32, "JWT_SIGNING_KEY"),

  // AES-256-GCM key protecting TOTP shared secrets at rest.
  TOTP_ENCRYPTION_KEY: base64Key(32, "TOTP_ENCRYPTION_KEY"),

  // Absolute origin of the deployment. Used for cookie scoping, CSRF
  // origin checks, and the TOTP issuer label.
  APP_ORIGIN: z.string().url(),

  APP_NAME: z.string().default("Fulcrum"),

  // Access tokens are deliberately short-lived; the refresh token is the
  // long-lived credential and it is rotated on every use.
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(600),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(3600)
    .max(60 * 60 * 24 * 30)
    .default(60 * 60 * 24 * 7),
  // Window between password+TOTP and the second factor challenge.
  MFA_PENDING_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
  // How long a re-authentication stays fresh for destructive admin actions.
  REAUTH_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),

  // Account lockout policy.
  MAX_FAILED_LOGINS: z.coerce.number().int().min(3).max(20).default(5),
  LOCKOUT_BASE_SECONDS: z.coerce.number().int().min(30).default(900),

  // Path to the pinned testssl.sh checkout (see README).
  TESTSSL_PATH: z.string().default("./vendor/testssl.sh/testssl.sh"),
  TESTSSL_TIMEOUT_MS: z.coerce.number().int().min(10_000).max(1_800_000).default(300_000),

  // Trust X-Forwarded-For only when a reverse proxy you control actually
  // sets it. Defaults off: a spoofable client IP would let an attacker
  // sidestep per-IP rate limiting.
  TRUST_PROXY_HEADERS: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),

  // How many reverse proxies you run in front of this app.
  //
  // This number is load-bearing, not cosmetic. X-Forwarded-For is a list
  // that each hop appends to, so the entries a client can forge are on the
  // LEFT and the ones your own infrastructure wrote are on the RIGHT.
  // Reading the left-most entry — the obvious-looking choice — reads
  // attacker-controlled data. The client address is the entry this many
  // places in from the right, and knowing the hop count is the only way to
  // find it.
  //
  // One Caddy/nginx/ALB in front: 1. Cloudflare in front of that: 2.
  TRUSTED_PROXY_HOPS: z.coerce.number().int().min(0).max(10).default(0),
})
  .superRefine((env, ctx) => {
    // Trusting the header without saying how many hops to skip would send
    // us back to reading the left-most, forgeable entry. Fail loudly at
    // boot rather than silently rate-limiting on an attacker's string.
    if (env.TRUST_PROXY_HEADERS && env.TRUSTED_PROXY_HOPS === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["TRUSTED_PROXY_HOPS"],
        message:
          "must be at least 1 when TRUST_PROXY_HEADERS is true — set it to the number of reverse proxies in front of this app",
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

let cached: Env | null = null;

export function getEnv(): Env {
  if (cached) return cached;

  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    // The message names variables, never values.
    throw new Error(`Invalid server environment:\n${issues}`);
  }

  cached = parsed.data;
  return cached;
}

/** Test-only escape hatch so suites can re-parse a mutated environment. */
export function resetEnvCache(): void {
  cached = null;
}

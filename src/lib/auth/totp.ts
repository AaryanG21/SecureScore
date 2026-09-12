import "server-only";
import { randomInt } from "node:crypto";
import {
  NobleCryptoPlugin,
  ScureBase32Plugin,
  TOTP,
  generateSecret,
  generateURI,
} from "otplib";
import { hash as argonHash, verify as argonVerify } from "@node-rs/argon2";
import type { Algorithm } from "@node-rs/argon2";
import { prisma } from "@/lib/db";
import { encryptSecret, decryptSecret } from "@/lib/crypto";
import { getEnv } from "@/lib/env";

/**
 * TOTP second factor (RFC 6238) plus one-time backup codes.
 *
 * 2FA is mandatory here, not opt-in: an account that has not finished
 * enrollment sits in UserStatus.PENDING_2FA and cannot obtain a full
 * session. See lib/auth/session.ts.
 *
 * Replay protection is database-backed rather than in-memory. A TOTP code
 * stays valid for its whole time step, so a code observed in transit could
 * otherwise be replayed for up to ~90 seconds. Each successful
 * verification records the matched time step on the user row, and the next
 * verification rejects anything at or below it — which also holds across
 * restarts and across multiple app instances, unlike a process-local cache.
 */

const PERIOD_SECONDS = 30;

/**
 * otplib v13's class API takes no plugins by default and throws
 * CryptoPluginMissingError if you do not supply them — unlike its
 * functional API, which pre-wires these two. Both are the library's own
 * audited defaults (@noble/hashes and @scure/base); constructing them once
 * here keeps every call site consistent.
 */
const CRYPTO_PLUGIN = new NobleCryptoPlugin();
const BASE32_PLUGIN = new ScureBase32Plugin();

/**
 * ±30s of clock tolerance. Wider windows meaningfully enlarge the guessing
 * surface for a 6-digit code, so this stays at one step either side.
 */
const EPOCH_TOLERANCE = PERIOD_SECONDS;

export const BACKUP_CODE_COUNT = 10;

export function generateTotpSecret(): string {
  // 160-bit, base32.
  return generateSecret({ length: 20, crypto: CRYPTO_PLUGIN, base32: BASE32_PLUGIN });
}

/** The otpauth:// URI an authenticator app scans. Contains the secret. */
export function buildOtpAuthUri(email: string, secret: string): string {
  return generateURI({
    strategy: "totp",
    issuer: getEnv().APP_NAME,
    label: email,
    secret,
    digits: 6,
    period: PERIOD_SECONDS,
  });
}

export function encryptTotpSecret(secret: string): string {
  return encryptSecret(secret);
}

export interface TotpCheck {
  valid: boolean;
  /** Present when valid: the RFC 6238 time step the code matched. */
  timeStep?: number;
}

/**
 * Verifies a code against the stored (encrypted) secret, rejecting any code
 * from a time step already spent by this user.
 *
 * Does NOT persist the new time step — the caller does that only once the
 * whole authentication step succeeds, via `commitTotpTimeStep`.
 */
export async function verifyTotpCode(
  encryptedSecret: string,
  code: string,
  lastTimeStep: number | null,
): Promise<TotpCheck> {
  const normalized = code.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) return { valid: false };

  let secret: string;
  try {
    secret = decryptSecret(encryptedSecret);
  } catch {
    // A secret that fails GCM authentication is tampered or key-rotated;
    // either way it cannot authenticate anyone.
    return { valid: false };
  }

  // The TOTP class rather than the generic `verify()` helper: the generic
  // one's return type unions TOTP and HOTP results, and only the TOTP
  // result carries the `timeStep` we need for replay protection.
  try {
    const totp = new TOTP({
      secret,
      digits: 6,
      period: PERIOD_SECONDS,
      crypto: CRYPTO_PLUGIN,
      base32: BASE32_PLUGIN,
    });

    const result = await totp.verify(normalized, {
      epochTolerance: EPOCH_TOLERANCE,
      // Replay rejection, enforced inside the library.
      ...(lastTimeStep !== null ? { afterTimeStep: lastTimeStep } : {}),
    });

    return result.valid
      ? { valid: true, timeStep: result.timeStep }
      : { valid: false };
  } catch {
    // A malformed stored secret, or any library-level rejection, denies
    // access rather than surfacing a 500 on the login path.
    return { valid: false };
  }
}

/** Records the spent time step so the same code cannot be used again. */
export async function commitTotpTimeStep(
  userId: string,
  timeStep: number,
): Promise<void> {
  // Guarded update: concurrent requests carrying the same code race here,
  // and only the first one moves the marker forward.
  await prisma.user.updateMany({
    where: {
      id: userId,
      OR: [
        { twoFactorLastTimeStep: null },
        { twoFactorLastTimeStep: { lt: timeStep } },
      ],
    },
    data: { twoFactorLastTimeStep: timeStep },
  });
}

/* -------------------------------------------------------------------- */
/* Backup codes                                                          */
/* -------------------------------------------------------------------- */

const ARGON2ID = 2 as Algorithm;

const BACKUP_PARAMS = {
  algorithm: ARGON2ID,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

/** Human-transcribable format: XXXX-XXXX from an unambiguous alphabet. */
function formatBackupCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1
  const pick = () =>
    Array.from({ length: 4 }, () => alphabet[randomInt(alphabet.length)]).join("");
  return `${pick()}-${pick()}`;
}

/**
 * Issues a fresh set of backup codes, replacing any existing ones.
 * Returns the plaintext codes — the ONLY time they exist outside the
 * user's hands. The caller must show them once and never persist them.
 */
export async function issueBackupCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: BACKUP_CODE_COUNT }, formatBackupCode);
  const hashes = await Promise.all(codes.map((c) => argonHash(c, BACKUP_PARAMS)));

  await prisma.$transaction([
    prisma.backupCode.deleteMany({ where: { userId } }),
    prisma.backupCode.createMany({
      data: hashes.map((codeHash) => ({ userId, codeHash })),
    }),
  ]);

  return codes;
}

/**
 * Redeems a backup code. Each code is single-use: the matching row is
 * marked spent by a conditional update, so two concurrent requests holding
 * the same code cannot both succeed.
 */
export async function redeemBackupCode(
  userId: string,
  submitted: string,
): Promise<boolean> {
  const normalized = submitted.trim().toUpperCase();
  if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normalized)) return false;

  const candidates = await prisma.backupCode.findMany({
    where: { userId, usedAt: null },
  });

  for (const candidate of candidates) {
    let matches = false;
    try {
      matches = await argonVerify(candidate.codeHash, normalized, BACKUP_PARAMS);
    } catch {
      matches = false;
    }
    if (!matches) continue;

    const spent = await prisma.backupCode.updateMany({
      where: { id: candidate.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    return spent.count === 1;
  }

  return false;
}

export async function countUnusedBackupCodes(userId: string): Promise<number> {
  return prisma.backupCode.count({ where: { userId, usedAt: null } });
}

import "server-only";
import { randomBytes } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import type { Algorithm } from "@node-rs/argon2";

/**
 * Password hashing: argon2id.
 *
 * Parameters follow the OWASP Password Storage Cheat Sheet's argon2id
 * recommendation (19 MiB memory, 2 iterations, parallelism 1). They are
 * stored inside the PHC-format hash string, so raising them later does not
 * invalidate existing hashes — `needsRehash` detects the stale ones and the
 * login path upgrades them transparently.
 */

// @node-rs/argon2 declares Algorithm as an ambient `const enum`, which
// TypeScript cannot reference under `isolatedModules` (the Next.js
// default). The numeric value is part of the package's public API.
const ARGON2ID = 2 as Algorithm;

const PARAMS = {
  algorithm: ARGON2ID,
  memoryCost: 19_456, // KiB
  timeCost: 2,
  parallelism: 1,
} as const;

/** Minimum length. Length beats composition rules; NIST agrees. */
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

export async function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, PARAMS);
}

/**
 * Verifies a password. Returns false rather than throwing on a malformed
 * stored hash, so a corrupt row denies access instead of 500-ing.
 */
export async function verifyPassword(
  storedHash: string,
  plaintext: string,
): Promise<boolean> {
  try {
    return await verify(storedHash, plaintext, PARAMS);
  } catch {
    return false;
  }
}

/** True when the stored hash was produced with weaker-than-current params. */
export function needsRehash(storedHash: string): boolean {
  const m = /\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(storedHash);
  if (!m) return true; // not argon2id at all (e.g. a legacy bcrypt hash)

  const [, memory, time, parallelism] = m;
  return (
    Number(memory) < PARAMS.memoryCost ||
    Number(time) < PARAMS.timeCost ||
    Number(parallelism) < PARAMS.parallelism
  );
}

/**
 * A decoy verify used on the "no such account" path so that login timing
 * does not reveal whether an email address is registered.
 *
 * The decoy hash is computed for real (once, lazily) rather than hard-coded:
 * a hard-coded string that failed to parse would throw instantly and burn
 * none of the CPU time that makes the two paths indistinguishable.
 */
let decoyHash: Promise<string> | null = null;

export async function fakeVerifyForTiming(plaintext: string): Promise<void> {
  decoyHash ??= hash(randomBytes(32).toString("hex"), PARAMS);
  await verifyPassword(await decoyHash, plaintext);
}

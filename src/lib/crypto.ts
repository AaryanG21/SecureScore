import "server-only";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { getEnv } from "@/lib/env";

/**
 * Symmetric encryption and hashing primitives.
 *
 * Scope note: this module protects TOTP secrets at rest and hashes opaque
 * tokens. Passwords do NOT go through here — they go through argon2id in
 * lib/auth/password.ts. Encrypting a password would make it recoverable,
 * which is the whole thing we are avoiding.
 */

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12; // 96-bit nonce, the GCM standard
const TAG_BYTES = 16;

function key(): Buffer {
  return Buffer.from(getEnv().TOTP_ENCRYPTION_KEY, "base64");
}

/**
 * Encrypts a UTF-8 string with AES-256-GCM.
 * Output format: v1.<iv b64url>.<ciphertext b64url>.<tag b64url>
 * The version prefix exists so the key/algorithm can be rotated later
 * without guessing at what an old row contains.
 */
export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    "v1",
    iv.toString("base64url"),
    ciphertext.toString("base64url"),
    tag.toString("base64url"),
  ].join(".");
}

/**
 * Reverses encryptSecret. Throws if the payload was tampered with — GCM
 * authentication failure is a security event, not a parsing hiccup, so it
 * is never swallowed into a "return null" path here.
 */
export function decryptSecret(payload: string): string {
  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("Malformed encrypted payload");
  }

  const iv = Buffer.from(parts[1], "base64url");
  const ciphertext = Buffer.from(parts[2], "base64url");
  const tag = Buffer.from(parts[3], "base64url");

  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("Malformed encrypted payload");
  }

  const decipher = createDecipheriv(ALGORITHM, key(), iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
    "utf8",
  );
}

/** Cryptographically random opaque token, URL-safe. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/**
 * SHA-256, hex. Used for refresh tokens and CSRF tokens — high-entropy
 * random values where a fast hash is appropriate. Never for passwords.
 */
export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Length-safe constant-time string comparison. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Compare against itself so the timing profile does not depend on
    // whether the length check failed.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

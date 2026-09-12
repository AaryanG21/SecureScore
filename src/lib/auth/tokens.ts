import "server-only";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { getEnv } from "@/lib/env";

/**
 * Short-lived JWTs.
 *
 * Three distinct token purposes share one signing key but are separated by
 * an explicit `typ` claim that is checked on verification. Without that
 * check, an mfa-pending token (issued after password but before the second
 * factor) would be accepted as a full access token — a complete 2FA bypass.
 */

export type TokenType = "access" | "mfa_pending" | "reauth";

export interface AccessClaims extends JWTPayload {
  typ: "access";
  sub: string;
  role: "USER" | "ADMIN";
  sid: string; // refresh-token family, so a revoked family kills the session
}

export interface MfaPendingClaims extends JWTPayload {
  typ: "mfa_pending";
  sub: string;
}

export interface ReauthClaims extends JWTPayload {
  typ: "reauth";
  sub: string;
}

const ISSUER = "fulcrum";
const AUDIENCE = "fulcrum-app";

function signingKey(): Uint8Array {
  return new Uint8Array(Buffer.from(getEnv().JWT_SIGNING_KEY, "base64"));
}

async function sign(
  payload: JWTPayload & { typ: TokenType },
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + ttlSeconds)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .sign(signingKey());
}

/**
 * Verifies a token AND enforces that it is the type the caller expected.
 * Returns null on any failure; callers treat null as "unauthenticated".
 */
async function verify<T extends JWTPayload>(
  token: string,
  expectedType: TokenType,
): Promise<T | null> {
  try {
    const { payload } = await jwtVerify(token, signingKey(), {
      issuer: ISSUER,
      audience: AUDIENCE,
      // Pinning the algorithm blocks alg-confusion ("alg": "none") attacks.
      algorithms: ["HS256"],
      clockTolerance: 5,
    });

    if (payload.typ !== expectedType) return null;
    return payload as T;
  } catch {
    return null;
  }
}

export function signAccessToken(args: {
  userId: string;
  role: "USER" | "ADMIN";
  sessionId: string;
}): Promise<string> {
  return sign(
    { typ: "access", sub: args.userId, role: args.role, sid: args.sessionId },
    getEnv().ACCESS_TOKEN_TTL_SECONDS,
  );
}

export function verifyAccessToken(token: string): Promise<AccessClaims | null> {
  return verify<AccessClaims>(token, "access");
}

/** Issued after a correct password, before the TOTP challenge. */
export function signMfaPendingToken(userId: string): Promise<string> {
  return sign({ typ: "mfa_pending", sub: userId }, getEnv().MFA_PENDING_TTL_SECONDS);
}

export function verifyMfaPendingToken(
  token: string,
): Promise<MfaPendingClaims | null> {
  return verify<MfaPendingClaims>(token, "mfa_pending");
}

/** Proof of a fresh password+TOTP check, required for destructive actions. */
export function signReauthToken(userId: string): Promise<string> {
  return sign({ typ: "reauth", sub: userId }, getEnv().REAUTH_TTL_SECONDS);
}

export function verifyReauthToken(token: string): Promise<ReauthClaims | null> {
  return verify<ReauthClaims>(token, "reauth");
}

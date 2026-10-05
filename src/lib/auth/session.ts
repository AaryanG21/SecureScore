import "server-only";
import { randomUUID } from "node:crypto";
import { prisma } from "@/lib/db";
import { getEnv } from "@/lib/env";
import { randomToken, sha256 } from "@/lib/crypto";
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  clearAllAuthCookies,
  readCookie,
  setAuthCookie,
} from "@/lib/auth/cookies";
import { signAccessToken, verifyAccessToken } from "@/lib/auth/tokens";
import { writeAudit } from "@/lib/audit";
import type { Role, UserStatus } from "@/generated/prisma/enums";

/**
 * Session lifecycle: issue, read, rotate, revoke.
 *
 * Shape: a short-lived signed access token (stateless, ~10 min) paired with
 * a long-lived opaque refresh token (stateful, rotated on every use). The
 * refresh token is stored only as a SHA-256 hash, so a database read does
 * not yield usable credentials.
 */

export interface SessionUser {
  id: string;
  email: string;
  role: Role;
  status: UserStatus;
  sessionId: string;
}

interface RequestContext {
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Starts a new session. Only ever called AFTER both factors have been
 * verified — there is no code path from password-only to a full session.
 */
export async function createSession(
  userId: string,
  role: Role,
  ctx: RequestContext = {},
): Promise<void> {
  const env = getEnv();
  const familyId = randomUUID();

  await issueTokenPair({ userId, role, familyId, ctx });

  await writeAudit({
    actorUserId: userId,
    action: "SESSION_CREATED",
    targetType: "User",
    targetId: userId,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    metadata: { familyId, ttlSeconds: env.REFRESH_TOKEN_TTL_SECONDS },
  });
}

async function issueTokenPair(args: {
  userId: string;
  role: Role;
  familyId: string;
  replacesId?: string;
  ctx: RequestContext;
}): Promise<void> {
  const env = getEnv();

  const refreshToken = randomToken(32);
  const expiresAt = new Date(Date.now() + env.REFRESH_TOKEN_TTL_SECONDS * 1000);

  // One transaction, because a half-finished rotation is a security
  // problem and not merely an inconsistency: if the new row were created
  // and the old row's replacedById never written, a replay of the old
  // token would not be recognised as reuse and the family would survive.
  await prisma.$transaction(async (tx) => {
    const created = await tx.refreshToken.create({
      data: {
        userId: args.userId,
        tokenHash: sha256(refreshToken),
        familyId: args.familyId,
        expiresAt,
        ipAddress: args.ctx.ipAddress ?? null,
        userAgent: args.ctx.userAgent ?? null,
      },
      select: { id: true },
    });

    if (args.replacesId) {
      await tx.refreshToken.update({
        where: { id: args.replacesId },
        data: { replacedById: created.id },
      });
    }
  });

  const accessToken = await signAccessToken({
    userId: args.userId,
    role: args.role,
    sessionId: args.familyId,
  });

  await setAuthCookie({
    name: ACCESS_COOKIE,
    value: accessToken,
    maxAgeSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
  });

  // Scoped to /api/auth so the refresh token is not attached to every
  // request that only needs the access token.
  await setAuthCookie({
    name: REFRESH_COOKIE,
    value: refreshToken,
    maxAgeSeconds: env.REFRESH_TOKEN_TTL_SECONDS,
    path: "/api/auth",
  });
}

/**
 * Resolves the current session from the access-token cookie.
 *
 * The user row is re-read on every call rather than trusted from the token:
 * a suspended account or a role that was just demoted must stop working
 * immediately, not when the access token happens to expire.
 */
export async function getSession(): Promise<SessionUser | null> {
  const token = await readCookie(ACCESS_COOKIE);
  if (!token) return null;

  const claims = await verifyAccessToken(token);
  if (!claims?.sub) return null;

  const user = await prisma.user.findUnique({
    where: { id: claims.sub },
    select: { id: true, email: true, role: true, status: true },
  });

  if (!user) return null;
  if (user.status !== "ACTIVE") return null;

  // The token's session family must still be live. This is what makes
  // "revoke all sessions" take effect before the access token expires.
  const familyAlive = await prisma.refreshToken.count({
    where: {
      familyId: claims.sid,
      userId: user.id,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
  });
  if (familyAlive === 0) return null;

  return { ...user, sessionId: claims.sid };
}

export type RefreshOutcome =
  | { ok: true }
  | { ok: false; reason: "missing" | "invalid" | "expired" | "revoked" | "reuse" | "inactive" };

/**
 * Rotates the refresh token.
 *
 * Reuse detection: presenting a token that has already been rotated means
 * either the old token leaked or the whole family did. We cannot tell which,
 * so the entire family is revoked and the user must log in again. This is
 * the standard OAuth 2.1 refresh-rotation guidance.
 */
export async function rotateSession(
  ctx: RequestContext = {},
): Promise<RefreshOutcome> {
  const presented = await readCookie(REFRESH_COOKIE);
  if (!presented) return { ok: false, reason: "missing" };

  const record = await prisma.refreshToken.findUnique({
    where: { tokenHash: sha256(presented) },
    include: {
      user: { select: { id: true, role: true, status: true } },
    },
  });

  if (!record) return { ok: false, reason: "invalid" };

  if (record.replacedById) {
    await handleReuse(record.userId, record.familyId, ctx);
    return { ok: false, reason: "reuse" };
  }

  // A token already spent by a rotation is reuse, even when replacedById
  // was never linked. Only a deliberate end-of-session (logout, password
  // change, suspension) is an ordinary "revoked".
  if (record.revokedAt) {
    if (record.revokedReason === "ROTATED") {
      await handleReuse(record.userId, record.familyId, ctx);
      return { ok: false, reason: "reuse" };
    }
    return { ok: false, reason: "revoked" };
  }

  if (record.expiresAt <= new Date()) return { ok: false, reason: "expired" };
  if (record.user.status !== "ACTIVE") return { ok: false, reason: "inactive" };

  // Claim the token with a single predicated UPDATE, and treat losing the
  // race as theft.
  //
  // Everything above this line is a read, so two requests presenting the
  // same refresh token at the same moment both passed all of those checks
  // before either wrote anything. The previous unconditional update let
  // both proceed: two live families from one token, and the reuse
  // detection — the whole point of rotation — never fired. Making the
  // revoke conditional on the row still being unspent moves the decision
  // into the database, where exactly one of the two can win.
  const claimed = await prisma.refreshToken.updateMany({
    where: { id: record.id, revokedAt: null, replacedById: null },
    data: { revokedAt: new Date(), revokedReason: "ROTATED" },
  });

  if (claimed.count === 0) {
    await handleReuse(record.userId, record.familyId, ctx);
    return { ok: false, reason: "reuse" };
  }

  await issueTokenPair({
    userId: record.userId,
    role: record.user.role,
    familyId: record.familyId,
    replacesId: record.id,
    ctx,
  });

  return { ok: true };
}

/**
 * The response to a refresh token being presented twice.
 *
 * Deliberately indiscriminate: we cannot tell the legitimate holder from
 * the thief, because both hold a valid-looking token. Revoking the whole
 * family logs out both and forces a fresh login with both factors, which
 * the attacker cannot complete.
 */
async function handleReuse(
  userId: string,
  familyId: string,
  ctx: RequestContext,
): Promise<void> {
  await revokeFamily(familyId, "REFRESH_TOKEN_REUSE_DETECTED");
  await clearAllAuthCookies();
  await writeAudit({
    actorUserId: userId,
    action: "REFRESH_TOKEN_REUSE_DETECTED",
    targetType: "RefreshTokenFamily",
    targetId: familyId,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });
}

export async function revokeFamily(
  familyId: string,
  reason: string,
): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { familyId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
}

/** Revokes every session for a user (password change, suspension, admin). */
export async function revokeAllSessions(
  userId: string,
  reason: string,
): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
}

export async function endSession(ctx: RequestContext = {}): Promise<void> {
  const presented = await readCookie(REFRESH_COOKIE);

  if (presented) {
    const record = await prisma.refreshToken.findUnique({
      where: { tokenHash: sha256(presented) },
      select: { familyId: true, userId: true },
    });

    if (record) {
      await revokeFamily(record.familyId, "LOGOUT");
      await writeAudit({
        actorUserId: record.userId,
        action: "LOGOUT",
        targetType: "User",
        targetId: record.userId,
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
      });
    }
  }

  await clearAllAuthCookies();
}

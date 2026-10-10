import "server-only";
import { errorMessage, log } from "@/lib/log";
import { prisma } from "@/lib/db";
import type { Prisma } from "@/generated/prisma/client";

/**
 * Audit logging.
 *
 * Two rules this module enforces rather than documents:
 *   1. Nothing sensitive gets written. Keys that look like credentials are
 *      stripped from metadata, and long opaque strings are truncated to a
 *      prefix so a leaked log cannot be replayed as a token.
 *   2. A logging failure never breaks the request it is describing, but it
 *      is surfaced to stderr so a silently-not-auditing deployment is
 *      detectable.
 *
 * Writes are INSERT-only. The database rejects UPDATE/DELETE on this table
 * (see prisma/migrations/..._audit_log_append_only).
 */

/**
 * Every action this application can record.
 *
 * A const array rather than a bare union, so the set can be validated at
 * runtime as well as checked at compile time. The admin audit view filters
 * on an `action` query parameter that arrives as a free-form string; with
 * only a type there was nothing to check it against, so a typo silently
 * returned zero rows and looked like "nothing happened" rather than "you
 * asked for an action that does not exist".
 *
 * Four names were removed from this list because nothing ever wrote them:
 * ACCOUNT_UNLOCKED, TWO_FACTOR_RESET, BACKUP_CODES_REGENERATED and
 * DOMAIN_VERIFICATION_REVOKED. The first and last were duplicates of the
 * ADMIN_* actions that are actually emitted; the other two described
 * features that do not exist. A declared action nobody writes is worse
 * than a missing one — it implies a capability, and it offers the audit
 * filter a value that can only ever return nothing.
 */
export const AUDIT_ACTIONS = [
  // Authentication
  "REGISTER",
  "LOGIN_PASSWORD_SUCCESS",
  "LOGIN_PASSWORD_FAILURE",
  "LOGIN_2FA_SUCCESS",
  "LOGIN_2FA_FAILURE",
  "LOGIN_BACKUP_CODE_USED",
  "LOGIN_BLOCKED_LOCKED",
  "LOGIN_BLOCKED_SUSPENDED",
  "LOGIN_BLOCKED_RATE_LIMIT",
  "LOGOUT",
  "SESSION_CREATED",
  "REFRESH_TOKEN_REUSE_DETECTED",
  "ACCOUNT_LOCKED",
  "PASSWORD_CHANGED",
  // Distinct from PASSWORD_CHANGED: a refused attempt is a different
  // event with different significance. Recording both under one name made
  // any count of password changes an overcount, and a burst of failures
  // against one account — which is what credential-stuffing a known
  // session looks like — indistinguishable from ordinary use unless you
  // opened the metadata of every row.
  "PASSWORD_CHANGE_REJECTED",
  // Erasure. Recorded in the append-only log precisely because the row it
  // describes is gone — without this, an account deletion would be the one
  // significant event that leaves no trace at all.
  "ACCOUNT_DELETED",
  "ACCOUNT_DATA_EXPORTED",
  "TWO_FACTOR_ENROLLED",
  "REAUTH_SUCCESS",
  "REAUTH_FAILURE",
  // Authorization / safety
  "CSRF_REJECTED",
  "RATE_LIMIT_TRIPPED",
  "FORBIDDEN_ROLE_ACCESS",
  // Domains
  "DOMAIN_ADDED",
  "DOMAIN_VERIFICATION_ATTEMPT",
  "DOMAIN_VERIFIED",
  "DOMAIN_REMOVED",
  // Scans
  "SCAN_REQUESTED",
  // Headers-only checks of hosts the caller does not own. Kept distinct
  // from SCAN_* so the log can answer "what have we been pointed at that
  // nobody proved they owned" without inspecting metadata on every row —
  // which is the question an operator asks when a target complains.
  "PUBLIC_SCAN_REQUESTED",
  "PUBLIC_SCAN_COMPLETED",
  "PUBLIC_SCAN_FAILED",
  "PUBLIC_SCAN_REFUSED",
  "SCAN_REFUSED_UNVERIFIED_DOMAIN",
  "SCAN_REFUSED_NOT_OWNER",
  "SCAN_COMPLETED",
  "SCAN_FAILED",
  "SCAN_INJECTION_ATTEMPT_IGNORED",
  // Admin
  "ADMIN_USER_SUSPENDED",
  "ADMIN_USER_REINSTATED",
  "ADMIN_USER_UNLOCKED",
  "ADMIN_DOMAIN_REVOKED",
  "ADMIN_AUDIT_LOG_VIEWED",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export function isAuditAction(value: string): value is AuditAction {
  return (AUDIT_ACTIONS as readonly string[]).includes(value);
}

export interface AuditEntry {
  actorUserId?: string | null;
  /**
   * Optional. When omitted and an actorUserId is given, it is looked up
   * once here so the log records who the actor was AT THE TIME — see the
   * note on AuditLog.actorEmail in the schema.
   */
  actorEmail?: string | null;
  action: AuditAction;
  targetType: string;
  targetId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  /**
   * Correlation id from src/proxy.ts, folded into metadata on write.
   *
   * It is what lets an audit row be matched to the reverse proxy's access
   * log line and to any operational log lines from the same request —
   * answering "what else happened while this was denied" without guessing
   * from timestamps.
   */
  requestId?: string | null;
  metadata?: Record<string, unknown> | null;
}

const FORBIDDEN_KEY = /pass(word|hash)|secret|token|otp|code|authorization|cookie|session/i;

/** Values longer than this are truncated to a non-replayable prefix. */
const MAX_VALUE_LENGTH = 120;

/**
 * Credential-shaped values, caught regardless of the key they arrived under.
 *
 * FORBIDDEN_KEY only looks at names, which works as long as whoever writes
 * the call site names the field honestly. The failure mode is a secret
 * arriving under an innocuous key — `evidence`, `detail`, `value`, or an
 * array element with no key at all — where it was merely truncated to 120
 * characters and written to a table that then refuses to let anyone delete
 * it. Truncating a JWT still leaves its header and most of its payload.
 *
 * So values are matched too:
 *
 *   - three base64url segments separated by dots: a JWT
 *   - a long unbroken run of hex: a token hash, a key, a session id
 *   - a long unbroken run of base64: anything from randomToken(32)
 *   - a PHC hash string: $argon2id$...
 *
 * Thresholds sit above what legitimate metadata contains. The longest real
 * values written here are cuids (25 chars) and hostnames, neither of which
 * is a 40-character hex run or a dotted triple. A false positive costs a
 * redacted log field; a false negative costs a permanent secret in an
 * append-only table.
 */
const JWT_SHAPE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const LONG_HEX = /^[0-9a-fA-F]{40,}$/;
const LONG_BASE64 = /^[A-Za-z0-9+/_-]{40,}={0,2}$/;
const PHC_HASH = /^\$argon2(id|i|d)\$/;

function looksLikeSecret(value: string): boolean {
  const trimmed = value.trim();
  if (PHC_HASH.test(trimmed)) return true;
  if (JWT_SHAPE.test(trimmed)) return true;
  if (LONG_HEX.test(trimmed)) return true;
  if (LONG_BASE64.test(trimmed)) return true;
  return false;
}

function redactString(value: string): string {
  if (looksLikeSecret(value)) return "[redacted: credential-shaped value]";
  return value.length > MAX_VALUE_LENGTH
    ? `${value.slice(0, MAX_VALUE_LENGTH)}…[truncated]`
    : value;
}

/**
 * Merges the correlation id into the metadata object that gets redacted.
 *
 * Done here rather than at every call site: there are three dozen
 * writeAudit calls and the one that forgets is the one investigated later.
 */
function withRequestId(entry: AuditEntry): Record<string, unknown> | null {
  if (!entry.requestId) return entry.metadata ?? null;
  return { ...(entry.metadata ?? {}), requestId: entry.requestId };
}

/**
 * Strips credential-shaped material out of metadata before it is persisted.
 * Deliberately conservative: an over-redacted log is an inconvenience, an
 * under-redacted one is a breach.
 */
export function redactMetadata(
  input: Record<string, unknown> | null | undefined,
  depth = 0,
): Record<string, unknown> | null {
  if (!input) return null;
  if (depth > 4) return { truncated: "max depth" };

  const out: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (FORBIDDEN_KEY.test(key)) {
      out[key] = "[redacted]";
      continue;
    }

    if (typeof value === "string") {
      out[key] = redactString(value);
    } else if (Array.isArray(value)) {
      out[key] = value
        .slice(0, 20)
        .map((v) =>
          typeof v === "object" && v !== null
            ? redactMetadata(v as Record<string, unknown>, depth + 1)
            : typeof v === "string"
              ? redactString(v)
              : v,
        );
    } else if (typeof value === "object" && value !== null) {
      out[key] = redactMetadata(value as Record<string, unknown>, depth + 1);
    } else {
      out[key] = value;
    }
  }

  return out;
}

export async function writeAudit(entry: AuditEntry): Promise<void> {
  try {
    // Attribution is denormalized onto the row because the audit log holds
    // no foreign key to User — the account may be deleted later, and the
    // record of what it did has to survive that.
    let actorEmail = entry.actorEmail ?? null;
    if (!actorEmail && entry.actorUserId) {
      const actor = await prisma.user.findUnique({
        where: { id: entry.actorUserId },
        select: { email: true },
      });
      actorEmail = actor?.email ?? null;
    }

    await prisma.auditLog.create({
      data: {
        actorUserId: entry.actorUserId ?? null,
        actorEmail,
        action: entry.action,
        targetType: entry.targetType,
        targetId: entry.targetId ?? null,
        ipAddress: entry.ipAddress ?? null,
        userAgent: entry.userAgent?.slice(0, 300) ?? null,
        metadata: (redactMetadata(withRequestId(entry)) ?? undefined) as
          | Prisma.InputJsonValue
          | undefined,
      },
    });
  } catch (error) {
    // Never rethrow: an auth denial must still be returned to the client
    // even if the audit insert failed. But make the failure visible.
    log.error("audit entry could not be persisted", {
      action: entry.action,
      requestId: entry.requestId,
      error: errorMessage(error),
    });
  }
}

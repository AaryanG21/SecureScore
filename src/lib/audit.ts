import "server-only";
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

export type AuditAction =
  // Authentication
  | "REGISTER"
  | "LOGIN_PASSWORD_SUCCESS"
  | "LOGIN_PASSWORD_FAILURE"
  | "LOGIN_2FA_SUCCESS"
  | "LOGIN_2FA_FAILURE"
  | "LOGIN_BACKUP_CODE_USED"
  | "LOGIN_BLOCKED_LOCKED"
  | "LOGIN_BLOCKED_SUSPENDED"
  | "LOGIN_BLOCKED_RATE_LIMIT"
  | "LOGOUT"
  | "SESSION_CREATED"
  | "REFRESH_TOKEN_REUSE_DETECTED"
  | "ACCOUNT_LOCKED"
  | "ACCOUNT_UNLOCKED"
  | "PASSWORD_CHANGED"
  | "TWO_FACTOR_ENROLLED"
  | "TWO_FACTOR_RESET"
  | "BACKUP_CODES_REGENERATED"
  | "REAUTH_SUCCESS"
  | "REAUTH_FAILURE"
  // Authorization / safety
  | "CSRF_REJECTED"
  | "RATE_LIMIT_TRIPPED"
  | "FORBIDDEN_ROLE_ACCESS"
  // Domains
  | "DOMAIN_ADDED"
  | "DOMAIN_VERIFICATION_ATTEMPT"
  | "DOMAIN_VERIFIED"
  | "DOMAIN_REMOVED"
  | "DOMAIN_VERIFICATION_REVOKED"
  // Scans
  | "SCAN_REQUESTED"
  | "SCAN_REFUSED_UNVERIFIED_DOMAIN"
  | "SCAN_REFUSED_NOT_OWNER"
  | "SCAN_COMPLETED"
  | "SCAN_FAILED"
  | "SCAN_INJECTION_ATTEMPT_IGNORED"
  // Admin
  | "ADMIN_USER_SUSPENDED"
  | "ADMIN_USER_REINSTATED"
  | "ADMIN_USER_UNLOCKED"
  | "ADMIN_DOMAIN_REVOKED"
  | "ADMIN_AUDIT_LOG_VIEWED";

export interface AuditEntry {
  actorUserId?: string | null;
  action: AuditAction;
  targetType: string;
  targetId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

const FORBIDDEN_KEY = /pass(word|hash)|secret|token|otp|code|authorization|cookie|session/i;

/** Values longer than this are truncated to a non-replayable prefix. */
const MAX_VALUE_LENGTH = 120;

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
      out[key] =
        value.length > MAX_VALUE_LENGTH
          ? `${value.slice(0, MAX_VALUE_LENGTH)}…[truncated]`
          : value;
    } else if (Array.isArray(value)) {
      out[key] = value
        .slice(0, 20)
        .map((v) =>
          typeof v === "object" && v !== null
            ? redactMetadata(v as Record<string, unknown>, depth + 1)
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
    await prisma.auditLog.create({
      data: {
        actorUserId: entry.actorUserId ?? null,
        action: entry.action,
        targetType: entry.targetType,
        targetId: entry.targetId ?? null,
        ipAddress: entry.ipAddress ?? null,
        userAgent: entry.userAgent?.slice(0, 300) ?? null,
        metadata: (redactMetadata(entry.metadata) ?? undefined) as
          | Prisma.InputJsonValue
          | undefined,
      },
    });
  } catch (error) {
    // Never rethrow: an auth denial must still be returned to the client
    // even if the audit insert failed. But make the failure visible.
    console.error("[audit] failed to persist entry", {
      action: entry.action,
      error: error instanceof Error ? error.message : "unknown",
    });
  }
}

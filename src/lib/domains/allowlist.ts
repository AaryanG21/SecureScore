import "server-only";
import { prisma } from "@/lib/db";
import { writeAudit } from "@/lib/audit";

/**
 * The scan authorization allowlist.
 *
 * Single chokepoint: nothing in this codebase may launch a scan without a
 * `granted` result from `authorizeScan`. Keeping the check in one function
 * — rather than repeating an `if (domain.verified)` at each call site — is
 * what makes "the agent must refuse, no exceptions" auditable.
 *
 * Every refusal is logged, as required.
 */

export type ScanAuthorization =
  | { granted: true; domainId: string; hostname: string }
  | {
      granted: false;
      reason: ScanRefusalReason;
      message: string;
      /**
       * Known for every refusal except one the caller invented a domain id
       * for. The refused ScanResult row records it so the user's history
       * says WHICH host was refused, not just that something was.
       */
      hostname?: string;
    };

export type ScanRefusalReason =
  | "domain_not_found"
  | "not_owner"
  | "not_verified"
  | "verification_revoked"
  | "account_not_active";

export interface AuthorizeArgs {
  userId: string;
  userStatus: string;
  domainId: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}

export async function authorizeScan(args: AuthorizeArgs): Promise<ScanAuthorization> {
  const refuse = async (
    reason: ScanRefusalReason,
    message: string,
    targetId: string,
    extra: Record<string, unknown> = {},
    hostname?: string,
  ): Promise<ScanAuthorization> => {
    await writeAudit({
      actorUserId: args.userId,
      action:
        reason === "not_owner"
          ? "SCAN_REFUSED_NOT_OWNER"
          : "SCAN_REFUSED_UNVERIFIED_DOMAIN",
      targetType: "Domain",
      targetId,
      ipAddress: args.ipAddress,
      userAgent: args.userAgent,
      metadata: { reason, ...extra },
    });
    return { granted: false, reason, message, ...(hostname ? { hostname } : {}) };
  };

  if (args.userStatus !== "ACTIVE") {
    return refuse(
      "account_not_active",
      "Your account is not active.",
      args.domainId,
      { userStatus: args.userStatus },
    );
  }

  const domain = await prisma.domain.findUnique({
    where: { id: args.domainId },
    select: {
      id: true,
      userId: true,
      hostname: true,
      verificationStatus: true,
      verifiedAt: true,
      revokedAt: true,
    },
  });

  if (!domain) {
    return refuse("domain_not_found", "That domain is not registered.", args.domainId);
  }

  // Ownership is checked before anything else is revealed about the row,
  // so this endpoint cannot be used to probe which domain IDs exist.
  if (domain.userId !== args.userId) {
    return refuse(
      "not_owner",
      "That domain is not registered.",
      domain.id,
      { hostname: domain.hostname },
      domain.hostname,
    );
  }

  if (domain.revokedAt || domain.verificationStatus === "REVOKED") {
    return refuse(
      "verification_revoked",
      "Verification for this domain was revoked. Re-verify before scanning.",
      domain.id,
      { hostname: domain.hostname },
      domain.hostname,
    );
  }

  if (domain.verificationStatus !== "VERIFIED" || !domain.verifiedAt) {
    return refuse(
      "not_verified",
      "Verify ownership of this domain before scanning it.",
      domain.id,
      { hostname: domain.hostname, status: domain.verificationStatus },
      domain.hostname,
    );
  }

  return { granted: true, domainId: domain.id, hostname: domain.hostname };
}

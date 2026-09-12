import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * The authorization allowlist: the agent must refuse to scan any domain the
 * caller has not registered AND verified, with no exceptions, and every
 * refusal must be logged.
 *
 * Needs a Prisma mock for domain.findUnique and for the audit writer.
 * Subject under test: authorizeScan from @/lib/domains/allowlist.
 */

describe("scan authorization allowlist", () => {
  describe("grants", () => {
    it("permits a VERIFIED domain owned by the caller", () => {
      // TODO: assert granted === true and the hostname is returned
    });
  });

  describe("refuses", () => {
    it("a domain that does not exist", () => {
      // TODO: assert reason === "domain_not_found"
    });

    it("a domain owned by a different user", () => {
      // TODO: assert reason === "not_owner"
      // TODO: assert the message does not reveal that the domain exists
    });

    it("a domain still PENDING verification", () => {
      // TODO: assert reason === "not_verified"
    });

    it("a domain whose verification FAILED", () => {
      // TODO: assert reason === "not_verified"
    });

    it("a domain whose verification was REVOKED by an admin", () => {
      // TODO: assert reason === "verification_revoked"
    });

    it("a domain marked VERIFIED but carrying a revokedAt timestamp", () => {
      // TODO: inconsistent state must fail closed, not open
    });

    it("a domain marked VERIFIED but with verifiedAt null", () => {
      // TODO: same — fail closed
    });

    it("any request from a suspended account", () => {
      // TODO: assert reason === "account_not_active"
    });
  });

  describe("refusal logging", () => {
    it("writes SCAN_REFUSED_UNVERIFIED_DOMAIN for an unverified target", () => {
      // TODO: assert the audit call, its actor, and its target
    });

    it("writes SCAN_REFUSED_NOT_OWNER for a domain belonging to someone else", () => {
      // TODO
    });

    it("logs every refusal path without exception", () => {
      // TODO: exercise each reason, assert writeAudit was called each time
    });
  });

  describe("bypass attempts", () => {
    it("ignores a hostname supplied alongside the domainId", () => {
      // TODO: the hostname comes from the database row, never the request
    });

    it("cannot be satisfied by a domainId belonging to another user", () => {
      // TODO
    });
  });
});

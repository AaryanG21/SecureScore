import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * Covers `isVerificationStale` and the staleness gate in `authorizeScan`
 * (src/lib/domains/allowlist.ts).
 *
 * What this is protecting: ownership is a claim about the present. A domain
 * verified once used to grant TLS-scanning rights for ever, so a lapsed or
 * resold registration left its previous owner able to open hundreds of
 * connections against a host that is no longer theirs.
 *
 * Pass an explicit `now` to isVerificationStale rather than mocking the
 * clock; it takes one for exactly this reason.
 */

describe("isVerificationStale", () => {
  it("treats a verification inside the TTL as current", () => {
    // TODO: verifiedAt 1 day ago, ttl 90 -> false
  });

  it("treats a verification older than the TTL as stale", () => {
    // TODO: verifiedAt 91 days ago, ttl 90 -> true
  });

  it("is not stale exactly at the TTL boundary", () => {
    // TODO: age exactly ttlDays -> false. The comparison is strictly
    // greater-than; pin the intended side of the boundary so a later
    // refactor to >= is caught.
  });

  it("treats a null verifiedAt as stale", () => {
    // TODO: null -> true, regardless of ttl. Fail closed: a VERIFIED row
    // with no timestamp is a broken row, and the safe reading of a broken
    // row is "not proven".
  });
});

describe("authorizeScan staleness gate", () => {
  it("grants a scan for a domain verified within the TTL", () => {
    // TODO: granted true
  });

  it("refuses a scan for a domain verified outside the TTL", () => {
    // TODO: granted false, reason "verification_stale"
  });

  it("names the verification date and the TTL in the refusal message", () => {
    // TODO: the user has to know what to do next; assert both appear
  });

  it("still records the hostname on a stale refusal", () => {
    // TODO: the refused ScanResult row must say WHICH host was refused
  });

  it("checks revocation before staleness", () => {
    // TODO: a revoked AND stale domain refuses as verification_revoked.
    // Revocation is an administrator's decision and must not be reported
    // as a routine expiry the user can clear by re-verifying.
  });
});

describe("refusal audit actions", () => {
  it("records a stale refusal as SCAN_REFUSED_STALE_VERIFICATION", () => {
    // TODO: specifically NOT SCAN_REFUSED_UNVERIFIED_DOMAIN. The domain was
    // verified; logging it as unverified would make the audit trail false.
  });

  it("maps every refusal reason to an audit action", () => {
    // TODO: every member of ScanRefusalReason has a REFUSAL_AUDIT_ACTION
    // entry, and each is a member of AUDIT_ACTIONS
  });
});

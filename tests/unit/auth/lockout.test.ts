import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * Needs a Prisma mock for user.update and for the audit writer.
 */

describe("account lockout", () => {
  describe("recordFailure", () => {
    it("increments the failure counter", () => {
      // TODO
    });

    it("does not lock before the threshold", () => {
      // TODO: with MAX_FAILED_LOGINS - 1 failures, assert locked === false
    });

    it("locks once the threshold is reached", () => {
      // TODO: at MAX_FAILED_LOGINS, assert lockedUntil is set
    });

    it("doubles the lock duration for each failure past the threshold", () => {
      // TODO: threshold+1 -> base, +2 -> 2x base, +3 -> 4x base
    });

    it("caps the lock at 24 hours", () => {
      // TODO: drive the counter high, assert the duration stops at 86400s
    });

    it("writes an ACCOUNT_LOCKED audit entry when it locks", () => {
      // TODO: assert the audit call, and that it contains no credentials
    });
  });

  describe("lockState", () => {
    it("reports unlocked when lockedUntil is null", () => {
      // TODO
    });

    it("reports unlocked when lockedUntil is in the past", () => {
      // TODO: the lock is time-boxed, not permanent
    });

    it("reports locked with a positive retryAfter when in the future", () => {
      // TODO
    });
  });

  describe("clearFailures", () => {
    it("resets the counter and clears the lock", () => {
      // TODO: assert failedLoginCount 0, lockedUntil null, reason null
    });
  });
});

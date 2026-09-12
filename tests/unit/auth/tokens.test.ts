import { describe, it } from "vitest";
import {
  signAccessToken,
  signMfaPendingToken,
  signReauthToken,
  verifyAccessToken,
  verifyMfaPendingToken,
  verifyReauthToken,
} from "@/lib/auth/tokens";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * The token-type separation tested here is the mechanism that makes 2FA
 * non-optional. If a mfa_pending token were ever accepted as an access
 * token, the second factor could be skipped entirely — so the cross-type
 * cases below matter more than the happy paths.
 */

describe("JWT tokens", () => {
  describe("access tokens", () => {
    it("round-trips subject, role, and session id", async () => {
      // TODO: sign with a known userId/role/sessionId
      // TODO: verify and assert sub, role, sid match
    });

    it("carries typ=access", async () => {
      // TODO: verify and assert claims.typ === "access"
    });

    it("rejects a token signed with a different key", async () => {
      // TODO: sign, then mutate JWT_SIGNING_KEY and reset the env cache
      // TODO: assert verifyAccessToken resolves null
    });

    it("rejects a tampered payload", async () => {
      // TODO: sign, decode, change role to ADMIN, re-encode without signing
      // TODO: assert verification returns null
    });

    it("rejects an expired token", async () => {
      // TODO: use fake timers to advance past ACCESS_TOKEN_TTL_SECONDS
      // TODO: assert verification returns null
    });

    it("rejects alg=none", async () => {
      // TODO: hand-craft a token with header {"alg":"none"}
      // TODO: assert verification returns null
    });
  });

  describe("token type separation", () => {
    it("does not accept an mfa_pending token as an access token", async () => {
      // TODO: signMfaPendingToken, then verifyAccessToken on it
      // TODO: assert null  ← this is the 2FA-bypass guard
    });

    it("does not accept a reauth token as an access token", async () => {
      // TODO: signReauthToken, then verifyAccessToken, assert null
    });

    it("does not accept an access token as a reauth token", async () => {
      // TODO: signAccessToken, then verifyReauthToken, assert null
    });

    it("does not accept an access token as an mfa_pending token", async () => {
      // TODO: signAccessToken, then verifyMfaPendingToken, assert null
    });
  });

  describe("lifetimes", () => {
    it("gives mfa_pending tokens a short lifetime", async () => {
      // TODO: decode exp - iat, assert it is <= 900 seconds
    });

    it("gives reauth tokens a short lifetime", async () => {
      // TODO: decode exp - iat, assert it is <= 900 seconds
    });
  });
});

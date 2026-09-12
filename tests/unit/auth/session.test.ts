import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * These need both a Prisma mock and a `next/headers` cookie-store mock:
 *
 * vi.mock("next/headers", () => ({
 *   cookies: async () => fakeCookieStore,
 * }));
 */

describe("session lifecycle", () => {
  describe("createSession", () => {
    it("stores only a hash of the refresh token, never the token itself", () => {
      // TODO: inspect the refreshToken.create payload
      // TODO: assert tokenHash is 64 hex chars and !== the cookie value
    });

    it("sets the refresh cookie httpOnly, SameSite=Strict, scoped to /api/auth", () => {
      // TODO: inspect the cookie options passed to the store
    });

    it("sets the access cookie httpOnly with a short max-age", () => {
      // TODO: assert httpOnly true and maxAge === ACCESS_TOKEN_TTL_SECONDS
    });

    it("marks cookies Secure when APP_ORIGIN is https", () => {
      // TODO: set APP_ORIGIN to https, reset env cache, assert secure: true
    });
  });

  describe("getSession", () => {
    it("returns null when no access cookie is present", () => {
      // TODO
    });

    it("returns null for a suspended user even with a valid token", () => {
      // TODO: mock the user row with status SUSPENDED
      // TODO: assert null — status is re-read, not trusted from the token
    });

    it("returns null when the token's refresh family has been revoked", () => {
      // TODO: mock refreshToken.count -> 0
      // TODO: assert null — this is what makes revocation take effect early
    });

    it("reflects a role change made after the token was issued", () => {
      // TODO: token says ADMIN, database row says USER
      // TODO: assert the returned role is USER
    });
  });

  describe("rotateSession", () => {
    it("issues a new pair and revokes the presented token", () => {
      // TODO: assert old row revokedAt set with reason ROTATED
      // TODO: assert a new row is created in the same family
    });

    it("links the old token to its replacement", () => {
      // TODO: assert replacedById is set on the old row
    });

    it("detects reuse and revokes the entire family", () => {
      // TODO: present a token that already has replacedById set
      // TODO: assert every row in the family is revoked
      // TODO: assert the outcome reason is "reuse"
      // TODO: assert a REFRESH_TOKEN_REUSE_DETECTED audit entry is written
    });

    it("refuses an expired refresh token", () => {
      // TODO
    });

    it("refuses a refresh token belonging to a suspended user", () => {
      // TODO
    });
  });

  describe("revokeAllSessions", () => {
    it("revokes every live token for the user and no one else's", () => {
      // TODO: assert the updateMany where-clause is scoped by userId
    });
  });

  describe("endSession", () => {
    it("revokes the family server-side, not just the cookies", () => {
      // TODO: assert refreshToken rows are revoked
      // TODO: assert all auth cookies are cleared
    });
  });
});

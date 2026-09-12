import { describe, it } from "vitest";
import {
  MIN_PASSWORD_LENGTH,
  hashPassword,
  needsRehash,
  verifyPassword,
} from "@/lib/auth/password";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 * Each block states what to prove; the body is intentionally empty.
 */

describe("password hashing", () => {
  describe("hashPassword", () => {
    it("produces a PHC-format argon2id string", async () => {
      // TODO: hash a known password
      // TODO: assert the result starts with "$argon2id$"
      // TODO: assert it encodes v=19 and the configured m/t/p parameters
    });

    it("produces a different hash each time for the same password", async () => {
      // TODO: hash the same input twice
      // TODO: assert the two hashes differ (proves a random salt is used)
    });

    it("never returns the plaintext anywhere in the hash", async () => {
      // TODO: hash a distinctive password
      // TODO: assert the hash string does not contain that plaintext
    });
  });

  describe("verifyPassword", () => {
    it("accepts the correct password", async () => {
      // TODO: hash, then verify with the same password, assert true
    });

    it("rejects an incorrect password", async () => {
      // TODO: hash, then verify with a different password, assert false
    });

    it("returns false rather than throwing on a malformed stored hash", async () => {
      // TODO: call verifyPassword("not-a-hash", "anything")
      // TODO: assert it resolves to false and does not reject
    });

    it("rejects an empty password against a real hash", async () => {
      // TODO: hash a real password, verify against "", assert false
    });
  });

  describe("needsRehash", () => {
    it("returns false for a hash at current parameters", async () => {
      // TODO: hash with the current config, assert needsRehash is false
    });

    it("returns true for a hash with lower memory cost", () => {
      // TODO: construct a PHC string with m= below the configured value
      // TODO: assert needsRehash returns true
    });

    it("returns true for a non-argon2id hash (e.g. a legacy bcrypt hash)", () => {
      // TODO: pass a $2b$ bcrypt-shaped string
      // TODO: assert needsRehash returns true
    });
  });

  describe("policy", () => {
    it("sets a minimum length of at least 12", () => {
      // TODO: assert MIN_PASSWORD_LENGTH >= 12
    });
  });
});

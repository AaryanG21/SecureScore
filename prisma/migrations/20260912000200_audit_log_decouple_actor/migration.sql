-- Decouple the audit log from the User table.
--
-- The bug this fixes: AuditLog.actorUserId carried a foreign key with
-- ON DELETE SET NULL. Deleting a user therefore issued an UPDATE against
-- AuditLog, which the append-only trigger (correctly) rejected — so no
-- account with any audit history could ever be deleted, and the failure
-- surfaced as a confusing trigger error from an unrelated statement.
--
-- The two constraints were in genuine conflict, and immutability is the
-- one that has to win. An append-only log cannot hold a relation to a
-- mutable table:
--
--   * SET NULL mutates the log — blocked by the trigger, and it would
--     erase attribution even if it succeeded.
--   * CASCADE deletes the log — destroying exactly the history that
--     matters most when an account is removed.
--   * RESTRICT keeps the log intact but still makes users undeletable.
--
-- So the FK goes away. actorUserId stays as an opaque string that outlives
-- the account, and the actor's email is denormalized at write time.
-- Storing the email as it was at the moment of the action is better
-- forensics than a join anyway: a join shows whatever that account is
-- called today, or nothing once it is gone.

ALTER TABLE "AuditLog" DROP CONSTRAINT IF EXISTS "AuditLog_actorUserId_fkey";

ALTER TABLE "AuditLog" ADD COLUMN IF NOT EXISTS "actorEmail" TEXT;

-- Backfill attribution for rows written before this column existed, while
-- the accounts they point at still exist.
--
-- This is an UPDATE on the append-only table, so the trigger has to come
-- off for the duration. That is not a hole in the control: a migration is
-- the one sanctioned, reviewable, version-controlled place to do this, it
-- runs inside the transaction Prisma wraps around the file, and the
-- trigger is restored before that transaction commits. If the re-enable
-- were ever to fail, the whole migration rolls back rather than leaving
-- the table unprotected.
ALTER TABLE "AuditLog" DISABLE TRIGGER audit_log_no_update;

UPDATE "AuditLog" AS a
SET "actorEmail" = u."email"
FROM "User" AS u
WHERE a."actorUserId" = u."id"
  AND a."actorEmail" IS NULL;

ALTER TABLE "AuditLog" ENABLE TRIGGER audit_log_no_update;

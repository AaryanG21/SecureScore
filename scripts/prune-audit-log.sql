-- Destroy audit records older than the published retention window.
--
-- WHY THIS IS A SCRIPT AND NOT APPLICATION CODE
--
-- The plan for this work proposed partitioning AuditLog by month and
-- dropping old partitions, so that retention would be DDL and the
-- immutability triggers would never be relaxed. That is the strongest
-- design and it is what a larger deployment should do. It is not what is
-- implemented here, for a specific reason: a partitioned table's primary
-- key must include the partition key, so the key becomes (id, createdAt).
-- Prisma models AuditLog with `id` alone as @id, so the schema would stop
-- matching the database and every subsequent migration would fight it.
--
-- The alternative considered was relaxing the DELETE trigger to permit
-- removing rows past the window. That was rejected: it would hand the
-- application a capability it does not need, and "the app can delete audit
-- rows, but only old ones" is a materially weaker sentence than "the app
-- cannot delete audit rows".
--
-- So retention stays out of the application entirely. This script is run by
-- the table owner — a scheduled task, reviewed and version-controlled —
-- and it is the only thing in the system that can remove an audit record.
-- A compromised application still cannot rewrite history, which is the
-- property the triggers exist to provide.
--
-- The trigger is disabled and re-enabled inside one transaction, exactly
-- as prisma/migrations/20260912000200_audit_log_decouple_actor does and for
-- the same reason: if the re-enable fails, the whole thing rolls back
-- rather than leaving the table unprotected.
--
-- KEEP IN SYNC: the interval below must match OPERATOR.auditRetentionDays
-- in src/lib/legal/operator.ts, which is the number the privacy policy
-- publishes. If they disagree, the policy is wrong.
--
-- Run with:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/prune-audit-log.sql

\set retention_days 180

BEGIN;

ALTER TABLE "AuditLog" DISABLE TRIGGER audit_log_no_delete;

DELETE FROM "AuditLog"
WHERE "createdAt" < (now() AT TIME ZONE 'utc') - (:'retention_days' || ' days')::interval;

ALTER TABLE "AuditLog" ENABLE TRIGGER audit_log_no_delete;

COMMIT;

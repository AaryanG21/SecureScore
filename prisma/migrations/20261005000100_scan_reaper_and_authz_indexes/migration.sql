-- Two indexes that the access patterns ask for.
--
-- ScanResult(status, startedAt)
--   The stalled-scan reaper looks for RUNNING rows older than a threshold,
--   and it runs on every boot. Nothing indexed status at all, so that was
--   a sequential scan over the whole scan history each time.
--
-- Domain(userId, verificationStatus)
--   authorizeScan filters on both columns together — is this domain owned
--   by the caller AND verified — and it is the single most
--   security-critical query in the application. Two separate
--   single-column indexes left Postgres picking one and filtering the
--   remainder.
--
-- Both are created IF NOT EXISTS so re-running against a database that
-- already has them is a no-op.

CREATE INDEX IF NOT EXISTS "ScanResult_status_startedAt_idx"
  ON "ScanResult" ("status", "startedAt");

CREATE INDEX IF NOT EXISTS "Domain_userId_verificationStatus_idx"
  ON "Domain" ("userId", "verificationStatus");

-- Headers-only scans against hosts the caller does not own.
--
-- The distinction this encodes is between passive observation and active
-- probing. A headers check is one HTTPS GET whose body is never read —
-- the same network footprint as a browser loading the page once. The TLS
-- step opens hundreds of handshakes probing cipher suites and protocol
-- versions, which is reconnaissance by any reasonable definition and stays
-- behind proof of ownership.
--
-- Three changes to ScanResult:
--
--   scanType   FULL or HEADERS_ONLY. What the scan was PERMITTED to do,
--              which is a different question from whether it succeeded.
--
--   hostname   Denormalized, and now required. A headers-only scan has no
--              Domain row to join to — but the better reason is forensic:
--              the hostname as scanned outlives the registration. The
--              first scan of this project's own site lost its hostname
--              when that registration was replaced.
--
--   domainId   Now nullable, and ON DELETE SET NULL rather than CASCADE.
--              Removing a domain registration previously destroyed its
--              scan history along with it. The scorecards are the record
--              of what was found and when; they should survive the
--              registration being changed, exactly as audit rows survive
--              the account that produced them.

CREATE TYPE "ScanType" AS ENUM ('FULL', 'HEADERS_ONLY');

ALTER TABLE "ScanResult"
  ADD COLUMN "scanType" "ScanType" NOT NULL DEFAULT 'FULL',
  ADD COLUMN "hostname" TEXT;

-- Backfill from the registration each existing scan still points at.
UPDATE "ScanResult" AS s
SET "hostname" = d."hostname"
FROM "Domain" AS d
WHERE s."domainId" = d."id" AND s."hostname" IS NULL;

-- Any row whose domain is already gone keeps a truthful placeholder rather
-- than a guess. There should be none, because the FK was CASCADE until now.
UPDATE "ScanResult" SET "hostname" = '(unknown)' WHERE "hostname" IS NULL;

ALTER TABLE "ScanResult" ALTER COLUMN "hostname" SET NOT NULL;

-- Relax the foreign key: nullable, and no longer cascading.
ALTER TABLE "ScanResult" DROP CONSTRAINT "ScanResult_domainId_fkey";
ALTER TABLE "ScanResult" ALTER COLUMN "domainId" DROP NOT NULL;
ALTER TABLE "ScanResult"
  ADD CONSTRAINT "ScanResult_domainId_fkey"
  FOREIGN KEY ("domainId") REFERENCES "Domain"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- Supports the per-target throttle, which asks how often a given hostname
-- has been scanned recently regardless of who asked.
CREATE INDEX IF NOT EXISTS "ScanResult_hostname_createdAt_idx"
  ON "ScanResult" ("hostname", "createdAt");

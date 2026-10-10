-- Record of the age and terms confirmation given at registration.
--
-- Nullable on purpose. Accounts created before this gate existed have no
-- such record, and back-filling a timestamp would manufacture evidence of
-- a consent that was never given — the opposite of what a consent record
-- is for.
--
-- Two columns for one checkbox: the same affirmative action covers both
-- statements today, but re-accepting changed Terms later must not
-- overwrite the record of when the age was confirmed.
--
-- No date of birth column. Confirming the 18+ threshold is what the
-- purpose requires; storing the exact date would be more personal data
-- than is needed, which is the storage-limitation principle applied rather
-- than merely cited.

ALTER TABLE "User"
  ADD COLUMN "ageConfirmedAt"  TIMESTAMP(3),
  ADD COLUMN "termsAcceptedAt" TIMESTAMP(3);

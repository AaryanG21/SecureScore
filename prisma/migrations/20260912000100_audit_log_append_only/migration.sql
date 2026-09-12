-- Make the audit log append-only at the database layer.
--
-- Application code never issues UPDATE or DELETE against "AuditLog", but
-- "the app doesn't do that" is a convention, not a control. This trigger
-- makes tampering fail even for a connection that has been compromised
-- through the application's own credentials.
--
-- Caveat, stated honestly: a superuser (or the table owner) can drop this
-- trigger. It raises the cost of tampering and makes it noisy; it does not
-- make the log cryptographically immutable. For that you would ship logs
-- off-host to append-only storage — see the README's security limitations.

CREATE OR REPLACE FUNCTION audit_log_reject_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'AuditLog is append-only: % is not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON "AuditLog"
  FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON "AuditLog"
  FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();

-- Truncate bypasses row-level triggers, so block it separately.
CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON "AuditLog"
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_mutation();

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, Panel, buttonClass, inputClass } from "@/components/ui";

/**
 * Export and deletion — the two data rights that need a UI.
 *
 * Export is a plain link with no friction. Putting obstacles in front of a
 * right someone is entitled to exercise is its own kind of dark pattern,
 * and nothing irreversible happens.
 *
 * Deletion is gated on re-entering the password and a 2FA code, because a
 * session left open on an unlocked laptop should not be enough to destroy
 * an account. The confirmation asks for the word "delete" rather than
 * offering a pre-focused button: the friction is in proportion to the
 * consequence, and there is nothing to undo afterwards.
 *
 * What it does NOT do is try to talk the user out of it, hide the control,
 * or bury it behind a support email. Deletion is a right, not a retention
 * opportunity.
 */
export function DataControls() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [confirmWord, setConfirmWord] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setOpen(false);
    setPassword("");
    setCode("");
    setConfirmWord("");
    setError(null);
  }

  async function deleteAccount(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    // Step up first. The reauth cookie it sets is what the delete endpoint
    // checks; without it the call returns 401 reauth_required.
    const stepUp = await apiFetch("/api/auth/reauth", {
      method: "POST",
      body: { password, code },
    });

    if (!stepUp.ok) {
      setBusy(false);
      setError(stepUp.error.message);
      return;
    }

    const result = await apiFetch<{ status: string }>("/api/account/delete", {
      method: "POST",
    });

    setBusy(false);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }

    // The session is gone server-side and the cookies are cleared.
    router.push("/");
    router.refresh();
  }

  return (
    <>
      <Panel
        title="Your data"
        description="Everything Fulcrum holds about this account."
      >
        <p className="text-sm leading-relaxed text-ink-muted">
          Download your account details, domains, scan results and sign-in
          history as a JSON file. Credentials are excluded — your password
          hash and two-factor secret describe the account rather than you,
          and a copy of either would be useful only to someone who should not
          have it.
        </p>

        <a
          href="/api/account/export"
          download
          className={`${buttonClass} mt-4 inline-block`}
        >
          Download my data
        </a>
      </Panel>

      <Panel
        title="Delete account"
        description="Permanent. This cannot be undone."
      >
        {!open ? (
          <>
            <p className="text-sm leading-relaxed text-ink-muted">
              Deletes your account, your domains, every scan result and your
              sign-in history. Security audit records naming you are held
              separately and are destroyed on the schedule described in the
              privacy policy — the log they live in cannot be edited, which
              is deliberate.
            </p>
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="mt-4 rounded-md border border-sev-critical/50 bg-sev-critical/10 px-4 py-2 text-sm font-medium text-sev-critical transition-colors hover:bg-sev-critical/20"
            >
              Delete my account
            </button>
          </>
        ) : (
          <form onSubmit={deleteAccount} className="space-y-4">
            <Alert tone="critical">
              This permanently deletes your account and all of your data.
              Confirm your identity to continue.
            </Alert>

            {error && <Alert>{error}</Alert>}

            <Field label="Your password">
              <input
                className={inputClass}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>

            <Field label="6-digit code" hint="From your authenticator app.">
              <input
                className={inputClass}
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                required
              />
            </Field>

            <Field
              label="Type delete to confirm"
              hint="Case-insensitive."
            >
              <input
                className={inputClass}
                value={confirmWord}
                onChange={(e) => setConfirmWord(e.target.value)}
                autoComplete="off"
                required
              />
            </Field>

            <div className="flex flex-wrap gap-3">
              <button
                type="submit"
                disabled={busy || confirmWord.trim().toLowerCase() !== "delete"}
                className="rounded-md bg-sev-critical px-4 py-2 text-sm font-semibold text-base transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busy ? "Deleting…" : "Delete permanently"}
              </button>
              <button
                type="button"
                onClick={reset}
                disabled={busy}
                className="rounded-md border border-line-bright px-4 py-2 text-sm text-ink transition-colors hover:bg-surface-2"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </Panel>
    </>
  );
}

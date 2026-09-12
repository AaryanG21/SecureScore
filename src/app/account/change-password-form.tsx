"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, buttonClass, inputClass } from "@/components/ui";

export function ChangePasswordForm() {
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setDone(false);

    const result = await apiFetch("/api/account/password", {
      method: "POST",
      body: { currentPassword, newPassword },
    });
    setBusy(false);

    if (!result.ok) {
      setError(result.error.details?.newPassword?.[0] ?? result.error.message);
      return;
    }

    setCurrentPassword("");
    setNewPassword("");
    setDone(true);
    router.refresh();
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && <Alert>{error}</Alert>}
      {done && (
        <Alert tone="signal">
          Password changed. Your other sessions have been signed out.
        </Alert>
      )}

      <Field label="Current password">
        <input
          className={inputClass}
          type="password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          autoComplete="current-password"
          required
        />
      </Field>

      <Field label="New password" hint="At least 12 characters.">
        <input
          className={inputClass}
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          autoComplete="new-password"
          minLength={12}
          required
        />
      </Field>

      <button type="submit" className={buttonClass} disabled={busy}>
        {busy ? "Updating…" : "Change password"}
      </button>
    </form>
  );
}

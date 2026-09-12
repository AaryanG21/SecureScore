"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, Panel, buttonClass, inputClass } from "@/components/ui";

/**
 * Two-step sign-in.
 *
 * The step machine here mirrors the server's token types exactly: the
 * password step yields only an mfa_pending cookie, and only the second step
 * can produce a session. The UI cannot skip a step, because there is no
 * client state that would let it — the server decides what comes next.
 */

type Step = "password" | "totp" | "enroll";

export function LoginFlow() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const result = await apiFetch<{ status: string }>("/api/auth/login", {
      method: "POST",
      body: { email, password },
    });

    setBusy(false);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }

    // Clear the password from component state as soon as it is no longer
    // needed. Minor, but it keeps it out of React DevTools and any error
    // reporting that serializes component state.
    setPassword("");
    setStep(result.data.status === "totp_required" ? "totp" : "enroll");
  }

  async function submitCode(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const result = await apiFetch<{ role: string; remainingBackupCodes: number }>(
      "/api/auth/2fa/verify",
      {
        method: "POST",
        body: useBackupCode ? { backupCode: code } : { code },
      },
    );

    setBusy(false);

    if (!result.ok) {
      setError(result.error.message);
      if (result.error.code === "mfa_session_expired") setStep("password");
      return;
    }

    router.push(result.data.role === "ADMIN" ? "/admin" : "/dashboard");
    router.refresh();
  }

  if (step === "enroll") {
    return (
      <Panel title="Two-factor setup required">
        <p className="text-sm text-ink-muted">
          Every account on Fulcrum uses an authenticator app. Finish enrollment
          to continue — it takes about a minute.
        </p>
        <button
          type="button"
          className={`${buttonClass} mt-4 w-full`}
          onClick={() => router.push("/enroll")}
        >
          Set up two-factor authentication
        </button>
      </Panel>
    );
  }

  if (step === "totp") {
    return (
      <Panel title="Verification code">
        <form onSubmit={submitCode} className="space-y-4">
          {error && <Alert>{error}</Alert>}

          {useBackupCode ? (
            <Field
              label="Backup code"
              hint="One of the single-use codes you saved at enrollment."
            >
              <input
                className={`${inputClass} font-mono tracking-widest`}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                placeholder="XXXX-XXXX"
                required
              />
            </Field>
          ) : (
            <Field label="6-digit code" hint="From your authenticator app.">
              <input
                className={`${inputClass} font-mono text-lg tracking-[0.4em]`}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                required
                autoFocus
              />
            </Field>
          )}

          <button type="submit" className={`${buttonClass} w-full`} disabled={busy}>
            {busy ? "Verifying…" : "Verify"}
          </button>

          <button
            type="button"
            className="w-full text-center text-xs text-ink-muted hover:text-ink"
            onClick={() => {
              setUseBackupCode((v) => !v);
              setCode("");
              setError(null);
            }}
          >
            {useBackupCode ? "Use my authenticator app instead" : "Use a backup code"}
          </button>
        </form>
      </Panel>
    );
  }

  return (
    <Panel title="Sign in">
      <form onSubmit={submitPassword} className="space-y-4">
        {error && <Alert>{error}</Alert>}

        <Field label="Email">
          <input
            className={inputClass}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            required
            autoFocus
          />
        </Field>

        <Field label="Password">
          <input
            className={inputClass}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>

        <button type="submit" className={`${buttonClass} w-full`} disabled={busy}>
          {busy ? "Checking…" : "Continue"}
        </button>

        <p className="text-center text-xs text-ink-faint">
          A second factor is required after this step.
        </p>
      </form>
    </Panel>
  );
}

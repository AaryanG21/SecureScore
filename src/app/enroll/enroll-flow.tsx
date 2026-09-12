"use client";

import Image from "next/image";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, Panel, buttonClass, inputClass } from "@/components/ui";

/**
 * TOTP enrollment.
 *
 * The backup codes shown at the end exist only in this response — the
 * server stores argon2id hashes and cannot recover them. The UI says so
 * plainly and makes the user acknowledge it before moving on, because a
 * user who breezes past this screen has no recovery path if they lose
 * their phone.
 */

interface SetupPayload {
  secret: string;
  otpauthUri: string;
  qrDataUri: string;
}

export function EnrollFlow() {
  const router = useRouter();
  const [setup, setSetup] = useState<SetupPayload | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Deliberately click-triggered rather than fired on mount: this call
  // generates and stores a NEW authenticator secret, which invalidates any
  // previous one. A mutation that significant should not happen because a
  // page happened to render — or re-render.
  async function beginSetup() {
    setBusy(true);
    setError(null);

    const result = await apiFetch<SetupPayload>("/api/auth/2fa/setup", {
      method: "POST",
    });
    setBusy(false);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }
    setSetup(result.data);
  }

  async function activate(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const result = await apiFetch<{ backupCodes: string[] }>(
      "/api/auth/2fa/activate",
      { method: "POST", body: { code } },
    );
    setBusy(false);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }

    setBackupCodes(result.data.backupCodes);
  }

  if (backupCodes) {
    return (
      <Panel title="Save your backup codes">
        <Alert tone="signal">
          These codes are shown once and cannot be recovered. Store them
          somewhere separate from your phone.
        </Alert>

        <ul className="mt-4 grid grid-cols-2 gap-2">
          {backupCodes.map((c) => (
            <li
              key={c}
              className="rounded border border-line-bright bg-surface-2 px-3 py-2 text-center font-mono text-sm tracking-widest text-ink"
            >
              {c}
            </li>
          ))}
        </ul>

        <p className="mt-4 text-xs text-ink-faint">
          Each code works once. Use one if you lose access to your
          authenticator app.
        </p>

        <label className="mt-4 flex items-start gap-2.5 text-sm text-ink-muted">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I have saved these codes somewhere safe.
        </label>

        <button
          type="button"
          className={`${buttonClass} mt-4 w-full`}
          disabled={!acknowledged}
          onClick={() => {
            router.push("/dashboard");
            router.refresh();
          }}
        >
          Continue to dashboard
        </button>
      </Panel>
    );
  }

  return (
    <Panel
      title="Set up two-factor authentication"
      description="Scan this with an authenticator app, then enter the code it shows."
    >
      {error && <Alert>{error}</Alert>}

      {setup ? (
        <div className="space-y-5">
          <div className="flex justify-center rounded-lg border border-line bg-white p-4">
            {/* Rendered server-side as a data URI: the secret never touches
                a third-party QR service. */}
            <Image
              src={setup.qrDataUri}
              alt="QR code for authenticator app enrollment"
              width={240}
              height={240}
              unoptimized
            />
          </div>

          <div>
            <p className="text-xs text-ink-faint">
              Cannot scan? Enter this key manually:
            </p>
            <code className="mt-1 block overflow-x-auto rounded border border-line-bright bg-surface-2 px-3 py-2 font-mono text-sm break-all text-ink">
              {setup.secret}
            </code>
          </div>

          <form onSubmit={activate} className="space-y-4">
            <Field label="Code from your app">
              <input
                className={`${inputClass} font-mono text-lg tracking-[0.4em]`}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                required
              />
            </Field>

            <button type="submit" className={`${buttonClass} w-full`} disabled={busy}>
              {busy ? "Verifying…" : "Confirm and enable"}
            </button>
          </form>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-ink-muted">
            You will need an authenticator app (1Password, Aegis, Google
            Authenticator, or similar). Generating a new secret replaces any
            authenticator you have previously set up on this account.
          </p>
          <button
            type="button"
            className={`${buttonClass} w-full`}
            onClick={beginSetup}
            disabled={busy}
          >
            {busy ? "Preparing…" : "Generate my authenticator secret"}
          </button>
        </div>
      )}
    </Panel>
  );
}

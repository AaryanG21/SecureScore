"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, Panel, buttonClass, inputClass } from "@/components/ui";

interface ScannableDomain {
  id: string;
  hostname: string;
}

/**
 * Starts a scan.
 *
 * Only verified domains appear in the picker — but that is a convenience,
 * not the control. The server re-checks authorization on every request via
 * `authorizeScan`, so submitting an arbitrary domainId still gets refused
 * and logged.
 */
export function ScanLauncher({ domains }: { domains: ScannableDomain[] }) {
  const router = useRouter();
  const [budget, setBudget] = useState(15);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // The selection is DERIVED, not stored, and that is load-bearing.
  //
  // `useState(domains[0]?.id)` would capture the list as it was on first
  // mount. This panel first renders with zero verified domains, so the
  // stored id would be "" — and it would stay "" after a domain was
  // verified and the props updated, because a useState initializer runs
  // once. A controlled <select> whose value matches no option still
  // displays the first one, so the form looked correct while posting an
  // empty domainId.
  //
  // Holding only an explicit user choice, and falling back to the first
  // available domain, means the rendered value and the submitted value
  // cannot drift apart.
  const [chosenId, setChosenId] = useState<string | null>(null);
  const domainId =
    chosenId && domains.some((d) => d.id === chosenId)
      ? chosenId
      : (domains[0]?.id ?? "");

  async function launch(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const result = await apiFetch<{ scanId: string }>("/api/scans", {
      method: "POST",
      body: { domainId, budget },
    });

    setBusy(false);

    if (!result.ok) {
      // Surface the specific field error when the server sent one; the
      // generic message alone ("Check the scan parameters.") gives the user
      // nothing to act on.
      const fieldError = result.error.details
        ? Object.entries(result.error.details)
            .map(([field, messages]) => `${field}: ${messages.join(", ")}`)
            .join(" · ")
        : null;
      setError(fieldError ? `${result.error.message} (${fieldError})` : result.error.message);
      return;
    }

    router.push(`/scans/${result.data.scanId}`);
  }

  if (domains.length === 0) {
    return (
      <Panel title="Run a scan">
        <p className="text-sm text-ink-muted">
          No verified domains yet. Register a domain and complete the ownership
          challenge above — the agent refuses to scan anything unverified, and
          logs the refusal.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Run a scan"
      description="Checks HTTP headers, TLS configuration via testssl.sh, and known CVEs for any disclosed versions."
    >
      <form onSubmit={launch} className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <Field label="Verified domain">
            <select
              className={inputClass}
              value={domainId}
              onChange={(e) => setChosenId(e.target.value)}
              required
            >
              {domains.map((domain) => (
                <option key={domain.id} value={domain.id}>
                  {domain.hostname}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <div className="w-40">
          <Field
            label="Fix-effort budget"
            hint="Arbitrary points. Roughly: 1 = a header, 13 = a project."
          >
            <input
              className={inputClass}
              type="number"
              min={1}
              max={1000}
              value={budget}
              onChange={(e) => setBudget(Number(e.target.value))}
              required
            />
          </Field>
        </div>

        <button type="submit" className={buttonClass} disabled={busy}>
          {busy ? "Scanning…" : "Run scan"}
        </button>
      </form>

      {busy && (
        <p className="mt-3 text-xs text-ink-faint">
          The TLS stage runs testssl.sh against the target and typically takes
          two to three minutes. Leave this tab open.
        </p>
      )}

      {error && (
        <div className="mt-3">
          <Alert>{error}</Alert>
        </div>
      )}
    </Panel>
  );
}

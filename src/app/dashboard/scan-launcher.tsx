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
  const [domainId, setDomainId] = useState(domains[0]?.id ?? "");
  const [budget, setBudget] = useState(15);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      setError(result.error.message);
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
              onChange={(e) => setDomainId(e.target.value)}
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

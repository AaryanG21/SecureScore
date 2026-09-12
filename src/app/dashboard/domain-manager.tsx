"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import {
  Alert,
  Badge,
  Field,
  Panel,
  buttonClass,
  buttonGhostClass,
  inputClass,
} from "@/components/ui";

interface Challenge {
  type: "DNS_TXT" | "HTTP_WELL_KNOWN";
  target: string;
  value: string;
}

export interface DomainRow {
  id: string;
  hostname: string;
  verificationStatus: "PENDING" | "VERIFIED" | "FAILED" | "REVOKED";
  verificationMethod: "DNS_TXT" | "HTTP_WELL_KNOWN";
  verifiedAt: string | null;
  createdAt: string;
  challenge: Challenge;
}

const STATUS_TONE = {
  VERIFIED: "signal",
  PENDING: "medium",
  FAILED: "high",
  REVOKED: "critical",
} as const;

/**
 * Domain allowlist management.
 *
 * The client renders state and submits intent; every decision — whether a
 * hostname is acceptable, whether a challenge passed, whether the caller
 * owns the row — is made on the server.
 */
export function DomainManager({ initialDomains }: { initialDomains: DomainRow[] }) {
  const router = useRouter();
  const [hostname, setHostname] = useState("");
  const [method, setMethod] = useState<"DNS_TXT" | "HTTP_WELL_KNOWN">("DNS_TXT");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  async function addDomain(event: React.FormEvent) {
    event.preventDefault();
    setAdding(true);
    setError(null);
    setNotice(null);

    const result = await apiFetch("/api/domains", {
      method: "POST",
      body: { hostname, method },
    });
    setAdding(false);

    if (!result.ok) {
      setError(result.error.details?.hostname?.[0] ?? result.error.message);
      return;
    }

    setHostname("");
    setNotice("Domain registered. Publish the challenge below, then verify.");
    router.refresh();
  }

  async function verify(id: string) {
    setBusyId(id);
    setError(null);
    setNotice(null);

    const result = await apiFetch(`/api/domains/${id}/verify`, { method: "POST" });
    setBusyId(null);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }

    setNotice("Ownership verified. This domain can now be scanned.");
    router.refresh();
  }

  async function remove(id: string) {
    setBusyId(id);
    setError(null);
    setNotice(null);

    const result = await apiFetch(`/api/domains/${id}`, { method: "DELETE" });
    setBusyId(null);

    if (!result.ok) {
      setError(result.error.message);
      return;
    }

    router.refresh();
  }

  return (
    <Panel
      title="Registered domains"
      description="Only verified domains can be scanned. Everything else is refused and logged."
    >
      <form onSubmit={addDomain} className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <Field label="Hostname" hint="Domain only — no scheme, path, or port.">
            <input
              className={inputClass}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="example.com"
              required
            />
          </Field>
        </div>

        <div className="min-w-48">
          <Field label="Verification method">
            <select
              className={inputClass}
              value={method}
              onChange={(e) =>
                setMethod(e.target.value as "DNS_TXT" | "HTTP_WELL_KNOWN")
              }
            >
              <option value="DNS_TXT">DNS TXT record (recommended)</option>
              <option value="HTTP_WELL_KNOWN">Well-known file</option>
            </select>
          </Field>
        </div>

        <button type="submit" className={buttonClass} disabled={adding}>
          {adding ? "Adding…" : "Add domain"}
        </button>
      </form>

      {error && (
        <div className="mt-3">
          <Alert>{error}</Alert>
        </div>
      )}
      {notice && (
        <div className="mt-3">
          <Alert tone="signal">{notice}</Alert>
        </div>
      )}

      <ul className="mt-5 space-y-3">
        {initialDomains.length === 0 && (
          <li className="text-sm text-ink-muted">No domains registered yet.</li>
        )}

        {initialDomains.map((domain) => (
          <li
            key={domain.id}
            className="rounded-md border border-line bg-surface-2 px-4 py-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-ink">{domain.hostname}</span>
                <Badge tone={STATUS_TONE[domain.verificationStatus]}>
                  {domain.verificationStatus.toLowerCase()}
                </Badge>
              </div>

              <div className="flex items-center gap-2">
                {domain.verificationStatus !== "VERIFIED" &&
                  domain.verificationStatus !== "REVOKED" && (
                    <button
                      type="button"
                      className={buttonGhostClass}
                      disabled={busyId === domain.id}
                      onClick={() => verify(domain.id)}
                    >
                      {busyId === domain.id ? "Checking…" : "Verify"}
                    </button>
                  )}
                <button
                  type="button"
                  className="rounded-md border border-line-bright px-3 py-2 text-sm text-ink-muted transition-colors hover:border-sev-critical/50 hover:text-ink disabled:opacity-50"
                  disabled={busyId === domain.id}
                  onClick={() => remove(domain.id)}
                >
                  Remove
                </button>
              </div>
            </div>

            {domain.verificationStatus !== "VERIFIED" && (
              <dl className="mt-3 space-y-1.5 text-xs">
                <div className="flex flex-wrap gap-2">
                  <dt className="text-ink-faint">
                    {domain.challenge.type === "DNS_TXT" ? "TXT record" : "URL"}:
                  </dt>
                  <dd className="font-mono break-all text-ink-muted">
                    {domain.challenge.target}
                  </dd>
                </div>
                <div className="flex flex-wrap gap-2">
                  <dt className="text-ink-faint">Value:</dt>
                  <dd className="font-mono break-all text-ink-muted">
                    {domain.challenge.value}
                  </dd>
                </div>
              </dl>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

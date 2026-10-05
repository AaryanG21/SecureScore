"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/client/api";
import { Alert, Field, Panel, buttonClass, inputClass } from "@/components/ui";

/**
 * Headers-only check of any public host.
 *
 * The copy here does real work. Someone arriving at a box that accepts any
 * hostname will reasonably assume it does what the other box does, and the
 * difference — one request versus hundreds of TLS handshakes — is the
 * difference between reading a page and probing a stranger's server. So it
 * says what it does before you use it, not only afterwards on the result.
 */
export function PublicCheck() {
  const router = useRouter();
  const [hostname, setHostname] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    const result = await apiFetch<{ scanId: string; cached: boolean }>(
      "/api/scans/public",
      { method: "POST", body: { hostname, budget: 20 } },
    );

    setBusy(false);

    if (!result.ok) {
      const fieldError = result.error.details
        ? Object.entries(result.error.details as Record<string, string[]>)
            .map(([field, messages]) => `${field}: ${messages.join(", ")}`)
            .join(" · ")
        : null;
      setError(fieldError ? `${result.error.message} (${fieldError})` : result.error.message);
      return;
    }

    router.push(`/scans/${result.data.scanId}`);
  }

  return (
    <Panel
      title="Check any site's headers"
      description="No ownership needed — one request, response headers only."
    >
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div className="min-w-64 flex-1">
          <Field label="Hostname" hint="Domain only — no scheme, path, or port.">
            <input
              className={inputClass}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
              required
            />
          </Field>
        </div>
        <button type="submit" className={buttonClass} disabled={busy || !hostname}>
          {busy ? "Checking…" : "Check headers"}
        </button>
      </form>

      {error && (
        <div className="mt-4">
          <Alert tone="critical">{error}</Alert>
        </div>
      )}

      <p className="mt-4 border-t border-line pt-4 text-xs leading-relaxed text-ink-faint">
        This sends the target <strong className="font-semibold">one</strong>{" "}
        HTTPS request and reads its response headers — the same thing a
        browser does when you visit the page. It does{" "}
        <strong className="font-semibold">not</strong> test TLS or
        certificates: that needs hundreds of handshakes, it looks like
        reconnaissance in the target&rsquo;s logs, and it stays behind proving
        you control the domain. A result from here describes HTTP headers and
        nothing else.
      </p>
    </Panel>
  );
}

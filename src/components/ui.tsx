import type { ReactNode } from "react";

/**
 * Small shared primitives. Deliberately plain — a security console should
 * read like an instrument panel, not a marketing page.
 */

export function Panel({
  title,
  description,
  action,
  children,
  className = "",
}: {
  title?: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-line bg-surface ${className}`}
    >
      {(title || action) && (
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div>
            {title && (
              <h2 className="text-sm font-semibold tracking-wide text-ink uppercase">
                {title}
              </h2>
            )}
            {description && (
              <p className="mt-1 text-sm text-ink-muted">{description}</p>
            )}
          </div>
          {action}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

type Tone = "signal" | "critical" | "high" | "medium" | "low" | "neutral";

const TONE_CLASS: Record<Tone, string> = {
  signal: "border-signal/40 bg-signal/10 text-signal",
  critical: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
  high: "border-sev-high/40 bg-sev-high/10 text-sev-high",
  medium: "border-sev-medium/40 bg-sev-medium/10 text-sev-medium",
  low: "border-sev-low/40 bg-sev-low/10 text-sev-low",
  neutral: "border-line-bright bg-surface-2 text-ink-muted",
};

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: Tone;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-xs ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3">
      <div className="text-xs tracking-wide text-ink-faint uppercase">{label}</div>
      <div className="mt-1 font-mono text-2xl text-ink">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-ink-faint">{hint}</div>}
    </div>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-ink">{label}</span>
      {hint && <span className="mt-0.5 block text-xs text-ink-faint">{hint}</span>}
      <div className="mt-1.5">{children}</div>
      {error && (
        <span role="alert" className="mt-1.5 block text-xs text-sev-critical">
          {error}
        </span>
      )}
    </label>
  );
}

export const inputClass =
  "w-full rounded-md border border-line-bright bg-surface-2 px-3 py-2 text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none";

export const buttonClass =
  "inline-flex items-center justify-center gap-2 rounded-md bg-signal px-4 py-2 text-sm font-semibold text-base transition-colors hover:bg-signal-dim hover:text-ink disabled:cursor-not-allowed disabled:opacity-50";

export const buttonGhostClass =
  "inline-flex items-center justify-center gap-2 rounded-md border border-line-bright bg-surface-2 px-4 py-2 text-sm font-medium text-ink transition-colors hover:border-signal/50 disabled:cursor-not-allowed disabled:opacity-50";

export function Alert({
  tone = "critical",
  children,
}: {
  tone?: "critical" | "signal" | "neutral";
  children: ReactNode;
}) {
  const cls =
    tone === "critical"
      ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical"
      : tone === "signal"
        ? "border-signal/40 bg-signal/10 text-signal"
        : "border-line-bright bg-surface-2 text-ink-muted";

  return (
    <div role="alert" className={`rounded-md border px-3 py-2 text-sm ${cls}`}>
      {children}
    </div>
  );
}

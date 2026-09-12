import Link from "next/link";
import { Badge } from "@/components/ui";

/**
 * Landing page.
 *
 * Copy discipline: nothing here claims the scanned site — or this app —
 * is "unhackable", "fully secure", or "protected". Everything is framed as
 * layered defence with stated limits, which is both honest and the only
 * claim the implementation can actually support.
 */

const CAPABILITIES = [
  {
    title: "Header & transport posture",
    body: "HSTS, CSP, frame options, cookie flags, and the TLS stack — protocols, ciphers, and certificate chain — checked against current guidance.",
  },
  {
    title: "Version-aware CVE context",
    body: "Fingerprinted software versions are cross-referenced with CVE and EPSS data, so a finding carries its real-world exploitation likelihood, not just a CVSS number.",
  },
  {
    title: "Budget-aware remediation",
    body: "Set a fix-effort budget. The agent ranks remediations by risk reduced per unit of effort and shows the reasoning behind the order it chose.",
  },
  {
    title: "Scans only what you own",
    body: "Every hostname must pass a DNS or well-known-file ownership challenge before it can be scanned. Unverified targets are refused and the refusal is logged.",
  },
];

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line">
        <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2.5">
            <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
            <span className="font-mono text-sm font-semibold tracking-widest text-ink uppercase">
              Fulcrum
            </span>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="rounded-md px-3 py-1.5 text-sm text-ink-muted transition-colors hover:text-ink"
            >
              Sign in
            </Link>
            <Link
              href="/register"
              className="rounded-md border border-line-bright bg-surface-2 px-3 py-1.5 text-sm text-ink transition-colors hover:border-signal/50"
            >
              Create account
            </Link>
          </div>
        </nav>
      </header>

      <main className="flex-1">
        <section className="grid-backdrop border-b border-line">
          <div className="mx-auto grid max-w-6xl gap-10 px-6 py-20 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
            <div>
              <Badge tone="signal">Scorecard + remediation agent</Badge>
              <h1 className="mt-5 text-4xl leading-tight font-semibold tracking-tight text-ink sm:text-5xl">
                Know what to fix first,
                <br />
                <span className="text-signal">within the effort you have.</span>
              </h1>
              <p className="mt-5 max-w-xl text-lg text-ink-muted">
                Fulcrum scans a domain you have proven you own, grades its
                security posture from A to F, and returns a prioritized
                remediation plan sized to a fix-effort budget you set — with the
                reasoning shown, not just a number.
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link
                  href="/register"
                  className="rounded-md bg-signal px-5 py-2.5 text-sm font-semibold text-base transition-colors hover:bg-signal-dim hover:text-ink"
                >
                  Get started
                </Link>
                <Link
                  href="/login"
                  className="rounded-md border border-line-bright bg-surface-2 px-5 py-2.5 text-sm font-medium text-ink transition-colors hover:border-signal/50"
                >
                  Sign in
                </Link>
              </div>
              <p className="mt-4 font-mono text-xs text-ink-faint">
                2FA required on every account · scans restricted to verified domains
              </p>
            </div>

            {/*
              PLACEHOLDER IMAGE SLOT — hero artwork to be generated
              separately (Higgsfield) and dropped in at /public/hero.png.
              Replace this whole block with:
                <Image src="/hero.png" alt="" width={720} height={540} priority />
              Keep the aspect ratio close to 4:3 so the layout does not shift.
            */}
            <div
              aria-hidden
              className="flex aspect-[4/3] items-center justify-center rounded-lg border border-dashed border-line-bright bg-surface/60"
            >
              <div className="text-center">
                <p className="font-mono text-xs tracking-widest text-ink-faint uppercase">
                  Hero image slot
                </p>
                <p className="mt-2 text-sm text-ink-faint">
                  /public/hero.png · 4:3
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="font-mono text-xs tracking-widest text-ink-faint uppercase">
            What the agent does
          </h2>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            {CAPABILITIES.map((item) => (
              <div
                key={item.title}
                className="rounded-lg border border-line bg-surface p-5"
              >
                <h3 className="text-base font-semibold text-ink">{item.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-ink-muted">
                  {item.body}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section className="border-t border-line bg-surface/40">
          <div className="mx-auto max-w-6xl px-6 py-14">
            <h2 className="font-mono text-xs tracking-widest text-ink-faint uppercase">
              What this is not
            </h2>
            <p className="mt-4 max-w-3xl text-sm leading-relaxed text-ink-muted">
              A passing grade here means the checks Fulcrum runs did not find a
              problem. It is not a guarantee that a site is secure, and no tool
              — this one included — can offer that. Fulcrum inspects what is
              reachable from the outside: headers, TLS configuration, and
              version fingerprints. It does not review your application logic,
              your dependencies, your infrastructure, or your people. Treat the
              scorecard as one input among several.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-6 text-xs text-ink-faint">
          <span className="font-mono">Fulcrum · defence in depth, honestly described</span>
          <span>Scan only domains you own and have verified.</span>
        </div>
      </footer>
    </div>
  );
}

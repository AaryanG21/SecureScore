import Link from "next/link";
import { Badge } from "@/components/ui";
import { SiteFooter } from "@/components/site-footer";

// Rendered per request, not prerendered.
//
// The CSP in src/proxy.ts carries a per-request nonce, and `'strict-dynamic'`
// makes browsers ignore the `'self'` source expression for scripts. A page
// prerendered at build time has no request and therefore no nonce, so its
// script tags are emitted bare and every one of them is blocked — the page
// ships with no working JavaScript at all. That failure is invisible in
// `next dev`, which does not prerender, and it only appears in a production
// build. Opting out of static generation is what keeps the nonce and the
// markup on the same request.
export const dynamic = "force-dynamic";


/**
 * Landing page.
 *
 * Copy discipline: nothing here claims the scanned site — or this app —
 * is "unhackable", "fully secure", or "protected". Everything is framed as
 * layered defence with stated limits, which is both honest and the only
 * claim the implementation can actually support.
 */

/**
 * Figures for the hero illustration. A worked example, labelled as such on
 * the page — these are the shapes the planner really produces (cheap fixes
 * first, by risk removed per effort point), with no claim to be any
 * particular site's result.
 */
const EXAMPLE_PLAN = [
  { title: "No clickjacking protection", effort: 1, removes: 11 },
  { title: "Certificate near expiry", effort: 2, removes: 14 },
  { title: "MIME sniffing not disabled", effort: 1, removes: 4 },
  { title: "Obsolete cipher suites", effort: 2, removes: 4 },
] as const;

const CAPABILITIES = [
  {
    title: "Header & transport posture",
    body: "Eight header checks — HSTS, CSP, frame options, MIME sniffing, referrer policy, permissions policy, version disclosure and cookie flags. TLS, including protocols, ciphers and the certificate chain, is examined by testssl.sh 3.2.4, pinned and run locally.",
  },
  {
    title: "Version-aware CVE context",
    body: "Where a server advertises its version, that version is matched against a curated set of 16 CVEs covering common web server software, carrying EPSS exploitation likelihood rather than CVSS alone. It is a snapshot, not a vulnerability database, and every result says so.",
  },
  {
    title: "Budget-aware remediation",
    body: "Set a fix-effort budget. The agent ranks remediations by risk reduced per unit of effort and shows the reasoning behind the order it chose — including when it defers the worst finding because three cheaper ones remove more risk.",
  },
  {
    title: "Probing requires proof of ownership",
    body: "A headers check is one request, so it runs against any public site. The TLS scan opens hundreds of connections, so it runs only against a domain you have verified by DNS or a well-known file. Refusals are logged.",
  },
];

export const metadata = {
  title: "Fulcrum — know what to fix first",
  description:
    "Grade any website's security headers in seconds, or verify a domain you control for a full TLS scan. Returns a remediation plan ranked by risk removed per unit of effort, with the reasoning shown.",
};

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
                Fulcrum grades a site&rsquo;s security posture from A to F and
                returns a remediation plan sized to a fix-effort budget you
                set — with the reasoning shown, not just a number. Check any
                site&rsquo;s headers in a second; prove you control a domain to
                run the full scan, including TLS.
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
              <p className="mt-4 font-mono text-xs text-ink-muted">
                2FA required on every account · TLS scanning restricted to
                verified domains
              </p>
            </div>

            {/*
              An illustration of the product's actual output, built from the
              same tokens the real scorecard uses. Deliberately not a
              screenshot and not an image file: nothing to download, nothing
              to keep in sync with the UI, and no layout shift. The figures
              are a worked example and are labelled as one — a marketing page
              showing an invented "real" result would be the kind of claim
              this project refuses to make elsewhere.
            */}
            <figure className="m-0">
              <div className="aspect-[4/3] rounded-lg border border-line bg-surface p-6">
                <div className="flex items-center gap-4">
                  <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-lg border-2 border-sev-high/50 bg-sev-high/10 font-mono text-3xl font-bold text-sev-high">
                    D
                  </div>
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm text-ink">
                      example.com
                    </p>
                    <p className="mt-0.5 text-xs text-ink-muted">
                      Score 50/100 · 10 findings
                    </p>
                  </div>
                </div>

                <ol className="mt-5 space-y-2">
                  {EXAMPLE_PLAN.map((step) => (
                    <li
                      key={step.title}
                      className="flex items-baseline justify-between gap-3 border-b border-line/60 pb-2 text-xs last:border-0"
                    >
                      <span className="truncate text-ink-muted">
                        {step.title}
                      </span>
                      <span className="shrink-0 font-mono text-ink-muted">
                        {step.effort}pt → &minus;{step.removes}
                      </span>
                    </li>
                  ))}
                </ol>

                <p className="mt-4 font-mono text-[11px] tracking-wide text-ink-muted">
                  budget 15 · 14 used · 3 deferred
                </p>
              </div>
              <figcaption className="mt-2 text-center text-xs text-ink-muted">
                Example output. Not a real site&rsquo;s result.
              </figcaption>
            </figure>
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

      <SiteFooter />
    </div>
  );
}

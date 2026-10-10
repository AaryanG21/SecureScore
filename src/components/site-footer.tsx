import Link from "next/link";
import { OPERATOR } from "@/lib/legal/operator";

/**
 * Shared footer.
 *
 * Exists so the legal pages are reachable from every public page — a
 * privacy policy nobody can find is not published in any meaningful sense,
 * and under the DPDP Act the operator and the grievance contact have to be
 * discoverable, not merely written down somewhere.
 *
 * The operator details come from lib/legal/operator.ts rather than being
 * typed here, so the footer and the documents cannot drift apart.
 */
export function SiteFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto max-w-6xl px-6 py-8 text-xs text-ink-muted">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="max-w-sm">
            <p className="font-mono text-ink-muted">
              Fulcrum · defence in depth, honestly described
            </p>
            <p className="mt-2 leading-relaxed">
              Operated by {OPERATOR.name}, {OPERATOR.legalForm}.
            </p>
            <p className="mt-1 leading-relaxed">
              Contact:{" "}
              <a
                href={`mailto:${OPERATOR.contactEmail}`}
                className="text-signal hover:underline"
              >
                {OPERATOR.contactEmail}
              </a>
            </p>
          </div>

          <nav aria-label="Legal and policies">
            <h2 className="font-mono text-[11px] tracking-widest text-ink-muted uppercase">
              Policies
            </h2>
            <ul className="mt-2 space-y-1.5">
              <li>
                <Link href="/privacy" className="hover:text-ink hover:underline">
                  Privacy policy
                </Link>
              </li>
              <li>
                <Link href="/terms" className="hover:text-ink hover:underline">
                  Terms of service
                </Link>
              </li>
              <li>
                <Link href="/cookies" className="hover:text-ink hover:underline">
                  Cookie policy
                </Link>
              </li>
            </ul>
          </nav>
        </div>

        <p className="mt-6 border-t border-line pt-4 leading-relaxed">
          Full scans require proving you control the domain. Headers-only
          checks send a single request and are rate limited. Do not use this
          service to generate traffic against a site on anyone&rsquo;s behalf.
        </p>
      </div>
    </footer>
  );
}

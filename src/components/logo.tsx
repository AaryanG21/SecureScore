/**
 * The Fulcrum mark.
 *
 * Replaces six verbatim copies of
 *
 *     <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
 *
 * which had drifted nowhere yet only because nobody had touched them. One
 * definition means the mark can now change in one place — and it has to, for
 * the favicon and the OG image to agree with the header.
 *
 * `aria-hidden` is deliberate and matches the previous markup: every site
 * that renders this puts the word "Fulcrum" immediately beside it, so naming
 * the mark as well would announce the product twice.
 *
 * Geometry note: the old mark was a 16px square rotated 45 degrees, so its
 * points stuck out past the 16px layout box it occupied — CSS rotation does
 * not resize the box. The diamond here is inscribed in the box instead, so
 * it is marginally smaller but cannot collide with neighbouring text. The
 * layout box is unchanged at h-4 w-4, so nothing reflows.
 */

interface LogoProps {
  /** Sizing and colour. Defaults to the 16px signal-coloured header mark. */
  className?: string;
}

export function Logo({ className = "h-4 w-4 text-signal" }: LogoProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={3}
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      <rect x="4.75" y="4.75" width="14.5" height="14.5" transform="rotate(45 12 12)" />
    </svg>
  );
}

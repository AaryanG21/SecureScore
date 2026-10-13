/**
 * Hand-authored icon set.
 *
 * Inline SVG rather than an icon package, for three reasons that all point
 * the same way:
 *
 *   1. The CSP is `default-src 'self'` with no third-party hosts, and the
 *      product's own landing page claims there is no third-party script
 *      anywhere. An icon dependency would make that claim false to win back
 *      about ten small shapes.
 *   2. Inline SVG is markup, not a fetched resource, so `img-src` never
 *      applies and there is no request to block, cache or fail.
 *   3. These are server components. They cost RSC payload bytes, not
 *      client-side JavaScript.
 *
 * ── The rule these exist under ──────────────────────────────────────────
 *
 * An icon here never carries information that is not also present as text
 * beside it, and no control is icon-only. They differentiate and they draw
 * the eye; they do not communicate. That is why every one of them is
 * `aria-hidden` without exception — a screen reader loses nothing by
 * skipping all of them, which is the test of whether the rule was followed.
 *
 * `focusable="false"` is there for older Edge/IE, which otherwise put SVG
 * elements in the tab order.
 */

import type { ReactNode } from "react";

interface IconProps {
  /** Tailwind sizing/colour classes. Defaults to a 16px square. */
  className?: string;
}

/**
 * Shared chassis. Stroke-based at a consistent 1.5 weight so the set reads
 * as one family, and `currentColor` so an icon inherits whatever text colour
 * its container already sets — no icon needs its own colour prop.
 */
function Icon({
  className = "h-4 w-4",
  children,
}: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

/** Transport and header posture. */
export function ShieldCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3 4.5 6v5.5c0 4.3 3 8.3 7.5 9.5 4.5-1.2 7.5-5.2 7.5-9.5V6Z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
    </Icon>
  );
}

/** Software version identification. */
export function Chip(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="7.5" y="7.5" width="9" height="9" rx="1.5" />
      <path d="M10 4.5v3M14 4.5v3M10 16.5v3M14 16.5v3M4.5 10h3M4.5 14h3M16.5 10h3M16.5 14h3" />
    </Icon>
  );
}

/** Effort budget — and the lever the product is named after. */
export function Scale(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4v16M7 20h10" />
      <path d="M4 8h16" />
      <path d="M7.5 8 5 13h5Z" />
      <path d="M16.5 8 14 13h5Z" />
    </Icon>
  );
}

/** Proof of ownership. */
export function KeyLock(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="5" y="10.5" width="14" height="9" rx="2" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3" />
      <path d="M12 14v2.5" />
    </Icon>
  );
}

/** Something needs attention. */
export function AlertTriangle(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4.5 21 19.5H3Z" />
      <path d="M12 10v4" />
      <path d="M12 16.75h.01" />
    </Icon>
  );
}

/** A qualification or caveat. */
export function InfoCircle(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5" />
      <path d="M12 8.25h.01" />
    </Icon>
  );
}

/** A check passed, or a domain is verified. */
export function Check(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="m5 12.5 4.5 4.5L19 7.5" />
    </Icon>
  );
}

/** Refused, or failed. */
export function X(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6.5 6.5 17.5 17.5M17.5 6.5 6.5 17.5" />
    </Icon>
  );
}

/** Elapsed time, and work still running. */
export function Clock(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 1.8" />
    </Icon>
  );
}

/** Forward navigation. */
export function ArrowRight(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4.5 12h15" />
      <path d="m13.5 6 6 6-6 6" />
    </Icon>
  );
}

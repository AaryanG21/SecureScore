import { ImageResponse } from "next/og";

/**
 * The card that appears when a link to Fulcrum is pasted into Slack,
 * iMessage, Discord or anywhere else that unfurls links. Without it they
 * render a blank rectangle.
 *
 * Note what this is NOT for: the root layout sets `robots: { index: false }`
 * site-wide, so this is not an SEO asset. It earns its place purely on
 * shared links.
 *
 * Two things worth knowing about the implementation:
 *
 *   - It must not be `force-dynamic`. Every page in this app opts out of
 *     static generation because a CSP nonce cannot reach prerendered HTML.
 *     That reasoning does not apply here: this route returns a PNG, carries
 *     no scripts and needs no nonce, so it can be generated once at build.
 *
 *   - The styles below are inline, and that is fine. They are consumed by
 *     Satori on the server to rasterise a PNG; no style attribute is ever
 *     sent to a browser, so the style-src CSP never sees them. This is the
 *     one place in the codebase where inline styles are correct.
 *
 * The font is the Geist regular bundled inside next/og, so rendering needs
 * no network access — which matters, because the Docker build has none.
 */

export const alt =
  "Fulcrum — a security scorecard and remediation agent for websites";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

// Kept in step with the @theme tokens in src/app/globals.css by hand; Satori
// cannot read CSS custom properties.
const BASE = "#07090d";
const SURFACE = "#0d1117";
const LINE = "#1f2a37";
const INK = "#e6edf3";
const INK_MUTED = "#9aa7b4";
const SIGNAL = "#3d9fd6";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: BASE,
          padding: 72,
          // The console grid from the landing page, at card scale.
          backgroundImage: `linear-gradient(to right, ${LINE} 1px, transparent 1px), linear-gradient(to bottom, ${LINE} 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          {/* The same diamond as the header mark and the favicon: a square
              turned 45 degrees, outlined, never filled. */}
          <div
            style={{
              width: 34,
              height: 34,
              border: `5px solid ${SIGNAL}`,
              transform: "rotate(45deg)",
            }}
          />
          <div
            style={{
              fontSize: 34,
              letterSpacing: 10,
              color: INK,
              fontWeight: 600,
            }}
          >
            FULCRUM
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ fontSize: 68, color: INK, lineHeight: 1.15 }}>
            Know what to fix first,
          </div>
          <div style={{ fontSize: 68, color: SIGNAL, lineHeight: 1.15 }}>
            within the effort you have.
          </div>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 18,
            borderTop: `2px solid ${LINE}`,
            paddingTop: 28,
          }}
        >
          <div
            style={{
              display: "flex",
              fontSize: 26,
              color: SIGNAL,
              background: SURFACE,
              border: `2px solid ${LINE}`,
              borderRadius: 999,
              padding: "8px 22px",
            }}
          >
            Scorecard + remediation agent
          </div>
          <div style={{ fontSize: 26, color: INK_MUTED }}>
            Graded A–F, with the reasoning shown
          </div>
        </div>
      </div>
    ),
    size,
  );
}

import { ImageResponse } from "next/og";

/**
 * The browser-tab icon.
 *
 * Until now the tab showed Vercel's triangle: `src/app/favicon.ico` arrived
 * with "Initial commit from Create Next App" and was never replaced. The
 * stock .ico is deleted alongside this file — leaving both would emit two
 * competing <link rel="icon"> tags.
 *
 * Generated rather than drawn so it cannot drift from the header mark in
 * src/components/logo.tsx. See opengraph-image.tsx for why inline styles
 * are correct here and nowhere else.
 */

export const size = { width: 32, height: 32 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#07090d",
        }}
      >
        {/* Outlined, not filled, so it stays legible at 16px. */}
        <div
          style={{
            width: 15,
            height: 15,
            border: "3px solid #3d9fd6",
            transform: "rotate(45deg)",
          }}
        />
      </div>
    ),
    size,
  );
}

import { ImageResponse } from "next/og";

/**
 * The iOS home-screen icon.
 *
 * The same mark as icon.tsx at the size iOS asks for. iOS composites its own
 * rounded-corner mask and never applies transparency, so this draws its own
 * opaque background rather than relying on one.
 */

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
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
        <div
          style={{
            width: 86,
            height: 86,
            border: "16px solid #3d9fd6",
            transform: "rotate(45deg)",
          }}
        />
      </div>
    ),
    size,
  );
}

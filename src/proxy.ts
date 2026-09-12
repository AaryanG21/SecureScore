import { NextResponse, type NextRequest } from "next/server";
import { securityHeaders } from "@/lib/security/headers";

/**
 * Next.js Proxy (the file convention formerly called Middleware).
 *
 * Responsibilities, deliberately narrow:
 *   - generate a per-request CSP nonce
 *   - attach security headers to every response
 *   - cheap, stateless coarse checks
 *
 * What it deliberately does NOT do: authentication or authorization
 * decisions. Proxy can run outside the app runtime and cannot be trusted
 * with database state, and an auth check that lives only here is bypassable
 * by anything that reaches a route directly. Every protected route calls
 * the guards in lib/auth/guards.ts instead. Redirecting unauthenticated
 * browsers here is a UX nicety layered on top of that, not a control.
 */

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const isHttps = request.nextUrl.protocol === "https:";

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  // Strip any client-supplied spoof of headers we generate ourselves.
  requestHeaders.delete("x-fulcrum-user");

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  for (const [key, value] of Object.entries(
    securityHeaders({ nonce, isDev, isHttps }),
  )) {
    if (value) response.headers.set(key, value);
    else response.headers.delete(key);
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Everything except Next's static output and the favicon. API routes
     * are intentionally included so that error responses also carry the
     * security headers.
     */
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};

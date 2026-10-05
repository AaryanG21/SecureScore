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

  // HSTS is decided from APP_ORIGIN, not from the request protocol.
  //
  // The deployment topology this project recommends terminates TLS at a
  // reverse proxy and forwards plain http to the app on loopback, so
  // `request.nextUrl.protocol` is "http:" on every request in production.
  // Deriving HSTS from it therefore dropped the header in precisely the
  // configuration the README tells you to run. APP_ORIGIN is validated at
  // boot and is the authoritative statement of how users reach this
  // deployment, which is the question HSTS actually asks — and it is the
  // same source `isSecureContext()` in lib/auth/cookies.ts uses for the
  // cookie Secure flag, so the two can no longer disagree.
  //
  // Read raw rather than through getEnv() because Proxy may be bundled for
  // a runtime that cannot resolve a "server-only" module.
  const isHttps = (process.env.APP_ORIGIN ?? "").startsWith("https://");

  const requestHeaders = new Headers(request.headers);

  // Strip any client-supplied spoof of headers we generate ourselves.
  requestHeaders.delete("x-fulcrum-user");

  // Correlation id, generated here and never accepted from the client.
  //
  // Taking an inbound x-request-id would let a caller choose the key that
  // its own log lines and audit rows are filed under — which means
  // colliding with someone else's requests, or splitting its own into
  // unrelated ids to make a pattern hard to see. It is set on both the
  // request (so handlers and audit rows can use it) and the response (so
  // it can be quoted in a support conversation), and the reverse proxy in
  // front of this app should log it alongside method, path and status.
  requestHeaders.delete("x-request-id");
  const requestId = crypto.randomUUID();
  requestHeaders.set("x-request-id", requestId);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("x-request-id", requestId);

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

import { NextResponse } from "next/server";
import { issueCsrfToken } from "@/lib/security/csrf";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Issues a CSRF token cookie and returns the value so the client can echo
 * it in the X-CSRF-Token header on state-changing requests.
 *
 * Safe to call unauthenticated: the token confers no authority by itself.
 */
export async function GET(): Promise<NextResponse> {
  const token = await issueCsrfToken();
  const response = NextResponse.json({ csrfToken: token });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

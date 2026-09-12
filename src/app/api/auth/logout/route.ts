import { type NextRequest } from "next/server";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { verifyCsrf } from "@/lib/security/csrf";
import { endSession } from "@/lib/auth/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Ends the session: revokes the whole refresh-token family server-side and
 * clears every auth cookie. Deleting cookies alone would leave a valid
 * refresh token in the database for anyone who captured it.
 */
export async function POST(request: NextRequest) {
  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  await endSession(getRequestMeta(request));

  return apiOk({ status: "signed_out" });
}

import { type NextRequest } from "next/server";
import { apiOk, getRequestMeta } from "@/lib/http";
import { enforceCsrf } from "@/lib/auth/guards";
import { endSession } from "@/lib/auth/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Ends the session: revokes the whole refresh-token family server-side and
 * clears every auth cookie. Deleting cookies alone would leave a valid
 * refresh token in the database for anyone who captured it.
 */
export async function POST(request: NextRequest) {
  const blocked = await enforceCsrf(request);
  if (blocked) return blocked;

  await endSession(getRequestMeta(request));

  return apiOk({ status: "signed_out" });
}

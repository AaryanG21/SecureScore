import { apiOk } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Liveness. Answers one question: is this process running and serving?
 *
 * Deliberately touches nothing — no database, no environment read, no
 * session. A liveness probe that depends on a downstream service turns a
 * database blip into a restart loop, which is strictly worse than a
 * process that is up and honestly reporting that it cannot serve requests
 * yet. That second question is /api/ready.
 *
 * Unauthenticated, and says nothing a stranger could use: no version, no
 * hostname, no build id, no uptime.
 */
export async function GET() {
  const response = apiOk({ status: "ok" });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

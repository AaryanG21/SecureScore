import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { countUnusedBackupCodes } from "@/lib/auth/totp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Current-session introspection for the client shell.
 *
 * Returns only what the UI needs to render. The role here drives which
 * links are shown; it is never what authorizes an action — every protected
 * route re-checks the role server-side against the database.
 */
export async function GET(request: NextRequest) {
  // Through the guard rather than getSession() directly, so this route is
  // covered by the blanket per-route ceiling like every other read. It is
  // polled by the client shell, which makes it the cheapest endpoint to
  // hammer.
  const guard = await requireUser(request, { skipCsrf: true, rateLimit: "api" });
  if (!guard.ok) return guard.response;
  const session = guard.value;

  const [user, remainingBackupCodes] = await Promise.all([
    prisma.user.findUnique({
      where: { id: session.id },
      select: {
        email: true,
        role: true,
        status: true,
        twoFactorEnabled: true,
        lastLoginAt: true,
        createdAt: true,
      },
    }),
    countUnusedBackupCodes(session.id),
  ]);

  if (!user) return apiError(401, "unauthenticated", "Sign in to continue.");

  const response = apiOk({ user: { id: session.id, ...user }, remainingBackupCodes });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

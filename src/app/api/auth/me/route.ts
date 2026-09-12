import { prisma } from "@/lib/db";
import { apiError, apiOk } from "@/lib/http";
import { getSession } from "@/lib/auth/session";
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
export async function GET() {
  const session = await getSession();
  if (!session) {
    return apiError(401, "unauthenticated", "Sign in to continue.");
  }

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

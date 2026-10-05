import { type NextRequest } from "next/server";
import QRCode from "qrcode";
import { prisma } from "@/lib/db";
import { apiError, apiOk, apiRateLimited, getRequestMeta } from "@/lib/http";
import { checkRateLimit, ipAccountKey } from "@/lib/security/rate-limit";
import { verifyCsrf } from "@/lib/security/csrf";
import { MFA_COOKIE, readCookie } from "@/lib/auth/cookies";
import { verifyMfaPendingToken } from "@/lib/auth/tokens";
import {
  buildOtpAuthUri,
  encryptTotpSecret,
  generateTotpSecret,
} from "@/lib/auth/totp";
import { getSession } from "@/lib/auth/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Begins TOTP enrollment: generates a secret, stores it encrypted, and
 * returns the otpauth URI plus a QR code for the authenticator app.
 *
 * Reachable in two states — a half-authenticated user who has passed the
 * password step but has no 2FA yet, and a fully-authenticated user
 * re-enrolling. The secret is written but `twoFactorEnabled` stays false
 * until /2fa/activate proves the user can actually produce a code; that
 * ordering prevents locking someone out of their own account with a
 * secret they never successfully stored.
 */
export async function POST(request: NextRequest) {
  const csrf = await verifyCsrf(request);
  if (!csrf.ok) {
    return apiError(403, "csrf_failed", "Request could not be verified.");
  }

  const session = await getSession();

  let userId: string | null = session?.id ?? null;
  if (!userId) {
    const pending = await readCookie(MFA_COOKIE);
    const claims = pending ? await verifyMfaPendingToken(pending) : null;
    userId = claims?.sub ?? null;
  }

  if (!userId) {
    return apiError(401, "unauthenticated", "Start again from the sign-in page.");
  }

  // Throttled once the account is known.
  //
  // Each call mints a fresh secret and overwrites the stored one, so an
  // unbounded endpoint lets anyone holding a half-authenticated cookie
  // churn a user's enrollment indefinitely — and every churn invalidates
  // the authenticator entry the user may have just scanned. Keyed on the
  // account rather than the request so it cannot be sidestepped by
  // reconnecting.
  const meta = getRequestMeta(request);
  const limit = checkRateLimit("twoFactor", ipAccountKey(meta.ipAddress, userId));
  if (!limit.allowed) return apiRateLimited(limit.retryAfterSeconds);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, status: true, twoFactorEnabled: true },
  });

  if (!user || user.status === "SUSPENDED") {
    return apiError(401, "unauthenticated", "Start again from the sign-in page.");
  }

  // Re-enrollment by an already-enrolled user must be re-authenticated,
  // otherwise a hijacked session could silently swap the second factor.
  if (user.twoFactorEnabled && !session) {
    return apiError(
      403,
      "reauth_required",
      "Sign in fully before changing your authenticator.",
    );
  }

  const secret = generateTotpSecret();
  const otpauthUri = buildOtpAuthUri(user.email, secret);

  await prisma.user.update({
    where: { id: user.id },
    data: { twoFactorSecret: encryptTotpSecret(secret) },
  });

  // Rendered server-side as a data URI so the secret never needs to reach
  // a third-party QR service.
  const qrDataUri = await QRCode.toDataURL(otpauthUri, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 240,
  });

  const response = apiOk({
    // The manual-entry key, for users who cannot scan.
    secret,
    otpauthUri,
    qrDataUri,
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

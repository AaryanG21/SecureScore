import "server-only";
import { cookies } from "next/headers";
import { getEnv } from "@/lib/env";

/**
 * Cookie policy.
 *
 * Every auth cookie is httpOnly, Secure (outside local dev over http), and
 * SameSite=Strict. No token is ever handed to client JavaScript or written
 * to localStorage — an XSS bug should not hand an attacker a portable
 * session. The one non-httpOnly cookie is the CSRF token, which is
 * deliberately readable so the client can echo it in a header.
 */

export const ACCESS_COOKIE = "fulcrum_at";
export const REFRESH_COOKIE = "fulcrum_rt";
export const MFA_COOKIE = "fulcrum_mfa";
export const REAUTH_COOKIE = "fulcrum_reauth";
export const CSRF_COOKIE = "fulcrum_csrf";

function isSecureContext(): boolean {
  return getEnv().APP_ORIGIN.startsWith("https://");
}

interface SetOptions {
  name: string;
  value: string;
  maxAgeSeconds: number;
  httpOnly?: boolean;
  path?: string;
}

export async function setAuthCookie(opts: SetOptions): Promise<void> {
  const store = await cookies();
  store.set({
    name: opts.name,
    value: opts.value,
    httpOnly: opts.httpOnly ?? true,
    secure: isSecureContext(),
    sameSite: "strict",
    path: opts.path ?? "/",
    maxAge: opts.maxAgeSeconds,
  });
}

export async function clearAuthCookie(name: string, path = "/"): Promise<void> {
  const store = await cookies();
  store.set({
    name,
    value: "",
    httpOnly: true,
    secure: isSecureContext(),
    sameSite: "strict",
    path,
    maxAge: 0,
  });
}

export async function readCookie(name: string): Promise<string | null> {
  const store = await cookies();
  return store.get(name)?.value ?? null;
}

/** Drops every auth cookie. Used by logout and by forced-revocation paths. */
export async function clearAllAuthCookies(): Promise<void> {
  await Promise.all([
    clearAuthCookie(ACCESS_COOKIE),
    clearAuthCookie(REFRESH_COOKIE, "/api/auth"),
    clearAuthCookie(MFA_COOKIE),
    clearAuthCookie(REAUTH_COOKIE),
  ]);
}

import "server-only";
import { isIP } from "node:net";
import { NextResponse } from "next/server";
import { getEnv } from "@/lib/env";

/**
 * Request/response helpers shared by every API route.
 */

export interface RequestMeta {
  ipAddress: string | null;
  userAgent: string | null;
  /** Minted in src/proxy.ts; null when a request bypassed it. */
  requestId: string | null;
}

/**
 * Client IP, or null when it cannot be established.
 *
 * Two things here are easy to get wrong and were:
 *
 * 1. `NextRequest.ip` was removed in Next 15. The previous fallback to it
 *    meant this function returned null on every request whenever
 *    TRUST_PROXY_HEADERS was false — which is the default. Every rate-limit
 *    key collapsed to "unknown-ip", and every audit row recorded no
 *    address. There is no socket address available to a route handler in
 *    this runtime, so behind no proxy the honest answer is null, and the
 *    per-account limits carry the load.
 *
 * 2. X-Forwarded-For must be read from the RIGHT. Each hop appends, so the
 *    left-hand entries are whatever the client sent and the right-hand ones
 *    are what your own proxies wrote. Reading the left-most entry — which
 *    this function used to do — lets a client set its own rate-limit
 *    bucket, and an attacker who can pick their bucket is not rate limited.
 *
 * Fails closed throughout: an unparseable chain, or one shorter than the
 * configured hop count, yields null rather than a guess.
 */
export function getClientIp(request: Request): string | null {
  const env = getEnv();

  if (!env.TRUST_PROXY_HEADERS) return null;

  const forwarded = request.headers.get("x-forwarded-for");
  if (!forwarded) return null;

  const chain = forwarded
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  // Skip the entries our own proxies appended. With one trusted proxy the
  // last entry is the address it observed, i.e. the client.
  const index = chain.length - env.TRUSTED_PROXY_HOPS;
  if (index < 0 || index >= chain.length) return null;

  const candidate = normalizeIp(chain[index]);
  return candidate;
}

/**
 * Accepts only a literal IP address.
 *
 * A hostname or arbitrary string in this position is either a broken proxy
 * or an injection attempt, and either way it must not become a rate-limit
 * key or an audit-log entry.
 */
function normalizeIp(value: string | undefined): string | null {
  if (!value) return null;

  // Some proxies emit "[2001:db8::1]:443" or "198.51.100.7:1234".
  let host = value;
  const bracketed = /^\[(.+)\](?::\d+)?$/.exec(host);
  if (bracketed?.[1]) {
    host = bracketed[1];
  } else if (host.split(":").length === 2) {
    host = host.split(":")[0] ?? host;
  }

  return isIP(host) === 0 ? null : host;
}

export function getRequestMeta(request: Request): RequestMeta {
  return {
    ipAddress: getClientIp(request),
    userAgent: request.headers.get("user-agent"),
    requestId: request.headers.get("x-request-id"),
  };
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown };
}

/**
 * Error response helper.
 *
 * Messages here are written for the client and are intentionally vague on
 * auth failures ("invalid credentials" rather than "no such user") — the
 * detailed reason goes to the audit log instead.
 */
export function apiError(
  status: number,
  code: string,
  message: string,
  details?: unknown,
): NextResponse<ApiErrorBody> {
  return NextResponse.json<ApiErrorBody>(
    { error: { code, message, ...(details ? { details } : {}) } },
    { status },
  );
}

export function apiOk<T extends object>(body: T, status = 200): NextResponse<T> {
  return NextResponse.json(body, { status });
}

/** 429 with a Retry-After header so well-behaved clients back off. */
export function apiRateLimited(retryAfterSeconds: number): NextResponse<ApiErrorBody> {
  const response = apiError(
    429,
    "rate_limited",
    "Too many attempts. Try again later.",
  );
  response.headers.set("Retry-After", String(Math.ceil(retryAfterSeconds)));
  return response;
}

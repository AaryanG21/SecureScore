import "server-only";
import { NextResponse } from "next/server";
import { getEnv } from "@/lib/env";

/**
 * Request/response helpers shared by every API route.
 */

export interface RequestMeta {
  ipAddress: string | null;
  userAgent: string | null;
}

/**
 * Best-effort client IP.
 *
 * X-Forwarded-For is trusted ONLY when TRUST_PROXY_HEADERS is set, because
 * the header is attacker-controlled otherwise and per-IP rate limiting keyed
 * on a spoofable value provides no limiting at all. When untrusted we fall
 * back to the platform-provided address, accepting that behind an untrusted
 * proxy every request may look like one IP (fail closed, not open).
 */
export function getClientIp(request: Request): string | null {
  const env = getEnv();

  if (env.TRUST_PROXY_HEADERS) {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) {
      const first = forwarded.split(",")[0]?.trim();
      if (first) return first;
    }
    const real = request.headers.get("x-real-ip");
    if (real) return real.trim();
  }

  // Next populates this on the platform adapter where available.
  const direct = (request as Request & { ip?: string }).ip;
  return direct ?? null;
}

export function getRequestMeta(request: Request): RequestMeta {
  return {
    ipAddress: getClientIp(request),
    userAgent: request.headers.get("user-agent"),
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

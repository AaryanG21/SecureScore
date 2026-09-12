"use client";

/**
 * Browser-side API client.
 *
 * Two things it guarantees for every state-changing call:
 *   - credentials are sent as cookies (never a token read from JS storage;
 *     the session cookies are httpOnly and unreadable here by design)
 *   - the CSRF token is fetched once and echoed in the X-CSRF-Token header
 *
 * Nothing in this file is a security control by itself. The server re-checks
 * CSRF, the session, and the role on every request — this just makes the
 * legitimate client's requests well-formed.
 */

export interface ApiFailure {
  code: string;
  message: string;
  details?: Record<string, string[]>;
  status: number;
}

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: ApiFailure };

let csrfToken: string | null = null;

async function getCsrfToken(force = false): Promise<string> {
  if (csrfToken && !force) return csrfToken;

  const response = await fetch("/api/auth/csrf", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });
  const body = (await response.json()) as { csrfToken: string };
  csrfToken = body.csrfToken;
  return csrfToken;
}

export async function apiFetch<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<ApiResult<T>> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };

  if (method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = await getCsrfToken();
  }

  let response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });

  // A stale CSRF token (cookie rotated, tab left open overnight) is a
  // recoverable condition, so retry once with a fresh one before surfacing
  // an error the user cannot act on.
  if (response.status === 403 && method !== "GET") {
    const cloned = response.clone();
    const maybe = (await cloned.json().catch(() => null)) as
      | { error?: { code?: string } }
      | null;

    if (maybe?.error?.code === "csrf_failed") {
      headers["X-CSRF-Token"] = await getCsrfToken(true);
      response = await fetch(path, {
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
    }
  }

  const payload = (await response.json().catch(() => null)) as
    | (T & { error?: { code: string; message: string; details?: Record<string, string[]> } })
    | null;

  if (!response.ok) {
    return {
      ok: false,
      error: {
        code: payload?.error?.code ?? "request_failed",
        message: payload?.error?.message ?? "Something went wrong.",
        details: payload?.error?.details,
        status: response.status,
      },
    };
  }

  return { ok: true, data: payload as T };
}

import "server-only";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isPublicAddress } from "@/lib/net/ip-classification";
import type { LookupFunction } from "node:net";

/**
 * Outbound requests to hostnames a user supplied.
 *
 * The threat this module exists for is SSRF, and specifically the variant
 * that hostname validation does not catch. `normalizeHostname` already
 * rejects IP literals, ports, userinfo and reserved suffixes like
 * `.internal`, and the callers already decline redirects — which closes
 * the obvious pivots. What none of that addresses is where a perfectly
 * ordinary public name RESOLVES to. `evil.example` with an A record
 * pointing at 169.254.169.254 passes every syntactic check, and the fetch
 * then reaches cloud instance metadata from inside the deployment.
 *
 * Two things are therefore required, and the second is the one usually
 * skipped:
 *
 *   1. Resolve the name and refuse non-public answers.
 *   2. Connect to the address that was actually vetted.
 *
 * Doing only (1) leaves a DNS-rebinding window: the attacker answers the
 * check with a public address and the connection with a private one, which
 * is a documented technique and not a theoretical one. So the vetted
 * address is pinned into the connection through a `lookup` function that
 * returns it without consulting DNS again. The hostname is still what gets
 * sent as SNI and `Host`, so certificate validation is unaffected — the
 * request is indistinguishable from an ordinary one apart from being
 * unable to land anywhere it was not allowed to.
 *
 * `fetch` cannot express that pinning without an undici dispatcher, which
 * would mean taking on a dependency Node already contains but does not
 * export. node:https accepts `lookup` directly, so that is what this uses.
 */

/** Why an address was refused. Surfaced to the caller, never to the target. */
export type AddressRefusal =
  | "unresolvable"
  | "private_address"
  | "no_public_address";

export type ResolveResult =
  | { ok: true; address: string; family: 4 | 6 }
  | { ok: false; refusal: AddressRefusal; reason: string };

/**
 * Resolves a hostname and returns one vetted public address.
 *
 * Every answer must be public, not merely the one we pick: a name that
 * returns both a public and a private record is either misconfigured or
 * probing for exactly this weakness, and there is no legitimate reason to
 * proceed with it.
 */
export async function resolveToPublicAddress(hostname: string): Promise<ResolveResult> {
  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await dnsLookup(hostname, { all: true, verbatim: true });
  } catch {
    return {
      ok: false,
      refusal: "unresolvable",
      reason: `${hostname} could not be resolved.`,
    };
  }

  if (answers.length === 0) {
    return {
      ok: false,
      refusal: "unresolvable",
      reason: `${hostname} resolved to no addresses.`,
    };
  }

  const offending = answers.find((answer) => !isPublicAddress(answer.address));
  if (offending) {
    // The offending address is named because the operator needs to see it,
    // and it is the user's own domain that pointed there.
    return {
      ok: false,
      refusal: "private_address",
      reason: `${hostname} resolves to ${offending.address}, which is a private, loopback, link-local or otherwise non-public address. Refusing to connect.`,
    };
  }

  const chosen = answers[0];
  if (!chosen) {
    return {
      ok: false,
      refusal: "no_public_address",
      reason: `${hostname} resolved to no usable address.`,
    };
  }

  return {
    ok: true,
    address: chosen.address,
    family: chosen.family === 6 ? 6 : 4,
  };
}

export interface SafeGetOptions {
  hostname: string;
  path: string;
  headers?: Record<string, string>;
  timeoutMs: number;
  /** Hard cap on the body. Omit to discard the body entirely. */
  maxBytes?: number;
}

export type SafeGetResult =
  | {
      ok: true;
      status: number;
      headers: Headers;
      /** Present only when maxBytes was set and the cap was not exceeded. */
      body?: string;
      /** True when the cap was hit; body is then undefined. */
      bodyTooLarge?: boolean;
    }
  | {
      ok: false;
      kind: "refused" | "timeout" | "network";
      refusal?: AddressRefusal;
      reason: string;
    };

/**
 * HTTPS GET to a user-supplied hostname, pinned to a vetted address.
 *
 * https only — the scheme is not a parameter, so no caller can downgrade
 * it. Redirects are never followed: a 3xx is returned as-is for the caller
 * to treat as it sees fit, which keeps the "do not follow redirects into
 * link-local space" rule in one place rather than in every call site.
 */
export async function safeHttpsGet(options: SafeGetOptions): Promise<SafeGetResult> {
  const resolved = await resolveToPublicAddress(options.hostname);
  if (!resolved.ok) {
    return {
      ok: false,
      kind: "refused",
      refusal: resolved.refusal,
      reason: resolved.reason,
    };
  }

  // Hand back the address we already vetted instead of resolving again.
  // This is what closes the rebinding window.
  const pinned: LookupFunction = (_hostname, _opts, callback) => {
    // The overload that takes { all: true } expects an array.
    const asAll = (_opts as { all?: boolean } | undefined)?.all === true;
    const entry = { address: resolved.address, family: resolved.family };
    if (asAll) {
      (callback as unknown as (
        err: NodeJS.ErrnoException | null,
        addresses: Array<{ address: string; family: number }>,
      ) => void)(null, [entry]);
    } else {
      callback(null, resolved.address, resolved.family);
    }
  };

  return new Promise<SafeGetResult>((resolve) => {
    let settled = false;
    const finish = (result: SafeGetResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = httpsRequest(
      {
        // The hostname, not the address: this is what drives SNI, the Host
        // header and certificate validation.
        host: options.hostname,
        servername: options.hostname,
        path: options.path,
        method: "GET",
        headers: options.headers ?? {},
        lookup: pinned,
        timeout: options.timeoutMs,
      },
      (res) => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(res.headers)) {
          if (Array.isArray(value)) for (const v of value) headers.append(key, v);
          else if (typeof value === "string") headers.set(key, value);
        }

        const status = res.statusCode ?? 0;

        if (options.maxBytes === undefined) {
          // Headers are all the caller wants; do not read megabytes of body.
          res.destroy();
          finish({ ok: true, status, headers });
          return;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        let tooLarge = false;

        res.on("data", (chunk: Buffer) => {
          total += chunk.byteLength;
          if (total > (options.maxBytes as number)) {
            tooLarge = true;
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("close", () => {
          if (tooLarge) {
            finish({ ok: true, status, headers, bodyTooLarge: true });
            return;
          }
          finish({
            ok: true,
            status,
            headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
        res.on("error", () =>
          finish({
            ok: false,
            kind: "network",
            reason: "The connection failed while reading the response.",
          }),
        );
      },
    );

    req.on("timeout", () => {
      req.destroy();
      finish({ ok: false, kind: "timeout", reason: "The request timed out." });
    });

    req.on("error", () =>
      finish({
        ok: false,
        kind: "network",
        reason: "Could not establish an HTTPS connection.",
      }),
    );

    req.end();
  });
}

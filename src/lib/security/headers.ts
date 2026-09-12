/**
 * Security response headers.
 *
 * Runs in the Next.js Proxy (formerly Middleware), which is deliberately
 * kept free of database or shared-module state — it may execute outside the
 * main app runtime.
 */

export interface HeaderOptions {
  nonce: string;
  isDev: boolean;
  /** HSTS is only meaningful, and only safe, when the origin is https. */
  isHttps: boolean;
}

/**
 * Builds a strict, nonce-based CSP.
 *
 * `'strict-dynamic'` means the nonce transitively covers scripts that
 * Next's own bootstrap loads, so no host allowlist is needed — host
 * allowlists are the main reason CSPs end up bypassable in practice.
 *
 * `'unsafe-eval'` appears in development only: React's dev build uses eval
 * to reconstruct server stack traces. It is absent from production builds.
 */
export function buildCsp({ nonce, isDev, isHttps }: HeaderOptions): string {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "connect-src 'self'",
    // No plugins, no embedded objects.
    "object-src 'none'",
    // Blocks <base href> hijacking of every relative URL on the page.
    "base-uri 'self'",
    // Form posts can only target this origin.
    "form-action 'self'",
    // Clickjacking defence; the modern equivalent of X-Frame-Options.
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
  ];

  if (isHttps) directives.push("upgrade-insecure-requests");

  return directives.join("; ");
}

export function securityHeaders(options: HeaderOptions): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Security-Policy": buildCsp(options),

    // Kept alongside CSP frame-ancestors for older browsers.
    "X-Frame-Options": "DENY",

    // Stops MIME sniffing turning an uploaded file into an executable script.
    "X-Content-Type-Options": "nosniff",

    // Send the full URL same-origin, only the origin cross-origin: scan
    // URLs and domain names should not leak to third parties.
    "Referrer-Policy": "strict-origin-when-cross-origin",

    // This app needs none of these. Denying them shrinks the surface a
    // successful XSS could reach for.
    "Permissions-Policy":
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()",

    // Cross-origin isolation: keeps this document out of other origins'
    // process and blocks cross-origin reads of its resources.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",

    // Hide the framework fingerprint. Minor, but free.
    "X-Powered-By": "",
  };

  if (options.isHttps) {
    // 2 years, subdomains included, preload-eligible.
    // Read the warning in the README before submitting to the preload
    // list — it is effectively irreversible for the apex domain.
    headers["Strict-Transport-Security"] =
      "max-age=63072000; includeSubDomains; preload";
  }

  return headers;
}

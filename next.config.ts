import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emits a self-contained server bundle for the Docker runtime image.
  output: "standalone",

  // Security headers are set per-request in src/proxy.ts, where the CSP
  // nonce is generated. Nothing is configured here so there is exactly one
  // place that decides them.

  // Do not advertise the framework version in responses.
  poweredByHeader: false,

  // Trailing-slash ambiguity has produced cache-poisoning and
  // authorization-bypass bugs in other stacks; pick one form and keep it.
  trailingSlash: false,

  // Lint runs as its own step (`npm run lint`) rather than inside the
  // build; Next 16 no longer accepts an `eslint` key here.

  typescript: {
    // A type error must fail the build. Never set this to true.
    ignoreBuildErrors: false,
  },
};

export default nextConfig;

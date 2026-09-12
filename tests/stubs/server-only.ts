/**
 * No-op stand-in for the `server-only` package.
 *
 * The real module throws when imported outside a React Server Component,
 * which is exactly what makes it a useful guard in application code — and
 * exactly what stops a Node-based unit test from importing any module that
 * uses it. Aliased in vitest.config.mts.
 *
 * This weakens nothing in the app: the guard still applies everywhere the
 * real bundler resolves it.
 */
export {};

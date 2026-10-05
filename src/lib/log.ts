/**
 * Structured logging.
 *
 * One line of JSON per event, on stdout/stderr, for whatever collects the
 * container's output. No dependency: a logger that only has to serialize a
 * flat object and pick a stream does not need one, and every package added
 * to a security tool is a package that has to be trusted and patched.
 *
 * Scope, stated honestly. This logs events the application decides are
 * worth recording. It is NOT per-request access logging, and this file
 * does not pretend to provide it: Next's Proxy runs before the response
 * exists, so it cannot see a status code or a duration, and the only way
 * to get those centrally would be to wrap every route handler. The
 * reverse proxy in front of the deployment — which the README already
 * requires — logs method, path, status and latency correctly, at the layer
 * that actually observes them. The request id minted in proxy.ts is what
 * ties the two together.
 *
 * Two kinds of record, kept separate on purpose:
 *
 *   AuditLog (lib/audit.ts)  security events, in Postgres, append-only,
 *                            redacted, queryable, and the forensic record
 *   this file                operational events — what failed, how long
 *                            something took, what a process did at boot
 *
 * Conflating them would be a mistake in both directions: audit rows must
 * survive log rotation, and operational noise must not be written to a
 * table nobody can delete from.
 *
 * Never pass a secret, a token, a password or a raw Error here. Log
 * `error.message`, never the Error object — a stack can carry argument
 * values, and this output goes somewhere with weaker access control than
 * the database.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogContext {
  /** Correlates with the reverse proxy's access log. See src/proxy.ts. */
  requestId?: string | null;
  route?: string;
  durationMs?: number;
  [key: string]: unknown;
}

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

/**
 * Minimum level, from LOG_LEVEL.
 *
 * Read directly rather than through getEnv() so that logging works during
 * startup and inside getEnv()'s own failure path — a logger that needs the
 * configuration to be valid cannot report that the configuration is
 * invalid. An unrecognized value falls back to "info" rather than
 * silencing output.
 */
function minimumLevel(): number {
  const configured = process.env.LOG_LEVEL?.toLowerCase();
  if (configured && configured in LEVEL_ORDER) {
    return LEVEL_ORDER[configured as LogLevel];
  }
  return LEVEL_ORDER.info;
}

function emit(level: LogLevel, message: string, context: LogContext = {}): void {
  if (LEVEL_ORDER[level] < minimumLevel()) return;

  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg: message,
  };

  for (const [key, value] of Object.entries(context)) {
    if (value !== undefined) record[key] = value;
  }

  let line: string;
  try {
    line = JSON.stringify(record);
  } catch {
    // A circular or unserializable value must not take down the caller,
    // and losing the log line silently would be worse than a degraded one.
    line = JSON.stringify({
      ts: record.ts,
      level,
      msg: message,
      logError: "context could not be serialized",
    });
  }

  // console rather than process.stdout/stderr, deliberately.
  //
  // This module is reachable from instrumentation.ts, which Next builds
  // for every runtime it targets including Edge, where process.stdout and
  // process.stderr do not exist — referencing them made the build emit
  // "a Node.js API is used which is not supported in the Edge Runtime".
  // console.error and console.log are available everywhere, and with a
  // single string argument they write exactly the same bytes plus the
  // newline we would have added ourselves.
  if (level === "error" || level === "warn") console.error(line);
  else console.log(line);
}

export const log = {
  debug: (message: string, context?: LogContext) => emit("debug", message, context),
  info: (message: string, context?: LogContext) => emit("info", message, context),
  warn: (message: string, context?: LogContext) => emit("warn", message, context),
  error: (message: string, context?: LogContext) => emit("error", message, context),
};

/** Normalizes a caught value to something safe to log. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown";
}

import "server-only";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { getEnv } from "@/lib/env";
import { normalizeHostname } from "@/lib/validation/hostname";
import { parseJsonBounded, sanitizeScannedText } from "@/lib/agent/sanitize";
import { finalizeFinding, mapExternalSeverity } from "@/lib/agent/scoring";
import type { Finding } from "@/lib/agent/types";

/**
 * Integration with the pinned external tool, testssl.sh v3.2.4.
 *
 * Threat model for this module, in order of how much it matters:
 *
 *   1. The hostname is attacker-influenced (a user registers it). It is
 *      passed through `execFile` as a discrete argv element — there is no
 *      shell, so there is nothing to inject into — and it is re-validated
 *      here even though the API layer already validated it. A value that
 *      could be read as a flag is rejected outright.
 *
 *   2. The target controls what the tool reports. Output is therefore
 *      untrusted: parsed under a schema, severity re-derived from our own
 *      vocabulary, and all free text quarantined in `evidence`.
 *
 *   3. The target controls how slowly it responds. The subprocess runs
 *      under a wall-clock timeout, an output cap, and a global concurrency
 *      limit, so a stalling host cannot pin the worker open. This is the
 *      application-layer half of DDoS resistance.
 */

const TESTSSL_VERSION = "3.2.4";

/** Simultaneous testssl.sh processes across the whole worker. */
const MAX_CONCURRENT_SCANS = 2;

/** Captured stdout/stderr cap. The real output goes to the JSON file. */
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/** Cap on the JSON file we are willing to read back. */
const MAX_JSON_BYTES = 16 * 1024 * 1024;

/* -------------------------------------------------------------------- */
/* Concurrency gate                                                      */
/* -------------------------------------------------------------------- */

let running = 0;
const waiting: Array<() => void> = [];

async function acquireSlot(): Promise<() => void> {
  if (running >= MAX_CONCURRENT_SCANS) {
    await new Promise<void>((resolve) => waiting.push(resolve));
  }
  running += 1;

  let released = false;
  return () => {
    if (released) return;
    released = true;
    running -= 1;
    waiting.shift()?.();
  };
}

/* -------------------------------------------------------------------- */
/* Output schema                                                         */
/* -------------------------------------------------------------------- */

/**
 * The flat `--jsonfile` format: a top-level array of finding records.
 *
 * `.passthrough()` is deliberately NOT used. Unknown keys are dropped, so
 * an invented field like `override_score` or `grade_override` cannot reach
 * any consumer even by accident.
 */
const testsslRecordSchema = z
  .object({
    id: z.string(),
    ip: z.string().optional(),
    port: z.string().optional(),
    severity: z.string(),
    cve: z.string().optional(),
    cwe: z.string().optional(),
    hint: z.string().optional(),
    finding: z.string(),
  })
  .strip();

const testsslOutputSchema = z.array(testsslRecordSchema);

export type TestsslRecord = z.infer<typeof testsslRecordSchema>;

/* -------------------------------------------------------------------- */
/* Host capability probe                                                 */
/* -------------------------------------------------------------------- */

/**
 * testssl.sh's --openssl-timeout / --connect-timeout flags are implemented
 * by shelling out to GNU coreutils `timeout`, and it aborts the whole scan
 * with a FATAL if that binary is absent. macOS ships without it (the
 * Dockerfile installs coreutils, so deployment is fine, but a developer
 * machine usually is not).
 *
 * Rather than fail the scan on a host tooling gap, probe once and drop the
 * flags when they cannot work. Our own subprocess timeout still bounds the
 * run — these flags only make individual connections fail faster.
 */
let timeoutBinaryAvailable: Promise<boolean> | null = null;

function hasTimeoutBinary(): Promise<boolean> {
  timeoutBinaryAvailable ??= new Promise<boolean>((resolve) => {
    execFile("sh", ["-c", "command -v timeout || command -v gtimeout"], (error) => {
      resolve(!error);
    });
  });
  return timeoutBinaryAvailable;
}

/* -------------------------------------------------------------------- */
/* Invocation                                                            */
/* -------------------------------------------------------------------- */

export type TestsslResult =
  | { ok: true; records: TestsslRecord[]; version: string }
  | { ok: false; reason: string; kind: "timeout" | "invalid_target" | "tool_error" | "bad_output" };

export async function runTestssl(hostname: string): Promise<TestsslResult> {
  const env = getEnv();

  // Re-validate rather than trust the caller. Defence in depth: this
  // module must be safe to call from anywhere, not only from the one route
  // that already checked.
  const normalized = normalizeHostname(hostname);
  if (!normalized.ok) {
    return { ok: false, kind: "invalid_target", reason: normalized.reason };
  }

  // A hostname can never legitimately begin with "-", and one that did
  // would be read by the tool as an option rather than a target. The
  // canonicalizer already rejects these; this is the belt to its braces.
  if (normalized.hostname.startsWith("-")) {
    return {
      ok: false,
      kind: "invalid_target",
      reason: "Hostname cannot begin with a hyphen",
    };
  }

  const release = await acquireSlot();
  let workDir: string | null = null;

  try {
    workDir = await mkdtemp(join(tmpdir(), "fulcrum-scan-"));
    const jsonPath = join(workDir, "testssl.json");

    const canUseTimeouts = await hasTimeoutBinary();

    const args = [
      // Flat JSON output, written to a path we control, one per scan so
      // concurrent scans cannot read each other's results.
      "--jsonfile",
      jsonPath,
      // No banner, no ANSI escapes: the output is machine-read, and escape
      // sequences in it would be an injection vector of their own.
      "--quiet",
      "--color",
      "0",
      // Stop on a testing error rather than continuing with partial state.
      "--warnings",
      "batch",
      // Report everything from LOW upward; INFO is noise for scoring.
      "--severity",
      "LOW",
      // A targeted check set rather than the default full run. Covers
      // everything the scorecard actually uses — protocols (-p), cipher
      // categories (-s), server defaults and certificate (-S), and the
      // vulnerability suite (-U) — in roughly two minutes instead of the
      // seven-plus a default invocation spends enumerating every cipher.
      "-p",
      "-s",
      "-S",
      "-U",
      // Per-connection bounds, so a stalling target fails fast rather than
      // running out the overall timeout. Only when the host has the
      // coreutils `timeout` binary these flags depend on.
      ...(canUseTimeouts
        ? ["--openssl-timeout", "30", "--connect-timeout", "30"]
        : []),
      // The target. Last, and a discrete argv element — never concatenated.
      normalized.hostname,
    ];

    const execution = await execFileAsync(env.TESTSSL_PATH, args, {
      timeoutMs: env.TESTSSL_TIMEOUT_MS,
      maxBuffer: MAX_OUTPUT_BYTES,
    });

    if (execution.timedOut) {
      return {
        ok: false,
        kind: "timeout",
        reason: `testssl.sh exceeded ${env.TESTSSL_TIMEOUT_MS}ms and was terminated`,
      };
    }

    let raw: string;
    try {
      raw = await readFile(jsonPath, "utf8");
    } catch {
      // No output file means the tool failed before writing anything. A
      // missing file is a failed scan, never an empty clean result.
      return {
        ok: false,
        kind: "tool_error",
        reason: execution.stderrExcerpt
          ? `testssl.sh produced no output file: ${execution.stderrExcerpt}`
          : "testssl.sh produced no output file",
      };
    }

    const parsed = parseJsonBounded(raw, { maxBytes: MAX_JSON_BYTES, maxDepth: 32 });
    if (!parsed.ok) {
      return { ok: false, kind: "bad_output", reason: parsed.reason };
    }

    const validated = testsslOutputSchema.safeParse(parsed.value);
    if (!validated.success) {
      return {
        ok: false,
        kind: "bad_output",
        reason: "testssl.sh output did not match the expected schema",
      };
    }

    return { ok: true, records: validated.data, version: TESTSSL_VERSION };
  } catch (error) {
    return {
      ok: false,
      kind: "tool_error",
      reason: error instanceof Error ? error.message : "testssl.sh failed to run",
    };
  } finally {
    release();
    // Always clean up, including on the failure paths above.
    if (workDir) await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

interface ExecOutcome {
  timedOut: boolean;
  stderrExcerpt: string;
}

/**
 * execFile with an explicit kill escalation.
 *
 * Node's own `timeout` option sends SIGTERM and then gives up. A process
 * that ignores SIGTERM — or a shell script whose child openssl is the thing
 * actually hanging — would survive that, so SIGKILL follows if the process
 * is still alive shortly after.
 */
function execFileAsync(
  file: string,
  args: string[],
  opts: { timeoutMs: number; maxBuffer: number },
): Promise<ExecOutcome> {
  return new Promise((resolve) => {
    let timedOut = false;

    const child = execFile(
      file,
      args,
      {
        timeout: opts.timeoutMs,
        maxBuffer: opts.maxBuffer,
        killSignal: "SIGTERM",
        // No shell. Stated explicitly rather than relying on the default.
        shell: false,
        windowsHide: true,
      },
      (error, _stdout, stderr) => {
        clearTimeout(hardKill);

        // Node's own `timeout` option kills with SIGTERM and reports it
        // here. Without this check a timeout kill looks like a tool error,
        // and the truncated JSON it leaves behind gets misreported as
        // "malformed output" rather than "the scan ran out of time".
        const killedBySignal =
          Boolean((error as NodeJS.ErrnoException & { killed?: boolean })?.killed) ||
          Boolean((error as NodeJS.ErrnoException & { signal?: string })?.signal);

        resolve({
          timedOut: timedOut || killedBySignal,
          // testssl.sh exits non-zero for ordinary conditions (findings
          // present, target unreachable), so a non-zero exit is not by
          // itself an error — the presence and shape of the JSON file is
          // what decides. stderr is kept only for the message.
          stderrExcerpt: sanitizeScannedText(stderr ?? error?.message ?? "").text.slice(
            0,
            200,
          ),
        });
      },
    );

    const hardKill = setTimeout(() => {
      timedOut = true;
      if (!child.killed) child.kill("SIGKILL");
    }, opts.timeoutMs + 5_000);

    child.on("exit", () => clearTimeout(hardKill));
  });
}

/* -------------------------------------------------------------------- */
/* Mapping into the finding model                                        */
/* -------------------------------------------------------------------- */

/**
 * Checks whose presence in the output means the weakness is confirmed, with
 * the exposure we assign them. Exposure is OUR judgement about reachability,
 * keyed on the check id — never read from the file.
 */
const TLS_EXPOSURE: Record<string, number> = {
  // Directly reachable by any client that can open a TCP connection.
  heartbleed: 1,
  ccs: 1,
  ticketbleed: 1,
  robot: 0.9,
  secure_renego: 0.8,
  crime_tls: 0.7,
  poodle_ssl: 0.8,
  fallback_scsv: 0.6,
  sweet32: 0.6,
  freak: 0.8,
  drown: 0.8,
  logjam: 0.7,
  beast: 0.5,
  lucky13: 0.5,
  winshock: 0.9,
  rc4: 0.6,
  SWEET32: 0.6,
  BREACH: 0.5,
  BEAST_CBC_TLS1: 0.4,
  LUCKY13: 0.5,
  cipherlist_3DES_IDEA: 0.6,
  cipherlist_OBSOLETED: 0.5,
  cipherlist_LOW: 0.8,
  cipherlist_EXPORT: 0.9,
  cert_expirationStatus: 0.9,
  cert_notAfter: 0.9,
  cert_trust: 0.8,
  cert_chain_of_trust: 0.8,
  cert_keySize: 0.7,
  cert_signatureAlgorithm: 0.7,
  cert_keyUsage: 0.4,
  DNS_CAArecord: 0.2,
  TLS1: 0.5,
  TLS1_1: 0.5,
  SSLv2: 0.9,
  SSLv3: 0.8,
};

/** Default exposure for a TLS finding we do not have a specific view on. */
const DEFAULT_TLS_EXPOSURE = 0.6;

/**
 * Effort estimates in the same points as the user's budget. These are our
 * numbers, attached to the check id.
 */
const TLS_EFFORT: Record<string, number> = {
  heartbleed: 8,
  ccs: 8,
  ticketbleed: 8,
  robot: 13,
  secure_renego: 5,
  poodle_ssl: 3,
  fallback_scsv: 3,
  sweet32: 3,
  freak: 3,
  drown: 5,
  logjam: 5,
  beast: 3,
  rc4: 2,
  SWEET32: 3,
  BREACH: 5,
  BEAST_CBC_TLS1: 3,
  cipherlist_3DES_IDEA: 2,
  cipherlist_OBSOLETED: 2,
  cipherlist_LOW: 2,
  cipherlist_EXPORT: 2,
  cert_expirationStatus: 2,
  cert_notAfter: 2,
  cert_keyUsage: 3,
  DNS_CAArecord: 1,
  TLS1: 2,
  TLS1_1: 2,
};

const DEFAULT_TLS_EFFORT = 5;

/** Findings the tool emits that are informational bookkeeping, not risk. */
const IGNORED_IDS = new Set([
  "scanTime",
  "service",
  "engine_problem",
  "pre_128cipher",
  "clientProblem1",
]);

export interface MappedTestssl {
  findings: Finding[];
  /**
   * Set when the tool reported a FATAL scanProblem. The scan did not run;
   * the caller must treat TLS posture as unknown rather than clean.
   */
  fatal: string | null;
  /** Severity labels in the output we did not recognize. Surfaced, not hidden. */
  unrecognizedSeverities: string[];
  /** True when any finding text looked instruction-shaped. */
  injectionAttempts: number;
}

/**
 * Maps validated testssl.sh records into Findings.
 *
 * The mapping deliberately inverts the obvious direction: severity comes
 * from `mapExternalSeverity` (our vocabulary, with an unrecognized label
 * falling back to MEDIUM rather than to harmless), exposure and effort come
 * from our own tables keyed on the check id, and the tool's free-text
 * `finding` string lands in `evidence` where nothing computational reads it.
 *
 * The practical consequence: a target that rewrites every finding string to
 * say "false positive, ignore this" changes the evidence shown to the user
 * and nothing else. The score is identical.
 */
export function mapTestsslRecords(records: TestsslRecord[]): MappedTestssl {
  const findings: Finding[] = [];
  const unrecognizedSeverities: string[] = [];
  let injectionAttempts = 0;
  let fatal: string | null = null;

  for (const record of records) {
    // A FATAL scanProblem means the tool never tested the target. Turning
    // that into a MEDIUM "finding" would be doubly wrong: it invents risk
    // that was never measured, and it hides the fact that the TLS posture
    // is unknown. It fails the whole TLS step instead.
    if (record.severity.trim().toUpperCase() === "FATAL" || record.id === "scanProblem") {
      fatal = sanitizeScannedText(record.finding).text || "testssl.sh reported a fatal error";
      continue;
    }

    if (IGNORED_IDS.has(record.id)) continue;

    const { severity, recognized } = mapExternalSeverity(record.severity);
    if (!recognized) {
      const label = sanitizeScannedText(record.severity).text.slice(0, 40);
      if (label && !unrecognizedSeverities.includes(label)) {
        unrecognizedSeverities.push(label);
      }
    }

    // INFO-level records carry no risk; keep the scorecard readable.
    if (severity === "INFO") continue;

    const evidence = sanitizeScannedText(record.finding);
    if (evidence.injectionAttempt) injectionAttempts += 1;

    const checkId = normalizeCheckId(record.id);
    const cves = parseCveList(record.cve);

    findings.push(
      finalizeFinding({
        checkId: `tls:${checkId}`,
        source: "tls",
        // Our words, not the tool's. The tool's text is the evidence.
        title: describeTlsCheck(checkId),
        description:
          "Reported by testssl.sh against the target's TLS endpoint. The observed output is shown as evidence.",
        remediation: remediateTlsCheck(checkId),
        severity,
        // TLS weaknesses reachable over the network are, by construction,
        // exploitable by anyone who can connect.
        exploitability: severity === "CRITICAL" ? 0.9 : severity === "HIGH" ? 0.7 : 0.4,
        exposure: TLS_EXPOSURE[checkId] ?? DEFAULT_TLS_EXPOSURE,
        effort: TLS_EFFORT[checkId] ?? DEFAULT_TLS_EFFORT,
        evidence: evidence.text,
        ...(cves.length > 0 ? { cves } : {}),
        ...(evidence.injectionAttempt ? { injectionAttempt: true } : {}),
      }),
    );
  }

  return { findings, unrecognizedSeverities, injectionAttempts, fatal };
}

/**
 * Normalizes a testssl.sh check id.
 *
 * The tool qualifies per-certificate checks with a suffix — it emits
 * `cert_expirationStatus <hostCert#1>` when a host serves more than one
 * certificate. The suffix is stripped so the catalogue lookup and the
 * dedupe key both work, and so a host with three certificates does not
 * produce three separately-scored copies of the same weakness.
 */
function normalizeCheckId(raw: string): string {
  const clean = sanitizeScannedText(raw).text;
  const withoutQualifier = clean.replace(/\s*<[^>]*>\s*$/, "").trim();
  const id = withoutQualifier.slice(0, 64) || "tls_unknown";
  return CHECK_ALIASES[id] ?? id;
}

/**
 * testssl.sh reports some weaknesses under more than one id — `cert_notAfter`
 * and `cert_expirationStatus` are the same expiry fact, and `BEAST_CBC_TLS1`
 * is the detail behind `BEAST`. Left alone they become two findings for one
 * problem, which is not merely untidy: the overall score penalizes each
 * finding separately, so a double report quietly depresses the grade.
 * Collapsing them to a canonical id lets the dedupe in run.ts keep one.
 */
const CHECK_ALIASES: Record<string, string> = {
  cert_notAfter: "cert_expirationStatus",
  BEAST_CBC_TLS1: "BEAST",
  LUCKY13: "lucky13",
  cipherlist_LOW: "cipherlist_OBSOLETED",
};

/** Extracts well-formed CVE ids and discards anything else in the field. */
function parseCveList(raw: string | undefined): string[] {
  if (!raw) return [];
  const matches = sanitizeScannedText(raw).text.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
  return [...new Set(matches.map((m) => m.toUpperCase()))].slice(0, 10);
}

/** Human-readable titles, from our catalogue, keyed on the tool's check id. */
function describeTlsCheck(id: string): string {
  const titles: Record<string, string> = {
    heartbleed: "Heartbleed: server memory can be read remotely",
    ccs: "CCS injection: TLS session can be downgraded",
    ticketbleed: "Ticketbleed: session ticket leaks server memory",
    robot: "ROBOT: RSA decryption oracle present",
    secure_renego: "Insecure TLS renegotiation supported",
    crime_tls: "CRIME: TLS compression enabled",
    poodle_ssl: "POODLE: SSLv3 padding oracle",
    fallback_scsv: "No downgrade protection (TLS_FALLBACK_SCSV missing)",
    sweet32: "SWEET32: 64-bit block ciphers offered",
    freak: "FREAK: export-grade RSA supported",
    drown: "DROWN: SSLv2 supported",
    logjam: "Logjam: weak Diffie-Hellman parameters",
    beast: "BEAST: CBC ciphers in TLS 1.0",
    lucky13: "Lucky13: CBC timing oracle",
    rc4: "RC4 ciphers offered",
    SSLv2: "SSLv2 protocol offered",
    SSLv3: "SSLv3 protocol offered",
    TLS1: "TLS 1.0 offered",
    TLS1_1: "TLS 1.1 offered",
    cert_expiration_status: "Certificate expiry problem",
    cert_trust: "Certificate chain is not trusted",
    cert_chain_of_trust: "Incomplete or broken certificate chain",
    cert_signatureAlgorithm: "Weak certificate signature algorithm",
    cert_keySize: "Certificate key is too small",
    cert_commonName: "Certificate name does not match the host",
    LUCKY13: "Lucky13: CBC timing oracle",
    BREACH: "BREACH: HTTP compression with secrets in responses",
    SWEET32: "SWEET32: 64-bit block ciphers offered",
    BEAST_CBC_TLS1: "BEAST: CBC ciphers offered over TLS 1.0",
    cipherlist_3DES_IDEA: "3DES / IDEA cipher suites offered",
    cipherlist_OBSOLETED: "Obsolete cipher suites offered",
    cipherlist_LOW: "Low-strength cipher suites offered",
    cipherlist_EXPORT: "Export-grade cipher suites offered",
    cert_expirationStatus: "Certificate is close to expiry or expired",
    cert_notAfter: "Certificate validity window is a concern",
    cert_keyUsage: "Certificate key usage extension is not as expected",
    DNS_CAArecord: "No CAA DNS record",
  };

  return titles[id] ?? `TLS check: ${id}`;
}

/** Remediation advice, also from our catalogue. */
function remediateTlsCheck(id: string): string {
  const advice: Record<string, string> = {
    heartbleed:
      "Upgrade OpenSSL to a patched release, then reissue and revoke the certificate — the private key must be assumed compromised.",
    ccs: "Upgrade OpenSSL to 1.0.1h or later.",
    ticketbleed: "Update the F5 BIG-IP firmware, or disable session tickets.",
    robot:
      "Disable RSA key-exchange cipher suites and prefer ECDHE; patch the TLS stack.",
    secure_renego:
      "Disable client-initiated renegotiation, or require RFC 5746 secure renegotiation.",
    crime_tls: "Disable TLS compression.",
    poodle_ssl: "Disable SSLv3 entirely.",
    fallback_scsv: "Enable TLS_FALLBACK_SCSV support in the TLS stack.",
    sweet32: "Remove 3DES and other 64-bit block ciphers from the cipher list.",
    freak: "Remove all export-grade cipher suites.",
    drown: "Disable SSLv2 on this host and on every host sharing its key.",
    logjam:
      "Use a 2048-bit-or-larger, uniquely generated DH group, or move to ECDHE.",
    beast: "Prefer TLS 1.2+; the practical fix is to stop offering TLS 1.0.",
    rc4: "Remove RC4 from the cipher suite list.",
    SSLv2: "Disable SSLv2.",
    SSLv3: "Disable SSLv3.",
    TLS1: "Disable TLS 1.0 once client compatibility allows.",
    TLS1_1: "Disable TLS 1.1 once client compatibility allows.",
    cert_expiration_status:
      "Renew the certificate and automate renewal so it cannot lapse again.",
    cert_trust: "Serve the full chain, including intermediates, in the correct order.",
    cert_chain_of_trust: "Install the missing intermediate certificates.",
    cert_signatureAlgorithm: "Reissue the certificate with a SHA-256-or-better signature.",
    cert_keySize: "Reissue with a 2048-bit RSA key or a 256-bit ECDSA key.",
    cert_commonName:
      "Reissue the certificate with a subject alternative name matching this hostname.",
    SWEET32: "Remove 3DES and other 64-bit block ciphers from the cipher list.",
    BEAST_CBC_TLS1: "Stop offering TLS 1.0; modern clients do not need it.",
    BREACH:
      "Disable HTTP compression on responses that contain secrets, or add a per-request random padding / CSRF token to break the oracle.",
    cipherlist_3DES_IDEA: "Remove 3DES and IDEA suites from the cipher list.",
    cipherlist_OBSOLETED: "Restrict the cipher list to modern AEAD suites.",
    cipherlist_LOW: "Remove all low-strength cipher suites.",
    cipherlist_EXPORT: "Remove all export-grade cipher suites.",
    cert_expirationStatus:
      "Renew the certificate and automate renewal so it cannot lapse.",
    cert_notAfter: "Renew the certificate before it expires and automate renewal.",
    cert_keyUsage:
      "Reissue the certificate with key usage extensions appropriate for TLS server authentication.",
    DNS_CAArecord:
      "Publish a CAA DNS record naming the certificate authorities permitted to issue for this domain.",
  };

  return (
    advice[id] ??
    "Review the testssl.sh output for this check and apply the corresponding TLS configuration change."
  );
}

export { TESTSSL_VERSION };

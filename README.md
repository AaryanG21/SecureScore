# Fulcrum

**Website Security Scorecard & Remediation Agent**

Fulcrum scans a domain you have proven you own, grades its external
security posture A–F, and returns a remediation plan ranked to a fix-effort
budget you set — with the reasoning shown, not just a number.

The project has two layers, and both are graded:

1. **The agent** — scanning, risk scoring, and budget-constrained
   remediation planning. No third-party agent framework is used; the
   reasoning loop is written directly.
2. **The application around it** — built to a high security standard,
   because a security tool that is itself insecure is worse than useless.

---

## Build status

| Layer | State |
| --- | --- |
| Project scaffold, Prisma schema, migrations | Complete |
| Authentication: argon2id, mandatory TOTP 2FA, backup codes | Complete |
| Sessions: short-lived JWT + rotating refresh tokens with reuse detection | Complete |
| RBAC, admin re-authentication, append-only audit log | Complete |
| CSRF, rate limiting, lockout, security headers, zod validation | Complete |
| Domain ownership allowlist (DNS TXT / well-known file) | Complete |
| UI: landing, sign-in, enrollment, dashboard, account, admin | Complete |
| Scanning agent: headers, TLS via testssl.sh, fingerprinting, CVE/EPSS | Complete |
| Risk scoring, budget-constrained remediation planner, scorecard UI | Complete |
| Hand-written test assertions | **Yours to write** — see `tests/README.md` |

The security foundation was built first, deliberately, so it could be
verified before the scanning layer went on top.

**Verified against live hosts**, not only by typecheck: a full run against
`example.com` completes in ~140s, producing header findings, TLS and
certificate findings from testssl.sh v3.2.4, and a ranked plan. A run
against a host advertising `nginx 1.10.3` correctly matched three CVEs and
ordered them by EPSS.

---

## How the agent works

A hand-written loop in `src/lib/agent/run.ts` — no agent framework, per the
course constraint. Four steps, each of which can degrade without killing
the scan:

1. **HTTP headers** (`headers.ts`) — one request, headers only, body never
   read. Checks CSP, HSTS, frame options, MIME sniffing, referrer policy,
   permissions policy, cookie flags, and version disclosure.
2. **Fingerprint** (`fingerprint.ts`) — reads product/version from the
   response, fed by step 1. Only the leading `product/version` token is
   parsed, against an allowlist of known products.
3. **CVE / EPSS** (`cve.ts`) — cross-references fingerprinted versions
   against a bundled dataset. **CVSS sets severity; EPSS sets
   exploitability.** Those answer different questions — "how bad if
   exploited" versus "how likely to be exploited" — and a plan that ignores
   the second sends people to fix theoretical 9.8s while a
   widely-exploited 7.5 stays open.
4. **TLS** (`testssl.ts`) — the pinned external tool, under a timeout,
   output cap, and concurrency limit.

Then: score, grade, and a plan ranked by **risk removed per effort point**,
filled greedily against the user's budget with a backfill pass. Greedy
rather than an exact knapsack solve, because the output has to be
explainable — "the highest-value-per-hour fix first" is advice someone can
argue with, where an optimal set from dynamic programming is a black box
that occasionally recommends skipping the obvious thing.

A step that fails is recorded in `degradedSteps` and shown on the
scorecard. **A TLS scan that times out never looks like a clean one** — the
scorecard says the TLS posture is unknown, not verified.

### How the score becomes a letter

The score is a penalty total: the worst finding counts in full, each
subsequent one counts for less (`risk / (index + 1)`). That ranks well, but
on its own it made the letter useless for comparison. A static site whose
only real problem was a missing `Content-Security-Policy` scored 54 and
graded **F** — one HIGH finding at risk 34 was three quarters of the total
penalty, and no site without a critical finding could reach above D.

F has to mean something. A scorecard that cannot tell "no CSP header" apart
from "exploitable TLS and a known-exploited CVE" is not being strict, it is
being uninformative — and the first operator who reads an F for a missing
header learns to discount every F after it.

So the letter is bounded below by the worst severity actually found:

| Worst finding | Cannot grade below |
| ------------- | ------------------ |
| CRITICAL      | — (F is reachable) |
| HIGH          | D                  |
| MEDIUM        | C                  |
| LOW           | B                  |
| nothing scored| A                  |

This is a **floor, never a ceiling**. Twenty HIGH findings still land at D
rather than being lifted — the score keeps doing the discriminating, and
accumulating problems still costs you.

The implementation keeps the injection-resistance property intact.
`computeGrade(score)` is unchanged and still takes exactly one argument;
the floor lives in `computeGradeWithFloor(score, worstSeverity)`, whose
second argument is one of five values from our own closed enum — set by our
own rules, or by `mapExternalSeverity`, which maps an unrecognized label
from testssl.sh to MEDIUM rather than trusting it. No target-supplied text
reaches either function.

### Two kinds of scan, and why the line is where it is

"Scanning" is not one action, and treating it as one forces a choice
between refusing everything and permitting everything.

| | Full scan | Headers-only check |
| --- | --- | --- |
| Requires proven ownership | **yes** | no |
| What the target sees | one GET, then hundreds of TLS handshakes probing cipher suites, protocol versions and renegotiation | **one** HTTPS GET, body never read |
| Checks | headers, fingerprint, CVE, TLS | headers, fingerprint, CVE |
| Endpoint | `POST /api/scans` | `POST /api/scans/public` |

The headers check sends exactly what a browser sends when someone visits
the page once, and the fingerprint and CVE steps work from that same
response without generating further traffic. There is no coherent sense in
which that is an intrusion. The TLS step is active probing, it looks like
reconnaissance in the target's logs, and it stays behind proof of control.

`includeTls: false` is hard-coded in the public route rather than read from
the request, so no request body can unlock the TLS step. The two routes are
kept separate for the same reason: one endpoint with a boolean would mean a
single code path deciding, from a request field, how much of the scanner to
unlock.

Three throttles, because this endpoint makes the server send a request on a
stranger's say-so:

- **Per caller** — 30/hour, and callers must be authenticated, so every
  request is attributable and every refusal is audited.
- **Per target** — 6/hour for one hostname across *all* callers. A per-user
  limit alone would let many accounts aim at one host; this is the half
  that protects the target rather than the service.
- **Result reuse** — a completed check is served again for 15 minutes. Ten
  people checking the same site in that window cost it one request, not
  ten. The strongest throttle is the one that removes the request entirely.

A headers-only result says so on its face — a badge beside the grade, a
warning above the explanation, and a `degraded` entry recording that TLS
was not examined. A host can have excellent headers and badly broken
transport security, and a grade that does not say which surface it looked
at is worse than no grade.

### Why scanned text cannot change a score

The `Finding` type separates the two categories of data structurally.
Everything the score is computed from — `severity`, `exploitability`,
`exposure`, `checkId` — is a closed enum or a bounded number this codebase
chose, keyed on which check ran. Everything the target supplied is
quarantined in a single `evidence` field that no scoring or planning code
reads.

`computeRiskScore` takes three named numbers rather than a `Finding`, so
there is no object to reach a target-supplied field through.
`computeGrade` takes a score and nothing else — there is no parameter an
injected instruction could attach itself to.

Sanitization (control-character stripping, length caps, instruction-pattern
flagging) is hygiene for the display path and the audit log. It is
explicitly *not* what keeps the score honest: delete it entirely and a
hostile banner still could not move a grade.

## Stack

- **Next.js 16** (App Router) + TypeScript + Tailwind CSS 4
- **PostgreSQL 17** via **Prisma 7** (driver adapter, `@prisma/adapter-pg`)
- Custom JWT session auth — `jose` for tokens, `@node-rs/argon2` for
  hashing, `otplib` for TOTP
- Validation with `zod`; tests with `vitest`
- Docker + docker-compose for local dev and single-host deployment

---

## Quick start

```bash
git clone --recurse-submodules <repo-url> fulcrum
cd fulcrum

# If you already cloned without submodules:
git submodule update --init --recursive

npm install

cp .env.example .env.local
# Generate the two keys and paste them in:
openssl rand -base64 32   # -> JWT_SIGNING_KEY
openssl rand -base64 32   # -> TOTP_ENCRYPTION_KEY

# Start Postgres (or point DATABASE_URL at your own instance)
docker compose up -d db

npm run db:migrate        # applies prisma/migrations
SEED_ADMIN_EMAIL=you@example.com SEED_ADMIN_PASSWORD='a-long-passphrase' npm run db:seed

npm run dev               # http://localhost:3000
```

The seeded admin lands in `PENDING_2FA`. Sign in, complete authenticator
enrollment, and **save the backup codes** — they are shown once and are not
recoverable.

### Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Development server |
| `npm run build` | `prisma generate` then a production build |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint |
| `npm test` / `npm run test:run` | Vitest, watch / single pass |
| `npm run db:migrate` | Apply migrations (`prisma migrate deploy`) |
| `npm run db:migrate:dev` | Create a migration during development |
| `npm run db:seed` | Seed an admin (refuses to run in production) |
| `npm run audit` | `npm audit --omit=dev` |

---

## Environment variables

Every variable is validated at boot by `src/lib/env.ts`. A missing or
malformed value stops the process with a message naming the variable —
never its value. The full annotated list is in `.env.example`; the ones
without defaults are:

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | Postgres connection string |
| `JWT_SIGNING_KEY` | base64, exactly 32 bytes. Rotating it ends all sessions |
| `TOTP_ENCRYPTION_KEY` | base64, exactly 32 bytes. **Rotating it makes every stored TOTP secret undecryptable** — plan a re-enrollment migration first |
| `APP_ORIGIN` | Absolute origin. Drives the cookie `Secure` flag and CSRF origin checks |

---

## Integrated open-source tools

### testssl.sh

| | |
| --- | --- |
| **Tool** | [testssl.sh](https://testssl.sh) — TLS/SSL protocol, cipher, and certificate testing |
| **Source** | <https://github.com/testssl/testssl.sh> |
| **Pinned version** | **v3.2.4** (released 2026-07-12) |
| **Pinned commit** | `97763a411c525720a5f9bd9d2cded416b10f210a` |
| **Location** | `vendor/testssl.sh`, a git submodule |
| **License** | GPLv2 |

The submodule is pinned to a tagged release, not to `main`. Updating it is
a deliberate, reviewable commit:

```bash
cd vendor/testssl.sh
git fetch --tags
git checkout v3.2.5          # or whatever the new stable tag is
cd ../..
git add vendor/testssl.sh
# …and update the version and commit recorded in this README.
```

**Invocation.** The scanner shells out to the pinned script through
`execFile` with an explicit argument vector — never through a shell, and
never by interpolating user input into a command string:

```
vendor/testssl.sh/testssl.sh \
  --jsonfile <per-scan temp path> \
  --quiet \
  --color 0 \
  --warnings batch \
  --severity LOW \
  -p -s -S -U \
  [--openssl-timeout 30 --connect-timeout 30]   # only when `timeout` exists
  <hostname>
```

`-p -s -S -U` is a targeted check set — protocols, cipher categories,
server defaults and certificate, and the vulnerability suite. It covers
everything the scorecard uses in roughly two minutes, against seven-plus
for a default run that enumerates every cipher.

The two timeout flags are added only when GNU coreutils `timeout` is on the
host. testssl.sh implements them by shelling out to that binary and aborts
the entire scan with a FATAL when it is missing — which macOS is, by
default. The Docker image installs `coreutils`, so deployments get them;
developer machines degrade to our own subprocess timeout instead of
failing.

The hostname is canonicalized and validated by
`src/lib/validation/hostname.ts` before it is passed as an argument.
Anything with a scheme, port, path, credential, control character, shell
metacharacter, or leading `-` is rejected outright rather than escaped.

**Output handling.** The flat `--jsonfile` output (a JSON array of
`{id, severity, cve, cwe, finding}` records) is size- and depth-bounded,
then validated by a zod schema that **strips unknown keys** — an invented
`override_score` or `grade_override` field cannot reach any consumer.
Severity comes from Fulcrum's own mapping, and an unrecognized label falls
back to MEDIUM rather than to harmless, with the unknown label surfaced to
the user. Exposure and effort come from our own tables keyed on the check
id. The tool's free-text `finding` string lands in `evidence`.

A `FATAL` record means the tool never tested the target. That fails the TLS
step rather than becoming a scored finding — turning it into a MEDIUM would
invent risk that was never measured *and* hide that the posture is unknown.

**Resource limits.** The subprocess runs under `TESTSSL_TIMEOUT_MS`
(default 5 minutes), a captured-output cap, and a concurrency limit. A slow
or deliberately stalling target cannot pin the scan worker open.

---

## Security design

Defence in depth, described honestly. Nothing here makes the app
unbreakable; each layer raises cost and narrows what a single mistake can
reach.

### Authentication

- **Passwords**: argon2id (19 MiB memory, t=2, p=1 — OWASP's current
  recommendation), stored as PHC strings. Parameters are upgraded
  transparently on the next successful login when they fall behind
  (`needsRehash`). Passwords are never logged, never encrypted, never
  recoverable.
- **2FA is mandatory**, not opt-in. An account that has not completed TOTP
  enrollment sits in `PENDING_2FA` and cannot hold a session.
- **Two-step login, enforced by token type.** A correct password yields
  only an `mfa_pending` token; only `/api/auth/2fa/verify` can exchange it
  for a session. The JWT `typ` claim is checked on every verification, so
  one token type can never be accepted as another — this is the mechanism
  that makes the second factor unskippable.
- **TOTP replay protection is database-backed.** Each successful
  verification records the RFC 6238 time step it matched; codes at or below
  that step are rejected. This survives restarts and works across replicas,
  unlike an in-process cache.
- **Backup codes**: ten single-use codes, argon2id-hashed, issued at
  enrollment and shown exactly once. Redemption uses a conditional update,
  so two concurrent requests cannot both spend the same code.
- **Login timing** does not disclose whether an email is registered: the
  unknown-account path performs a decoy argon2id verification.

### Sessions

- Short-lived signed access token (10 min default) + long-lived **opaque**
  refresh token, stored only as a SHA-256 hash.
- **Refresh rotation with reuse detection**: presenting an already-rotated
  token revokes the entire token family and forces a fresh login (OAuth 2.1
  guidance).
- All auth cookies are `httpOnly`, `Secure` (when `APP_ORIGIN` is https),
  and `SameSite=Strict`. **No token is ever placed in `localStorage` or
  exposed to client JavaScript.** The refresh cookie is path-scoped to
  `/api/auth`.
- Sessions are re-validated against the database on every request — a
  suspension, demotion, or revocation takes effect immediately rather than
  when the access token happens to expire.

### Authorization

- Roles (`USER`, `ADMIN`) live in the database and are checked server-side
  on every protected route via `src/lib/auth/guards.ts`. Client-side role
  checks only decide what to render.
- Destructive admin actions additionally require **re-authentication**
  (password + current TOTP) within the last 5 minutes.
- An admin cannot suspend their own account.
- Cross-tenant lookups return the same response as a nonexistent record, so
  no endpoint doubles as an existence oracle.

### Scan authorization allowlist

A scan is permitted only for a domain that is registered to the calling
user **and** verified. Ownership is proven by one of:

- **DNS TXT** — a record at `_fulcrum-challenge.<hostname>` (recommended;
  requires registrar or nameserver control)
- **HTTP well-known file** — `https://<hostname>/.well-known/fulcrum-challenge.txt`
  (weaker: satisfiable by anyone who can write to the webroot)

`authorizeScan` in `src/lib/domains/allowlist.ts` is the single chokepoint.
Every refusal — unverified, revoked, not the owner, inactive account — is
written to the audit log. Inconsistent rows (marked verified but carrying a
revocation timestamp) fail closed.

The well-known fetch does not follow redirects (a redirect to
`169.254.169.254` is the standard SSRF pivot to cloud instance metadata),
caps the response size, and times out.

### Untrusted input from scanned targets

Everything a scan reads is attacker-controlled: server banners, certificate
fields, page content — and, because testssl.sh faithfully reports what the
target said, its JSON output too.

The rule the implementation holds to: **scanned text is data.** It is never
read as an instruction, and no string from a target can move a computed
risk score, severity, or grade. Scores come only from the scoring
function's own inputs (severity × exploitability × exposure), derived from
which check ran. Unknown fields in the tool's output are ignored;
out-of-vocabulary severities fall back to a safe default rather than being
passed through.

`tests/unit/agent/injection-resistance.test.ts` and
`tests/fixtures/hostile-scan-output.ts` encode this as the project's
refusal / injection test case.

### Application hardening

- **CSRF**: double-submit cookie (`X-CSRF-Token` vs `fulcrum_csrf`,
  compared in constant time) plus an `Origin`/`Referer` check against
  `APP_ORIGIN`, on every state-changing request. `SameSite=Strict` is a
  third layer, not the only one.
- **Rate limiting**: 5 attempts / 15 minutes per IP **and** account on
  login, 2FA, password change, and re-authentication, with exponential
  backoff; tighter budgets on scans and domain verification; a blanket
  ceiling on all other API routes.
- **Account lockout**: persisted per account, so distributed guessing that
  rotates IPs still stalls. Time-boxed and admin-clearable, because a
  permanent lockout is itself a denial-of-service vector.
- **Security headers** (`src/lib/security/headers.ts`, applied in
  `src/proxy.ts`): nonce-based CSP with `strict-dynamic` and no host
  allowlist, HSTS (https only), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, a restrictive
  `Permissions-Policy`, and cross-origin isolation headers.
- **Input validation**: zod on every endpoint, rejecting rather than
  sanitizing-and-continuing. The one transformation is hostname
  canonicalization, which is a documented canonical form that still rejects
  anything ambiguous.
- **SQL**: Prisma query builder throughout. There is no raw SQL string
  concatenation anywhere in `src/`.
- **Secrets**: environment only, validated at boot, never committed.
  `.env.example` ships placeholders.
- **Audit log**: every auth event, authorization refusal, domain action,
  and admin action. Metadata is redacted before it is stored — keys that
  look like credentials become `[redacted]`, long values are truncated to a
  non-replayable prefix. Reading the audit log is itself audited.
  Immutability is enforced by **Postgres triggers** that reject `UPDATE`,
  `DELETE`, and `TRUNCATE` on the table, not merely by application
  convention.

  The audit log holds **no foreign key** to `User`. An append-only table
  cannot have a relation to a mutable one: `ON DELETE SET NULL` would
  mutate the log (blocked by the trigger, making accounts undeletable),
  and `CASCADE` would erase precisely the history that matters most when
  an account is removed. `actorUserId` is an opaque string that outlives
  the account, and `actorEmail` is denormalized at write time — the email
  as it was when the action happened is the forensic fact, where a join
  would show whatever that account is called today, or nothing at all.

### Dependency hygiene

Run `npm audit` before each release, and enable Dependabot (or Renovate) on
the repository for ongoing alerts. Treat it as a standing practice, not a
one-time gate.

Known and accepted at the time of writing: `npm audit` reports advisories
in `mysql2` and `deepmerge-ts`, reached transitively through the **Prisma
CLI** — a dev dependency. This project uses PostgreSQL, so the MySQL driver
path is never loaded, and the CLI does not ship in the runtime image. The
fix offered by `npm audit fix --force` is a downgrade to Prisma 6, which
would be a larger regression than the risk it removes. Re-evaluate when
Prisma updates the dependency.

---

## Testing

**All grading tests are hand-written by the project author.** The files in
`tests/` are scaffolds: structure, fixtures, and mocks are in place, and
every `it(...)` body is a set of `// TODO:` comments describing what to
prove. No assertion logic is provided.

Note that an empty test block passes vacuously — a green `npm test` on the
scaffolds means "nothing is written yet", not "everything works".

See `tests/README.md` for the layout and the coverage the scaffolds aim at.

---

## Deployment (EC2 / Hetzner)

```bash
# On the host
git clone --recurse-submodules <repo-url> /opt/fulcrum
cd /opt/fulcrum

cat > .env <<'EOF'
POSTGRES_PASSWORD=<long random>
JWT_SIGNING_KEY=<openssl rand -base64 32>
TOTP_ENCRYPTION_KEY=<openssl rand -base64 32>
APP_ORIGIN=https://fulcrum.example.com
TRUST_PROXY_HEADERS=true
EOF
chmod 600 .env

docker compose run --rm migrate      # apply migrations first
docker compose up -d --build
```

The app binds to `127.0.0.1:3000`. Put a reverse proxy in front of it
(Caddy and nginx both work; Caddy gets you automatic certificates) and
terminate TLS there.

Host checklist:

- Firewall: allow 22, 80, 443 only. The Postgres container is on an
  internal Docker network with no published port.
- Set `TRUST_PROXY_HEADERS=true` **only** when the proxy in front is one
  you control and it sets `X-Forwarded-For`. Otherwise the client IP is
  spoofable and per-IP rate limiting becomes decorative.
- `APP_ORIGIN` must be the https origin, or cookies will not be marked
  `Secure` and CSRF origin checks will reject legitimate requests.
- Back up the database volume, and store `TOTP_ENCRYPTION_KEY` somewhere
  you can recover it — losing it means every user re-enrolls their
  authenticator.
- Before submitting the domain to the HSTS preload list, understand that
  removal takes months. The header ships preload-eligible; submission is a
  separate, deliberate act.

---

## Security limitations

An honest accounting. None of this is hypothetical hedging — each item is a
real gap in what the current implementation can promise.

**This app is not unhackable, and nothing here claims it is.** These are
the controls it implements and the ones it does not.

1. **A passing grade is not a security guarantee.** Fulcrum inspects what
   is reachable from outside: headers, TLS configuration, version
   fingerprints. It does not review application logic, authentication
   flows, dependencies, infrastructure, or people. An A grade means the
   checks it ran found nothing — no more than that.

2. **Application-layer throttling is not DDoS protection.** The rate
   limiter stops credential stuffing and brute force. A volumetric attack
   saturates the network link or the event loop before any of this code
   runs. Real mitigation lives at the network edge — put Cloudflare, AWS
   Shield, or an equivalent in front of the deployment. Application code
   alone cannot provide it, and this README will not pretend otherwise.

3. **Rate limiting is in-memory and single-instance.** It does not survive
   a restart and does not coordinate across replicas. Horizontal scaling
   requires moving the store to Redis behind the existing
   `RateLimitStore` interface. Account lockout, which is database-backed,
   is unaffected.

4. **Audit-log immutability is enforced by a trigger, which a database
   superuser can drop.** It makes tampering fail loudly for the
   application's own credentials; it is not cryptographic immutability.
   For that, ship logs off-host to append-only storage.

5. **Per-account lockout is itself a denial-of-service vector.** Anyone who
   knows an email address can lock it. The lock is time-boxed with
   exponential growth and admin-clearable, which bounds the damage rather
   than eliminating it.

6. **TOTP is phishing-susceptible.** A convincing proxy can relay a code in
   real time. WebAuthn/passkeys would close this; they are not implemented.

7. **The HTTP well-known verification method is weaker than DNS.** Anyone
   who can write to the webroot — a shared-hosting neighbour, a compromised
   CMS — can satisfy it. DNS TXT is recommended and is the default.

8. **No email verification, and no password reset flow.** There is
   currently no way to recover an account without either the password or a
   backup code. Adding reset-by-email introduces a new attack surface that
   deserves its own design rather than a bolt-on.

9. **Registration is open.** Any address can create an account. A real
   deployment likely wants an invite or approval step.

10. **A headers-only check still touches a host you do not own.** It is one
    GET, the same as a browser visit, and Fulcrum throttles per caller, per
    target, and by reusing recent results — but it is still an outbound
    request made on someone's behalf, and a determined caller can learn
    which hosts are reachable from this deployment. Full scans consume real
    resources on a third-party host, and ownership verification is what
    keeps those legitimate. It is not a substitute for
    telling your hosting provider what you are doing, and running this
    against infrastructure you do not control is both prohibited by the app
    and, in many jurisdictions, unlawful.

11. **CSP `strict-dynamic` relies on the nonce reaching every script.** A
    future change that injects an inline script without the nonce will
    break silently in the browser rather than loudly in CI. Check the
    console after touching the layout.

12. **Secrets live in environment variables.** Anything that can read the
    process environment — a shell on the host, a debug endpoint, a crash
    dump — can read them. A secrets manager with short-lived credentials
    would be better.

13. **The CVE dataset is curated, not comprehensive.** It covers common web
    server software and is snapshotted, not live. A clean CVE section means
    "nothing in our list matched", not "no known vulnerabilities exist".
    The scorecard states this on every result. Live EPSS refresh exists but
    is opt-in, because querying FIRST.org per scan tells them which hosts
    you are interested in and roughly when you scanned them.

14. **Fingerprints are the target's own claims.** A server can advertise any
    banner it likes, including one that invents a vulnerability it does not
    have. CVE findings are scored with reduced exposure for that reason and
    are labelled self-reported, but a deliberately lying host can still
    skew its own grade — in either direction.

15. **Scans run synchronously inside the request.** A scan holds the
    connection for two to three minutes. That is fine for a handful of
    users and wrong at any real volume: it ties up a server process per
    scan and dies with the request. The fix is a job queue with a worker
    pool, which is the next structural change this codebase needs.

16. **Only two scans run concurrently, process-wide.** A deliberate limit
    so a slow target cannot exhaust the worker, but it is per-process and
    in-memory — the same caveat as the rate limiter. Multiple replicas
    would each get their own budget of two.

---

## Licence and attribution

`vendor/testssl.sh` is [testssl.sh](https://github.com/testssl/testssl.sh)
by Dirk Wetter and contributors, GPLv2, vendored unmodified at tag v3.2.4.

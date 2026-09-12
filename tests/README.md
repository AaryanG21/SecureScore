# Tests

**These test files are scaffolds. The assertions are mine to write.**

Every `it(...)` block below has a body of `// TODO:` comments describing
what the case should establish, and nothing else. That is deliberate and it
is a course requirement: the grading tests must be hand-written, so the
structure, fixtures, and mocks are provided but no assertion logic is.

When you fill one in, delete the TODO comments in that block — a block with
both TODOs and assertions is ambiguous about whether it is finished.

## Layout

```
tests/
  setup.ts                     env for every run (throwaway keys)
  fixtures/                    reusable inputs, incl. hostile scan output
  unit/
    auth/                      password, TOTP, tokens, session, lockout
    security/                  CSRF, rate limiting, headers, audit redaction
    validation/                hostname canonicalization, zod schemas
    agent/                     scoring + prompt-injection resistance
  integration/                 full request flows against route handlers
```

## Running

```bash
npm test            # watch
npm run test:run    # single pass
```

Unit tests need no database. The integration tests do — point
`DATABASE_URL` at a scratch database you do not mind truncating, and note
that the audit-log trigger deliberately blocks `DELETE`, so tear-down must
drop and recreate rather than delete rows.

## Coverage the scaffolds aim at

Security-relevant behaviour, not line count. Roughly:

- passwords are argon2id and never recoverable
- neither factor alone produces a session
- a TOTP code cannot be replayed inside its window
- backup codes are single-use
- refresh-token reuse revokes the whole family
- role checks are server-side and cannot be spoofed by the client
- destructive admin actions require fresh re-authentication
- CSRF and rate limiting reject what they should, and only that
- unverified domains are refused for scanning, and the refusal is logged
- text scraped from a scanned target cannot change a computed risk score

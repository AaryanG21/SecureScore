# Fulcrum — multi-stage build.
#
# Notes that matter for security rather than size:
#   - the runtime image runs as a non-root user
#   - only the standalone build output, the Prisma migrations, and the
#     pinned testssl.sh checkout are copied into it; no source, no dev deps
#   - bash, openssl, and coreutils are installed because testssl.sh is a
#     bash script that shells out to openssl. Alpine's default ash is not
#     sufficient for it.
#   - no secrets are baked in. Everything comes from the environment at
#     runtime and is validated at boot.

# ---------------------------------------------------------------------------
FROM node:24-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
FROM node:24-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generates the Prisma client into src/generated, then builds Next.
# A dummy DATABASE_URL is enough for codegen; it is never connected to.
ENV NEXT_TELEMETRY_DISABLED=1
RUN DATABASE_URL="postgresql://build:build@localhost:5432/build" \
    JWT_SIGNING_KEY="YnVpbGQtdGltZS1wbGFjZWhvbGRlci1rZXktMzJieXRlcw==" \
    TOTP_ENCRYPTION_KEY="YnVpbGQtdGltZS1wbGFjZWhvbGRlci1rZXktMzJieXRlcw==" \
    APP_ORIGIN="http://localhost:3000" \
    npm run build

# ---------------------------------------------------------------------------
FROM node:24-alpine AS runner
WORKDIR /app

# testssl.sh dependencies.
RUN apk add --no-cache bash openssl coreutils procps drill

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
ENV TESTSSL_PATH=/app/vendor/testssl.sh/testssl.sh

RUN addgroup --system --gid 1001 fulcrum \
 && adduser --system --uid 1001 --ingroup fulcrum fulcrum

COPY --from=builder --chown=fulcrum:fulcrum /app/.next/standalone ./
COPY --from=builder --chown=fulcrum:fulcrum /app/.next/static ./.next/static
COPY --from=builder --chown=fulcrum:fulcrum /app/public ./public

# Migrations and the Prisma CLI, so the container can run `prisma migrate
# deploy` on start-up if the deployment chooses to.
COPY --from=builder --chown=fulcrum:fulcrum /app/prisma ./prisma
COPY --from=builder --chown=fulcrum:fulcrum /app/prisma.config.ts ./prisma.config.ts

# The pinned external tool.
COPY --from=builder --chown=fulcrum:fulcrum /app/vendor/testssl.sh ./vendor/testssl.sh

USER fulcrum

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]

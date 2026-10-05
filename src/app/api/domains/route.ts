import { type NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { apiError, apiOk, getRequestMeta } from "@/lib/http";
import { requireUser } from "@/lib/auth/guards";
import { addDomainSchema, parseJsonBody } from "@/lib/validation/schemas";
import {
  DNS_CHALLENGE_PREFIX,
  HTTP_CHALLENGE_PATH,
  generateVerificationToken,
} from "@/lib/domains/verification";
import { writeAudit } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Lists the caller's own domains. Scoped by userId, never by a client filter. */
export async function GET(request: NextRequest) {
  const guard = await requireUser(request, { skipCsrf: true, rateLimit: "api" });
  if (!guard.ok) return guard.response;

  const domains = await prisma.domain.findMany({
    where: { userId: guard.value.id },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      hostname: true,
      verificationStatus: true,
      verificationMethod: true,
      verificationToken: true,
      verifiedAt: true,
      revokedAt: true,
      lastCheckedAt: true,
      createdAt: true,
    },
  });

  return apiOk({
    domains: domains.map((d) => ({
      ...d,
      challenge:
        d.verificationMethod === "DNS_TXT"
          ? { type: "DNS_TXT", name: `${DNS_CHALLENGE_PREFIX}.${d.hostname}`, value: d.verificationToken }
          : { type: "HTTP_WELL_KNOWN", url: `https://${d.hostname}${HTTP_CHALLENGE_PATH}`, value: d.verificationToken },
    })),
  });
}

/**
 * Registers a domain and issues an ownership challenge.
 *
 * The row starts PENDING and stays unscannable until /verify succeeds.
 * A hostname is globally unique: once one account has registered it, a
 * second account cannot claim it, which stops a "register it first, verify
 * later" land-grab from blocking the real owner's verification.
 */
export async function POST(request: NextRequest) {
  const meta = getRequestMeta(request);

  const guard = await requireUser(request, { rateLimit: "domainVerify" });
  if (!guard.ok) return guard.response;

  const body = await parseJsonBody(request, addDomainSchema);
  if (!body.ok) {
    return apiError(400, "invalid_input", "Check the hostname.", body.fieldErrors);
  }

  const { hostname, method } = body.data;

  const existing = await prisma.domain.findUnique({
    where: { hostname },
    select: { id: true, userId: true },
  });

  if (existing) {
    // Same wording either way: whether someone else has registered this
    // hostname is not the caller's business.
    return apiError(
      409,
      "already_registered",
      "That hostname is already registered.",
    );
  }

  const domain = await prisma.domain.create({
    data: {
      userId: guard.value.id,
      hostname,
      verificationMethod: method,
      verificationToken: generateVerificationToken(),
      verificationStatus: "PENDING",
    },
    select: {
      id: true,
      hostname: true,
      verificationMethod: true,
      verificationToken: true,
      verificationStatus: true,
      createdAt: true,
    },
  });

  await writeAudit({
    actorUserId: guard.value.id,
    action: "DOMAIN_ADDED",
    targetType: "Domain",
    targetId: domain.id,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
    metadata: { hostname, method },
  });

  return apiOk(
    {
      domain,
      challenge:
        method === "DNS_TXT"
          ? {
              type: "DNS_TXT",
              name: `${DNS_CHALLENGE_PREFIX}.${hostname}`,
              value: domain.verificationToken,
              instructions:
                "Add this as a TXT record, then run verification. DNS changes can take a few minutes to propagate.",
            }
          : {
              type: "HTTP_WELL_KNOWN",
              url: `https://${hostname}${HTTP_CHALLENGE_PATH}`,
              value: domain.verificationToken,
              instructions:
                "Serve this exact string at that URL over HTTPS, with no redirect, then run verification.",
            },
    },
    201,
  );
}

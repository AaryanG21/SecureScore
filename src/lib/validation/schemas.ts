import { z } from "zod";
import { MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH } from "@/lib/auth/password";
import { normalizeHostname } from "@/lib/validation/hostname";

/**
 * Request schemas.
 *
 * Policy: reject, do not sanitize-and-continue. Silently "cleaning" input
 * means the thing that gets stored is not the thing the user sent, and it
 * is how filter-bypass bugs are born. The one place we transform rather
 * than reject is hostname normalization, which is a documented canonical
 * form (lowercase + IDNA) applied before any allowlist comparison — and it
 * still rejects anything that fails to canonicalize.
 */

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .email("Enter a valid email address");

export const passwordSchema = z
  .string()
  .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters`)
  .max(MAX_PASSWORD_LENGTH, "Password is too long");

export const totpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, "Enter the 6-digit code from your authenticator app");

export const backupCodeSchema = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/, "Enter a backup code in the form XXXX-XXXX");

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

export const twoFactorVerifySchema = z
  .object({
    code: totpCodeSchema.optional(),
    backupCode: backupCodeSchema.optional(),
  })
  .refine((v) => Boolean(v.code) !== Boolean(v.backupCode), {
    message: "Provide either a 6-digit code or a backup code, not both",
  });

export const reauthSchema = z.object({
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
  code: totpCodeSchema,
});

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
    newPassword: passwordSchema,
  })
  .refine((v) => v.currentPassword !== v.newPassword, {
    message: "Choose a password you have not used here before",
    path: ["newPassword"],
  });

/**
 * Hostname input for the authorization allowlist.
 *
 * This is the single most security-relevant validator in the app: it is
 * what stands between "scan a domain I proved I own" and "use this service
 * to scan someone else". It normalizes to a canonical form and rejects
 * anything ambiguous, rather than trying to strip bad characters out.
 */
export const hostnameSchema = z
  .string()
  .trim()
  .min(1, "Enter a hostname")
  .max(253, "Hostname is too long")
  .transform((value, ctx) => {
    const result = normalizeHostname(value);
    if (!result.ok) {
      ctx.addIssue({ code: "custom", message: result.reason });
      return z.NEVER;
    }
    return result.hostname;
  });

export const addDomainSchema = z.object({
  hostname: hostnameSchema,
  method: z.enum(["DNS_TXT", "HTTP_WELL_KNOWN"]).default("DNS_TXT"),
});

export const scanRequestSchema = z.object({
  domainId: z.string().min(1).max(64),
  /**
   * "Fix effort budget" in arbitrary effort points. The agent ranks
   * remediations and fills the budget greedily by risk-reduction per point.
   */
  budget: z.coerce.number().int().min(1).max(1000),
});

export const adminUserActionSchema = z.object({
  userId: z.string().min(1).max(64),
  reason: z.string().trim().min(3).max(500),
});

export const adminRevokeDomainSchema = z.object({
  domainId: z.string().min(1).max(64),
  reason: z.string().trim().min(3).max(500),
});

export const paginationSchema = z.object({
  cursor: z.string().max(64).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

/**
 * Parses a JSON request body against a schema.
 *
 * Returns a discriminated result rather than throwing, so routes handle
 * validation failure as an ordinary 400 path. Field errors are returned to
 * the client for form UX; they never echo the submitted values back.
 */
export async function parseJsonBody<S extends z.ZodType>(
  request: Request,
  schema: S,
): Promise<
  | { ok: true; data: z.infer<S> }
  | { ok: false; fieldErrors: Record<string, string[]> }
> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return { ok: false, fieldErrors: { _: ["Request body must be valid JSON"] } };
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const fieldErrors: Record<string, string[]> = {};
    for (const issue of parsed.error.issues) {
      const key = issue.path.join(".") || "_";
      (fieldErrors[key] ??= []).push(issue.message);
    }
    return { ok: false, fieldErrors };
  }

  return { ok: true, data: parsed.data };
}

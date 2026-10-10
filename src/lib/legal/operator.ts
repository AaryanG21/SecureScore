/**
 * Who operates this service, and how to reach them.
 *
 * ────────────────────────────────────────────────────────────────────────
 *  THIS IS THE ONE FILE TO EDIT BEFORE LAUNCH. Every legal page, the
 *  footer and the registration notice read from here, so the details
 *  cannot drift apart between documents.
 * ────────────────────────────────────────────────────────────────────────
 *
 * Why these specific fields: India's Digital Personal Data Protection Act
 * 2023 requires a Data Fiduciary — the person or entity deciding why and
 * how personal data is processed — to be identifiable, and to publish the
 * contact details of a person who answers questions and complaints about
 * that processing. A privacy policy signed by nobody, with no way to reach
 * anyone, does not satisfy that however well written it is.
 *
 * The placeholders are deliberately loud. `isConfigured` below is false
 * while any remain, and the legal pages render a visible warning rather
 * than quietly publishing "[YOUR NAME HERE]" to the internet.
 */

/** Replace every PLACEHOLDER value before the site goes public. */
export const OPERATOR = {
  /**
   * The Data Fiduciary. A personal name is fine — most of these pages are
   * operated by individuals, and claiming to be a company you have not
   * registered is worse than saying you are one person.
   */
  name: "PLACEHOLDER — your name or registered entity",

  /**
   * How the operator is constituted. Shown verbatim, so it should be true.
   * For a personal project: "an individual, not a registered company".
   */
  legalForm: "PLACEHOLDER — e.g. an individual, not a registered company",

  /** General contact. Must be monitored; it is published. */
  contactEmail: "PLACEHOLDER@example.com",

  /**
   * Where Data Principals (users) send questions, complaints, and erasure
   * requests. DPDP requires this to be published. It may be the same
   * address as above — what matters is that someone reads it.
   */
  grievanceEmail: "PLACEHOLDER@example.com",

  /**
   * Origin the service is served from, without a trailing slash. Used for
   * canonical URLs, the sitemap and the cookie scope description.
   */
  siteUrl: "https://PLACEHOLDER.example.com",

  /** Shown on the legal pages so a reader knows how current they are. */
  lastUpdated: "2026-10-11",

  /**
   * How long security audit records naming a person are kept before the
   * partition holding them is dropped. Stated in the privacy policy, so
   * this constant and that sentence can never disagree.
   */
  auditRetentionDays: 180,
} as const;

/** The jurisdiction the legal documents are written against. */
export const JURISDICTION = {
  country: "India",
  law: "Digital Personal Data Protection Act, 2023",
  lawShort: "DPDP Act",
  /** Minimum age to hold an account. See the registration age gate. */
  minimumAge: 18,
} as const;

/**
 * False while any placeholder survives.
 *
 * Checked by the legal pages, which render a warning banner instead of
 * publishing the placeholder text. A missing name on a privacy policy is
 * not a cosmetic problem — it is the difference between a document that
 * identifies a Data Fiduciary and one that does not.
 */
export const isConfigured: boolean = !Object.values(OPERATOR).some(
  (value) => typeof value === "string" && value.includes("PLACEHOLDER"),
);

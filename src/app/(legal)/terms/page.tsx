import Link from "next/link";
import { JURISDICTION, OPERATOR } from "@/lib/legal/operator";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Terms of service",
  description:
    "The rules for using Fulcrum: what you may scan, what you may not, and what the service does and does not promise.",
};

/**
 * Terms of service.
 *
 * The acceptable-use section is the one that does real work. Everything
 * else here is ordinary. Fulcrum can be pointed at a host the user does not
 * own — deliberately, in a narrow, throttled form — so the boundary between
 * that and unauthorised scanning has to be stated in the terms and not only
 * enforced in code. Enforcement without notice leaves someone who crosses
 * the line able to say nobody told them.
 */
export default function Terms() {
  return (
    <>
      <h1>Terms of service</h1>

      <p>
        These terms govern your use of Fulcrum, operated by {OPERATOR.name},{" "}
        {OPERATOR.legalForm}. By creating an account you accept them. If you do
        not, do not use the service.
      </p>

      <h2>Eligibility</h2>

      <p>
        You must be {JURISDICTION.minimumAge} or older. You confirm this when
        you register. Accounts belonging to people under{" "}
        {JURISDICTION.minimumAge} will be deleted.
      </p>

      <h2>The service</h2>

      <p>
        Fulcrum examines what a website exposes publicly — HTTP response
        headers, TLS configuration, and software versions a server advertises
        about itself — and returns a graded scorecard with a remediation plan
        ordered by how much risk each fix removes per unit of effort.
      </p>

      <p>It is free. There are no paid tiers, and no charges of any kind.</p>

      <h2>What you may scan</h2>

      <p>
        This is the most important section of these terms. There are two kinds
        of check, and they are treated differently because what they do to the
        target is different.
      </p>

      <h3>Full scans — only domains you control</h3>

      <p>
        A full scan includes a TLS examination that opens hundreds of
        connections to the target, probing cipher suites, protocol versions and
        renegotiation behaviour. In a target&rsquo;s logs this is
        indistinguishable from reconnaissance.
      </p>

      <p>
        You may therefore run a full scan <strong>only</strong> against a
        domain you have proven you control, by publishing a challenge we issue
        to its DNS or its web root. The service enforces this and refuses
        anything else. Proving control of a domain is not the same as being
        authorised to test it: if the domain belongs to an employer or a
        client, you are responsible for having their permission.
      </p>

      <h3>Headers-only checks — any public site</h3>

      <p>
        A headers-only check sends the target <strong>one</strong> HTTPS
        request and reads the response headers, which is what a browser does
        when anyone visits the page. No ownership proof is required for this,
        and no TLS probing happens.
      </p>

      <p>
        These checks are rate limited per account, limited per target across
        all accounts, and recent results are reused rather than refetched, so
        the service cannot be turned into a source of traffic against a site.
      </p>

      <h3>What you must not do</h3>

      <ul>
        <li>
          Use the service to generate traffic against any site, or to
          circumvent the rate limits above.
        </li>
        <li>
          Attempt to run a full scan against a domain you do not control,
          including by falsifying ownership verification.
        </li>
        <li>
          Use results to attack a system, or to assist anyone else in doing so.
        </li>
        <li>
          Scan systems where doing so is unlawful in your jurisdiction or the
          target&rsquo;s. Unauthorised scanning is a criminal offence in many
          countries, including under the Information Technology Act, 2000 in
          India.
        </li>
        <li>
          Probe, overload or attempt to break the service itself, or access
          another user&rsquo;s account or results.
        </li>
      </ul>

      <p>
        Refusals and abuse are logged. Accounts that break these rules may be
        suspended without notice.
      </p>

      <h2>What a grade does and does not mean</h2>

      <p>
        A good grade means the checks Fulcrum ran did not find a problem.{" "}
        <strong>It is not a statement that a site is secure</strong>, and no
        tool can make that statement.
      </p>

      <p>Fulcrum does not examine:</p>

      <ul>
        <li>application logic, authentication, or access control;</li>
        <li>your dependencies or supply chain;</li>
        <li>infrastructure, configuration or people;</li>
        <li>anything requiring credentials or reaching past the public surface.</li>
      </ul>

      <p>
        The vulnerability data is a small curated set covering common web
        server software, snapshotted rather than live. The absence of a CVE
        finding means nothing in that set matched — not that no known
        vulnerability exists. The scorecard says so on every result, and checks
        that fail to complete are shown as incomplete rather than clean.
      </p>

      <h2>Your account</h2>

      <p>
        Two-factor authentication is required. You are responsible for keeping
        your password, authenticator and backup codes safe, and for activity
        under your account.
      </p>

      <p>
        Recovery is by backup code only. If you lose your authenticator and
        your backup codes, access cannot be restored — we hold nothing that
        would let us verify your identity. This is a consequence of not
        collecting that information in the first place.
      </p>

      <h2>No warranty</h2>

      <p>
        The service is provided as it is, without warranty of any kind. It may
        be unavailable, may contain defects, and may report findings that are
        incomplete or wrong. Do not rely on it as your only assessment of a
        system&rsquo;s security.
      </p>

      <h2>Limitation of liability</h2>

      <p>
        To the extent permitted by law, {OPERATOR.name} is not liable for any
        indirect or consequential loss arising from your use of the service,
        including loss arising from a security issue it did not detect, from a
        finding that proved incorrect, or from acting on a remediation plan.
      </p>

      <p>
        Nothing here excludes liability that cannot lawfully be excluded.
      </p>

      <h2>Ending your use</h2>

      <p>
        You may delete your account at any time from the account page, which
        removes your data as described in the{" "}
        <Link href="/privacy">privacy policy</Link>. We may suspend or remove
        an account that breaks these terms, or stop offering the service
        entirely — it is free and comes with no commitment to continue.
      </p>

      <h2>Governing law</h2>

      <p>
        These terms are governed by the laws of {JURISDICTION.country}.
      </p>

      <h2>Contact</h2>

      <p>
        Questions about these terms:{" "}
        <a href={`mailto:${OPERATOR.contactEmail}`}>{OPERATOR.contactEmail}</a>.
      </p>
    </>
  );
}

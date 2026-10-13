import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * The CSP sets `style-src 'self' 'nonce-...'` with no 'unsafe-inline', and
 * nonces do not apply to attributes. So a server-rendered style attribute
 * is silently dropped by the browser: the element renders, just without the
 * geometry or colour that was supposed to be on it. Nothing throws and
 * nothing logs server-side, which is what makes it worth a test.
 *
 * This is the regression guard for the whole inline-SVG approach in
 * src/components/viz.tsx.
 */

describe("no inline style attributes reach the browser", () => {
  it("renders every public route without a style attribute", () => {
    // TODO: fetch /, /login, /register, /privacy, /terms, /cookies and
    // assert the HTML contains no `style="`
  });

  it("renders the scorecard without a style attribute", () => {
    // TODO: render Scorecard with representative findings and a plan;
    // this is where the data-driven geometry lives
  });

  it("keeps unsafe-inline out of style-src", () => {
    // TODO: build the header via buildCsp and assert style-src contains
    // neither 'unsafe-inline' nor 'unsafe-hashes'
  });
});

describe("known exception", () => {
  it("permits inline styles only in next/og image routes", () => {
    // TODO: opengraph-image / icon / apple-icon are rasterised to PNG by
    // Satori on the server, so their inline styles never reach a browser
    // and the CSP never applies to them. Assert these are the ONLY files
    // outside src/app/global-error.tsx that use style={{...}}.
    //
    // global-error.tsx is a real pre-existing violation, not an exception:
    // it renders unstyled in production. Tighten this test once fixed.
  });
});

import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * These cover src/components/viz.tsx, whose whole reason for existing is
 * that a strict style-src means geometry cannot travel through CSS. Every
 * number below is emitted as an SVG attribute, so these are assertions
 * about rendered markup — render with renderToStaticMarkup and read the
 * attributes off the output.
 *
 * The regression this file is really guarding: a graphic that disagrees
 * with the number printed next to it.
 */

describe("ScoreGauge", () => {
  it("draws an arc proportional to the score", () => {
    // TODO: score 41 -> stroke-dasharray first value is 0.41 * 2*PI*42
  });

  it("draws no arc at all for a score of zero", () => {
    // TODO: assert the progress circle is absent, not merely zero-length.
    // A round linecap paints a visible dot on a zero-length dash, which
    // reads as a nonzero score. This regressed once already.
  });

  it("draws a full circle at 100", () => {
    // TODO: dasharray first value === circumference
  });

  it("clamps out-of-range scores and reports the clamped value", () => {
    // TODO: -5 and 150 -> geometry clamped AND aria-label agrees with the
    // geometry rather than echoing the raw input
  });

  it("names the grade and score in its accessible label", () => {
    // TODO: role="img" with an aria-label carrying both
  });

  it("emits no style attribute", () => {
    // TODO: the rendered markup must contain no `style=` anywhere
  });
});

describe("SeverityBar", () => {
  it("uses the total count as its viewBox width so widths are literal counts", () => {
    // TODO: {critical:2, high:3} -> viewBox "0 0 5 1", widths 2 and 3
  });

  it("lays segments end to end without gaps or overlap", () => {
    // TODO: each rect's x equals the sum of all previous widths
  });

  it("orders segments worst-first", () => {
    // TODO: critical, high, medium, low, info
  });

  it("renders nothing when every count is zero", () => {
    // TODO: null, not an empty svg — a zero viewBox width divides by zero
  });

  it("does not inflate a small segment to a minimum width", () => {
    // TODO: 1 critical among 200 stays width 1. Deliberate: the bar must
    // not overstate what the count badges say.
  });
});

describe("BudgetMeter", () => {
  it("renders nothing for a zero or negative limit", () => {
    // TODO: null for limit 0 and limit -1
  });

  it("clamps an over-budget plan to a full bar and marks it", () => {
    // TODO: used 20 of 15 -> width 15, overflow tone, and the aria-label
    // still says "20 of 15" rather than the clamped number
  });
});

describe("RiskBar", () => {
  it("maps a 0-100 risk directly to width", () => {
    // TODO: risk 72 -> width 72 against a viewBox of 100
  });

  it("is hidden from assistive technology", () => {
    // TODO: aria-hidden — the numeral above it is the readout
  });
});

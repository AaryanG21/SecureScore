/**
 * Data visualisation, under a strict CSP.
 *
 * ── Why these are SVG and not styled divs ───────────────────────────────
 *
 * The obvious way to draw a bar is `style={{ width: "47%" }}`. It does not
 * work here. `style-src` carries a nonce but no 'unsafe-inline', and nonces
 * do not apply to attributes — so a server-rendered style attribute is
 * dropped by the browser and the bar renders at zero width. Weakening the
 * CSP to allow it is not on the table: "no third-party script, no inline
 * style" is a claim this product makes about itself on its own landing page.
 *
 * SVG geometry is the way through. `width`, `x`, `r` and `stroke-dasharray`
 * are XML presentation attributes, not CSS, so `style-src` never applies to
 * them. Every number below is computed on the server and emitted as an
 * attribute. Colour comes from Tailwind classes (an external stylesheet,
 * which `style-src 'self'` permits) or from `currentColor`.
 *
 * ── Why no module-level imports ─────────────────────────────────────────
 *
 * Nothing here imports anything and nothing uses a hook, so a client
 * component can import a single function from this file without dragging a
 * dependency graph across the server/client boundary with it.
 *
 * ── Honesty constraints ─────────────────────────────────────────────────
 *
 * Every graphic here sits beside the number it depicts; none of them is the
 * only readout of anything. And none of them animates from a neutral
 * starting value — a gauge sweeping up from zero displays, for a moment, a
 * score that is not the score.
 */

type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Worst first, so the eye meets the bad news at the left edge. */
const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

const SEVERITY_FILL: Record<Severity, string> = {
  critical: "fill-sev-critical",
  high: "fill-sev-high",
  medium: "fill-sev-medium",
  low: "fill-sev-low",
  info: "fill-sev-info",
};

const GRADE_TEXT: Record<string, string> = {
  A: "text-signal",
  B: "text-signal",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * The grade, with the score drawn around it.
 *
 * Replaces a plain letter in a box, and keeps that box's exact h-24 w-24
 * footprint so nothing on the scorecard moves.
 *
 * The arc is `stroke-dasharray` — a dash as long as the score followed by a
 * gap long enough to never repeat — rotated so that it starts at twelve
 * o'clock rather than three.
 */
export function ScoreGauge({
  score,
  grade,
  className = "h-24 w-24",
}: {
  score: number;
  grade: string;
  className?: string;
}) {
  const safeScore = clamp(Math.round(score), 0, 100);
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const filled = (safeScore / 100) * circumference;
  const tone = GRADE_TEXT[grade] ?? "text-ink-muted";

  return (
    <svg
      viewBox="0 0 100 100"
      className={`${className} ${tone}`}
      role="img"
      aria-label={`Grade ${grade}, score ${safeScore} out of 100`}
    >
      {/* Unfilled remainder, so the gauge reads as a proportion rather than
          a free-floating arc. */}
      <circle
        cx="50"
        cy="50"
        r={radius}
        fill="none"
        className="stroke-line-bright"
        strokeWidth={6}
      />
      {/* Omitted entirely at zero rather than drawn with a zero-length dash.
          A round linecap paints a cap even when the dash has no length, so
          score 0 rendered as a small dot at twelve o'clock — a mark on the
          gauge where the honest picture is nothing at all. */}
      {safeScore > 0 && (
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={6}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          transform="rotate(-90 50 50)"
        />
      )}
      <text
        x="50"
        y="50"
        textAnchor="middle"
        dominantBaseline="central"
        fill="currentColor"
        className="font-mono text-[2.5rem] font-bold"
      >
        {grade}
      </text>
    </svg>
  );
}

/**
 * Relative weight of findings by severity.
 *
 * The viewBox is the trick: setting it to the total count means one
 * user-space unit is one finding, so each rect's width attribute is the
 * literal count. No percentages, no rounding drift, no segment that is one
 * pixel wrong because of accumulated floating point.
 *
 * `preserveAspectRatio="none"` lets that square-ish coordinate space stretch
 * to a thin bar. Strokes would distort under that scaling, so this is fills
 * only.
 *
 * Deliberately NOT done: giving tiny counts a minimum width so they stay
 * visible. One critical finding among two hundred really is a sliver. The
 * count badges beside this bar are the authoritative readout; inflating the
 * sliver would make the picture disagree with them.
 */
export function SeverityBar({
  counts,
  className = "h-2 w-full",
}: {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}) {
  const present = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: Math.max(0, counts[severity] ?? 0),
  })).filter((entry) => entry.count > 0);

  const total = present.reduce((sum, entry) => sum + entry.count, 0);

  // Nothing to show, and a zero-width viewBox is a division by zero.
  if (total === 0) return null;

  // Prefix sums computed up front rather than accumulated inside the map.
  // Mutating a counter mid-render is the kind of thing that works until a
  // render is retried or interrupted and then silently draws the segments
  // on top of each other.
  const segments = present.reduce<
    { severity: Severity; x: number; width: number }[]
  >((acc, entry) => {
    const previous = acc[acc.length - 1];
    const x = previous ? previous.x + previous.width : 0;
    acc.push({ severity: entry.severity, x, width: entry.count });
    return acc;
  }, []);

  return (
    <svg
      viewBox={`0 0 ${total} 1`}
      preserveAspectRatio="none"
      className={`${className} overflow-hidden rounded-full`}
      role="img"
      aria-label={present.map((e) => `${e.count} ${e.severity}`).join(", ")}
    >
      {segments.map((segment) => (
        <rect
          key={segment.severity}
          x={segment.x}
          y={0}
          width={segment.width}
          height={1}
          className={SEVERITY_FILL[segment.severity]}
        />
      ))}
    </svg>
  );
}

/**
 * How much of the effort budget the remediation plan consumed.
 *
 * Same viewBox-as-scale technique: one unit is one budget point.
 */
export function BudgetMeter({
  used,
  limit,
  className = "h-1.5 w-full",
}: {
  used: number;
  limit: number;
  className?: string;
}) {
  // A zero or negative limit is not a meaningful denominator, and would
  // make the viewBox degenerate.
  if (!Number.isFinite(limit) || limit <= 0) return null;

  // The planner should never exceed the budget, but drawing off the end of
  // the canvas is a silent failure, whereas a full bar is at least true in
  // the direction it is wrong.
  const safeUsed = clamp(used, 0, limit);
  const over = used > limit;

  return (
    <svg
      viewBox={`0 0 ${limit} 1`}
      preserveAspectRatio="none"
      className={`${className} overflow-hidden rounded-full`}
      role="img"
      aria-label={`${used} of ${limit} effort points used`}
    >
      <rect x={0} y={0} width={limit} height={1} className="fill-line-bright" />
      <rect
        x={0}
        y={0}
        width={safeUsed}
        height={1}
        className={over ? "fill-sev-high" : "fill-signal"}
      />
    </svg>
  );
}

/**
 * A finding's composite risk, 0-100.
 *
 * Sits under the numeral in the findings table rather than beside it, so
 * the column keeps its width.
 */
export function RiskBar({
  risk,
  className = "h-1 w-10",
}: {
  risk: number;
  className?: string;
}) {
  const safeRisk = clamp(risk, 0, 100);
  const tone =
    safeRisk >= 70 ? "fill-sev-critical" : safeRisk >= 40 ? "fill-sev-high" : "fill-sev-low";

  return (
    <svg
      viewBox="0 0 100 1"
      preserveAspectRatio="none"
      className={`${className} overflow-hidden rounded-full`}
      aria-hidden="true"
    >
      <rect x={0} y={0} width={100} height={1} className="fill-line-bright" />
      <rect x={0} y={0} width={safeRisk} height={1} className={tone} />
    </svg>
  );
}

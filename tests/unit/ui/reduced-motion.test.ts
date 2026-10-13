import { describe, it } from "vitest";

/**
 * SCAFFOLD ONLY — assertions are hand-written by the project author.
 *
 * Read src/app/globals.css as text and assert on the rules it declares.
 *
 * Why this file exists: the global reduced-motion block zeroes
 * animation-DURATION but not animation-NAME. A zeroed animation does not
 * stop — it jumps to its final keyframe. For the sweep bar that means the
 * segment parks off the end of its track and a reduced-motion user is left
 * looking at an empty box where the busy indicator should be. Every
 * animated class therefore needs its own declared resting state, and it is
 * easy to add a fourth animation later and forget.
 */

describe("reduced-motion resting states", () => {
  it("declares a resting state for every animated class", () => {
    // TODO: for each class with an `animation:` rule (.spin, .sweep,
    // .pulse), assert a matching rule inside a prefers-reduced-motion
    // block. Derive the list from the file; do not hard-code it, or the
    // test cannot catch the animation someone adds next.
  });

  it("leaves the sweep track visibly filled rather than empty", () => {
    // TODO: the reduced-motion .sweep rule sets width 100% and no translate
  });

  it("orders the resting states after the global kill switch", () => {
    // TODO: the specific rules must appear later in the file than the
    // `*` block, or they lose the !important tie-break
  });

  it("starts no animation from a state that hides content", () => {
    // TODO: no @keyframes in the file has a 0%/from frame with opacity 0
    // or a transform that moves content out of view. If an animation never
    // runs, the content must already be correct.
  });
});

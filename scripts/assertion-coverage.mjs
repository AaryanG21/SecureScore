#!/usr/bin/env node
/**
 * Counts assertions per test file and prints a summary.
 *
 * Why this exists: every assertion in tests/ is hand-written by the
 * author, and the committed files are scaffolds whose `it` bodies are
 * `// TODO` comments. Vitest treats an empty test body as a pass, so the
 * suite reports hundreds of passing tests while verifying nothing.
 *
 * That is disclosed in tests/README.md and in the main README, but a CI
 * run showing a green suite undoes the disclosure — nobody reads a
 * caveat in a file when the badge says passing. This turns it into a
 * number.
 *
 * It never fails the build. Enforcing a threshold would block all work
 * until the assertions are written; the goal is visibility, not a gate.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const TESTS = join(ROOT, "tests");

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith(".test.ts") || entry.endsWith(".test.tsx")) out.push(full);
  }
  return out;
}

let files;
try {
  files = walk(TESTS).sort();
} catch {
  console.log("No tests directory; nothing to report.");
  process.exit(0);
}

const rows = files.map((file) => {
  const source = readFileSync(file, "utf8");
  const cases = (source.match(/\bit\s*\(/g) ?? []).length;
  const asserts = (source.match(/\bexpect\s*\(/g) ?? []).length;
  return { file: relative(ROOT, file), cases, asserts };
});

const totalCases = rows.reduce((n, r) => n + r.cases, 0);
const totalAsserts = rows.reduce((n, r) => n + r.asserts, 0);
const written = rows.filter((r) => r.asserts > 0).length;

const width = Math.max(...rows.map((r) => r.file.length), 4);
const lines = [
  "Assertion coverage — assertions are hand-written, so this is progress, not a gate.",
  "",
  `${"file".padEnd(width)}  cases  expect()`,
  `${"-".repeat(width)}  -----  --------`,
  ...rows.map(
    (r) => `${r.file.padEnd(width)}  ${String(r.cases).padStart(5)}  ${String(r.asserts).padStart(8)}`,
  ),
  `${"-".repeat(width)}  -----  --------`,
  `${"total".padEnd(width)}  ${String(totalCases).padStart(5)}  ${String(totalAsserts).padStart(8)}`,
  "",
  `${written} of ${rows.length} files have at least one assertion.`,
];

if (totalAsserts === 0) {
  lines.push(
    "",
    "Every test body is still a TODO. The suite passes vacuously: a green run",
    "here means the imports resolve, not that anything is verified.",
  );
}

const report = lines.join("\n");
console.log(report);

// Surface it on the workflow summary page too, where it is actually seen.
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFileSync } = await import("node:fs");
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    `## Assertion coverage\n\n\`\`\`\n${report}\n\`\`\`\n`,
  );
}

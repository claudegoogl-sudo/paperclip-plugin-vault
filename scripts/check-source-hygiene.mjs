#!/usr/bin/env node
// Internal ticket ids and real infra/vault namespace strings have no
// business in first-party plugin source that ships to a public repo.
// Scoped to src/ and tests/ only, so CONTRIBUTING.md (which legitimately
// quotes these forbidden patterns to document this rule) never trips it.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOTS = ["src", "tests"].filter((dir) => {
  try {
    return statSync(dir).isDirectory();
  } catch {
    return false;
  }
});

const TICKET_ID_RE = new RegExp("\\bPLA" + "-\\d{1,5}\\b");
const NAMESPACE_STRINGS = [
  "host-secrets",
  "github-pats",
  "cloudflared-cert",
  "company-pla",
  "company-dpr",
  "Platform Operations",
];
const NAMESPACE_RE = new RegExp(
  NAMESPACE_STRINGS.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"),
  "i",
);

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

const offenders = [];
for (const root of ROOTS) {
  for (const file of walk(root)) {
    const text = readFileSync(file, "utf8");
    if (TICKET_ID_RE.test(text) || NAMESPACE_RE.test(text)) {
      offenders.push(file);
    }
  }
}

if (offenders.length > 0) {
  console.error("Internal ticket ids or real namespace strings found in source:");
  for (const file of offenders) console.error(`  ${file}`);
  console.error(
    "\nRewrite the offending comment/string to plain English or a neutral example before merging.",
  );
  process.exit(1);
}

console.log(`Source hygiene check passed (${ROOTS.join(", ")}).`);

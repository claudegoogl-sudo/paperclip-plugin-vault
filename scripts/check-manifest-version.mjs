#!/usr/bin/env node
/**
 * Manifest-version drift gate.
 *
 * Imports the built plugin manifest (resolved via
 * `package.json.paperclipPlugin.manifest`, mirroring
 * `scripts/validate-manifest.mjs`) and asserts
 * `manifest.version === package.json.version`.
 *
 * The fix here is structural: `src/manifest.ts` references the
 * esbuild-injected `__PLUGIN_VERSION__` constant, so the only way the
 * two can desynchronise is if the build pipeline regresses (e.g. the
 * `define` is removed, or someone reintroduces a hardcoded literal).
 * This gate makes that regression a non-zero exit before the package is
 * released. Wired into the `postbuild` lifecycle so it runs on every
 * `npm run build`, and called as a final step in the
 * `manifest-validate.yml` CI workflow.
 *
 * Exit codes:
 *   0 — versions match
 *   1 — drift detected (manifest.version !== pkg.version)
 *   2 — unexpected error (missing manifest, missing version, etc.)
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

async function loadPackageJson() {
  const pkgPath = resolve(REPO_ROOT, "package.json");
  const pkg = JSON.parse(await readFile(pkgPath, "utf8"));
  if (typeof pkg.version !== "string" || pkg.version.length === 0) {
    throw new Error(`package.json is missing a string 'version' field.`);
  }
  const manifestRel = pkg?.paperclipPlugin?.manifest;
  if (typeof manifestRel !== "string" || manifestRel.length === 0) {
    throw new Error(
      `package.json is missing 'paperclipPlugin.manifest' (got ${JSON.stringify(manifestRel)}).`,
    );
  }
  return { pkg, manifestRel };
}

async function loadBuiltManifest(manifestRel) {
  const manifestAbs = resolve(REPO_ROOT, manifestRel);
  if (!existsSync(manifestAbs)) {
    throw new Error(`Built manifest not found at ${manifestAbs}. Run 'npm run build' first.`);
  }
  const mod = await import(pathToFileURL(manifestAbs).href);
  const manifest = mod?.default ?? mod;
  if (!manifest || typeof manifest !== "object") {
    throw new Error(`Built manifest at ${manifestAbs} did not export an object.`);
  }
  return { manifest, manifestAbs };
}

async function main() {
  const { pkg, manifestRel } = await loadPackageJson();
  const { manifest, manifestAbs } = await loadBuiltManifest(manifestRel);
  const manifestVersion = manifest.version;
  if (typeof manifestVersion !== "string" || manifestVersion.length === 0) {
    console.error(
      `[check-manifest-version] FAILED — manifest.version is not a non-empty string ` +
        `(got ${JSON.stringify(manifestVersion)}). Source file: ${manifestAbs}.`,
    );
    return 1;
  }
  if (manifestVersion !== pkg.version) {
    console.error(
      `[check-manifest-version] FAILED — version drift detected.\n` +
        `  package.json.version : ${pkg.version}\n` +
        `  manifest.version     : ${manifestVersion}\n` +
        `  built manifest       : ${manifestAbs}\n` +
        `\nFix: ensure src/manifest.ts references the build-time-injected ` +
        `__PLUGIN_VERSION__ constant and esbuild.config.mjs defines it ` +
        `from package.json.version.`,
    );
    return 1;
  }
  console.log(
    `[check-manifest-version] OK — ${manifestVersion} (package.json ↔ ${manifestAbs}).`,
  );
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("[check-manifest-version] unexpected error:", err?.stack ?? err);
    process.exit(2);
  });

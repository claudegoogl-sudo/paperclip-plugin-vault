#!/usr/bin/env node
/**
 * Release-time plugin manifest validation gate.
 *
 * Runs the host plugin-manifest validator against the built
 * `dist/manifest.js` BEFORE a tarball can be packed/published. v0.1.1
 * of plugin-cad shipped with `cad:run_script` tool names that the
 * current host validator rejects, and the release passed CI before
 * the operator's install attempt revealed the manifest was unloadable.
 * This gate makes the same class of regression a build failure.
 *
 * Resolves the manifest module via package.json's `paperclipPlugin.manifest`
 * field (per PLUGIN_SPEC §10.1). Wired into:
 *   - `npm run validate:manifest` (developer ergonomic)
 *   - `prepack` lifecycle hook (blocks `npm pack` / `npm publish`)
 *   - `.github/workflows/manifest-validate.yml` (PR + push gate)
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { pluginManifestV1Schema } from "@paperclipai/shared/validators/plugin";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

/**
 * Tool-name allowlist — mirrored from the host validator's
 * `pluginToolDeclarationSchema.name` regex. Tool names are namespaced
 * at runtime as `<plugin-id>:<tool-name>`, so the bare name must not
 * contain `:`. A lowercase alnum allowlist also keeps whitespace,
 * control chars, path separators, and unicode lookalikes out of the
 * registry key. Mirrored here so the gate matches host behaviour even
 * when the published `@paperclipai/shared` lags the fork validator.
 */
const TOOL_NAME_REGEX = /^[a-z0-9][a-z0-9._-]*$/;
const TOOL_NAME_REGEX_MESSAGE =
  "Tool name must start with a lowercase alphanumeric and contain only " +
  "lowercase letters, digits, dots, hyphens, or underscores (no ':')";

export function validateManifest(manifest) {
  const errors = [];
  const parsed = pluginManifestV1Schema.safeParse(manifest);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const p = issue.path.length > 0 ? issue.path.join(".") : "<root>";
      errors.push(`[zod] ${p}: ${issue.message}`);
    }
  }
  const m = typeof manifest === "object" && manifest !== null ? manifest : {};
  if (Array.isArray(m.tools)) {
    m.tools.forEach((tool, idx) => {
      const name = tool && typeof tool === "object" ? tool.name : undefined;
      if (typeof name !== "string" || !TOOL_NAME_REGEX.test(name)) {
        errors.push(
          `[tool-name] tools[${idx}].name=${JSON.stringify(name)}: ${TOOL_NAME_REGEX_MESSAGE}`,
        );
      }
    });
  }
  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

async function loadManifestFromPackageJson() {
  const pkgPath = resolve(REPO_ROOT, "package.json");
  const pkg = JSON.parse(await readFile(pkgPath, "utf8"));
  const manifestRel = pkg?.paperclipPlugin?.manifest;
  if (typeof manifestRel !== "string" || manifestRel.length === 0) {
    throw new Error(
      `package.json is missing 'paperclipPlugin.manifest' (got ${JSON.stringify(manifestRel)}).`,
    );
  }
  const manifestAbs = resolve(REPO_ROOT, manifestRel);
  if (!existsSync(manifestAbs)) {
    throw new Error(`Built manifest not found at ${manifestAbs}. Run 'npm run build' first.`);
  }
  const mod = await import(pathToFileURL(manifestAbs).href);
  return { manifest: mod?.default ?? mod, manifestAbs };
}

async function main() {
  const { manifest, manifestAbs } = await loadManifestFromPackageJson();
  const result = validateManifest(manifest);
  if (result.ok) {
    const toolCount = Array.isArray(manifest?.tools) ? manifest.tools.length : 0;
    console.log(`[validate-manifest] OK — ${manifestAbs} (tools: ${toolCount}).`);
    return 0;
  }
  console.error(`[validate-manifest] FAILED — ${manifestAbs}:`);
  for (const err of result.errors) console.error(`  - ${err}`);
  console.error(
    "\nHost validator source: packages/shared/src/validators/plugin.ts (pluginManifestV1Schema).",
  );
  return 1;
}

const isDirectInvocation = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return pathToFileURL(resolve(entry)).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (isDirectInvocation) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error("[validate-manifest] unexpected error:", err);
      process.exit(2);
    });
}

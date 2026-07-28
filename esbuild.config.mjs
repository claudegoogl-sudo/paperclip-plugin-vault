import esbuild from "esbuild";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPluginBundlerPresets } from "@paperclipai/plugin-sdk/bundlers";

const REPO_ROOT = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  await readFile(resolve(REPO_ROOT, "package.json"), "utf8"),
);
const define = {
  __PLUGIN_VERSION__: JSON.stringify(pkg.version),
};

const presets = createPluginBundlerPresets({});
const watch = process.argv.includes("--watch");

// The SDK preset defaults to `sourcemap: true`, which inlines every original
// TypeScript file the bundle pulls in — this plugin plus the vendored
// @paperclipai/shared and plugin-sdk fork source — into `dist/*.map`.
// `package.json` ships `dist` verbatim, so those maps would land in the packed
// tarball. "external" keeps the map on disk for local debugging but drops the
// sourcemap footer; the `files` negation keeps `dist/**/*.map` out of the
// package.
const sourcemap = "external";

// Source comments carry internal engineering context (tracker ids, design
// notes) that has no business in a published artifact. esbuild's
// `legalComments` only governs license/@preserve banners, so it does not
// help here; `minifyWhitespace` drops every ordinary comment while leaving
// identifier names intact. Names matter: the post-build gates in
// `scripts/` re-parse the emitted bundles, so full `minify` would buy
// nothing and risk breaking them.
const minifyWhitespace = true;

const workerCtx = await esbuild.context({
  ...presets.esbuild.worker,
  sourcemap,
  minifyWhitespace,
  define: { ...(presets.esbuild.worker.define ?? {}), ...define },
});
const manifestCtx = await esbuild.context({
  ...presets.esbuild.manifest,
  sourcemap,
  minifyWhitespace,
  define: { ...(presets.esbuild.manifest.define ?? {}), ...define },
});

if (watch) {
  await Promise.all([workerCtx.watch(), manifestCtx.watch()]);
  console.log("esbuild watch mode enabled for worker and manifest");
} else {
  await Promise.all([workerCtx.rebuild(), manifestCtx.rebuild()]);
  await Promise.all([workerCtx.dispose(), manifestCtx.dispose()]);
}

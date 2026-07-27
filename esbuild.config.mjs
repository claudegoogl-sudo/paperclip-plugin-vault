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

const workerCtx = await esbuild.context({
  ...presets.esbuild.worker,
  define: { ...(presets.esbuild.worker.define ?? {}), ...define },
});
const manifestCtx = await esbuild.context({
  ...presets.esbuild.manifest,
  define: { ...(presets.esbuild.manifest.define ?? {}), ...define },
});

if (watch) {
  await Promise.all([workerCtx.watch(), manifestCtx.watch()]);
  console.log("esbuild watch mode enabled for worker and manifest");
} else {
  await Promise.all([workerCtx.rebuild(), manifestCtx.rebuild()]);
  await Promise.all([workerCtx.dispose(), manifestCtx.dispose()]);
}

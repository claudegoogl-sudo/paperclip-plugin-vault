import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const REPO_ROOT = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf8"));

export default defineConfig({
  define: {
    __PLUGIN_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    include: ["tests/*.spec.ts"],
    // tests/integration/** reaches a live vault; it must never run on a public CI runner.
    exclude: ["**/node_modules/**", "**/dist/**", "tests/integration/**"],
    environment: "node",
  },
});

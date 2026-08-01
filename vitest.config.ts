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
    // crypto.spec.ts's KAT fixtures run real 600k+-iteration PBKDF2 through
    // VaultwardenBackend.unlock() (async, via the libuv threadpool) — under
    // load that can take several seconds of wall-clock time even though it
    // never blocks the event loop. The 5s vitest default is too tight for
    // that on a busy runner; a genuine hang is still caught well within 30s.
    testTimeout: 30_000,
  },
});

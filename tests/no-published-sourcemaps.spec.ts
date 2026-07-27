import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// Sourcemaps inline the full original TypeScript of everything the bundle
// pulls in — this plugin plus the host packages — under a `sourcesContent`
// key. Release tarballs are attached to public GitHub releases, so shipping
// the maps publishes that source. The build still writes them to dist/ for
// local debugging; this asserts they never reach the tarball.
//
// The scanned needles are spelled as JSON-key / footer forms so this file's
// own prose cannot trip the check if it ever ends up packaged.
const SOURCES_CONTENT_KEY = `"sourcesContent"`;
const SOURCE_MAPPING_FOOTER = `sourceMappingURL=`;

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(REPO_ROOT, "dist");
const tempDirs: string[] = [];

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function npmPack(args: string[]): string {
  return execFileSync("npm", ["pack", "--ignore-scripts", ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("published tarball", () => {
  it("is built, and still emits sourcemaps on disk for local debugging", () => {
    expect(statSync(join(DIST, "worker.js")).isFile()).toBe(true);
    expect(walk(DIST).filter((f) => f.endsWith(".map")).length).toBeGreaterThan(0);
  });

  it("packs no sourcemap entries", () => {
    const listed = JSON.parse(npmPack(["--dry-run", "--json"])) as Array<{
      files: Array<{ path: string }>;
    }>;
    const paths = listed[0].files.map((f) => f.path);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.filter((p) => p.endsWith(".map"))).toEqual([]);
  });

  it("packs no file carrying inlined sources or a sourcemap footer", () => {
    const dest = mkdtempSync(join(tmpdir(), "pack-"));
    tempDirs.push(dest);
    const tarball = npmPack(["--pack-destination", dest]).trim().split("\n").pop()!;
    execFileSync("tar", ["-xzf", join(dest, tarball), "-C", dest]);

    const offenders = walk(join(dest, "package")).filter((file) => {
      const text = readFileSync(file, "utf8");
      return text.includes(SOURCES_CONTENT_KEY) || text.includes(SOURCE_MAPPING_FOOTER);
    });
    expect(offenders.map((f) => f.slice(dest.length + 1))).toEqual([]);
  });
}, 180_000);

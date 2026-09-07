import {
  createCipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createVaultRuntimeResolver } from "../src/worker.js";
import { hkdfExpand } from "../src/worker/VaultwardenBackend.js";

/**
 * Regression test for the concurrent-unlock / thundering-herd finding from
 * the PR #9 security review: making session priming fire-and-forget (so it
 * never blocks worker activation) introduced a window where a burst of
 * concurrent dispatches landing on a cold/expiring cache each independently
 * cleared and re-primed the shared `VaultwardenBackend`, which had no
 * in-flight guard — every dispatch would run its own prelogin + password
 * resolve + PBKDF2 + token exchange + `/api/sync` against the same
 * Vaultwarden service account. Ordinary legitimate concurrent load right
 * after a cold start (or a config edit) could trip Vaultwarden's own login
 * rate limiting and lock the plugin out for every tenant.
 *
 * Fixed by single-flighting `VaultwardenBackend.unlock()` (all callers
 * converge on one in-progress unlock) and having the TTL-reprime branch in
 * `createVaultRuntimeResolver` piggyback on an already in-flight prime
 * instead of clearing state and starting a duplicate.
 */

const EMAIL = "vault-svc@paperclip.local";
const PASSWORD = "correct horse battery staple";
const ITERATIONS = 600_000;

/** Encrypt a buffer as a type-2 (AesCbc256_HmacSha256_B64) EncString. */
function encType2(plaintext: Buffer, enc: Buffer, mac: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", enc, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const m = createHmac("sha256", mac).update(iv).update(ct).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${m.toString("base64")}`;
}

function buildTokenPayload() {
  const masterKey = pbkdf2Sync(
    Buffer.from(PASSWORD, "utf8"),
    Buffer.from(EMAIL, "utf8"),
    ITERATIONS,
    32,
    "sha256",
  );
  const stretchedEnc = hkdfExpand(masterKey, "enc", 32);
  const stretchedMac = hkdfExpand(masterKey, "mac", 32);
  const userEnc = randomBytes(32);
  const userMac = randomBytes(32);
  const protectedUserKey = encType2(
    Buffer.concat([userEnc, userMac]),
    stretchedEnc,
    stretchedMac,
  );
  return {
    access_token: "access-token",
    expires_in: 3600,
    Key: protectedUserKey,
    Kdf: 0,
    KdfIterations: ITERATIONS,
  };
}

function res(obj: unknown) {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function fakeLogger() {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  };
}

function fakeCtx(config: Record<string, unknown>) {
  return {
    config: { get: async () => config },
    logger: fakeLogger(),
    secrets: { resolve: async () => PASSWORD, resolveService: async () => PASSWORD },
    http: {} as never,
    activity: { log: async () => {} },
  };
}

describe("concurrent dispatches share one unlock instead of a thundering herd", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("N concurrent resolveRuntime('read') calls against a fresh cold resolver hit prelogin/token/sync exactly once", async () => {
    const token = buildTokenPayload();
    const callCounts = { prelogin: 0, token: 0, sync: 0 };

    // Production traffic runs through ctx.http.fetch (the host-mediated
    // client), never globalThis.fetch — so the single-flight mock has to
    // sit on http.fetch, otherwise it would never be hit.
    const httpFetch = vi.fn(async (url: string | URL) => {
      const u = String(url);
      if (u.endsWith("/api/accounts/prelogin")) {
        callCounts.prelogin++;
        return res({ kdf: 0, kdfIterations: ITERATIONS });
      }
      if (u.endsWith("/identity/connect/token")) {
        callCounts.token++;
        return res(token);
      }
      if (u.endsWith("/api/sync")) {
        callCounts.sync++;
        return res({ Profile: { Organizations: [] }, Collections: [], Ciphers: [] });
      }
      return new Response("unexpected path", { status: 404 });
    });

    const ctx = fakeCtx({
      serviceAccountEmail: EMAIL,
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://**"],
    });
    (ctx as { http: unknown }).http = { fetch: httpFetch };

    const resolveRuntime = createVaultRuntimeResolver(ctx as never);

    const CONCURRENCY = 8;
    const results = await Promise.all(
      Array.from({ length: CONCURRENCY }, () => resolveRuntime("read")),
    );

    expect(results.every((r) => r.ok)).toBe(true);
    expect(callCounts.prelogin).toBe(1);
    expect(callCounts.token).toBe(1);
    expect(callCounts.sync).toBe(1);
  });
});

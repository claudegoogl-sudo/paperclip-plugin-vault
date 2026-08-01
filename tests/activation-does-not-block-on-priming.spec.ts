import { afterEach, describe, expect, it, vi } from "vitest";
import { createVaultWorker } from "../src/worker.js";

/**
 * The host's worker `initialize` RPC has a fixed, non-tunable ~15s budget.
 * `setup()` must register tools and return well inside that budget even when
 * the Vaultwarden session prime (a network round-trip plus a 600k+-iteration
 * PBKDF2 derivation) is slow or never resolves. Before this fix,
 * `createVaultRuntimeResolver`'s cold-build branch did `await backend.prime()`
 * on the same path `createVaultWorker` awaits for "setup" — so a slow/hung
 * prime blocked `setup()` from ever returning, deterministically overrunning
 * the activation budget once the prime source (network + libuv threadpool KDF)
 * took long enough to reach it within the window.
 */

function fakeLogger() {
  const logs: Array<{ level: string; message: string; meta?: unknown }> = [];
  return {
    logs,
    logger: {
      info: (m: string, meta?: unknown) => logs.push({ level: "info", message: m, meta }),
      warn: (m: string, meta?: unknown) => logs.push({ level: "warn", message: m, meta }),
      error: (m: string, meta?: unknown) => logs.push({ level: "error", message: m, meta }),
      debug: (m: string, meta?: unknown) => logs.push({ level: "debug", message: m, meta }),
    },
  };
}

function fakeCtx(config: Record<string, unknown>) {
  const { logger, logs } = fakeLogger();
  const registered = new Map<string, unknown>();
  const ctx = {
    config: { get: async () => config },
    logger,
    secrets: { resolve: async () => "unused-master-password" },
    http: {} as never,
    activity: { log: async () => {} },
    tools: {
      register: (name: string, declaration: unknown, handler: unknown) => {
        registered.set(name, { declaration, handler });
      },
    },
  };
  return { ctx, logs, registered };
}

describe("createVaultWorker does not block activation on session priming", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("setup() resolves promptly even when the prelogin fetch never resolves (simulates a slow/hung KDF+network prime)", async () => {
    // A fetch that never settles stands in for "priming takes longer than
    // the activation budget" without actually waiting that long in the test.
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );

    const { ctx, registered } = fakeCtx({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://ORG/coll/*"],
    });

    const ACTIVATION_BUDGET_MS = 15_000;
    const SAFETY_MARGIN_MS = 500;

    const result = await Promise.race([
      createVaultWorker(ctx as never),
      new Promise<"timed_out">((resolve) =>
        setTimeout(() => resolve("timed_out"), ACTIVATION_BUDGET_MS - SAFETY_MARGIN_MS),
      ),
    ]);

    expect(result).not.toBe("timed_out");
    // A constructed (if not yet warm) backend, returned without waiting on
    // the hung prime.
    expect((result as Awaited<ReturnType<typeof createVaultWorker>>).backend).not.toBeNull();
    // Tools must be registered regardless of prime state (AC4).
    expect(registered.has("vault.read")).toBe(true);
    expect(registered.has("vault.list")).toBe(true);
  });
});

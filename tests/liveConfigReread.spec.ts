/**
 * `vault.read` / `vault.list` must re-read config (allowList, handleMode,
 * companyPolicies) from `ctx.config.get()` on EVERY dispatch, never off a
 * value captured once at setup(). A single worker process interleaves
 * dispatches for many tenant companies, so a config change (an operator
 * editing an allowList or companyPolicies entry) — or a plugin that finishes
 * being configured after the worker already booted unconfigured — must be
 * reflected on the very next tool call, with no worker restart. These drive
 * the RPC surface through the SDK test harness and use `harness.setConfig()`
 * to mutate config BETWEEN dispatches with no re-registration in between,
 * proving the read happens inside the handler.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { createTestHarness } from "@paperclipai/plugin-sdk/testing";
import { createVaultWorker } from "../src/worker.js";
import { policyDenyMessage } from "../src/worker/registerTools.js";
import { InMemoryVaultBackend } from "../src/worker/VaultBackend.js";
import manifest from "../src/manifest.js";

const CAPABILITIES = [
  "http.outbound",
  "secrets.read-ref",
  "agent.tools.register",
  "activity.log.write",
] as const;

function setupHarness(initialConfig: Record<string, unknown>) {
  const backend = new InMemoryVaultBackend();
  backend.set(
    { org: "EXAMPLE", collection: "svc-secrets", item: "tunnel-cert" },
    "tunnel-token-1234",
  );
  backend.set({ org: "OTHER", collection: "ci", item: "pat" }, "other-secret");

  const harness = createTestHarness({
    manifest,
    capabilities: [...CAPABILITIES],
    config: initialConfig,
  });

  const readTool = (companyId: string, secretRef: string) =>
    harness.executeTool<{ data?: unknown; error?: string; content?: string }>(
      "vault.read",
      { secretRef },
      { companyId },
    );

  return { harness, backend, readTool };
}

describe("vault config gates are re-read live on every dispatch (no setup-time caching)", () => {
  it("picks up a companyPolicies ENTRY widened AFTER setup, on the very next call, with no worker restart", async () => {
    // Live-reread must hold for the only grant source there is: the map
    // entry. Widening the entry (map present throughout) is honored on the
    // next dispatch.
    const configWith = (entryAllowList: string[]) => ({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://**"],
      companyPolicies: { "company-a": { allowList: entryAllowList } },
    });
    const { harness, backend, readTool } = setupHarness(
      configWith(["vault://EXAMPLE/svc-secrets/other-item"]),
    );
    await createVaultWorker(harness.ctx, {
      backendOverride: backend,
    });

    const before = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(before.error).toMatch(/^prerequisite_missing/);

    // Operator widens the ENTRY — no re-registration / worker restart.
    harness.setConfig(configWith(["vault://EXAMPLE/svc-secrets/*"]));

    const after = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(after.error).toBeUndefined();
  });

  it("self-heals a worker that booted unconfigured once a FULL config (including the companyPolicies map) arrives, with no restart", async () => {
    const { harness, backend, readTool } = setupHarness({});
    await createVaultWorker(harness.ctx, {
      backendOverride: backend,
    });

    const before = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(before.error).toMatch(/^prerequisite_missing/);

    harness.setConfig({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
      },
    });

    const after = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(after.error).toBeUndefined();
  });

  it("denies the very next call when an operator DELETES companyPolicies live — even with the instance allowList intact (drift shape A)", async () => {
    const configured = {
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
      },
    };
    const { harness, backend, readTool } = setupHarness(configured);
    await createVaultWorker(harness.ctx, {
      backendOverride: backend,
    });

    const granted = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(granted.error).toBeUndefined();

    // The drift: the map is deleted; the instance-level allowList survives
    // untouched. Pre-0.2.0 the next call SUCCEEDED via the top-level
    // fallback; now it must deny loudly on the very next dispatch.
    harness.setConfig({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
    });

    const after = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(after.error).toBe(policyDenyMessage("policymap_missing"));
    // Loud per call + the ordinary audit/alarm channel still fires.
    expect(
      harness.logs.some(
        (e) => e.level === "error" && e.message === "vault.policymap_missing",
      ),
    ).toBe(true);
    expect(
      harness.activity.some(
        (a) =>
          a.entityType === "vault.read" &&
          a.metadata?.outcome === "denied_by_allowlist",
      ),
    ).toBe(true);
  });

  it("denies the very next call when a live edit strips allowList from an entry (drift shape B)", async () => {
    const configured = {
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
      },
    };
    const { harness, backend, readTool } = setupHarness(configured);
    await createVaultWorker(harness.ctx, {
      backendOverride: backend,
    });

    const granted = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(granted.error).toBeUndefined();

    // The drift: the entry survives but loses its allowList (and even asks
    // for handleMode). Entries never inherit — the next call denies.
    harness.setConfig({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: { "company-a": { handleMode: true } },
    });

    const after = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(after.error).toBe(policyDenyMessage("entry_missing_allowlist"));
    expect(
      harness.logs.some(
        (e) =>
          e.level === "error" &&
          e.message === "vault.policy_entry_missing_allowlist" &&
          e.meta?.companyId === "company-a",
      ),
    ).toBe(true);
  });

  it("two companies each resolve their OWN live companyPolicies entry, not a value cached from the other's dispatch", async () => {
    const { harness, backend, readTool } = setupHarness({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://**"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
        "company-b": { allowList: ["vault://OTHER/ci/*"] },
      },
    });
    await createVaultWorker(harness.ctx, {
      backendOverride: backend,
    });

    // Seed both companies' state by dispatching company-a first.
    const aOwn = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(aOwn.error).toBeUndefined();
    const aCrossTenant = await readTool("company-a", "vault://OTHER/ci/pat");
    expect(aCrossTenant.error).toMatch(/^prerequisite_missing/);

    // company-b's very next dispatch must resolve ITS OWN policy, not
    // company-a's (which just ran on this same worker process).
    const bOwn = await readTool("company-b", "vault://OTHER/ci/pat");
    expect(bOwn.error).toBeUndefined();
    const bCrossTenant = await readTool("company-b", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(bCrossTenant.error).toMatch(/^prerequisite_missing/);

    // An operator now swaps the two companies' grants — live, no restart —
    // and the very next dispatch for each sees its NEW policy, not the one
    // observed above.
    harness.setConfig({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://**"],
      companyPolicies: {
        "company-a": { allowList: ["vault://OTHER/ci/*"] },
        "company-b": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
      },
    });

    const aAfterSwap = await readTool("company-a", "vault://OTHER/ci/pat");
    expect(aAfterSwap.error).toBeUndefined();
    const bAfterSwap = await readTool("company-b", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(bAfterSwap.error).toBeUndefined();
  });

  it("(no backendOverride) a worker that booted unconfigured builds and reaches a real backend once config arrives, with no restart", async () => {
    // createVaultWorker fires an un-awaited service-scope priming fetch as
    // soon as a live VaultwardenBackend is constructed — stub global fetch
    // so this test never reaches the real network (same pattern as
    // validate-vault-server-url.spec.ts).
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 500 })),
    );
    try {
      const { harness, readTool } = setupHarness({});
      await createVaultWorker(harness.ctx);

      const before = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
      expect(before.error).toMatch(/^prerequisite_missing/);

      harness.setConfig({
        serviceAccountEmail: "svc@example.com",
        masterPasswordRef: "vault-master-password-secret",
        allowList: ["vault://EXAMPLE/svc-secrets/*"],
        companyPolicies: {
          "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
        },
      });

      const after = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
      // No longer the routine "unconfigured" state — the live-rebuilt backend
      // was reached (and failed on the stubbed 500, which is a genuine
      // backend error, not a config gate).
      expect(after.error).not.toMatch(/^prerequisite_missing/);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("fails closed and logs loudly at error when the use-time config read throws — distinct from routine prerequisite_missing", async () => {
    const { harness, readTool } = setupHarness({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
    });
    await createVaultWorker(harness.ctx, {
      backendOverride: new InMemoryVaultBackend(),
    });

    // Simulate a host RPC failure on the use-time config read.
    harness.ctx.config.get = (async () => {
      throw new Error("host config RPC unavailable");
    }) as typeof harness.ctx.config.get;

    const result = await readTool("company-a", "vault://EXAMPLE/svc-secrets/tunnel-cert");
    expect(result.error).toBe(
      "prerequisite_missing: vault plugin config could not be read",
    );
    // Loud, not swallowed: logged at error with plugin + method — this is
    // what distinguishes an RPC failure from a genuinely unconfigured plugin.
    expect(
      harness.logs.some(
        (e) =>
          e.level === "error" &&
          e.message === "vault.config_read_failed" &&
          e.meta?.method === "read" &&
          e.meta?.plugin === "platform.vault",
      ),
    ).toBe(true);
  });
});

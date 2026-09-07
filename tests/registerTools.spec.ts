import { describe, expect, it } from "vitest";
import {
  policyDenyMessage,
  registerVaultTools,
  type AuditRow,
  type VaultToolDependencies,
} from "../src/worker/registerTools.js";
import {
  InMemoryVaultBackend,
  VaultBackendError,
  VaultItemNotFoundError,
  type VaultBackend,
  type VaultListItem,
} from "../src/worker/VaultBackend.js";

/**
 * This suite exercises `registerVaultTools`'s read/list/audit/policy logic
 * against a FIXED backend + config snapshot per test (live-reread-per-dispatch
 * behavior itself is covered separately in
 * `tests/worker/liveConfigReread.spec.ts`). `resolveRuntime` is still called
 * fresh on every dispatch here, exactly like production — it just always
 * resolves to the same values, which is a faithful stand-in for "config
 * hasn't changed between calls" rather than a captured-at-registration value.
 */
interface StaticRuntimeDeps {
  backend: VaultBackend;
  allowList: readonly string[];
  writeAudit: (entry: AuditRow) => Promise<void>;
  logger: VaultToolDependencies["logger"];
  handleMode?: boolean;
  companyPolicies?: Record<
    string,
    { allowList?: readonly string[]; handleMode?: boolean }
  >;
}

function withStaticRuntime(deps: StaticRuntimeDeps): VaultToolDependencies {
  const { backend, allowList, handleMode, companyPolicies, writeAudit, logger } = deps;
  // Entries are the only grant source (0.2.0 semantics). Fixtures that do
  // not spell out companyPolicies get their top-level allowList/handleMode
  // wrapped as the dispatching company's entry, so the plumbing tests
  // (grant, parse, audit, list filtering, handle minting) keep exercising
  // the real entry path. Drift-shape tests pass `companyPolicies: undefined`
  // (map absent), `{}` (map empty), or an entry without `allowList`
  // explicitly.
  const effectivePolicies =
    "companyPolicies" in deps
      ? companyPolicies
      : {
          [runCtx.companyId]: {
            allowList: [...allowList],
            handleMode: handleMode ?? false,
          },
        };
  return {
    resolveRuntime: async () => ({
      ok: true,
      backend,
      allowList,
      handleMode: handleMode ?? false,
      companyPolicies: effectivePolicies,
    }),
    writeAudit,
    logger,
  };
}

interface RegisteredTool {
  declaration: unknown;
  handler: (
    params: unknown,
    runCtx: { agentId: string; runId: string; companyId: string; projectId: string; artifacts: unknown },
  ) => Promise<{ content?: string; data?: unknown; error?: string }>;
}

function makeFakeCtx(secrets?: {
  mintHandle: (value: string, runId: string) => Promise<string>;
}) {
  const tools = new Map<string, RegisteredTool>();
  const logs: Array<{ level: string; message: string; meta?: unknown }> = [];
  const audits: AuditRow[] = [];
  // Build a minimal subset of PluginContext for the registerVaultTools call.
  // The real ctx has many more fields; we cast on return.
  const ctx = {
    tools: {
      register(name: string, declaration: unknown, handler: RegisteredTool["handler"]) {
        tools.set(name, { declaration, handler });
      },
    },
    logger: {
      info: (m: string, meta?: unknown) => logs.push({ level: "info", message: m, meta }),
      warn: (m: string, meta?: unknown) => logs.push({ level: "warn", message: m, meta }),
      error: (m: string, meta?: unknown) => logs.push({ level: "error", message: m, meta }),
      debug: (m: string, meta?: unknown) => logs.push({ level: "debug", message: m, meta }),
    },
    ...(secrets ? { secrets } : {}),
  };
  return { ctx, tools, logs, audits };
}

const runCtx = {
  agentId: "agent-aaa",
  runId: "run-bbb",
  companyId: "company-ccc",
  projectId: "project-ddd",
  artifacts: {} as never,
};

describe("vault.read tool", () => {
  it("returns the plaintext for an allowed ref and writes a success audit row", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set(
      { org: "EXAMPLE", collection: "svc-secrets", item: "tunnel-cert" },
      "tunnel-token-1234",
    );
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/tunnel-cert"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert" },
      runCtx,
    );
    expect(result.content).toBe("tunnel-token-1234");
    expect(result.data).toEqual({
      value: "tunnel-token-1234",
      ref: "vault://EXAMPLE/svc-secrets/tunnel-cert",
    });
    expect(audits).toEqual([
      expect.objectContaining({
        outcome: "success",
        agentId: "agent-aaa",
        runId: "run-bbb",
        companyId: "company-ccc",
        secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert",
      }),
    ]);
  });

  it("denies refs outside the allowList WITHOUT contacting the backend", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    let backendCalls = 0;
    const backend = {
      async read() {
        backendCalls += 1;
        return "should-not-happen";
      },
      async list() {
        return [];
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/tunnel-cert"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/api-tokens/board" },
      runCtx,
    );
    expect(result.error).toMatch(/^prerequisite_missing/);
    expect(backendCalls).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
  });

  it("returns invalid_ref on malformed input without contacting the backend", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    let backendCalls = 0;
    const backend = {
      async read() {
        backendCalls += 1;
        return "no";
      },
      async list() {
        return [];
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler({ secretRef: "not-a-vault-ref" }, runCtx);
    expect(result.error).toMatch(/^invalid_ref/);
    expect(backendCalls).toBe(0);
    expect(audits).toEqual([expect.objectContaining({ outcome: "invalid_ref" })]);
  });

  it("returns not_found when the backend can't resolve the ref", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/missing" },
      runCtx,
    );
    expect(result.error).toMatch(/^not_found/);
    expect(audits).toEqual([expect.objectContaining({ outcome: "not_found" })]);
  });

  it("redacts plaintext from the audit row in every outcome", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set(
      { org: "EXAMPLE", collection: "svc-secrets", item: "shh" },
      "super-secret-XYZ-987",
    );
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/shh"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    await tool.handler({ secretRef: "vault://EXAMPLE/svc-secrets/shh" }, runCtx);
    for (const row of audits) {
      const blob = JSON.stringify(row);
      expect(blob).not.toContain("super-secret-XYZ-987");
    }
  });
});

// Handle-mode opt-in. These must fail on pre-change
// code (which always returned plaintext and ignored handleMode).
describe("vault.read handle mode", () => {
  const ALLOWED = "vault://EXAMPLE/svc-secrets/tunnel-cert";
  const PLAINTEXT = "tunnel-token-1234";

  function backendWith(value: string): VaultBackend {
    const b = new InMemoryVaultBackend();
    b.set({ org: "EXAMPLE", collection: "svc-secrets", item: "tunnel-cert" }, value);
    return b;
  }

  it("returns the opaque handle on BOTH content and data.value, never plaintext", async () => {
    const mintCalls: Array<[string, string]> = [];
    const { ctx, tools, audits } = makeFakeCtx({
      mintHandle: async (value, runId) => {
        mintCalls.push([value, runId]);
        return "handle://opaque-xyz";
      },
    });
    registerVaultTools(ctx as never, withStaticRuntime({
      backend: backendWith(PLAINTEXT),
      allowList: [ALLOWED],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
      handleMode: true,
    }));
    const result = await tools.get("vault.read")!.handler({ secretRef: ALLOWED }, runCtx);

    expect(result.content).toBe("handle://opaque-xyz");
    expect(result.data).toEqual({ value: "handle://opaque-xyz", ref: ALLOWED });
    // Plaintext must NOT appear anywhere in the persisted result.
    expect(JSON.stringify(result)).not.toContain(PLAINTEXT);
    // Mint was called with the resolved plaintext + the calling run id.
    expect(mintCalls).toEqual([[PLAINTEXT, "run-bbb"]]);
    expect(audits).toEqual([expect.objectContaining({ outcome: "success" })]);
  });

  it("fails closed when mintHandle throws — returns { error }, never plaintext", async () => {
    const { ctx, tools, audits } = makeFakeCtx({
      mintHandle: async () => {
        throw new Error("host refused to mint");
      },
    });
    registerVaultTools(ctx as never, withStaticRuntime({
      backend: backendWith(PLAINTEXT),
      allowList: [ALLOWED],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
      handleMode: true,
    }));
    const result = await tools.get("vault.read")!.handler({ secretRef: ALLOWED }, runCtx);

    expect(result.error).toMatch(/^error: mint_failed/);
    expect(result.content).toBeUndefined();
    expect((result.data as { value?: string } | undefined)?.value).toBeUndefined();
    // Neither the plaintext nor the raw mint error body leak out.
    expect(JSON.stringify({ result, audits })).not.toContain(PLAINTEXT);
    expect(JSON.stringify({ result, audits })).not.toContain("host refused to mint");
    expect(audits).toEqual([expect.objectContaining({ outcome: "error" })]);
  });

  it("with handleMode OFF returns plaintext and never mints (back-compat)", async () => {
    let minted = false;
    const { ctx, tools } = makeFakeCtx({
      mintHandle: async () => {
        minted = true;
        return "handle://should-not-happen";
      },
    });
    registerVaultTools(ctx as never, withStaticRuntime({
      backend: backendWith(PLAINTEXT),
      allowList: [ALLOWED],
      writeAudit: async () => {},
      logger: ctx.logger,
      // handleMode omitted → defaults off
    }));
    const result = await tools.get("vault.read")!.handler({ secretRef: ALLOWED }, runCtx);

    expect(result.content).toBe(PLAINTEXT);
    expect(result.data).toEqual({ value: PLAINTEXT, ref: ALLOWED });
    expect(minted).toBe(false);
  });
});

describe("vault.list tool", () => {
  it("returns names with no values, honoring allowList", async () => {
    const { ctx, tools } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set(
      { org: "EXAMPLE", collection: "svc-secrets", item: "a" },
      "secret-a",
    );
    backend.set(
      { org: "EXAMPLE", collection: "svc-secrets", item: "b" },
      "secret-b",
    );
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      writeAudit: async () => {},
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.list")!;
    const result = await tool.handler(
      { collectionGlob: "vault://EXAMPLE/svc-secrets/*" },
      runCtx,
    );
    expect(result.data).toEqual({ names: expect.arrayContaining(["a", "b"]) });
    const blob = JSON.stringify(result);
    expect(blob).not.toContain("secret-a");
    expect(blob).not.toContain("secret-b");
  });

  it("denies a list filter outside the allowList", async () => {
    const { ctx, tools } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      writeAudit: async () => {},
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.list")!;
    const result = await tool.handler(
      { collectionGlob: "vault://OTHER/svc-secrets/*" },
      runCtx,
    );
    expect(result.error).toMatch(/^prerequisite_missing/);
  });

  // F2: an unscoped list (no glob) previously skipped the allowList entirely
  // and returned names across every readable org/collection.
  it("with NO glob returns only names inside an allowed scope", async () => {
    const { ctx, tools } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "allowed-a" }, "x");
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "allowed-b" }, "y");
    backend.set({ org: "EXAMPLE", collection: "api-tokens", item: "off-scope" }, "z");
    backend.set({ org: "OTHER", collection: "svc-secrets", item: "other-org" }, "w");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      writeAudit: async () => {},
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.list")!;
    const result = await tool.handler({}, runCtx);
    const names = (result.data as { names: string[] }).names;
    expect(names.sort()).toEqual(["allowed-a", "allowed-b"]);
    expect(names).not.toContain("off-scope");
    expect(names).not.toContain("other-org");
  });

  // F4: list success and error must produce audit rows.
  it("writes a success audit row for a list", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "a" }, "secret");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.list")!;
    await tool.handler({ collectionGlob: "vault://EXAMPLE/svc-secrets/*" }, runCtx);
    expect(audits).toEqual([
      expect.objectContaining({ operation: "list", outcome: "success" }),
    ]);
  });

  it("writes an error audit row for a failing list and scrubs server bodies", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend: VaultBackend = {
      async read() {
        throw new Error("unused");
      },
      async list(): Promise<VaultListItem[]> {
        throw new Error("HTTP 500: SENSITIVE-SERVER-BODY-xyz");
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.list")!;
    const result = await tool.handler(
      { collectionGlob: "vault://EXAMPLE/svc-secrets/*" },
      runCtx,
    );
    expect(result.error).not.toContain("SENSITIVE-SERVER-BODY-xyz");
    expect(audits).toEqual([
      expect.objectContaining({ operation: "list", outcome: "error" }),
    ]);
    expect(JSON.stringify(audits)).not.toContain("SENSITIVE-SERVER-BODY-xyz");
  });
});

// F8: server response bodies and arbitrary backend detail must never reach
// the audit log or the returned error string, across every error outcome.
describe("error-string scrubbing (F8)", () => {
  it("reduces an unknown error (carrying a server body) to its class name", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend: VaultBackend = {
      async read() {
        throw new Error("vaultwarden GET /api/sync -> 500: LEAKED-BODY-abc123");
      },
      async list() {
        return [];
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert" },
      runCtx,
    );
    expect(result.error).toBe("error: backend_error: Error");
    expect(result.error).not.toContain("LEAKED-BODY-abc123");
    expect(JSON.stringify(audits)).not.toContain("LEAKED-BODY-abc123");
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "error", error: "backend_error: Error" }),
    ]);
  });

  it("surfaces a body-free VaultBackendError message but not its detail body", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend: VaultBackend = {
      async read() {
        throw new VaultBackendError(
          "vaultwarden GET /api/sync -> 500",
          "SENSITIVE-DETAIL-body",
        );
      },
      async list() {
        return [];
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert" },
      runCtx,
    );
    expect(result.error).toBe("error: vaultwarden GET /api/sync -> 500");
    expect(JSON.stringify({ result, audits })).not.toContain("SENSITIVE-DETAIL-body");
  });

  it("keeps not_found free of plaintext and surfaces only the ref coordinates", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend: VaultBackend = {
      async read(ref) {
        throw new VaultItemNotFoundError(ref);
      },
      async list() {
        return [];
      },
    };
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const tool = tools.get("vault.read")!;
    const result = await tool.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/missing" },
      runCtx,
    );
    expect(result.error).toMatch(/^not_found/);
    expect(audits).toEqual([expect.objectContaining({ outcome: "not_found" })]);
  });
});

describe("fail-closed policyFor (no top-level inheritance)", () => {
  /** Backend that counts calls; any contact is a test failure signal. */
  const countingBackend = () => {
    const backend = {
      reads: 0,
      lists: 0,
      async read() {
        backend.reads += 1;
        return "should-not-happen";
      },
      async list() {
        backend.lists += 1;
        return [];
      },
    };
    return backend;
  };

  it("T1: denies vault.read when companyPolicies is absent — no top-level fallback, no backend contact", async () => {
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      // Adversarial top-level fields: any surviving inheritance path would
      // turn this into a success.
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: undefined,
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const result = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    expect(result.error).toBe(policyDenyMessage("policymap_missing"));
    expect(backend.reads).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({
        outcome: "denied_by_allowlist",
        companyId: "company-ccc",
      }),
    ]);
    expect(
      logs.some(
        (e) => e.level === "error" && e.message === "vault.policymap_missing",
      ),
    ).toBe(true);
  });

  it("T2: denies vault.list (unscoped and globbed) when companyPolicies is absent", async () => {
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: undefined,
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const unscoped = await tools.get("vault.list")!.handler({}, runCtx);
    expect(unscoped.error).toBe(policyDenyMessage("policymap_missing"));
    const globbed = await tools
      .get("vault.list")!
      .handler({ collectionGlob: "vault://EXAMPLE/svc-secrets/*" }, runCtx);
    expect(globbed.error).toBe(policyDenyMessage("policymap_missing"));
    expect(backend.lists).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
    expect(
      logs.filter(
        (e) => e.level === "error" && e.message === "vault.policymap_missing",
      ).length,
    ).toBe(2);
  });

  it("T3/T4: denies read and list when companyPolicies is an empty map", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: {},
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const read = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    expect(read.error).toBe(policyDenyMessage("policymap_missing"));
    const list = await tools.get("vault.list")!.handler({}, runCtx);
    expect(list.error).toBe(policyDenyMessage("policymap_missing"));
    expect(backend.reads).toBe(0);
    expect(backend.lists).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
  });

  it("T5: an entry without allowList denies read and names the drift event", async () => {
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: { "company-ccc": { handleMode: true } },
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const read = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    expect(read.error).toBe(policyDenyMessage("entry_missing_allowlist"));
    expect(backend.reads).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
    const events = logs.filter(
      (e) =>
        e.level === "error" &&
        e.message === "vault.policy_entry_missing_allowlist",
    );
    expect(events.length).toBe(1);
    expect(events[0]!.meta).toMatchObject({ companyId: "company-ccc" });
  });

  it("T6: an entry without allowList denies list", async () => {
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: { "company-ccc": { handleMode: true } },
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const list = await tools.get("vault.list")!.handler({}, runCtx);
    expect(list.error).toBe(policyDenyMessage("entry_missing_allowlist"));
    expect(backend.lists).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
  });

  it("T7: handleMode absent in the entry is OFF even when the instance-level handleMode is true", async () => {
    const { ctx, tools } = makeFakeCtx({
      mintHandle: async () => {
        throw new Error("mintHandle must never be called");
      },
    });
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "pat" }, "secret-a");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      handleMode: true,
      companyPolicies: { "company-ccc": { allowList: ["vault://EXAMPLE/**"] } },
      writeAudit: async () => {},
      logger: ctx.logger,
    }));
    const result = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    // PLAINTEXT — the entry is authoritative; the instance flag is dead.
    expect(result.content).toBe("secret-a");
    expect(result.data).toEqual({
      value: "secret-a",
      ref: "vault://EXAMPLE/svc-secrets/pat",
    });
  });

  it("T8: the entry allowList REPLACES the instance list — outside-entry refs are denied even when the instance list matches", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "pat" }, "secret-a");
    backend.set({ org: "OTHER", collection: "ci", item: "pat-b" }, "secret-b");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      companyPolicies: {
        "company-ccc": { allowList: ["vault://EXAMPLE/svc-secrets/*"] },
      },
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const read = tools.get("vault.read")!;
    const inside = await read.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/pat" },
      runCtx,
    );
    expect(inside.content).toBe("secret-a");
    const outsideButInstanceMatch = await read.handler(
      { secretRef: "vault://OTHER/ci/pat-b" },
      runCtx,
    );
    expect(outsideButInstanceMatch.error).toMatch(
      /is not in this adapter's allowList/,
    );
    expect(audits.map((a) => a.outcome)).toEqual([
      "success",
      "denied_by_allowlist",
    ]);
  });

  it("T9: an empty entry allowList denies by matching nothing (schema-independent)", async () => {
    const { ctx, tools, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      companyPolicies: { "company-ccc": { allowList: [] } },
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const read = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    expect(read.error).toMatch(/is not in this adapter's allowList/);
    expect(backend.reads).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
  });

  it("T10: an invalid entry pattern denies loudly via the existing compile-failed event", async () => {
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = countingBackend();
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      companyPolicies: { "company-ccc": { allowList: ["no-vault-prefix"] } },
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const read = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, runCtx);
    expect(read.error).toBe(policyDenyMessage("allowlist_compile_failed"));
    expect(backend.reads).toBe(0);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist" }),
    ]);
    expect(
      logs.some(
        (e) =>
          e.level === "error" && e.message === "vault.allowlist_compile_failed",
      ),
    ).toBe(true);
  });
});

describe("companyPolicies (fail-closed tenant scoping)", () => {
  const makePolicyFixture = () => {
    const { ctx, tools, audits } = makeFakeCtx({
      mintHandle: async (value, runId) => `vault-handle://${runId}/abc`,
    });
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "pat" }, "secret-a");
    backend.set({ org: "OTHER", collection: "ci", item: "pat-b" }, "secret-b");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://**"],
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/**"] },
        "company-b": { allowList: ["vault://OTHER/**"], handleMode: true },
      },
    }));
    return { tools, audits };
  };
  const ctxFor = (companyId: string) => ({ ...runCtx, companyId });

  it("denies read AND list for a company with no policy entry", async () => {
    const { tools, audits } = makePolicyFixture();
    const read = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, ctxFor("company-unknown"));
    expect(read.error).toMatch(/^prerequisite_missing: no vault policy/);
    const list = await tools.get("vault.list")!.handler({}, ctxFor("company-unknown"));
    expect(list.error).toMatch(/^prerequisite_missing: no vault policy/);
    expect(audits).toEqual([
      expect.objectContaining({ outcome: "denied_by_allowlist", companyId: "company-unknown" }),
      expect.objectContaining({ outcome: "denied_by_allowlist", companyId: "company-unknown" }),
    ]);
  });

  it("scopes each company to its own allowList (tenant B cannot read tenant A refs)", async () => {
    const { tools } = makePolicyFixture();
    const read = tools.get("vault.read")!;
    const crossTenant = await read.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/pat" },
      ctxFor("company-b"),
    );
    expect(crossTenant.error).toMatch(/^prerequisite_missing/);
    const ownTenant = await read.handler(
      { secretRef: "vault://EXAMPLE/svc-secrets/pat" },
      ctxFor("company-a"),
    );
    expect(ownTenant.content).toBe("secret-a");
  });

  it("applies per-company handleMode and filters list per company", async () => {
    const { tools } = makePolicyFixture();
    const dprRead = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://OTHER/ci/pat-b" }, ctxFor("company-b"));
    expect(dprRead.content).toBe("vault-handle://run-bbb/abc");
    expect(JSON.stringify(dprRead)).not.toContain("secret-b");
    const dprList = await tools.get("vault.list")!.handler({}, ctxFor("company-b"));
    expect(dprList.data).toEqual({ names: ["pat-b"] });
    const listA = await tools.get("vault.list")!.handler({}, ctxFor("company-a"));
    expect(listA.data).toEqual({ names: ["pat"] });
  });

  it("denies every company when companyPolicies is absent (no legacy instance-wide grant)", async () => {
    // Pre-0.2.0 this asserted SUCCESS via the top-level allowList fallback.
    // Inversion is the point: the instance-level list grants nothing now —
    // an absent map denies every company, loudly.
    const { ctx, tools, logs, audits } = makeFakeCtx();
    const backend = new InMemoryVaultBackend();
    backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "pat" }, "secret-a");
    registerVaultTools(ctx as never, withStaticRuntime({
      backend,
      allowList: ["vault://EXAMPLE/**"],
      companyPolicies: undefined,
      writeAudit: async (e) => void audits.push(e),
      logger: ctx.logger,
    }));
    const result = await tools
      .get("vault.read")!
      .handler({ secretRef: "vault://EXAMPLE/svc-secrets/pat" }, ctxFor("any-company"));
    expect(result.error).toBe(policyDenyMessage("policymap_missing"));
    expect(result.content).toBeUndefined();
    expect(audits).toEqual([
      expect.objectContaining({
        outcome: "denied_by_allowlist",
        companyId: "any-company",
      }),
    ]);
    expect(
      logs.some(
        (e) => e.level === "error" && e.message === "vault.policymap_missing",
      ),
    ).toBe(true);
  });
});

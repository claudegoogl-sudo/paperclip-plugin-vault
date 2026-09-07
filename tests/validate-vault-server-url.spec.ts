import { afterEach, describe, expect, it, vi } from "vitest";
import { validateVaultServerUrl } from "../src/worker/validateVaultServerUrl.js";
import { VaultAuthError } from "../src/worker/VaultBackend.js";
import { VaultwardenBackend } from "../src/worker/VaultwardenBackend.js";
import { createVaultWorker } from "../src/worker.js";

/**
 * Safety follow-up: vault must not send the resolved service-account master
 * password to a host it was not configured to talk to, regardless of what
 * value reaches config. Before this fix `VaultwardenBackend`'s constructor
 * only checked `/^https:\/\//` on the raw string — no host constraint at
 * all, so "https, any host" was accepted — and `createVaultWorker` never
 * caught a constructor throw, so an invalid value would crash worker setup
 * instead of failing closed.
 *
 * These tests fail against the pre-fix code: `validateVaultServerUrl` did
 * not exist, the constructor's regex check let any https host through, and
 * `createVaultWorker` had no try/catch around `new VaultwardenBackend(...)`.
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

describe("validateVaultServerUrl (unit)", () => {
  it("accepts the live default server with no allowlist configured", () => {
    const result = validateVaultServerUrl("https://vault.timms-gitclaw.de");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.url.host).toBe("vault.timms-gitclaw.de");
  });

  it("rejects a non-https scheme", () => {
    const result = validateVaultServerUrl("http://vault.timms-gitclaw.de");
    expect(result).toEqual({
      ok: false,
      reason: "unsupported_scheme",
      host: "vault.timms-gitclaw.de",
    });
  });

  it("rejects an unparseable value", () => {
    const result = validateVaultServerUrl("not a url");
    expect(result).toEqual({ ok: false, reason: "unparseable", host: null });
  });

  it("rejects an attacker origin whose PATH merely contains the expected host (ported from paperclip-plugin-cad's parseGitHubUrl F4 test)", () => {
    const result = validateVaultServerUrl(
      "https://attacker.example/path/vault.timms-gitclaw.de/api",
      ["vault.timms-gitclaw.de"],
    );
    expect(result).toEqual({
      ok: false,
      reason: "host_not_allowed",
      host: "attacker.example",
    });
  });

  it("accepts when the host matches an explicit allowlist", () => {
    const result = validateVaultServerUrl("https://vault.internal/", ["vault.internal"]);
    expect(result.ok).toBe(true);
  });

  it("rejects when the host does not match an explicit allowlist", () => {
    const result = validateVaultServerUrl("https://other.example/", ["vault.internal"]);
    expect(result).toEqual({ ok: false, reason: "host_not_allowed", host: "other.example" });
  });
});

describe("VaultwardenBackend constructor fails closed on an invalid serverUrl", () => {
  const { logger } = fakeLogger();
  const baseOpts = {
    email: "svc@example.com",
    resolvePassword: async () => "unused",
    http: {} as never,
    logger,
  };

  it("throws VaultAuthError (host + reason only, never the full raw value) for a non-https scheme", () => {
    let caught: unknown;
    try {
      new VaultwardenBackend({ ...baseOpts, serverUrl: "http://attacker.example/steal-here" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(VaultAuthError);
    const message = (caught as Error).message;
    expect(message).toContain("attacker.example");
    expect(message).not.toContain("/steal-here");
  });

  it("throws for an attacker origin whose path merely contains the allowed host", () => {
    expect(
      () =>
        new VaultwardenBackend({
          ...baseOpts,
          serverUrl: "https://attacker.example/path/vault.internal/api",
          allowedServerHosts: ["vault.internal"],
        }),
    ).toThrow(VaultAuthError);
  });

  it("does not throw for a well-formed https URL with no allowlist configured (no behavior change for the live default)", () => {
    expect(
      () => new VaultwardenBackend({ ...baseOpts, serverUrl: "https://vault.timms-gitclaw.de" }),
    ).not.toThrow();
  });
});

describe("createVaultWorker fails closed on an invalid serverUrl", () => {
  function fakeCtx(config: Record<string, unknown>) {
    const { logger, logs } = fakeLogger();
    const registered = new Map<string, unknown>();
    const ctx = {
      config: { get: async () => config },
      logger,
      secrets: { resolve: async () => "unused-master-password", resolveService: async () => "unused-master-password" },
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

  it("falls back to permissive-init (backend: null) when serverUrl is rejected, and warns without leaking the master-password ref", async () => {
    const { ctx, logs } = fakeCtx({
      serverUrl: "http://attacker.example/steal-here",
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://ORG/coll/*"],
    });
    const result = await createVaultWorker(ctx as never);
    expect(result.backend).toBeNull();
    const warnLine = logs.find(
      (e) => e.level === "warn" && e.message.includes("rejected serverUrl"),
    );
    expect(warnLine).toBeDefined();
    expect(JSON.stringify(warnLine)).not.toContain("vault-master-password-secret");
  });

  it("does not throw / crash worker setup on an invalid serverUrl", async () => {
    const { ctx } = fakeCtx({
      serverUrl: "not a url",
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://ORG/coll/*"],
    });
    await expect(createVaultWorker(ctx as never)).resolves.not.toThrow();
  });

  it("still constructs a live backend for a valid config with no allowedServerHosts set (no behavior change for existing single-host configs)", async () => {
    // createVaultWorker fires an un-awaited session-priming fetch as soon as
    // a VaultwardenBackend is constructed — stub global fetch so this
    // assertion never reaches the real network.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { status: 500 })),
    );
    try {
      const { ctx } = fakeCtx({
        serviceAccountEmail: "svc@example.com",
        masterPasswordRef: "vault-master-password-secret",
        allowList: ["vault://ORG/coll/*"],
      });
      const result = await createVaultWorker(ctx as never);
      expect(result.backend).not.toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });
});

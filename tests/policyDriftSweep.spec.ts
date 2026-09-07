/**
 * Boot-time misconfiguration sweep for the companyPolicies map
 * (`reportPolicyDrift` in src/worker.ts) and the ready-log drift fields.
 *
 * The sweep is the loud, boot-time signal for the two drift shapes that
 * fail closed at call time: an absent/empty map (`vault.policymap_missing`)
 * and entries lacking `allowList` (`vault.policy_entry_missing_allowlist`).
 * It must stay WIRED through `createVaultWorker`: the wiring tests below
 * fail if the sweep call is deleted from worker startup.
 */
import { describe, expect, it } from "vitest";
import { createTestHarness } from "@paperclipai/plugin-sdk/testing";
import { createVaultWorker, reportPolicyDrift } from "../src/worker.js";
import { InMemoryVaultBackend } from "../src/worker/VaultBackend.js";
import manifest from "../src/manifest.js";
import type { PluginLogger } from "@paperclipai/plugin-sdk";

function recordingLogger(): { logger: PluginLogger; events: Array<{ level: string; message: string; meta?: unknown }> } {
  const events: Array<{ level: string; message: string; meta?: unknown }> = [];
  const logger = {
    info: (message: string, meta?: unknown) => events.push({ level: "info", message, meta }),
    warn: (message: string, meta?: unknown) => events.push({ level: "warn", message, meta }),
    error: (message: string, meta?: unknown) => events.push({ level: "error", message, meta }),
    debug: (message: string, meta?: unknown) => events.push({ level: "debug", message, meta }),
  };
  return { logger: logger as unknown as PluginLogger, events };
}

describe("reportPolicyDrift (pure helper)", () => {
  it("logs vault.policymap_missing when the map is absent", () => {
    const { logger, events } = recordingLogger();
    reportPolicyDrift({ companyPolicies: undefined, allowList: ["vault://**"] }, logger);
    expect(events).toEqual([
      expect.objectContaining({
        level: "error",
        message: "vault.policymap_missing",
        meta: expect.objectContaining({ plugin: "platform.vault", method: "setup" }),
      }),
    ]);
  });

  it("logs vault.policymap_missing when the map is empty", () => {
    const { logger, events } = recordingLogger();
    reportPolicyDrift({ companyPolicies: {}, allowList: ["vault://**"] }, logger);
    expect(events.map((e) => e.message)).toEqual(["vault.policymap_missing"]);
  });

  it("logs one policy_entry_missing_allowlist per entry lacking allowList, naming the companyId", () => {
    const { logger, events } = recordingLogger();
    reportPolicyDrift(
      {
        companyPolicies: {
          "company-good": { allowList: ["vault://EXAMPLE/**"] },
          "company-bad-1": { handleMode: true },
          "company-bad-2": {},
        },
        allowList: ["vault://**"],
      },
      logger,
    );
    const drift = events.filter((e) => e.message === "vault.policy_entry_missing_allowlist");
    expect(drift.length).toBe(2);
    expect(drift.map((e) => (e.meta as { companyId: string }).companyId).sort()).toEqual([
      "company-bad-1",
      "company-bad-2",
    ]);
    expect(events.every((e) => e.level === "error")).toBe(true);
  });

  it("logs nothing for a well-formed map", () => {
    const { logger, events } = recordingLogger();
    reportPolicyDrift(
      {
        companyPolicies: {
          "company-a": { allowList: ["vault://EXAMPLE/**"], handleMode: true },
          "company-b": { allowList: ["vault://OTHER/**"] },
        },
        allowList: ["vault://**"],
      },
      logger,
    );
    expect(events).toEqual([]);
  });
});

describe("reportPolicyDrift wiring through createVaultWorker", () => {
  const CAPABILITIES = [
    "http.outbound",
    "secrets.read-ref",
    "agent.tools.register",
    "activity.log.write",
  ] as const;

  async function bootWith(config: Record<string, unknown>) {
    const harness = createTestHarness({
      manifest,
      capabilities: [...CAPABILITIES],
      config,
    });
    await createVaultWorker(harness.ctx, {
      backendOverride: new InMemoryVaultBackend(),
    });
    return harness;
  }

  it("a boot with an absent map logs the drift event at setup and reports it in the ready log", async () => {
    const harness = await bootWith({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      // companyPolicies deleted — drift shape A.
    });
    expect(
      harness.logs.some(
        (e) =>
          e.level === "error" &&
          e.message === "vault.policymap_missing" &&
          e.meta?.method === "setup",
      ),
    ).toBe(true);
    const ready = harness.logs.find((e) => e.message === "paperclip-plugin-vault worker ready");
    expect(ready?.meta).toMatchObject({
      companyPolicyCount: 0,
      misconfiguredPolicyEntries: 0,
    });
  });

  it("a boot with a bad entry names the companyId at setup and counts it in the ready log", async () => {
    const harness = await bootWith({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/**"] },
        "company-b": { handleMode: true },
      },
    });
    expect(
      harness.logs.some(
        (e) =>
          e.level === "error" &&
          e.message === "vault.policy_entry_missing_allowlist" &&
          e.meta?.companyId === "company-b",
      ),
    ).toBe(true);
    const ready = harness.logs.find((e) => e.message === "paperclip-plugin-vault worker ready");
    expect(ready?.meta).toMatchObject({
      companyPolicyCount: 2,
      misconfiguredPolicyEntries: 1,
    });
  });

  it("a well-formed config boots without drift events", async () => {
    const harness = await bootWith({
      serviceAccountEmail: "svc@example.com",
      masterPasswordRef: "vault-master-password-secret",
      allowList: ["vault://EXAMPLE/svc-secrets/*"],
      companyPolicies: {
        "company-a": { allowList: ["vault://EXAMPLE/svc-secrets/*"], handleMode: true },
      },
    });
    expect(
      harness.logs.some((e) => e.level === "error" && e.message.startsWith("vault.policy")),
    ).toBe(false);
    const ready = harness.logs.find((e) => e.message === "paperclip-plugin-vault worker ready");
    expect(ready?.meta).toMatchObject({
      companyPolicyCount: 1,
      misconfiguredPolicyEntries: 0,
    });
  });
});

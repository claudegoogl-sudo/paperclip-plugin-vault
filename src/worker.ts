import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";
import { registerVaultTools } from "./worker/registerTools.js";
import type { VaultBackend } from "./worker/VaultBackend.js";
import { VaultwardenBackend } from "./worker/VaultwardenBackend.js";
import type { VaultRuntimeResult } from "./worker/vaultRuntime.js";

interface VaultConfig {
  serverUrl?: string;
  /**
   * Operator-configurable host allowlist for `serverUrl` (safety
   * follow-up). When omitted or empty, defaults to the single host parsed
   * out of `serverUrl` itself. See `worker/validateVaultServerUrl.ts`.
   */
  allowedServerHosts?: string[];
  serviceAccountEmail?: string;
  masterPasswordRef?: string;
  allowList?: string[];
  sessionTtlSeconds?: number;
  /**
   * Per-binding opt-in to borrowed-handle mode (borrowed-handle mode). When
   * true, `vault.read` returns an opaque host-minted handle on both `content`
   * and `data.value` instead of plaintext; the value resolves only when a
   * downstream tool param routes through the host egress chokepoint. Defaults
   * false so plaintext-reading consumers (e.g. the tunnel-cert sha256
   * check) keep working until their binding opts in.
   */
  handleMode?: boolean;
  /**
   * Per-company policy keyed by Paperclip companyId. FAIL-CLOSED: when
   * present and non-empty, only listed companies may call the vault tools;
   * each entry may narrow `allowList` and override `handleMode` for that
   * company. See registerTools.ts.
   */
  companyPolicies?: Record<
    string,
    { allowList?: string[]; handleMode?: boolean }
  >;
}

const DEFAULT_SERVER_URL = "https://vault.timms-gitclaw.de";

export interface CreateVaultWorkerOptions {
  /** Override the backend (tests). */
  backendOverride?: VaultBackend;
}

interface BackendIdentity {
  serverUrl: string;
  allowedServerHosts: string[] | undefined;
  serviceAccountEmail: string | undefined;
  masterPasswordRef: string | undefined;
  sessionTtlSeconds: number;
}

function backendIdentityOf(config: Partial<VaultConfig>): BackendIdentity {
  return {
    serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
    allowedServerHosts: config.allowedServerHosts,
    serviceAccountEmail: config.serviceAccountEmail,
    masterPasswordRef: config.masterPasswordRef,
    sessionTtlSeconds: config.sessionTtlSeconds ?? 3600,
  };
}

function identitiesEqual(a: BackendIdentity, b: BackendIdentity): boolean {
  return (
    a.serverUrl === b.serverUrl &&
    a.serviceAccountEmail === b.serviceAccountEmail &&
    a.masterPasswordRef === b.masterPasswordRef &&
    a.sessionTtlSeconds === b.sessionTtlSeconds &&
    JSON.stringify(a.allowedServerHosts ?? []) ===
      JSON.stringify(b.allowedServerHosts ?? [])
  );
}

/**
 * Builds a resolver that re-reads `ctx.config.get()` on every call — setup
 * and every dispatch alike — and never caches the raw config values used for
 * authorization (`allowList`, `handleMode`, `companyPolicies`). The
 * constructed `VaultwardenBackend` (a stateful client with its own
 * session/TTL machinery) IS reused across calls, but only while the
 * connection-identity fields it was built from (serverUrl, service account,
 * master-password ref, TTL) are unchanged — a config edit (or a worker that
 * booted unconfigured and was fixed afterwards) is picked up on the very
 * next call, no restart required. This mirrors the fail-closed pattern in
 * `paperclip-klipper`'s live-config-reread fix: the read happens inside the
 * call path, and a read failure is logged loudly at `error`, distinct from
 * the routine `prerequisite_missing` case of a genuinely unconfigured plugin.
 */
export function createVaultRuntimeResolver(
  ctx: PluginContext,
  options: CreateVaultWorkerOptions = {},
): (method: string) => Promise<VaultRuntimeResult> {
  let cached: {
    identity: BackendIdentity;
    backend: VaultwardenBackend;
    lastPrimedAt: number;
  } | null = null;

  return async (method: string): Promise<VaultRuntimeResult> => {
    let rawConfig: Partial<VaultConfig>;
    try {
      rawConfig = ((await ctx.config.get()) ?? {}) as Partial<VaultConfig>;
    } catch (err) {
      ctx.logger.error("vault.config_read_failed", {
        plugin: "platform.vault",
        method,
        error: String(err instanceof Error ? err.message : err),
      });
      return {
        ok: false,
        error: "prerequisite_missing: vault plugin config could not be read",
      };
    }

    const allowList = rawConfig.allowList ?? [];
    const handleMode = rawConfig.handleMode === true;
    const companyPolicies = rawConfig.companyPolicies;

    if (options.backendOverride) {
      return {
        ok: true,
        backend: options.backendOverride,
        allowList,
        handleMode,
        companyPolicies,
      };
    }

    if (
      !rawConfig.serviceAccountEmail ||
      !rawConfig.masterPasswordRef ||
      allowList.length === 0
    ) {
      // Permissive-init pattern: an incomplete config is a routine, expected
      // state (plugin install exits 0; operator fixes it via the config UI
      // later) — not an error. Tool calls surface `prerequisite_missing`.
      return {
        ok: false,
        error:
          "prerequisite_missing: vault plugin is not fully configured " +
          "(serviceAccountEmail, masterPasswordRef, and a non-empty allowList are required)",
      };
    }

    const identity = backendIdentityOf(rawConfig);
    const ttlMs = identity.sessionTtlSeconds * 1000;

    if (cached && identitiesEqual(cached.identity, identity)) {
      // Same connection identity as last time: reuse the warm backend. Its
      // own session cache handles the common case (same company that owns
      // the master-password secret re-unlocking cheaply); proactively
      // re-prime on a TTL cadence so OTHER companies' dispatches — which
      // cannot unlock a cold session themselves, only the owning company's
      // secrets.resolve scope can — always find a warm session. This check
      // runs live on every dispatch instead of a background timer, so it
      // never keys off a stale setup-time TTL value.
      if (Date.now() - cached.lastPrimedAt >= ttlMs) {
        cached.backend.clear();
        try {
          await cached.backend.prime();
          cached.lastPrimedAt = Date.now();
        } catch (err) {
          ctx.logger.warn("vault.session_reprime_failed", {
            plugin: "platform.vault",
            method,
            error: String(err instanceof Error ? err.message : err),
          });
        }
      }
      return {
        ok: true,
        backend: cached.backend,
        allowList,
        handleMode,
        companyPolicies,
      };
    }

    // No cached backend, or the config identity changed (including the
    // unconfigured -> configured transition) — (re)build now, live.
    let backend: VaultwardenBackend;
    try {
      backend = new VaultwardenBackend({
        serverUrl: identity.serverUrl,
        allowedServerHosts: identity.allowedServerHosts,
        email: rawConfig.serviceAccountEmail,
        // The SDK types require a dispatch runId, but the host ALSO supports
        // worker-lifetime calls (service-context branch): with runId
        // omitted, the server back-fills the plugin's own service-scope runId
        // and authorizes against the secret's owning company. Priming
        // (below) relies on that path.
        resolvePassword: (runId) =>
          runId === undefined
            ? (
                ctx.secrets.resolve as unknown as (ref: string) => Promise<string>
              )(rawConfig.masterPasswordRef!)
            : ctx.secrets.resolve(rawConfig.masterPasswordRef!, runId),
        http: ctx.http,
        logger: ctx.logger,
      });
    } catch (err) {
      // Fail closed and loudly: a serverUrl that fails validation (bad
      // scheme, unparseable, or host outside allowedServerHosts) must never
      // reach a constructed backend — the master-password resolve must never
      // even be attempted against it. The thrown error's message carries the
      // rejected reason + host only (see VaultwardenBackend's constructor),
      // never the raw serverUrl and never a credential.
      ctx.logger.warn(
        "vault plugin rejected serverUrl — tool calls will return prerequisite_missing until this is fixed",
        {
          plugin: "platform.vault",
          method,
          error: String(err instanceof Error ? err.message : err),
        },
      );
      cached = null;
      return {
        ok: false,
        error: "prerequisite_missing: vault serverUrl is misconfigured",
      };
    }

    try {
      await backend.prime();
    } catch (err) {
      ctx.logger.warn("vault.session_prime_failed", {
        plugin: "platform.vault",
        method,
        error: String(err instanceof Error ? err.message : err),
      });
    }
    cached = { identity, backend, lastPrimedAt: Date.now() };
    ctx.logger.info("vault backend (re)built for the current config", {
      method,
      serverUrl: identity.serverUrl,
    });

    return { ok: true, backend, allowList, handleMode, companyPolicies };
  };
}

export async function createVaultWorker(
  ctx: PluginContext,
  options: CreateVaultWorkerOptions = {},
): Promise<{ backend: VaultBackend | null }> {
  const resolveRuntime = createVaultRuntimeResolver(ctx, options);

  // One eager resolve at setup: gives the operator an immediate signal (info
  // or warn log) rather than waiting for the first dispatch, and seeds the
  // resolver's warm-backend cache. This is a convenience only — every
  // dispatch re-resolves live regardless of what happened here.
  const initial = await resolveRuntime("setup");
  if (!initial.ok) {
    ctx.logger.warn(
      "vault plugin started without a usable backend — tool calls will return prerequisite_missing until config is fixed",
      { reason: initial.error },
    );
  } else {
    ctx.logger.info("paperclip-plugin-vault worker ready", {
      allowListSize: initial.allowList.length,
      handleMode: initial.handleMode,
      companyPolicyCount: Object.keys(initial.companyPolicies ?? {}).length,
    });
  }

  registerVaultTools(ctx, {
    resolveRuntime,
    writeAudit: makeActivityAudit(ctx),
    logger: ctx.logger,
  });

  return { backend: initial.ok ? initial.backend : null };
}

function makeActivityAudit(
  ctx: PluginContext,
): (entry: import("./worker/registerTools.js").AuditRow) => Promise<void> {
  return async (entry) => {
    const tool = `vault.${entry.operation}`;
    await ctx.activity.log({
      companyId: entry.companyId,
      entityType: tool,
      entityId: entry.secretRef,
      message: `${tool} ${entry.outcome}`,
      metadata: {
        agentId: entry.agentId,
        runId: entry.runId,
        operation: entry.operation,
        outcome: entry.outcome,
        secretRef: entry.secretRef,
        ...(entry.error ? { error: entry.error } : {}),
      },
    });
  };
}

const plugin = definePlugin({
  async setup(ctx) {
    await createVaultWorker(ctx);
  },

  async onHealth() {
    return { status: "ok", message: "paperclip-plugin-vault worker is running" };
  },
});

export default plugin;
runWorker(plugin, import.meta.url);

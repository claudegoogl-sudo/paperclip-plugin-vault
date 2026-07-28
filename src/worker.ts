import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";
import { registerVaultTools } from "./worker/registerTools.js";
import type { VaultBackend } from "./worker/VaultBackend.js";
import { VaultwardenBackend } from "./worker/VaultwardenBackend.js";

interface VaultConfig {
  serverUrl?: string;
  /**
   * Operator-configurable host allowlist for `serverUrl` (PLA safety
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

export async function createVaultWorker(
  ctx: PluginContext,
  options: CreateVaultWorkerOptions = {},
): Promise<{ backend: VaultBackend | null }> {
  const rawConfig = (await ctx.config.get()) as Partial<VaultConfig>;
  const allowList = rawConfig.allowList ?? [];
  const handleMode = rawConfig.handleMode === true;

  if (
    !options.backendOverride &&
    (!rawConfig.serviceAccountEmail ||
      !rawConfig.masterPasswordRef ||
      allowList.length === 0)
  ) {
    // Permissive init pattern : allow the worker to load with
    // incomplete config so plugin install exits 0 and the operator can fix
    // it via the config UI. Tool calls surface `prerequisite_missing`.
    ctx.logger.warn(
      "vault plugin started with incomplete config — tool calls will return prerequisite_missing",
      {
        hasServiceAccount: Boolean(rawConfig.serviceAccountEmail),
        hasMasterPasswordRef: Boolean(rawConfig.masterPasswordRef),
        allowListSize: allowList.length,
      },
    );
    registerVaultTools(ctx, {
      backend: makeUnconfiguredBackend(),
      allowList: [],
      writeAudit: makeActivityAudit(ctx),
      logger: ctx.logger,
      handleMode,
    });
    return { backend: null };
  }

  let backend: VaultBackend;
  if (options.backendOverride) {
    backend = options.backendOverride;
  } else {
    try {
      backend = new VaultwardenBackend({
        serverUrl: rawConfig.serverUrl ?? DEFAULT_SERVER_URL,
        allowedServerHosts: rawConfig.allowedServerHosts,
        email: rawConfig.serviceAccountEmail!,
        // The SDK types require a dispatch runId, but the host ALSO supports
        // worker-lifetime calls (service-context branch): with runId
        // omitted, the server back-fills the plugin's own service-scope runId
        // and authorizes against the secret's owning company. Session priming
        // (no active dispatch) relies on that path, hence the cast.
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
      // Fail closed and loudly (PLA safety follow-up): a serverUrl that
      // fails validation (bad scheme, unparseable, or host outside
      // allowedServerHosts) must never reach a constructed backend — the
      // master-password resolve must never even be attempted against it.
      // The thrown error's message carries the rejected reason + host
      // only (see VaultwardenBackend's constructor), never the raw
      // serverUrl and never a credential.
      ctx.logger.warn(
        "vault plugin rejected serverUrl — tool calls will return prerequisite_missing until this is fixed",
        { error: String(err instanceof Error ? err.message : err) },
      );
      registerVaultTools(ctx, {
        backend: makeUnconfiguredBackend(),
        allowList: [],
        writeAudit: makeActivityAudit(ctx),
        logger: ctx.logger,
        handleMode,
      });
      return { backend: null };
    }
  }

  // Session lifecycle: prime the unlocked session from THIS worker-lifetime
  // context so the master-password resolve runs under the plugin's own
  // service scope. The host gates `secrets.resolve` by the dispatch scope, so
  // a cold unlock inside a tool call only works for the company that owns the
  // master-password secret — every other company's calls depend on a warm
  // session. The TTL timer therefore re-primes right after each hygiene
  // clear instead of leaving the session cold.
  const ttlMs = (rawConfig.sessionTtlSeconds ?? 3600) * 1000;
  if (backend instanceof VaultwardenBackend) {
    const prime = (phase: string) =>
      backend.prime().then(
        () => ctx.logger.info("vault session primed", { phase }),
        (err) =>
          ctx.logger.warn("vault session prime failed", {
            phase,
            error: String(err instanceof Error ? err.message : err),
          }),
      );
    void prime("setup");
    const timer = setInterval(() => {
      backend.clear();
      void prime("ttl-refresh");
    }, ttlMs);
    timer.unref?.();
  }

  registerVaultTools(ctx, {
    backend,
    allowList,
    writeAudit: makeActivityAudit(ctx),
    logger: ctx.logger,
    handleMode,
    companyPolicies: rawConfig.companyPolicies,
  });

  ctx.logger.info("paperclip-plugin-vault worker ready", {
    serverUrl: rawConfig.serverUrl ?? DEFAULT_SERVER_URL,
    serviceAccountEmail: rawConfig.serviceAccountEmail,
    allowListSize: allowList.length,
    sessionTtlSeconds: rawConfig.sessionTtlSeconds ?? 3600,
    handleMode,
    companyPolicyCount: Object.keys(rawConfig.companyPolicies ?? {}).length,
  });

  return { backend };
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

function makeUnconfiguredBackend(): VaultBackend {
  return {
    read: async () => {
      throw new Error("vault plugin not configured");
    },
    list: async () => [],
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

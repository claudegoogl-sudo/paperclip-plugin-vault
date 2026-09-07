import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext, PluginLogger } from "@paperclipai/plugin-sdk";
import { registerVaultTools } from "./worker/registerTools.js";
import type { VaultBackend } from "./worker/VaultBackend.js";
import { VaultwardenBackend } from "./worker/VaultwardenBackend.js";
import type { VaultRuntimeOk, VaultRuntimeResult } from "./worker/vaultRuntime.js";
import { raiseDeniedAlarmIfNew } from "./worker/deniedAlarm.js";
import { resolveMasterPassword } from "./worker/secretRefBinding.js";

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
  /**
   * Instance-level vault ref patterns. Since 0.2.0 this is an ACTIVATION
   * requirement only — a non-empty list is required to activate the worker
   * (a worker that boots without one never registers working tools), but it
   * grants nothing: per-company grants come exclusively from
   * `companyPolicies` entries (see `policyFor` in
   * worker/registerTools.ts). Never inherited by any company.
   */
  allowList?: string[];
  sessionTtlSeconds?: number;
  /**
   * Instance-level borrowed-handle flag. Since 0.2.0 it is NEVER inherited
   * and has no runtime effect: `handleMode` comes only from each company's
   * `companyPolicies` entry (omitted there = OFF). Kept in the config shape
   * so existing instance configs continue to validate; setting it does
   * nothing. See `policyFor` in worker/registerTools.ts.
   */
  handleMode?: boolean;
  /**
   * Per-company policy keyed by Paperclip companyId — the ONLY grant source
   * since 0.2.0. A company may call the vault tools iff it is listed here
   * with a non-empty `allowList`, and its grant is exactly that entry's
   * list: an entry REPLACES (never intersects or narrows) the instance-level
   * list. FAIL-CLOSED on every drift shape:
   * - map absent or empty → EVERY company is denied (`vault.policymap_missing`).
   * - entry without `allowList` → that company is denied
   *   (`vault.policy_entry_missing_allowlist`) — an entry never inherits the
   *   instance-level list.
   * - `handleMode` omitted in an entry = OFF, even when the instance-level
   *   `handleMode` is true.
   * Both drift shapes are surfaced loudly at boot (see `reportPolicyDrift`)
   * and on each denied call (structured error events), and denied calls
   * still produce the ordinary `denied_by_allowlist` audit row + alarm.
   * See `policyFor` in worker/registerTools.ts.
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
    /**
     * Tracks a currently-running {@link VaultwardenBackend.prime} for this
     * cached backend (started either by the cold-build path below or by the
     * TTL-reprime branch here). While set, a dispatch that observes an
     * expired `lastPrimedAt` piggybacks on it instead of calling `clear()` +
     * starting a second `prime()` — `VaultwardenBackend.unlock()` is itself
     * single-flighted, so a second `prime()` would converge on the same
     * network round-trip anyway, but skipping the redundant `clear()` avoids
     * wiping a session another concurrent dispatch is about to receive.
     * Never rejects: prime failures are caught and logged where the promise
     * is created.
     */
    primeInFlight: Promise<void> | null;
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
        if (cached.primeInFlight) {
          // Another concurrent dispatch already started a reprime (or this
          // is still the cold-build prime from below); await it instead of
          // clearing the session out from under it and starting a duplicate.
          await cached.primeInFlight;
        } else {
          cached.backend.clear();
          const primeStarted = cached;
          const primePromise = cached.backend.prime().then(
            () => {
              if (cached === primeStarted) {
                cached.lastPrimedAt = Date.now();
              }
            },
            (err) => {
              ctx.logger.warn("vault.session_reprime_failed", {
                plugin: "platform.vault",
                method,
                error: String(err instanceof Error ? err.message : err),
              });
            },
          );
          cached.primeInFlight = primePromise.finally(() => {
            if (cached === primeStarted) {
              cached.primeInFlight = null;
            }
          });
          await cached.primeInFlight;
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
        // See `resolveMasterPassword` for why the call shape differs between
        // the priming (no runId) and in-dispatch (runId) cases.
        resolvePassword: (runId) =>
          resolveMasterPassword(ctx.secrets, rawConfig.masterPasswordRef!, runId),
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

    // Priming is best-effort and must never sit on this resolver's return
    // path: the caller may be the eager "setup" resolve, which the host's
    // worker-activation RPC (`initialize`) is waiting on with a fixed,
    // non-tunable budget. Session priming does a network round-trip plus a
    // 600k+-iteration PBKDF2 derivation, which can easily run long under
    // host load — so it runs fire-and-forget here. A cold/still-priming
    // session doesn't block activation or tool registration; it only risks
    // the *first* tool call for a company that isn't the master-password
    // owner failing with a retryable error until the background prime (or
    // that company's own dispatch-triggered unlock) lands.
    cached = { identity, backend, lastPrimedAt: 0, primeInFlight: null };
    const primeStarted = cached;
    const primePromise = backend.prime().then(
      () => {
        if (cached === primeStarted) {
          cached.lastPrimedAt = Date.now();
        }
        ctx.logger.info("vault session primed", { method });
      },
      (err) => {
        ctx.logger.warn("vault.session_prime_failed", {
          plugin: "platform.vault",
          method,
          error: String(err instanceof Error ? err.message : err),
        });
      },
    );
    cached.primeInFlight = primePromise.finally(() => {
      if (cached === primeStarted) {
        cached.primeInFlight = null;
      }
    });
    ctx.logger.info("vault backend (re)built for the current config", {
      method,
      serverUrl: identity.serverUrl,
    });

    return { ok: true, backend, allowList, handleMode, companyPolicies };
  };
}

/**
 * Boot-time misconfiguration sweep for the companyPolicies map. Pure: reads
 * the freshly-resolved runtime and writes structured `error` events; never
 * throws, never mutates, and (deliberately) never fails startup — config is
 * re-read live on every dispatch, so a worker that boots with drifted config
 * and is fixed later must self-heal (`tests/liveConfigReread.spec.ts`),
 * and a startup failure would convert a config drift into a registration
 * outage. The loud signal is the error events themselves, the per-call deny
 * events, and the ordinary `denied_by_allowlist` audit/alarm path.
 *
 * Emits `vault.policymap_missing` when the map is absent or empty, and
 * `vault.policy_entry_missing_allowlist` (once per bad entry, with
 * `companyId`) for entries lacking an `allowList` — the two drift shapes
 * that deny at call time. An operator whose edit broke tenant scoping sees
 * the exact companyId at the next worker start without waiting for a denied
 * call. Deliberately asymmetric with call-time enforcement: an entry with a
 * present-but-empty `allowList` is schema-invalid (minItems 1) and denies
 * by matching nothing, but is not a named drift event on either path.
 */
export function reportPolicyDrift(
  runtime: Pick<VaultRuntimeOk, "companyPolicies" | "allowList">,
  logger: PluginLogger,
): void {
  const missing = policyEntriesMissingAllowList(runtime.companyPolicies);
  if (missing === null) {
    logger.error("vault.policymap_missing", {
      plugin: "platform.vault",
      method: "setup",
    });
    return;
  }
  for (const companyId of missing) {
    logger.error("vault.policy_entry_missing_allowlist", {
      plugin: "platform.vault",
      method: "setup",
      companyId,
    });
  }
}

/**
 * Shared misconfigured-entry predicate behind `reportPolicyDrift` and the
 * ready log. Returns `null` when the map itself is absent/empty (drift
 * shape A — the whole map is missing), otherwise the list of companyIds
 * whose entries lack a usable `allowList` (drift shape B; an entry value
 * that is not an object counts as lacking). An `allowList` present but not
 * an array also counts as lacking; a present-but-empty array does not —
 * it denies by matching nothing (same asymmetry as the call-time events).
 */
function policyEntriesMissingAllowList(
  companyPolicies: VaultRuntimeOk["companyPolicies"],
): string[] | null {
  if (!companyPolicies || typeof companyPolicies !== "object") return null;
  const entries = Object.entries(companyPolicies);
  if (entries.length === 0) return null;
  const missing: string[] = [];
  for (const [companyId, entry] of entries) {
    const allowList = (entry as { allowList?: unknown } | null)?.allowList;
    if (!Array.isArray(allowList)) missing.push(companyId);
  }
  return missing;
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
    // Boot-time drift sweep: name misconfigured companyPolicies state in the
    // log at startup so an operator sees the exact companyId without waiting
    // for a denied call. Not a startup failure and not a health flip — see
    // reportPolicyDrift.
    reportPolicyDrift(initial, ctx.logger);
    const missing = policyEntriesMissingAllowList(initial.companyPolicies);
    ctx.logger.info("paperclip-plugin-vault worker ready", {
      companyPolicyCount: Object.keys(initial.companyPolicies ?? {}).length,
      misconfiguredPolicyEntries: missing === null ? 0 : missing.length,
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
    // Denied-by-allowList rows additionally raise an idempotent Paperclip
    // issue so the platform team sees them within hours, not on a fortnightly
    // audit-review cadence. The row already carries every field the alarm
    // needs (agentId, runId, companyId, secretRef) — we do NOT widen what the
    // plugin logs to drive this; the alarm consumes the existing row. The
    // alarm fires after the audit row is durably written so a state or issue
    // failure never loses the audit record. Best-effort: errors are caught
    // inside `raiseDeniedAlarmIfNew` and never reach the caller.
    if (entry.outcome === "denied_by_allowlist") {
      await raiseDeniedAlarmIfNew(
        {
          getState: (key) =>
            ctx.state.get({
              scopeKind: "company",
              scopeId: entry.companyId,
              namespace: "denied-alarms",
              stateKey: key,
            }),
          setState: (key, value) =>
            ctx.state.set(
              {
                scopeKind: "company",
                scopeId: entry.companyId,
                namespace: "denied-alarms",
                stateKey: key,
              },
              value,
            ),
          createIssue: (input) =>
            ctx.issues.create({
              companyId: entry.companyId,
              title: input.title,
              description: input.description,
              priority: input.priority,
            }),
          log: (level, message, meta) => ctx.logger[level](message, meta),
          companyId: entry.companyId,
        },
        entry,
      );
    }
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

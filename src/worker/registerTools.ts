import type {
  PluginContext,
  PluginLogger,
  ToolResult,
  ToolRunContext,
} from "@paperclipai/plugin-sdk";
import {
  InvalidAllowPatternError,
  InvalidSecretRefError,
  compileAllowList,
  parseVaultRef,
} from "./secretRef.js";
import {
  VaultAuthError,
  VaultBackendError,
  VaultItemNotFoundError,
} from "./VaultBackend.js";
import type { VaultRuntimeOk, VaultRuntimeResult } from "./vaultRuntime.js";

export interface VaultToolDependencies {
  /**
   * Resolves the live backend + authorization config for the CURRENT call.
   * Invoked at the top of every `vault.read` / `vault.list` dispatch — never
   * once at registration time — so a config edit (allowList, handleMode,
   * companyPolicies) or a plugin that finishes being configured after
   * startup takes effect on the very next call, no worker restart. `method`
   * identifies the calling tool for error logs.
   */
  resolveRuntime: (method: string) => Promise<VaultRuntimeResult>;
  /**
   * Audit log writer. Defaults to ctx.activity.log; tests inject a stub.
   * Receives outcome `success`, `denied_by_allowlist`, `not_found`,
   * `invalid_ref`, or `error` and never the resolved plaintext.
   */
  writeAudit: (entry: AuditRow) => Promise<void>;
  logger: PluginLogger;
}

export interface AuditRow {
  /** Which tool produced the row; drives the activity entityType. */
  operation: "read" | "list";
  agentId: string;
  runId: string;
  companyId: string;
  /** For `read` the requested ref; for `list` the requested glob (or a
   * scope sentinel when unscoped). Never a secret value. */
  secretRef: string;
  outcome:
    | "success"
    | "denied_by_allowlist"
    | "invalid_ref"
    | "not_found"
    | "error";
  error?: string;
}

/**
 * Wire the `vault.read` and `vault.list` tools onto a plugin context.
 *
 * `vault.read` returns the resolved plaintext on `data.value`. The string
 * is also placed on `content` so SDK consumers that read content directly
 * (rather than parsing data) still see the value — but the plugin never
 * logs, persists, or echoes it. Out-of-allowList refs return an
 * `error: "prerequisite_missing: ..."` result without contacting the vault.
 *
 * MIGRATION (borrowed-handle mode): when the binding sets `handleMode`, both
 * `content` and `data.value` carry an opaque host-minted handle rather than
 * plaintext. Consumers must route `data.value` through a downstream tool
 * param (the host egress chokepoint resolves it) instead of reading it
 * directly. `handleMode` defaults off, so plaintext-reading callers keep
 * working until their binding opts in.
 */
type CompiledPolicy = { compiled: readonly RegExp[]; handleMode: boolean };

/**
 * Compile the live runtime's allowList / companyPolicies into an effective
 * policy for `companyId`. Runs on every call (the runtime it reads was
 * itself just live-resolved) rather than once at registration, so a pattern
 * edited in config takes effect on the next dispatch. Returns `null` when
 * companyPolicies is configured and the company isn't listed (fail-closed:
 * no fallback to the instance-wide allowList), or when a pattern fails to
 * compile (fail-closed + loud: logged at `error`, never a silent deny).
 */
function policyFor(
  runtime: Pick<VaultRuntimeOk, "allowList" | "handleMode" | "companyPolicies">,
  companyId: string,
  logger: PluginLogger,
  method: string,
): CompiledPolicy | null {
  const compileSafely = (patterns: readonly string[]): readonly RegExp[] | null => {
    try {
      for (const pattern of patterns) {
        compileAllowList([pattern]);
      }
      return compileAllowList(patterns);
    } catch (err) {
      logger.error("vault.allowlist_compile_failed", {
        plugin: "platform.vault",
        method,
        error:
          err instanceof InvalidAllowPatternError
            ? err.message
            : String(err instanceof Error ? err.message : err),
      });
      return null;
    }
  };

  const companyPolicies = runtime.companyPolicies ?? {};
  const policyCompanyIds = Object.keys(companyPolicies);

  if (policyCompanyIds.length === 0) {
    const compiled = compileSafely(runtime.allowList);
    if (!compiled) return null;
    return { compiled, handleMode: runtime.handleMode };
  }

  const policy = companyPolicies[companyId];
  if (!policy) return null;
  const list = policy.allowList ?? runtime.allowList;
  const compiled = compileSafely(list);
  if (!compiled) return null;
  return { compiled, handleMode: policy.handleMode ?? runtime.handleMode };
}

export function registerVaultTools(
  ctx: PluginContext,
  deps: VaultToolDependencies,
): void {
  const { resolveRuntime, writeAudit, logger } = deps;

  ctx.tools.register(
    "vault.read",
    {
      displayName: "Vault Read",
      description:
        "Resolve a vault:// reference to its plaintext secret value. " +
        "Checked against the adapter's allowList before any network call.",
      parametersSchema: {
        type: "object",
        properties: {
          secretRef: { type: "string", pattern: "^vault://[^/]+/[^/]+/[^/]+$" },
        },
        required: ["secretRef"],
        additionalProperties: false,
      },
    },
    async (params: unknown, runCtx: ToolRunContext): Promise<ToolResult> => {
      const secretRef = readSecretRefParam(params);
      const baseAudit: Omit<AuditRow, "outcome"> = {
        operation: "read",
        agentId: runCtx.agentId,
        runId: runCtx.runId,
        companyId: runCtx.companyId,
        secretRef,
      };

      const runtime = await resolveRuntime("read");
      if (!runtime.ok) {
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "error",
          error: runtime.error,
        });
        return { error: runtime.error };
      }
      const { backend } = runtime;

      const policy = policyFor(runtime, runCtx.companyId, logger, "read");
      if (!policy) {
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "denied_by_allowlist",
        });
        return {
          error:
            `prerequisite_missing: no vault policy is configured for this ` +
            `company. Ask the Platform CTO to add a companyPolicies entry.`,
        };
      }

      let parsed;
      try {
        parsed = parseVaultRef(secretRef);
      } catch (err) {
        if (err instanceof InvalidSecretRefError) {
          await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "invalid_ref" });
          return { error: `invalid_ref: ${err.message}` };
        }
        throw err;
      }

      if (!policy.compiled.some((re) => re.test(secretRef))) {
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "denied_by_allowlist",
        });
        return {
          error:
            `prerequisite_missing: ${secretRef} is not in this adapter's allowList. ` +
            `Update the plugin instance config or ask CTO to extend the grant.`,
        };
      }

      try {
        const value = await backend.read(parsed, runCtx.runId);
        if (policy.handleMode) {
          // Borrowed-handle mode: hand back an opaque borrowed handle instead
          // of plaintext. The host mints a per-run handle that resolves to the
          // real value only when a downstream tool param routes through the
          // egress chokepoint; the persisted transcript keeps the handle.
          // Fail-closed: a mint failure NEVER falls back to plaintext.
          let handle: string;
          try {
            handle = await ctx.secrets.mintHandle(value, runCtx.runId);
          } catch (mintErr) {
            const name =
              mintErr instanceof Error && mintErr.name ? mintErr.name : "Error";
            await safeAudit(writeAudit, logger, {
              ...baseAudit,
              outcome: "error",
              error: `mint_failed: ${name}`,
            });
            return { error: `error: mint_failed: ${name}` };
          }
          await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "success" });
          return { content: handle, data: { value: handle, ref: secretRef } };
        }
        await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "success" });
        return { content: value, data: { value, ref: secretRef } };
      } catch (err) {
        if (err instanceof VaultItemNotFoundError) {
          await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "not_found" });
          return { error: `not_found: ${err.message}` };
        }
        const msg = safeBackendErrorMessage(err);
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "error",
          error: msg,
        });
        // Surface a body-free, allowlisted error string only — never an
        // arbitrary backend message that could carry a server response body.
        return { error: `error: ${msg}` };
      }
    },
  );

  ctx.tools.register(
    "vault.list",
    {
      displayName: "Vault List",
      description:
        "List item names the adapter is allowed to resolve, optionally " +
        "filtered to a vault://<org>/<collection>/* glob. Never returns values.",
      parametersSchema: {
        type: "object",
        properties: {
          collectionGlob: { type: "string" },
        },
        additionalProperties: false,
      },
    },
    async (params: unknown, runCtx: ToolRunContext): Promise<ToolResult> => {
      const glob = readListGlobParam(params);
      const baseAudit: Omit<AuditRow, "outcome"> = {
        operation: "list",
        agentId: runCtx.agentId,
        runId: runCtx.runId,
        companyId: runCtx.companyId,
        // No-glob lists are scoped by the allowList post-filter below; record
        // the requested glob, or a sentinel when the caller passed none.
        secretRef: glob ?? "(no glob: allowList scopes)",
      };

      const runtime = await resolveRuntime("list");
      if (!runtime.ok) {
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "error",
          error: runtime.error,
        });
        return { error: runtime.error };
      }
      const { backend } = runtime;

      const policy = policyFor(runtime, runCtx.companyId, logger, "list");
      if (!policy) {
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "denied_by_allowlist",
        });
        return {
          error:
            `prerequisite_missing: no vault policy is configured for this ` +
            `company. Ask the Platform CTO to add a companyPolicies entry.`,
        };
      }

      let filter: { org?: string; collection?: string } | undefined;
      if (glob) {
        const m = /^vault:\/\/([^/]+)\/([^/]+)\/[*]$/.exec(glob);
        if (!m) {
          await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "invalid_ref" });
          return {
            error:
              `invalid_glob: list filter must look like vault://<org>/<collection>/*`,
          };
        }
        filter = { org: m[1]!, collection: m[2]! };
        // Honor allowList: caller can't widen the listing past their grant.
        const probe = `${glob.slice(0, -1)}__probe__`;
        if (!policy.compiled.some((re) => re.test(probe))) {
          await safeAudit(writeAudit, logger, {
            ...baseAudit,
            outcome: "denied_by_allowlist",
          });
          return {
            error: `prerequisite_missing: ${glob} is outside this adapter's allowList.`,
          };
        }
      }
      try {
        // Always re-filter every returned item against the allowList by its
        // full ref. This is the real authz boundary: an unscoped call
        // (no glob) lists the whole vault at the backend but only names
        // inside an allowed scope ever leave this function. F2.
        const items = await backend.list(filter, runCtx.runId);
        const names = Array.from(
          new Set(
            items
              .filter((e) =>
                policy.compiled.some((re) =>
                  re.test(`vault://${e.org}/${e.collection}/${e.item}`),
                ),
              )
              .map((e) => e.item),
          ),
        );
        await safeAudit(writeAudit, logger, { ...baseAudit, outcome: "success" });
        return { data: { names } };
      } catch (err) {
        const msg = safeBackendErrorMessage(err);
        await safeAudit(writeAudit, logger, {
          ...baseAudit,
          outcome: "error",
          error: msg,
        });
        logger.warn("vault.list_failed", { error: msg });
        return { error: `error: ${msg}` };
      }
    },
  );
}

function readSecretRefParam(params: unknown): string {
  if (!params || typeof params !== "object") {
    throw new Error("invalid_params: expected object");
  }
  const ref = (params as { secretRef?: unknown }).secretRef;
  if (typeof ref !== "string") {
    throw new Error("invalid_params: secretRef must be a string");
  }
  return ref;
}

function readListGlobParam(params: unknown): string | null {
  if (!params || typeof params !== "object") return null;
  const g = (params as { collectionGlob?: unknown }).collectionGlob;
  return typeof g === "string" && g.length > 0 ? g : null;
}

/**
 * Reduce a backend error to a body-free string safe to audit and return.
 *
 * Only errors whose classes guarantee a body-free `message`
 * ({@link VaultItemNotFoundError}, {@link VaultAuthError},
 * {@link VaultBackendError}) have their message surfaced. Any other error —
 * including a raw transport error that may carry a server response body or
 * secret-bearing detail — is reduced to its class name. This is the F8
 * boundary: server response bodies never reach the audit log or the caller.
 */
export function safeBackendErrorMessage(err: unknown): string {
  if (
    err instanceof VaultItemNotFoundError ||
    err instanceof VaultAuthError ||
    err instanceof VaultBackendError
  ) {
    return err.message;
  }
  const name = err instanceof Error && err.name ? err.name : "Error";
  return `backend_error: ${name}`;
}

async function safeAudit(
  writeAudit: (entry: AuditRow) => Promise<void>,
  logger: PluginLogger,
  entry: AuditRow,
): Promise<void> {
  try {
    await writeAudit(entry);
  } catch (err) {
    // Audit failures must not break the tool call but should be loud.
    logger.error("vault.audit_write_failed", {
      outcome: entry.outcome,
      secretRef: entry.secretRef,
      error: String(err instanceof Error ? err.message : err),
    });
  }
}

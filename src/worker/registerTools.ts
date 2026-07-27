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
  type VaultBackend,
} from "./VaultBackend.js";

export interface VaultToolDependencies {
  backend: VaultBackend;
  allowList: readonly string[];
  /**
   * Audit log writer. Defaults to ctx.activity.log; tests inject a stub.
   * Receives outcome `success`, `denied_by_allowlist`, `not_found`,
   * `invalid_ref`, or `error` and never the resolved plaintext.
   */
  writeAudit: (entry: AuditRow) => Promise<void>;
  logger: PluginLogger;
  /**
   * Per-binding opt-in to borrowed-handle mode (borrowed-handle mode).
   * When true, `vault.read` returns an opaque host-minted handle (via
   * `ctx.secrets.mintHandle`) on both `content` and `data.value` instead of
   * plaintext. Defaults false: behaviour is unchanged until a binding opts in.
   */
  handleMode?: boolean;
  /**
   * Per-company policy keyed by Paperclip companyId. FAIL-CLOSED: when this
   * map is present and non-empty, ONLY listed companies may call the vault
   * tools — any other `runCtx.companyId` is denied before parsing or any
   * network call. Each entry may narrow `allowList` (defaults to the
   * instance allowList) and override `handleMode` (defaults to the instance
   * flag). When absent/empty, the legacy single-allowList behaviour applies
   * to every company.
   */
  companyPolicies?: Record<
    string,
    { allowList?: readonly string[]; handleMode?: boolean }
  >;
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
export function registerVaultTools(
  ctx: PluginContext,
  deps: VaultToolDependencies,
): void {
  const { backend, allowList, writeAudit, logger } = deps;
  const defaultHandleMode = deps.handleMode ?? false;
  // Validate every allowList (instance default + per-company) at
  // registration time so a bad pattern fails loudly (before the first tool
  // call) rather than silently denying every request.
  const validatePatterns = (patterns: readonly string[]): void => {
    for (const pattern of patterns) {
      try {
        compileAllowList([pattern]);
      } catch (err) {
        if (err instanceof InvalidAllowPatternError) throw err;
        throw new Error(`failed to compile allowList pattern ${pattern}: ${String(err)}`);
      }
    }
  };
  validatePatterns(allowList);
  const defaultCompiled = compileAllowList(allowList);

  const companyPolicies = deps.companyPolicies ?? {};
  const policyCompanyIds = Object.keys(companyPolicies);
  const compiledByCompany = new Map<
    string,
    { compiled: readonly RegExp[]; handleMode: boolean }
  >();
  for (const companyId of policyCompanyIds) {
    const policy = companyPolicies[companyId]!;
    const list = policy.allowList ?? allowList;
    validatePatterns(list);
    compiledByCompany.set(companyId, {
      compiled: compileAllowList(list),
      handleMode: policy.handleMode ?? defaultHandleMode,
    });
  }

  /**
   * Effective policy for the calling company. `null` = denied: when
   * companyPolicies is configured, an unlisted company gets NO vault access
   * (fail-closed) rather than falling back to the instance-wide allowList.
   */
  const policyFor = (
    companyId: string,
  ): { compiled: readonly RegExp[]; handleMode: boolean } | null => {
    if (policyCompanyIds.length === 0) {
      return { compiled: defaultCompiled, handleMode: defaultHandleMode };
    }
    return compiledByCompany.get(companyId) ?? null;
  };

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

      const policy = policyFor(runCtx.companyId);
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

      const policy = policyFor(runCtx.companyId);
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

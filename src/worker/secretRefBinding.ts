import type { EnvSecretRefBinding, PluginContext } from "@paperclipai/plugin-sdk";

/**
 * Wrap a stored (legacy, bare-UUID) Paperclip secret-ref string into the
 * shared `{ type: "secret_ref", secretId, version? }` object binding shape.
 */
export function toSecretRefBinding(
  secretRef: MasterPasswordRef,
): EnvSecretRefBinding {
  if (typeof secretRef === "string") {
    return { type: "secret_ref", secretId: secretRef };
  }
  if (
    secretRef === null ||
    typeof secretRef !== "object" ||
    secretRef.type !== "secret_ref" ||
    typeof secretRef.secretId !== "string" ||
    secretRef.secretId.length === 0
  ) {
    throw new Error(
      'masterPasswordRef must be a secret UUID string or { type: "secret_ref", secretId, version? }',
    );
  }
  // Re-build instead of passing through: never double-wrap, never forward
  // unknown fields.
  const binding: EnvSecretRefBinding = {
    type: "secret_ref",
    secretId: secretRef.secretId,
  };
  if (secretRef.version !== undefined) {
    (binding as { version?: unknown }).version = secretRef.version;
  }
  return binding;
}

/**
 * Stored config shape for `masterPasswordRef`: the legacy bare secret UUID
 * string, or the shared `{ type: "secret_ref", secretId, version? }` object.
 */
export type MasterPasswordRef =
  | string
  | { type: "secret_ref"; secretId: string; version?: number | "latest" };

/** Stable identity key for config-change detection (string vs object differ). */
export function masterPasswordRefKey(ref: MasterPasswordRef | undefined): string | undefined {
  return ref === undefined ? undefined : JSON.stringify(ref);
}

/**
 * Resolve the vault plugin's `masterPasswordRef` through `ctx.secrets`,
 * picking the call shape the host's route requires for each case:
 *
 * - `runId === undefined` (worker-lifetime priming, no active dispatch, no
 *   company context attached): `ctx.secrets.resolveService` never has a
 *   companyId to route through the upstream object-ref-only
 *   `resolveWithCompanyContext` path, so it still accepts — and must be
 *   given — the legacy bare-UUID string shape.
 * - `runId` defined (in-dispatch call): the host attaches company context
 *   for this runId, which routes to `resolveWithCompanyContext`. That path
 *   requires the shared `{ type: "secret_ref", secretId }` object binding
 *   shape and rejects a bare string outright with `InvalidSecretRefError`.
 *
 * This is the exact call shape `VaultwardenBackend`'s injected
 * `resolvePassword(runId)` emits — see worker.ts.
 */
export function resolveMasterPassword(
  secrets: Pick<PluginContext["secrets"], "resolve" | "resolveService">,
  masterPasswordRef: MasterPasswordRef,
  runId: string | undefined,
): Promise<string> {
  const binding = toSecretRefBinding(masterPasswordRef);
  return runId === undefined
    ? secrets.resolveService(binding.secretId)
    : secrets.resolve(binding, { runId });
}

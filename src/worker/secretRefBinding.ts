import type { EnvSecretRefBinding, PluginContext } from "@paperclipai/plugin-sdk";

/**
 * Wrap a stored (legacy, bare-UUID) Paperclip secret-ref string into the
 * shared `{ type: "secret_ref", secretId, version? }` object binding shape.
 */
export function toSecretRefBinding(secretRef: string): EnvSecretRefBinding {
  return { type: "secret_ref", secretId: secretRef };
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
  masterPasswordRef: string,
  runId: string | undefined,
): Promise<string> {
  return runId === undefined
    ? secrets.resolveService(masterPasswordRef)
    : secrets.resolve(toSecretRefBinding(masterPasswordRef), { runId });
}

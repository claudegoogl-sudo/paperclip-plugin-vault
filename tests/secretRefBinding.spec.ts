import { describe, expect, it } from "vitest";
import { resolveMasterPassword, toSecretRefBinding } from "../src/worker/secretRefBinding.js";

/**
 * Regression test for the vault worker's in-dispatch secret-ref call shape.
 *
 * These fakes model the two branches of the host's real
 * `plugin-secrets-handler.js` `resolve()` route:
 *
 *  - `resolveWithCompanyContext` (entered for any in-dispatch call, i.e.
 *    whenever a runId/company context is attached) throws
 *    `InvalidSecretRefError` when handed a bare string, and only accepts the
 *    `{ type: "secret_ref", secretId }` object shape.
 *  - the legacy no-company-context path (used by `resolveService`, which the
 *    host never attaches a companyId to) only accepts a bare string.
 *
 * A worker that sends the wrong shape into either path reproduces the live
 * reported live failure (`vault.list`/`vault.read` return `backend_error:
 * JsonRpcCallError` / `InvalidSecretRefError` in server.log). Reverting
 * `resolveMasterPassword` to the old
 * `ctx.secrets.resolve(masterPasswordRef, runId)` positional-string call
 * turns this test red.
 */
function fakeHostSecretsClient() {
  const resolveCalls: unknown[] = [];
  const resolveServiceCalls: unknown[] = [];
  return {
    resolveCalls,
    resolveServiceCalls,
    // Models `resolveWithCompanyContext`: object-shape only.
    resolve: async (secretRef: unknown, options?: { runId?: string }) => {
      resolveCalls.push({ secretRef, options });
      if (typeof secretRef === "string") {
        throw new Error(
          'InvalidSecretRefError: Use { type: "secret_ref", secretId, version? }',
        );
      }
      if (!options?.runId) {
        throw new Error("runcontext_invalid: no active dispatch runId");
      }
      return "unlocked-master-password";
    },
    // Models the legacy no-company-context path: bare string only.
    resolveService: async (secretRef: unknown) => {
      resolveServiceCalls.push({ secretRef });
      if (typeof secretRef !== "string") {
        throw new Error("invalid_ref: legacy path requires a bare secret UUID string");
      }
      return "unlocked-master-password";
    },
  };
}

const MASTER_PASSWORD_REF = "7b4199e0-be01-46ca-9871-3f37d7e2d38d";

describe("resolveMasterPassword (secret-ref call shape)", () => {
  it("in-dispatch call (runId present) sends the object secret_ref shape and succeeds", async () => {
    const secrets = fakeHostSecretsClient();

    const value = await resolveMasterPassword(secrets, MASTER_PASSWORD_REF, "run-123");

    expect(value).toBe("unlocked-master-password");
    expect(secrets.resolveCalls).toEqual([
      {
        secretRef: { type: "secret_ref", secretId: MASTER_PASSWORD_REF },
        options: { runId: "run-123" },
      },
    ]);
    expect(secrets.resolveServiceCalls).toHaveLength(0);
  });

  it("worker-lifetime priming call (no runId) sends the legacy bare-string shape and succeeds", async () => {
    const secrets = fakeHostSecretsClient();

    const value = await resolveMasterPassword(secrets, MASTER_PASSWORD_REF, undefined);

    expect(value).toBe("unlocked-master-password");
    expect(secrets.resolveServiceCalls).toEqual([{ secretRef: MASTER_PASSWORD_REF }]);
  });

  it("toSecretRefBinding produces the shared object binding shape", () => {
    expect(toSecretRefBinding(MASTER_PASSWORD_REF)).toEqual({
      type: "secret_ref",
      secretId: MASTER_PASSWORD_REF,
    });
  });
});

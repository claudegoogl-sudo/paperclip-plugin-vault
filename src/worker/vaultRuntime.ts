import type { VaultBackend } from "./VaultBackend.js";

export interface VaultRuntimeOk {
  ok: true;
  backend: VaultBackend;
  allowList: readonly string[];
  handleMode: boolean;
  companyPolicies?: Record<
    string,
    { allowList?: readonly string[]; handleMode?: boolean }
  >;
}

export interface VaultRuntimeError {
  ok: false;
  /** Already formatted as a `prerequisite_missing: ...` tool error string. */
  error: string;
}

export type VaultRuntimeResult = VaultRuntimeOk | VaultRuntimeError;

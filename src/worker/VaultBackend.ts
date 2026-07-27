import type { VaultRef } from "./secretRef.js";

/**
 * A single listable item, identified by its full (org, collection, item)
 * coordinates. The tool layer reconstructs `vault://org/collection/item`
 * from these fields and re-checks every entry against the allowList before
 * returning any name to the caller (see registerTools.ts), so the backend
 * may safely return everything the service account can see.
 */
export interface VaultListItem {
  org: string;
  collection: string;
  item: string;
}

/**
 * Pluggable vault backend. Production implementation is
 * {@link VaultwardenBackend}; tests use {@link InMemoryVaultBackend}.
 *
 * Backends are responsible for:
 *   - authenticating against the vault on first use,
 *   - decrypting cipher values per call,
 *   - returning ONLY the secret value (no metadata leakage),
 *   - not persisting plaintext beyond the returned promise.
 */
export interface VaultBackend {
  /**
   * Resolve a vault reference to its current plaintext value.
   * Throws {@link VaultItemNotFoundError} if the org/collection/item triple
   * does not resolve to a cipher this service account can read.
   *
   * `runId` is the calling agent run; it is threaded down to the master-
   * password unlock (`ctx.secrets.resolve(ref, runId)`). Omitted for
   * worker-lifetime calls (session priming), which resolve under the
   * plugin's own service scope — the host gates `secrets.resolve` by the
   * DISPATCH scope, so a run-scoped resolve only succeeds for the company
   * that owns the master-password secret. Priming keeps the session warm
   * so run-scoped calls from other companies never need to resolve.
   */
  read(ref: VaultRef, runId?: string): Promise<string>;

  /**
   * List items the service account can see, optionally scoped to a single
   * (org, collection) pair. Returns full coordinates (never values) so the
   * tool layer can re-filter against the allowList. `runId` is threaded to
   * the unlock path (see {@link read}).
   */
  list(
    filter: { org?: string; collection?: string } | undefined,
    runId?: string,
  ): Promise<VaultListItem[]>;
}

export class VaultItemNotFoundError extends Error {
  constructor(public readonly ref: VaultRef) {
    super(
      `vault item not found: org=${ref.org} collection=${ref.collection} item=${ref.item}`,
    );
    this.name = "VaultItemNotFoundError";
  }
}

export class VaultAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultAuthError";
  }
}

/**
 * A backend transport/HTTP failure. The `message` is body-free by
 * construction (method + path + status only); any server response body is
 * carried separately on {@link detail} for the logger and is NEVER placed
 * in `message`, so it cannot leak into audited or returned error strings.
 */
export class VaultBackendError extends Error {
  constructor(message: string, readonly detail?: string) {
    super(message);
    this.name = "VaultBackendError";
  }
}

/**
 * In-memory backend for tests. Stores plaintext directly so unit tests
 * can assert on the tool surface without exercising Bitwarden crypto.
 */
export class InMemoryVaultBackend implements VaultBackend {
  private readonly items = new Map<string, string>();

  set(ref: { org: string; collection: string; item: string }, value: string): void {
    this.items.set(this.key(ref), value);
  }

  async read(ref: VaultRef): Promise<string> {
    const value = this.items.get(this.key(ref));
    if (value === undefined) {
      throw new VaultItemNotFoundError(ref);
    }
    return value;
  }

  async list(filter?: { org?: string; collection?: string }): Promise<VaultListItem[]> {
    const out: VaultListItem[] = [];
    for (const k of this.items.keys()) {
      const [org, collection, item] = k.split("\u0000") as [string, string, string];
      if (filter?.org && filter.org !== org) continue;
      if (filter?.collection && filter.collection !== collection) continue;
      out.push({ org, collection, item });
    }
    return out;
  }

  private key(ref: { org: string; collection: string; item: string }): string {
    return `${ref.org}\u0000${ref.collection}\u0000${ref.item}`;
  }
}

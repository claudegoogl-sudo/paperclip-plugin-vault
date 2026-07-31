import {
  constants as cryptoConstants,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  type KeyObject,
  pbkdf2Sync,
  privateDecrypt,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type {
  PluginHttpClient,
  PluginLogger,
  PluginSecretsClient,
} from "@paperclipai/plugin-sdk";
import {
  VaultAuthError,
  VaultBackendError,
  VaultItemNotFoundError,
  type VaultBackend,
  type VaultListItem,
} from "./VaultBackend.js";
import type { VaultRef } from "./secretRef.js";
import { validateVaultServerUrl } from "./validateVaultServerUrl.js";

/**
 * Bitwarden / Vaultwarden REST + crypto client.
 *
 * Implements the minimum protocol needed to:
 *   1. Authenticate a service-account user with a master password
 *      (PBKDF2-SHA256 or Argon2id KDF; Vaultwarden 1.36 supports both).
 *   2. Derive the master encryption key and exchange it for an
 *      access token + the user's protected symmetric key.
 *   3. Fetch ciphers via `/api/sync` and decrypt them on demand.
 *
 * **Scope**: this backend only implements:
 *   - PBKDF2-SHA256 KDF (the default for accounts created against
 *     Vaultwarden 1.36). Argon2 support is a follow-up.
 *   - Cipher EncStrings of type 2 (AesCbc256_HmacSha256_B64) — the
 *     default for accounts after 2018.
 *   - Decryption of the Name and Login.Password (or Notes when password
 *     is empty) fields. List operations decrypt Name only.
 *
 * **Plaintext discipline**:
 *   - The master password is fetched per unlock via ctx.secrets.resolve
 *     and dropped immediately after key derivation.
 *   - The derived master key, user symmetric key, and org symmetric keys
 *     are held in worker memory until {@link clear} is called or the
 *     session TTL expires (see worker.ts).
 *   - Decrypted cipher values are returned from {@link read} and never
 *     stored on the client.
 *
 * **Outbound scoping**: all requests target the configured `serverUrl` and
 * go through `ctx.http` (the host-mediated client), never a bare `fetch`.
 * That means the host's SSRF hardening (protocol allowlist, private-IP
 * filtering, DNS pinning) and the `http.outbound` capability gate both apply
 * to every Vaultwarden request; `scopedUrl` below is a second, structural
 * guard on top, not a substitute for host enforcement.
 */

/**
 * Minimum acceptable PBKDF2-SHA256 iteration count. Matches the current
 * Bitwarden default (and OWASP guidance) for SHA-256. See F5.
 */
const MIN_PBKDF2_ITERATIONS = 600_000;

/**
 * Modern Vaultwarden/Bitwarden `/api/*` responses use camelCase keys, while
 * this backend (and the legacy Bitwarden API) is written against PascalCase.
 * The identity token endpoint still returns PascalCase, so we normalise only
 * the `/api/sync` payload: recursively upper-case the first character of every
 * object key. Idempotent against already-PascalCase servers. Only keys are
 * rewritten — string values (EncStrings) are untouched.
 */
function pascalizeKeys<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((v) => pascalizeKeys(v)) as unknown as T;
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const nk = k.length > 0 ? k[0]!.toUpperCase() + k.slice(1) : k;
      out[nk] = pascalizeKeys(v);
    }
    return out as unknown as T;
  }
  return value;
}

export interface VaultwardenBackendOptions {
  serverUrl: string;
  email: string;
  /**
   * Resolve the master password per unlock; never cached on the backend.
   * Receives the calling agent `runId` so the underlying
   * `ctx.secrets.resolve(ref, runId)` satisfies the fork.10+ host contract.
   * Called with `undefined` for worker-lifetime unlocks (session priming),
   * which must resolve under the plugin's service scope.
   */
  resolvePassword: (runId?: string) => Promise<string>;
  http: PluginHttpClient;
  logger: PluginLogger;
  /** Deterministic UUID for the device identifier (tests). */
  deviceIdentifier?: string;
  /**
   * Override the transport entirely, bypassing `http` (tests only). The
   * production default is `http.fetch` (see {@link FetchLike}); this exists
   * so unit tests can stub raw HTTP without standing up a `PluginHttpClient`.
   * Never set this outside tests — it skips the host's SSRF validation.
   */
  fetchImpl?: typeof fetch;
  /**
   * Operator-configurable host allowlist for `serverUrl` (PLA safety
   * follow-up). When omitted or empty, defaults to the single host parsed
   * out of `serverUrl` itself — see `validateVaultServerUrl.ts`.
   */
  allowedServerHosts?: string[];
}

interface PreloginResponse {
  kdf: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
}

interface TokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  Key: string;
  PrivateKey?: string;
  Kdf: number;
  KdfIterations: number;
}

interface SyncProfile {
  Id: string;
  Organizations: Array<{
    Id: string;
    Name: string;
    Key: string;
    Status: number;
    Enabled: boolean;
  }>;
}

interface SyncCollection {
  Id: string;
  OrganizationId: string;
  Name: string;
}

interface SyncCipher {
  Id: string;
  OrganizationId: string | null;
  CollectionIds: string[];
  Type: number;
  Name: string;
  Notes: string | null;
  Login?: {
    Password: string | null;
    Username: string | null;
  };
}

interface SyncResponse {
  Profile: SyncProfile;
  Collections: SyncCollection[];
  Ciphers: SyncCipher[];
}

interface UnlockedSession {
  accessToken: string;
  tokenExpiresAt: number;
  userKey: Buffer;
  userMacKey: Buffer | null;
  orgKeys: Map<string, { enc: Buffer; mac: Buffer | null }>;
  collections: Map<string, { name: string; orgId: string }>;
  ciphers: SyncCipher[];
}

/**
 * The exact shape {@link VaultwardenBackend.request} calls its transport
 * with — deliberately narrower than both `RequestInit` and
 * `PluginHttpFetchInit` so either a raw `fetch` (tests) or
 * `PluginHttpClient.fetch` (production) can serve as `fetchImpl` without an
 * adapter at the call site.
 */
type FetchLike = (
  url: string,
  init: { method: "GET" | "POST"; headers: Record<string, string>; body?: string },
) => Promise<Response>;

export class VaultwardenBackend implements VaultBackend {
  private session: UnlockedSession | null = null;
  private readonly fetchImpl: FetchLike;
  private readonly deviceIdentifier: string;
  /**
   * Canonical, validated form of `opts.serverUrl` — WHATWG-parsed once here
   * rather than re-parsed from the raw string on every request, so the
   * scoping check in {@link request} can never disagree with what was
   * validated at construction time.
   */
  private readonly serverUrl: URL;

  constructor(private readonly opts: VaultwardenBackendOptions) {
    // Strict WHATWG URL parse + host allowlist (default: the configured
    // host only) — never a regex/prefix check on the raw string. See
    // validateVaultServerUrl.ts for why a substring check is insufficient.
    const validated = validateVaultServerUrl(opts.serverUrl, opts.allowedServerHosts);
    if (!validated.ok) {
      throw new VaultAuthError(
        `serverUrl rejected (${validated.reason}); host=${validated.host ?? "<unparseable>"}`,
      );
    }
    this.serverUrl = validated.url;
    // Production default is the host-mediated client (SSRF-validated,
    // capability-gated, audit-logged); `fetchImpl` is a raw-`fetch` test
    // seam only (see the option's doc comment).
    this.fetchImpl = opts.fetchImpl ?? ((url, init) => opts.http.fetch(url, init));
    this.deviceIdentifier = opts.deviceIdentifier ?? randomUUID();
  }

  /** Drop all cached keys + tokens. Called on session TTL expiry. */
  clear(): void {
    if (this.session) {
      this.session.userKey.fill(0);
      if (this.session.userMacKey) this.session.userMacKey.fill(0);
      for (const v of this.session.orgKeys.values()) {
        v.enc.fill(0);
        if (v.mac) v.mac.fill(0);
      }
      this.session = null;
    }
  }

  /**
   * Establish (or refresh) the unlocked session from a worker-lifetime
   * context. The master-password resolve then runs under the plugin's own
   * service scope, so later run-scoped reads from companies that do NOT own
   * the master-password secret hit a warm session and never resolve.
   */
  async prime(): Promise<void> {
    await this.unlock(undefined);
  }

  async read(ref: VaultRef, runId?: string): Promise<string> {
    const session = await this.unlock(runId);
    const orgId = this.resolveOrgId(session, ref.org);
    const collectionId = this.resolveCollectionId(session, orgId, ref.collection);
    const cipher = this.findCipher(session, orgId, collectionId, ref.item);
    if (!cipher) throw new VaultItemNotFoundError(ref);
    const keys = this.keyForCipher(session, cipher);
    // Prefer Login.Password, fall back to Notes, then SecureNote contents.
    if (cipher.Login?.Password) {
      return decryptString(cipher.Login.Password, keys.enc, keys.mac);
    }
    if (cipher.Notes) {
      return decryptString(cipher.Notes, keys.enc, keys.mac);
    }
    throw new VaultItemNotFoundError(ref);
  }

  async list(
    filter: { org?: string; collection?: string } | undefined,
    runId?: string,
  ): Promise<VaultListItem[]> {
    const session = await this.unlock(runId);
    const orgNames = (session as UnlockedSession & { orgNames: Map<string, string> }).orgNames;
    const reqOrg = filter?.org?.trim().toLowerCase();
    const reqCol = filter?.collection?.trim().toLowerCase();
    const out: VaultListItem[] = [];
    for (const cipher of session.ciphers) {
      if (!cipher.OrganizationId) continue;
      const orgName = orgNames.get(cipher.OrganizationId);
      if (!orgName) continue;
      if (reqOrg && orgName.trim().toLowerCase() !== reqOrg) continue;
      let itemName: string;
      try {
        const keys = this.keyForCipher(session, cipher);
        itemName = decryptString(cipher.Name, keys.enc, keys.mac);
      } catch {
        // Skip ciphers we can't decrypt (no org key, key version, etc.).
        continue;
      }
      // Emit one entry per collection so the tool can re-filter each full
      // (org, collection, item) ref against the allowList.
      for (const cid of cipher.CollectionIds) {
        const col = session.collections.get(cid);
        if (!col || col.orgId !== cipher.OrganizationId) continue;
        if (reqCol && col.name.trim().toLowerCase() !== reqCol) continue;
        out.push({ org: orgName, collection: col.name, item: itemName });
      }
    }
    return out;
  }

  private async unlock(runId?: string): Promise<UnlockedSession> {
    if (this.session && this.session.tokenExpiresAt > Date.now() + 30_000) {
      return this.session;
    }
    const email = this.opts.email.trim().toLowerCase();
    const prelogin = await this.postJson<PreloginResponse>(
      "/api/accounts/prelogin",
      { email },
      { auth: false },
    );
    if (prelogin.kdf !== 0) {
      throw new VaultAuthError(
        `unsupported KDF type ${prelogin.kdf}; only PBKDF2-SHA256 (0) is implemented`,
      );
    }
    // F5: prelogin is unauthenticated, so a downgraded `kdfIterations` would
    // let a MITM weaken the master-key derivation. Enforce the current
    // Bitwarden/OWASP PBKDF2-SHA256 floor; the service account must be
    // provisioned at or above it.
    if (
      typeof prelogin.kdfIterations !== "number" ||
      prelogin.kdfIterations < MIN_PBKDF2_ITERATIONS
    ) {
      throw new VaultAuthError(
        `PBKDF2 iteration count ${prelogin.kdfIterations} is below the required floor of ${MIN_PBKDF2_ITERATIONS}`,
      );
    }
    const password = await this.opts.resolvePassword(runId);
    let masterKey: Buffer;
    let hashedPassword: string;
    try {
      masterKey = pbkdf2Sync(
        Buffer.from(password, "utf8"),
        Buffer.from(email, "utf8"),
        prelogin.kdfIterations,
        32,
        "sha256",
      );
      hashedPassword = pbkdf2Sync(
        masterKey,
        Buffer.from(password, "utf8"),
        1,
        32,
        "sha256",
      ).toString("base64");
    } finally {
      // Drop the plaintext password reference as fast as we can.
      // (Strings are immutable in JS; the runtime owns GC. We at least
      //  don't keep it on a long-lived object.)
    }

    const tokenBody = new URLSearchParams({
      grant_type: "password",
      username: email,
      password: hashedPassword,
      scope: "api offline_access",
      client_id: "cli",
      deviceType: "14",
      deviceIdentifier: this.deviceIdentifier,
      deviceName: "paperclip-plugin-vault",
    });
    const tokenRes = await this.postForm<TokenResponse>(
      "/identity/connect/token",
      tokenBody,
    );

    // Decrypt the protected user key with the stretched master key.
    const { enc: userEnc, mac: userMac } = stretchAndUnpackKey(
      masterKey,
      tokenRes.Key,
    );
    masterKey.fill(0);

    // Fetch sync (ciphers, collections, orgs).
    const sync = pascalizeKeys(
      await this.getJson<SyncResponse>("/api/sync", {
        bearer: tokenRes.access_token,
      }),
    );

    // The user's RSA private key (PKCS#8 DER) is itself a type-2 EncString
    // protected by the user symmetric key. Org symmetric keys are RSA-OAEP
    // encrypted to the matching public key, so we need it to unwrap them.
    let userPrivateKey: KeyObject | null = null;
    if (tokenRes.PrivateKey) {
      try {
        const der = decryptToBuffer(tokenRes.PrivateKey, userEnc, userMac);
        userPrivateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
      } catch (err) {
        this.opts.logger.warn("vault.private_key_decrypt_failed", {
          error: String(err instanceof Error ? err.message : err),
        });
      }
    }

    // Decrypt each org's symmetric key (stored on profile.Organizations).
    const orgKeys = new Map<string, { enc: Buffer; mac: Buffer | null }>();
    for (const org of sync.Profile.Organizations ?? []) {
      if (!org.Enabled || org.Status < 2) continue;
      try {
        const orgKeyBuf = decryptToBuffer(org.Key, userEnc, userMac, userPrivateKey);
        orgKeys.set(org.Id, splitEncMac(orgKeyBuf));
      } catch (err) {
        this.opts.logger.warn("vault.org_key_decrypt_failed", {
          orgId: org.Id,
          orgName: org.Name,
          error: String(err instanceof Error ? err.message : err),
        });
      }
    }

    const collections = new Map<string, { name: string; orgId: string }>();
    for (const c of sync.Collections ?? []) {
      const keys = orgKeys.get(c.OrganizationId);
      if (!keys) continue;
      try {
        collections.set(c.Id, {
          name: decryptString(c.Name, keys.enc, keys.mac),
          orgId: c.OrganizationId,
        });
      } catch {
        // ignore undecryptable collection names
      }
    }

    // Build an org-name → orgId map by decrypting org names.
    // We store both id and name on the session via collections + ciphers.
    this.session = {
      accessToken: tokenRes.access_token,
      tokenExpiresAt: Date.now() + tokenRes.expires_in * 1000,
      userKey: userEnc,
      userMacKey: userMac,
      orgKeys,
      collections,
      ciphers: sync.Ciphers ?? [],
    };
    // Stash a separate org-name map computed once.
    (this.session as UnlockedSession & { orgNames: Map<string, string> }).orgNames =
      this.buildOrgNameMap(sync.Profile.Organizations ?? [], userEnc, userMac);
    return this.session;
  }

  private buildOrgNameMap(
    orgs: SyncProfile["Organizations"],
    userEnc: Buffer,
    userMac: Buffer | null,
  ): Map<string, string> {
    const m = new Map<string, string>();
    for (const o of orgs) {
      // Vaultwarden returns org names in plaintext (not encrypted), unlike
      // collection names. Use them directly.
      m.set(o.Id, o.Name);
    }
    return m;
  }

  private resolveOrgId(session: UnlockedSession, name: string): string {
    const orgId = this.tryResolveOrgId(session, name);
    if (!orgId) {
      throw new VaultItemNotFoundError({
        raw: `vault://${name}/?/?`,
        org: name,
        collection: "?",
        item: "?",
      });
    }
    return orgId;
  }

  private tryResolveOrgId(session: UnlockedSession, name: string): string | null {
    const orgNames = (session as UnlockedSession & { orgNames: Map<string, string> }).orgNames;
    const requested = name.trim().toLowerCase();
    // F7: resolve unambiguously. The previous fuzzy match silently resolved
    // two orgs that normalized equal to whichever the Map yielded first,
    // which could route a ref to the wrong organization. Prefer an exact
    // case-insensitive match; only when there is none do we fall back to the
    // documented leading-prefix convenience (`vault://EXAMPLE/...` -> "EXAMPLE —
    // Example Org"). Either tier fails closed on ambiguity.
    const exact: string[] = [];
    const prefix: string[] = [];
    const requestedPrefix = orgNamePrefix(requested);
    for (const [id, n] of orgNames.entries()) {
      const norm = n.trim().toLowerCase();
      if (norm === requested) exact.push(id);
      else if (orgNamePrefix(norm) === requestedPrefix) prefix.push(id);
    }
    const tier = exact.length > 0 ? exact : prefix;
    if (tier.length > 1) {
      throw new VaultAuthError(
        `ambiguous org name ${JSON.stringify(name)}: matches ${tier.length} organizations`,
      );
    }
    return tier[0] ?? null;
  }

  private resolveCollectionId(
    session: UnlockedSession,
    orgId: string,
    name: string,
  ): string {
    const id = this.tryResolveCollectionId(session, orgId, name);
    if (!id) {
      throw new VaultItemNotFoundError({
        raw: `vault://?/${name}/?`,
        org: "?",
        collection: name,
        item: "?",
      });
    }
    return id;
  }

  private tryResolveCollectionId(
    session: UnlockedSession,
    orgId: string,
    name: string,
  ): string | null {
    for (const [id, c] of session.collections.entries()) {
      if (c.orgId === orgId && c.name === name) return id;
    }
    return null;
  }

  private findCipher(
    session: UnlockedSession,
    orgId: string,
    collectionId: string,
    itemName: string,
  ): SyncCipher | null {
    for (const cipher of session.ciphers) {
      if (cipher.OrganizationId !== orgId) continue;
      if (!cipher.CollectionIds.includes(collectionId)) continue;
      const keys = this.keyForCipher(session, cipher);
      try {
        const name = decryptString(cipher.Name, keys.enc, keys.mac);
        if (name === itemName) return cipher;
      } catch {
        // Skip undecryptable.
      }
    }
    return null;
  }

  private keyForCipher(
    session: UnlockedSession,
    cipher: SyncCipher,
  ): { enc: Buffer; mac: Buffer | null } {
    if (cipher.OrganizationId) {
      const k = session.orgKeys.get(cipher.OrganizationId);
      if (!k) {
        throw new VaultAuthError(
          `no decrypted org key for ${cipher.OrganizationId}`,
        );
      }
      return k;
    }
    return { enc: session.userKey, mac: session.userMacKey };
  }

  private async postJson<T>(
    path: string,
    body: unknown,
    opts?: { auth?: boolean; bearer?: string },
  ): Promise<T> {
    return this.request<T>("POST", path, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      ...opts,
    });
  }

  private async postForm<T>(path: string, body: URLSearchParams): Promise<T> {
    return this.request<T>("POST", path, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  }

  private async getJson<T>(path: string, opts?: { bearer?: string }): Promise<T> {
    return this.request<T>("GET", path, opts ?? {});
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    opts: {
      headers?: Record<string, string>;
      body?: string;
      bearer?: string;
    },
  ): Promise<T> {
    const url = this.scopedUrl(path).toString();
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
    const res = await this.fetchImpl(url, {
      method,
      headers,
      body: opts.body,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      // F8: keep the server response body OUT of the thrown message — it may
      // echo request material or server internals that must never reach the
      // audit log or a tool caller. Log it (detail) for operators instead.
      this.opts.logger.warn("vault.http_error", {
        method,
        path,
        status: res.status,
        body: body.slice(0, 200),
      });
      throw new VaultBackendError(
        `vaultwarden ${method} ${path} -> ${res.status}`,
        body.slice(0, 200),
      );
    }
    return (await res.json()) as T;
  }

  /**
   * Build a request URL relative to the validated `serverUrl` and assert
   * the final origin matches. All call sites in this class pass a fixed
   * literal path today, but resolving against the raw config string on
   * every call (the pre-fix behavior) left no structural guard against a
   * future call site that builds `path` from server-supplied data — an
   * absolute or protocol-relative `path` would otherwise silently redirect
   * the request (and any bearer token attached to it) off-host. Mirrors
   * MoonrakerClient.scopedUrl in paperclip-klipper.
   */
  private scopedUrl(path: string): URL {
    const url = new URL(path, this.serverUrl);
    if (url.host !== this.serverUrl.host || url.protocol !== this.serverUrl.protocol) {
      throw new VaultBackendError(
        `vault request path resolved outside the configured server (got host=${url.host}, expected host=${this.serverUrl.host})`,
      );
    }
    return url;
  }
}

/**
 * Normalize an org name to its leading segment before the first separator
 * (em-dash, hyphen, colon, pipe). Used only as a fallback convenience so a
 * ref like `vault://EXAMPLE/...` can resolve against `EXAMPLE — Example Org`.
 * Resolution still fails closed when more than one org shares a prefix.
 */
function orgNamePrefix(normalizedLower: string): string {
  return normalizedLower.split(/[—\-:|]/)[0]!.trim();
}

/**
 * HKDF-Expand (RFC 5869 §2.3) with the supplied PRK — NO extract step.
 *
 * Bitwarden's key-stretch derives the stretched (enc, mac) keys with
 * HKDF-**Expand only**, treating the 32-byte master key directly as the
 * PRK. Node's `hkdfSync` performs the full extract+expand (HMAC over the
 * salt first), which yields a *different* PRK and therefore wrong stretched
 * keys — the user-key MAC check then fails on real vault data (F3 defect 1).
 */
export function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  const hashLen = 32; // SHA-256
  const blocks = Math.ceil(length / hashLen);
  const infoBuf = Buffer.from(info, "utf8");
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  for (let i = 1; i <= blocks; i++) {
    t = createHmac("sha256", prk)
      .update(Buffer.concat([t, infoBuf, Buffer.from([i])]))
      .digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, length);
}

/**
 * Stretch a 32-byte master key into (32B enc, 32B mac) via HKDF-Expand,
 * then decrypt the protected user key blob. Returns split enc/mac buffers.
 */
function stretchAndUnpackKey(
  masterKey: Buffer,
  protectedKey: string,
): { enc: Buffer; mac: Buffer | null } {
  const enc = hkdfExpand(masterKey, "enc", 32);
  const mac = hkdfExpand(masterKey, "mac", 32);
  const decrypted = decryptToBuffer(protectedKey, enc, mac);
  return splitEncMac(decrypted);
}

function splitEncMac(buf: Buffer): { enc: Buffer; mac: Buffer | null } {
  if (buf.length === 64) {
    return { enc: buf.subarray(0, 32), mac: buf.subarray(32, 64) };
  }
  if (buf.length === 32) {
    return { enc: buf, mac: null };
  }
  throw new VaultAuthError(`unexpected key length ${buf.length}`);
}

/**
 * Decrypt a Bitwarden EncString. Supports types:
 *   0 — AesCbc256_B64 (iv|ct), no MAC.
 *   2 — AesCbc256_HmacSha256_B64 (iv|ct|mac).
 *   3 — Rsa2048_OaepSha256_B64 (RSA-OAEP-SHA256), requires `privateKey`.
 *   4 — Rsa2048_OaepSha1_B64 (RSA-OAEP-SHA1), requires `privateKey`.
 *
 * Org symmetric keys are RSA-encrypted to the user's public key (typically
 * type 4), so resolving any org secret requires the RSA branch (F3 defect 2).
 */
export function decryptToBuffer(
  encString: string,
  encKey: Buffer,
  macKey: Buffer | null,
  privateKey?: KeyObject | null,
): Buffer {
  const dot = encString.indexOf(".");
  if (dot === -1) throw new VaultAuthError("malformed EncString: missing type");
  const type = Number(encString.slice(0, dot));
  const parts = encString.slice(dot + 1).split("|");
  if (type === 0) {
    // F6: fail closed on an unauthenticated-cipher downgrade. If a MAC key is
    // in play, every cipher we accept must be MAC'd; a type-0 (no-MAC) blob
    // here is either corruption or a stripped-MAC downgrade attempt.
    if (macKey) {
      throw new VaultAuthError(
        "type-0 (unauthenticated) EncString rejected because a macKey is present",
      );
    }
    if (parts.length !== 2) throw new VaultAuthError("type-0 EncString needs iv|ct");
    const iv = Buffer.from(parts[0]!, "base64");
    const ct = Buffer.from(parts[1]!, "base64");
    return aesCbcDecrypt(encKey, iv, ct);
  }
  if (type === 2) {
    if (parts.length !== 3) throw new VaultAuthError("type-2 EncString needs iv|ct|mac");
    if (!macKey) throw new VaultAuthError("type-2 EncString requires macKey");
    const iv = Buffer.from(parts[0]!, "base64");
    const ct = Buffer.from(parts[1]!, "base64");
    const mac = Buffer.from(parts[2]!, "base64");
    const expected = createHmac("sha256", macKey).update(iv).update(ct).digest();
    if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) {
      throw new VaultAuthError("MAC verification failed");
    }
    return aesCbcDecrypt(encKey, iv, ct);
  }
  if (type === 3 || type === 4) {
    if (!privateKey) {
      throw new VaultAuthError(`EncString type ${type} requires an RSA private key`);
    }
    const ct = Buffer.from(parts[0]!, "base64");
    const oaepHash = type === 3 ? "sha256" : "sha1";
    return privateDecrypt(
      { key: privateKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash },
      ct,
    );
  }
  throw new VaultAuthError(`unsupported EncString type ${type}`);
}

export function decryptString(
  encString: string,
  encKey: Buffer,
  macKey: Buffer | null,
): string {
  return decryptToBuffer(encString, encKey, macKey).toString("utf8");
}

function aesCbcDecrypt(key: Buffer, iv: Buffer, ct: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

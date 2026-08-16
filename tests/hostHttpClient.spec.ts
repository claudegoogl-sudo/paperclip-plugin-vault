import {
  constants as cryptoConstants,
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginHttpClient } from "@paperclipai/plugin-sdk";
import { hkdfExpand, VaultwardenBackend } from "../src/worker/VaultwardenBackend.js";

/**
 * Proves the production transport is `ctx.http.fetch` (the host-mediated
 * `PluginHttpClient`), not a bare `fetch`. Every request in this file is
 * routed only through a fake `PluginHttpClient`; `globalThis.fetch` is
 * stubbed to throw, so any accidental fallback to it fails the test loudly
 * instead of silently reaching the real network or masking the bug this
 * change fixes.
 *
 * The fake client reconstructs responses the same way the real SDK's
 * worker-rpc-host does (`new Response(bodyText, { status, headers })`),
 * including non-ASCII content, so this also confirms — rather than assumes
 * — that a JSON round trip through the host client preserves UTF-8 exactly
 * as the notes on this change call for.
 */

const STUB_LOGGER = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
} as never;

function encType2(plaintext: Buffer, enc: Buffer, mac: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", enc, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const m = createHmac("sha256", mac).update(iv).update(ct).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${m.toString("base64")}`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface Fixture {
  backend: VaultwardenBackend;
  httpFetch: ReturnType<typeof vi.fn>;
  rawFetch: ReturnType<typeof vi.fn>;
  orgName: string;
  itemName: string;
  secretValue: string;
}

function buildFixtureRoutedThroughHostClient(): Fixture {
  const iterations = 600_000;
  const email = "vault-svc@paperclip.local";
  const password = "correct horse battery staple";
  // Deliberately non-ASCII: Vaultwarden returns org names in plaintext (see
  // VaultwardenBackend.buildOrgNameMap), so this is the field most exposed
  // to a lossy text round trip through the host RPC boundary.
  const orgName = "Café Ops — équipe 🔐";
  const itemName = "tunnel-cert";
  const secretValue = "sïgné-🔑-tunnel-token-一二三";

  const masterKey = pbkdf2Sync(
    Buffer.from(password, "utf8"),
    Buffer.from(email.toLowerCase(), "utf8"),
    iterations,
    32,
    "sha256",
  );
  const stretchedEnc = hkdfExpand(masterKey, "enc", 32);
  const stretchedMac = hkdfExpand(masterKey, "mac", 32);

  const userEnc = randomBytes(32);
  const userMac = randomBytes(32);
  const protectedUserKey = encType2(
    Buffer.concat([userEnc, userMac]),
    stretchedEnc,
    stretchedMac,
  );

  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const protectedPrivateKey = encType2(
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer,
    userEnc,
    userMac,
  );

  const orgEnc = randomBytes(32);
  const orgMac = randomBytes(32);
  const orgKeyEnc =
    "4." +
    publicEncrypt(
      { key: publicKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
      Buffer.concat([orgEnc, orgMac]),
    ).toString("base64");

  const orgId = "11111111-1111-1111-1111-111111111111";
  const colId = "22222222-2222-2222-2222-222222222222";

  const sync = {
    Profile: {
      Id: "user-1",
      Organizations: [
        { Id: orgId, Name: orgName, Key: orgKeyEnc, Status: 2, Enabled: true },
      ],
    },
    Collections: [
      {
        Id: colId,
        OrganizationId: orgId,
        Name: encType2(Buffer.from("svc-secrets", "utf8"), orgEnc, orgMac),
      },
    ],
    Ciphers: [
      {
        Id: "cipher-1",
        OrganizationId: orgId,
        CollectionIds: [colId],
        Type: 1,
        Name: encType2(Buffer.from(itemName, "utf8"), orgEnc, orgMac),
        Notes: null,
        Login: {
          Password: encType2(Buffer.from(secretValue, "utf8"), orgEnc, orgMac),
          Username: null,
        },
      },
    ],
  };

  const token = {
    access_token: "access-token",
    expires_in: 3600,
    Key: protectedUserKey,
    PrivateKey: protectedPrivateKey,
    Kdf: 0,
    KdfIterations: iterations,
  };

  const rawFetch = vi.fn(() => {
    throw new Error("must not fall back to globalThis.fetch — production path must use ctx.http");
  });
  vi.stubGlobal("fetch", rawFetch);

  const httpFetch = vi.fn(async (url: string) => {
    const u = String(url);
    if (u.endsWith("/api/accounts/prelogin")) {
      return jsonResponse({ kdf: 0, kdfIterations: iterations });
    }
    if (u.endsWith("/identity/connect/token")) return jsonResponse(token);
    if (u.endsWith("/api/sync")) return jsonResponse(sync);
    return jsonResponse("unexpected path", 404);
  });
  const http: PluginHttpClient = { fetch: httpFetch as unknown as PluginHttpClient["fetch"] };

  const backend = new VaultwardenBackend({
    serverUrl: "https://vault.example.test",
    email,
    resolvePassword: async () => password,
    http,
    logger: STUB_LOGGER,
    // No fetchImpl: exercise the production default transport.
  });

  return { backend, httpFetch, rawFetch, orgName, itemName, secretValue };
}

describe("VaultwardenBackend routes production traffic through ctx.http, not globalThis.fetch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reads a secret end-to-end using only the injected PluginHttpClient", async () => {
    const { backend, httpFetch, rawFetch, orgName, itemName, secretValue } =
      buildFixtureRoutedThroughHostClient();

    const value = await backend.read({
      raw: `vault://${orgName}/svc-secrets/${itemName}`,
      org: orgName,
      collection: "svc-secrets",
      item: itemName,
    });

    expect(value).toBe(secretValue);
    // prelogin, token, sync — every request went through the host client.
    expect(httpFetch).toHaveBeenCalledTimes(3);
    expect(rawFetch).not.toHaveBeenCalled();
  });

  it("preserves the plaintext org name (multi-byte UTF-8) through the host client's Response reconstruction", async () => {
    const { backend, orgName } = buildFixtureRoutedThroughHostClient();

    const items = await backend.list(undefined);

    expect(items).toEqual([{ org: orgName, collection: "svc-secrets", item: "tunnel-cert" }]);
  });

  it("sends the expected method and content-type headers through the host client", async () => {
    const { backend, httpFetch } = buildFixtureRoutedThroughHostClient();

    await backend.read({
      raw: "vault://x/y/z",
      org: "Café Ops — équipe 🔐",
      collection: "svc-secrets",
      item: "tunnel-cert",
    });

    const [preloginUrl, preloginInit] = httpFetch.mock.calls[0]!;
    expect(String(preloginUrl)).toBe("https://vault.example.test/api/accounts/prelogin");
    expect(preloginInit.method).toBe("POST");
    expect(preloginInit.headers["content-type"]).toBe("application/json");

    const [tokenUrl, tokenInit] = httpFetch.mock.calls[1]!;
    expect(String(tokenUrl)).toBe("https://vault.example.test/identity/connect/token");
    expect(tokenInit.headers["content-type"]).toBe("application/x-www-form-urlencoded");

    const [syncUrl, syncInit] = httpFetch.mock.calls[2]!;
    expect(String(syncUrl)).toBe("https://vault.example.test/api/sync");
    expect(syncInit.headers.authorization).toBe("Bearer access-token");
  });
});

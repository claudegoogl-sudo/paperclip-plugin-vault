import {
  constants as cryptoConstants,
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decryptToBuffer,
  hkdfExpand,
  VaultwardenBackend,
} from "../src/worker/VaultwardenBackend.js";

/**
 * Crypto known-answer + hardening tests (vectors F3, F5, F6, F7).
 *
 * The end-to-end vector is self-consistent: the "encrypt" side here uses
 * Node's standard AES-CBC / HMAC-SHA256 / RSA-OAEP-SHA1 / PKCS#8 primitives
 * following the Bitwarden EncString wire format, and asserts the production
 * decrypt path is its inverse across the full chain
 * (KDF -> stretch -> unwrap user key -> unwrap RSA org key -> decrypt
 * type-2 cipher). The HKDF-Expand step is additionally pinned against the
 * raw HMAC definition below so the vector can't pass on a self-consistent
 * but wrong stretch implementation.
 */

const STUB_LOGGER = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
} as never;

/** Encrypt a buffer as a type-2 (AesCbc256_HmacSha256_B64) EncString. */
function encType2(plaintext: Buffer, enc: Buffer, mac: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", enc, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const m = createHmac("sha256", mac).update(iv).update(ct).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${m.toString("base64")}`;
}

/** Encrypt a buffer as a type-0 (AesCbc256_B64, no MAC) EncString. */
function encType0(plaintext: Buffer, enc: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", enc, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return `0.${iv.toString("base64")}|${ct.toString("base64")}`;
}

interface FakeRes {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}
function res(obj: unknown, ok = true, status = 200): FakeRes {
  return {
    ok,
    status,
    json: async () => obj,
    text: async () => (typeof obj === "string" ? obj : JSON.stringify(obj)),
  };
}

interface VaultFixtureOpts {
  iterations?: number;
  orgName?: string;
  /** Add a second organization with this name (ambiguity test). */
  duplicateOrgName?: string;
}

function buildVault(opts: VaultFixtureOpts = {}) {
  const iterations = opts.iterations ?? 600_000;
  const orgName = opts.orgName ?? "EXAMPLE";
  const email = "vault-svc@paperclip.local";
  const password = "correct horse battery staple";

  const masterKey = pbkdf2Sync(
    Buffer.from(password, "utf8"),
    Buffer.from(email.toLowerCase(), "utf8"),
    iterations,
    32,
    "sha256",
  );
  // Stretch via HKDF-Expand-only — the value under test (F3 defect 1).
  const stretchedEnc = hkdfExpand(masterKey, "enc", 32);
  const stretchedMac = hkdfExpand(masterKey, "mac", 32);

  // User symmetric key, protected (type-2) by the stretched master key.
  const userEnc = randomBytes(32);
  const userMac = randomBytes(32);
  const protectedUserKey = encType2(
    Buffer.concat([userEnc, userMac]),
    stretchedEnc,
    stretchedMac,
  );

  // User RSA keypair; private key (PKCS#8 DER) protected (type-2) by user key.
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const privDer = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const protectedPrivateKey = encType2(privDer, userEnc, userMac);

  // Org symmetric key, RSA-OAEP-SHA1 encrypted to the user pubkey (type-4).
  const orgEnc = randomBytes(32);
  const orgMac = randomBytes(32);
  const orgKeyEnc =
    "4." +
    publicEncrypt(
      {
        key: publicKey,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
      },
      Buffer.concat([orgEnc, orgMac]),
    ).toString("base64");

  const orgId = "11111111-1111-1111-1111-111111111111";
  const colId = "22222222-2222-2222-2222-222222222222";

  const organizations = [
    { Id: orgId, Name: orgName, Key: orgKeyEnc, Status: 2, Enabled: true },
  ];
  if (opts.duplicateOrgName) {
    organizations.push({
      Id: "99999999-9999-9999-9999-999999999999",
      Name: opts.duplicateOrgName,
      Key: orgKeyEnc,
      Status: 2,
      Enabled: true,
    });
  }

  const sync = {
    Profile: { Id: "user-1", Organizations: organizations },
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
        Name: encType2(Buffer.from("tunnel-cert", "utf8"), orgEnc, orgMac),
        Notes: null,
        Login: {
          Password: encType2(
            Buffer.from("tunnel-token-1234", "utf8"),
            orgEnc,
            orgMac,
          ),
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

  const fetchImpl = (async (url: string | URL) => {
    const u = String(url);
    if (u.endsWith("/api/accounts/prelogin")) {
      return res({ kdf: 0, kdfIterations: iterations });
    }
    if (u.endsWith("/identity/connect/token")) return res(token);
    if (u.endsWith("/api/sync")) return res(sync);
    return res("unexpected path", false, 404);
  }) as unknown as typeof fetch;

  const backend = new VaultwardenBackend({
    serverUrl: "https://vault.example.test",
    email,
    resolvePassword: async () => password,
    http: {} as never,
    logger: STUB_LOGGER,
    fetchImpl,
  });

  return { backend, orgName };
}

describe("hkdfExpand (HKDF-Expand-only, F3 defect 1)", () => {
  it("matches the raw HMAC definition for a single output block", () => {
    const prk = randomBytes(32);
    const got = hkdfExpand(prk, "enc", 32);
    // RFC 5869 expand, one block: T(1) = HMAC(PRK, info || 0x01).
    const expected = createHmac("sha256", prk)
      .update(Buffer.concat([Buffer.from("enc", "utf8"), Buffer.from([1])]))
      .digest();
    expect(got.equals(expected)).toBe(true);
  });

  it("chains blocks correctly when length exceeds one hash (T1||T2)", () => {
    const prk = randomBytes(32);
    const info = Buffer.from("mac", "utf8");
    const t1 = createHmac("sha256", prk)
      .update(Buffer.concat([info, Buffer.from([1])]))
      .digest();
    const t2 = createHmac("sha256", prk)
      .update(Buffer.concat([t1, info, Buffer.from([2])]))
      .digest();
    const expected = Buffer.concat([t1, t2]).subarray(0, 40);
    expect(hkdfExpand(prk, "mac", 40).equals(expected)).toBe(true);
  });

  it("differs from Node's full HKDF (extract+expand) — old code was wrong", async () => {
    const { hkdfSync } = await import("node:crypto");
    const prk = randomBytes(32);
    const expandOnly = hkdfExpand(prk, "enc", 32);
    const fullHkdf = Buffer.from(
      hkdfSync("sha256", prk, Buffer.alloc(0), "enc", 32),
    );
    expect(expandOnly.equals(fullHkdf)).toBe(false);
  });
});

describe("decryptToBuffer EncString types (F6 downgrade, F3 RSA)", () => {
  it("rejects type-0 when a macKey is present (downgrade, F6)", () => {
    const enc = randomBytes(32);
    const mac = randomBytes(32);
    const blob = encType0(Buffer.from("plaintext"), enc);
    expect(() => decryptToBuffer(blob, enc, mac)).toThrow(/type-0/);
  });

  it("still decrypts a legitimate type-0 when no macKey is configured", () => {
    const enc = randomBytes(32);
    const blob = encType0(Buffer.from("legacy-value"), enc);
    expect(decryptToBuffer(blob, enc, null).toString("utf8")).toBe("legacy-value");
  });

  it("decrypts a type-4 (RSA-OAEP-SHA1) EncString with the private key", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const secret = randomBytes(64);
    const blob =
      "4." +
      publicEncrypt(
        {
          key: publicKey,
          padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha1",
        },
        secret,
      ).toString("base64");
    const out = decryptToBuffer(blob, Buffer.alloc(0), null, privateKey);
    expect(out.equals(secret)).toBe(true);
  });

  it("throws for type-4 without an RSA private key", () => {
    expect(() => decryptToBuffer("4.AAAA", Buffer.alloc(0), null)).toThrow(
      /requires an RSA private key/,
    );
  });
});

describe("VaultwardenBackend end-to-end KAT (F3)", () => {
  it("reads an org secret through the full KDF->RSA org key->type-2 chain", async () => {
    const { backend } = buildVault();
    const value = await backend.read(
      {
        raw: "vault://EXAMPLE/svc-secrets/tunnel-cert",
        org: "EXAMPLE",
        collection: "svc-secrets",
        item: "tunnel-cert",
      },
      "test-run",
    );
    expect(value).toBe("tunnel-token-1234");
  });

  it("lists org item coordinates without exposing values", async () => {
    const { backend } = buildVault();
    const items = await backend.list({ org: "EXAMPLE", collection: "svc-secrets" }, "test-run");
    expect(items).toEqual([
      { org: "EXAMPLE", collection: "svc-secrets", item: "tunnel-cert" },
    ]);
  });
});

describe("PBKDF2 iteration floor (F5)", () => {
  it("rejects a prelogin iteration count below the 600k floor", async () => {
    const { backend } = buildVault({ iterations: 100_000 });
    await expect(
      backend.read(
        {
          raw: "vault://EXAMPLE/svc-secrets/tunnel-cert",
          org: "EXAMPLE",
          collection: "svc-secrets",
          item: "tunnel-cert",
        },
        "test-run",
      ),
    ).rejects.toThrow(/below the required floor/);
  });
});

describe("org-name resolution (F7)", () => {
  const ref = {
    raw: "vault://EXAMPLE/svc-secrets/tunnel-cert",
    org: "EXAMPLE",
    collection: "svc-secrets",
    item: "tunnel-cert",
  };

  it("resolves the documented leading-prefix convenience for one org", async () => {
    const { backend } = buildVault({ orgName: "EXAMPLE — Example Org" });
    await expect(backend.read(ref, "test-run")).resolves.toBe("tunnel-token-1234");
  });

  it("throws on an ambiguous (duplicate) case-insensitive org name", async () => {
    const { backend } = buildVault({ orgName: "EXAMPLE", duplicateOrgName: "example" });
    await expect(backend.read(ref, "test-run")).rejects.toThrow(/ambiguous org name/);
  });

  it("throws when two orgs share the requested prefix", async () => {
    const { backend } = buildVault({
      orgName: "EXAMPLE — Example Org",
      duplicateOrgName: "EXAMPLE — Example Archive",
    });
    await expect(backend.read(ref, "test-run")).rejects.toThrow(/ambiguous org name/);
  });
});

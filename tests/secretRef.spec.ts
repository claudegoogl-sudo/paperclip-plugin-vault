import { describe, expect, it } from "vitest";
import {
  InvalidAllowPatternError,
  InvalidSecretRefError,
  compileAllowList,
  isAllowed,
  parseVaultRef,
} from "../src/worker/secretRef.js";

describe("parseVaultRef", () => {
  it("parses a well-formed ref", () => {
    expect(parseVaultRef("vault://EXAMPLE/svc-secrets/tunnel-cert")).toEqual({
      raw: "vault://EXAMPLE/svc-secrets/tunnel-cert",
      org: "EXAMPLE",
      collection: "svc-secrets",
      item: "tunnel-cert",
    });
  });

  it("rejects refs missing the scheme", () => {
    expect(() => parseVaultRef("EXAMPLE/svc-secrets/x")).toThrow(InvalidSecretRefError);
  });

  it("rejects refs with fewer than three segments", () => {
    expect(() => parseVaultRef("vault://EXAMPLE/svc-secrets")).toThrow(InvalidSecretRefError);
  });

  it("rejects refs with extra segments", () => {
    expect(() => parseVaultRef("vault://EXAMPLE/svc-secrets/x/y")).toThrow(
      InvalidSecretRefError,
    );
  });

  it("rejects empty segments", () => {
    expect(() => parseVaultRef("vault://EXAMPLE//x")).toThrow(InvalidSecretRefError);
  });
});

describe("compileAllowList + isAllowed", () => {
  it("matches an exact pattern", () => {
    const list = ["vault://EXAMPLE/svc-secrets/tunnel-cert"];
    expect(isAllowed("vault://EXAMPLE/svc-secrets/tunnel-cert", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/svc-secrets/other", list)).toBe(false);
  });

  it("expands `*` to a single segment", () => {
    const list = ["vault://EXAMPLE/svc-secrets/*"];
    expect(isAllowed("vault://EXAMPLE/svc-secrets/tunnel-cert", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/svc-secrets/anything", list)).toBe(true);
    // `*` does not cross `/` segments — sub-paths should NOT match.
    expect(isAllowed("vault://EXAMPLE/svc-secrets/nested/item", list)).toBe(false);
    expect(isAllowed("vault://EXAMPLE/api-tokens/board", list)).toBe(false);
  });

  it("expands `**` to any depth", () => {
    const list = ["vault://EXAMPLE/**"];
    expect(isAllowed("vault://EXAMPLE/svc-secrets/tunnel-cert", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/api-tokens/board", list)).toBe(true);
    expect(isAllowed("vault://OTHER/svc-secrets/x", list)).toBe(false);
  });

  it("escapes regex metacharacters in literal segments", () => {
    const list = ["vault://EXAMPLE/svc-secrets/a.b+c"];
    // The dot/plus must be literal — random characters should NOT match.
    expect(isAllowed("vault://EXAMPLE/svc-secrets/a.b+c", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/svc-secrets/aXbXc", list)).toBe(false);
  });

  it("rejects patterns missing the vault:// prefix", () => {
    expect(() => compileAllowList(["EXAMPLE/svc-secrets/*"])).toThrow(
      InvalidAllowPatternError,
    );
  });

  it("supports multiple patterns (any-match)", () => {
    const list = [
      "vault://EXAMPLE/svc-secrets/tunnel-cert",
      "vault://EXAMPLE/api-tokens/*",
    ];
    expect(isAllowed("vault://EXAMPLE/svc-secrets/tunnel-cert", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/api-tokens/board", list)).toBe(true);
    expect(isAllowed("vault://EXAMPLE/svc-secrets/other", list)).toBe(false);
  });
});

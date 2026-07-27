import { describe, expect, it } from "vitest";
import manifest from "../src/manifest.js";

describe("plugin manifest", () => {
  it("declares the expected id, capabilities, and tools", () => {
    expect(manifest.id).toBe("platform.vault");
    expect(manifest.apiVersion).toBe(1);
    expect(manifest.capabilities).toEqual(
      expect.arrayContaining([
        "http.outbound",
        "secrets.read-ref",
        "agent.tools.register",
        "activity.log.write",
      ]),
    );
    expect(manifest.tools?.map((t) => t.name)).toEqual([
      "vault.read",
      "vault.list",
    ]);
  });

  it("requires the safety-critical config fields", () => {
    const required = (manifest.instanceConfigSchema as { required: string[] }).required;
    expect(required).toEqual(
      expect.arrayContaining(["serviceAccountEmail", "masterPasswordRef", "allowList"]),
    );
  });

  it("locks the masterPasswordRef to a Paperclip secret reference", () => {
    const props = (manifest.instanceConfigSchema as {
      properties: Record<string, { format?: string }>;
    }).properties;
    expect(props.masterPasswordRef?.format).toBe("secret-ref");
  });
});

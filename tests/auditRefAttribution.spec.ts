import { describe, expect, it } from "vitest";
import {
  AUDIT_INVALID_REF,
  AUDIT_NO_GLOB,
  INVALID_READ_PARAMS_ERROR,
  registerVaultTools,
  type AuditRow,
} from "../src/worker/registerTools.js";
import { InMemoryVaultBackend } from "../src/worker/VaultBackend.js";
import { raiseDeniedAlarmIfNew, alarmStateKey } from "../src/worker/deniedAlarm.js";

/**
 * Audit rows are written through the host activity log, and the host runs
 * its sanitizer over the metadata. That sanitizer redacts the VALUE of any
 * key whose NAME matches the pattern below. This is a verbatim copy of
 * `SECRET_FIELD_NAME_PATTERN` from `server/src/redaction.ts` in
 * claudegoogl-sudo/paperclip at commit
 * 5911dfbc0ad5eb926301bf31ec730eed068f67f1. If the host pattern changes,
 * update this copy and re-run the suite.
 */
const SECRET_FIELD_NAME_PATTERN =
  String.raw`[A-Za-z0-9_-]*(?:api[-_]?key|access[-_]?token|auth(?:_?token)?|token|authorization|bearer|secret|passwd|password|credential|jwt|private[-_]?key|cookie|connectionstring|browser[-_]?code|login[-_]?url)[A-Za-z0-9_-]*`;
const SECRET_PAYLOAD_KEY_RE = new RegExp(SECRET_FIELD_NAME_PATTERN, "i");
const REDACTED = "***REDACTED***";

/** Key-name rule of the host sanitizer (the part that caused the bug). */
function hostKeyRule(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    out[k] = SECRET_PAYLOAD_KEY_RE.test(k) ? REDACTED : v;
  }
  return out;
}

/** Same metadata shape as `makeActivityAudit` in src/worker.ts. */
function activityMetadata(e: AuditRow): Record<string, unknown> {
  return {
    agentId: e.agentId,
    runId: e.runId,
    operation: e.operation,
    outcome: e.outcome,
    vaultRef: e.vaultRef,
    ...(e.error ? { error: e.error } : {}),
  };
}

const runCtx = {
  agentId: "11111111-1111-1111-1111-111111111111",
  runId: "22222222-2222-2222-2222-222222222222",
  companyId: "33333333-3333-3333-3333-333333333333",
  projectId: "44444444-4444-4444-4444-444444444444",
  artifacts: {},
};
const ALLOWED = "vault://EXAMPLE/svc-secrets/tunnel-cert";
const DENIED = "vault://EXAMPLE/other/item";

type Handler = (p: unknown, c: typeof runCtx) => Promise<{ error?: string; data?: unknown }>;

function setup() {
  const tools = new Map<string, Handler>();
  const audits: AuditRow[] = [];
  const noop = () => {};
  const ctx = {
    tools: { register: (name: string, _d: unknown, h: Handler) => void tools.set(name, h) },
    secrets: { mintHandle: async () => "h" },
  };
  const backend = new InMemoryVaultBackend();
  backend.set({ org: "EXAMPLE", collection: "svc-secrets", item: "tunnel-cert" }, "plaintext-not-logged");
  registerVaultTools(ctx as never, {
    resolveRuntime: async () => ({
      ok: true,
      backend,
      allowList: [],
      handleMode: false,
      companyPolicies: {
        [runCtx.companyId]: { allowList: ["vault://EXAMPLE/svc-secrets/*"], handleMode: false },
      },
    }),
    writeAudit: async (e) => void audits.push(e),
    logger: { info: noop, warn: noop, error: noop, debug: noop } as never,
  });
  return { tools, audits };
}

function survivesHost(row: AuditRow): Record<string, unknown> {
  return hostKeyRule(activityMetadata(row));
}

describe("audit rows keep the vault ref after host sanitization", () => {
  it("the audit key itself does not match the host secret-field pattern", () => {
    expect(SECRET_PAYLOAD_KEY_RE.test("vaultRef")).toBe(false);
    // Control: the old key is redacted by the same rule.
    expect(SECRET_PAYLOAD_KEY_RE.test("secretRef")).toBe(true);
  });

  it("success read row carries the exact ref", async () => {
    const { tools, audits } = setup();
    await tools.get("vault.read")!({ secretRef: ALLOWED }, runCtx);
    expect(audits.map((a) => a.outcome)).toEqual(["success"]);
    expect(survivesHost(audits[0]!).vaultRef).toBe(ALLOWED);
  });

  it("denied_by_allowlist read row carries the exact ref", async () => {
    const { tools, audits } = setup();
    await tools.get("vault.read")!({ secretRef: DENIED }, runCtx);
    expect(audits.map((a) => a.outcome)).toEqual(["denied_by_allowlist"]);
    expect(survivesHost(audits[0]!).vaultRef).toBe(DENIED);
  });

  it("list rows carry the glob, or the no-glob sentinel", async () => {
    const { tools, audits } = setup();
    await tools.get("vault.list")!({ collectionGlob: "vault://EXAMPLE/svc-secrets/*" }, runCtx);
    await tools.get("vault.list")!({}, runCtx);
    expect(audits.map((a) => a.outcome)).toEqual(["success", "success"]);
    expect(survivesHost(audits[0]!).vaultRef).toBe("vault://EXAMPLE/svc-secrets/*");
    expect(survivesHost(audits[1]!).vaultRef).toBe(AUDIT_NO_GLOB);
  });

  it("a malformed list glob is stored as the fixed marker, not echoed", async () => {
    const { tools, audits } = setup();
    const r = await tools.get("vault.list")!({ collectionGlob: "pasted-value-XYZ" }, runCtx);
    expect(r.error).toMatch(/^invalid_glob/);
    expect(audits[0]!.vaultRef).toBe(AUDIT_INVALID_REF);
    expect(JSON.stringify(audits)).not.toContain("pasted-value-XYZ");
  });

  it("an invalid ref string is stored as the fixed marker, not echoed", async () => {
    const { tools, audits } = setup();
    const r = await tools.get("vault.read")!({ secretRef: "pasted-value-XYZ" }, runCtx);
    expect(r.error).toMatch(/^invalid_ref/);
    expect(audits).toEqual([expect.objectContaining({ outcome: "invalid_ref", vaultRef: AUDIT_INVALID_REF })]);
    expect(JSON.stringify(audits)).not.toContain("pasted-value-XYZ");
  });
});

describe("vault.read with wrong params is a client error, audited", () => {
  for (const [label, params] of [
    ["wrong key {ref}", { ref: "pasted-value-XYZ" }],
    ["non-string secretRef", { secretRef: 42 }],
    ["non-object params", "pasted-value-XYZ"],
    ["null params", null],
  ] as const) {
    it(`${label}: returns invalid_params (no throw) and writes an invalid_params row`, async () => {
      const { tools, audits } = setup();
      const r = await tools.get("vault.read")!(params, runCtx);
      expect(r).toEqual({ error: INVALID_READ_PARAMS_ERROR });
      expect(audits).toHaveLength(1);
      expect(audits[0]!.outcome).toBe("invalid_params");
      expect(survivesHost(audits[0]!).vaultRef).toBe(AUDIT_INVALID_REF);
      expect(JSON.stringify(audits)).not.toContain("pasted-value-XYZ");
    });
  }
});

describe("denied alarm still keys on (agentId, vaultRef)", () => {
  it("dedupes a repeated denial of the same ref and uses the same state key", async () => {
    const { tools, audits } = setup();
    await tools.get("vault.read")!({ secretRef: DENIED }, runCtx);
    await tools.get("vault.read")!({ secretRef: DENIED }, runCtx);
    const state = new Map<string, unknown>();
    let created = 0;
    const deps = {
      companyId: runCtx.companyId,
      getState: async (k: string) => state.get(k) ?? null,
      setState: async (k: string, v: unknown) => void state.set(k, v),
      createIssue: async (i: { description: string }) => {
        created++;
        expect(i.description).toContain(`vaultRef: ${DENIED}`);
        return { id: `issue-${created}` };
      },
      log: () => {},
    };
    const a = await raiseDeniedAlarmIfNew(deps as never, audits[0]!);
    const b = await raiseDeniedAlarmIfNew(deps as never, audits[1]!);
    expect(created).toBe(1);
    expect(b).toBe(a);
    // State key format unchanged, so alarms raised before the rename still dedupe.
    expect([...state.keys()]).toEqual([alarmStateKey(runCtx.agentId, DENIED)]);
  });
});

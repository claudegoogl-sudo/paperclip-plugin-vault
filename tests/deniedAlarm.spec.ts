import { describe, expect, it, vi } from "vitest";
import {
  ALARM_ISSUE_TITLE_PREFIX,
  alarmIssueDescription,
  alarmIssueTitle,
  raiseDeniedAlarmIfNew,
  type DeniedAlarmDeps,
} from "../src/worker/deniedAlarm.js";
import type { AuditRow } from "../src/worker/registerTools.js";

/**
 * Focused unit tests for the denied-by-allowlist alarm. The full audit
 * pipeline (audit-row write → alarm side-effect) is exercised through the
 * registerTools integration suite; here we test the alarm module directly
 * with in-memory stubs so the idempotency, value-leak, and best-effort
 * semantics are pinned down in isolation.
 */

function makeRow(overrides: Partial<AuditRow> = {}): AuditRow {
  return {
    operation: "read",
    agentId: "agent-aaa-1111-2222-3333",
    runId: "run-bbb-4444-5555-6666",
    companyId: "company-ccc-7777-8888",
    secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert",
    outcome: "denied_by_allowlist",
    ...overrides,
  };
}

interface StubParts {
  state: Map<string, unknown>;
  createdIssues: Array<{
    title: string;
    description: string;
    priority: string;
    companyId?: string;
  }>;
  logs: Array<{ level: string; message: string; meta?: unknown }>;
}

function makeDeps(
  companyId = "company-ccc-7777-8888",
  parts: StubParts = { state: new Map(), createdIssues: [], logs: [] },
): DeniedAlarmDeps & { parts: StubParts } {
  return {
    companyId,
    getState: vi.fn(async (key: string) => parts.state.get(key) ?? null),
    setState: vi.fn(async (key: string, value: unknown) => {
      parts.state.set(key, value);
    }),
    createIssue: vi.fn(async (input) => {
      parts.createdIssues.push(input);
      const id = `issue-${parts.createdIssues.length.toString().padStart(3, "0")}`;
      return { id };
    }),
    log: vi.fn((level, message, meta) => {
      parts.logs.push({ level, message, meta });
    }),
    parts,
  };
}

describe("raiseDeniedAlarmIfNew — outcomes", () => {
  it("ignores audit rows whose outcome is not denied_by_allowlist", async () => {
    const deps = makeDeps();
    for (const outcome of ["success", "invalid_ref", "not_found", "error"] as const) {
      const result = await raiseDeniedAlarmIfNew(deps, makeRow({ outcome }));
      expect(result).toBe(null);
    }
    expect(deps.createIssue).not.toHaveBeenCalled();
    expect(deps.setState).not.toHaveBeenCalled();
  });

  it("creates an alarm issue on the first denial and records the issueId in state", async () => {
    const deps = makeDeps();
    const row = makeRow();
    const result = await raiseDeniedAlarmIfNew(deps, row);

    expect(result).toBe("issue-001");
    expect(deps.createIssue).toHaveBeenCalledTimes(1);
    expect(deps.parts.createdIssues[0]?.title).toContain(
      "platform.vault: denied_by_allowlist",
    );
    expect(deps.setState).toHaveBeenCalledTimes(1);
    const stored = deps.parts.state.get(`denied:${row.agentId}:vault://EXAMPLE/svc-secrets/tunnel-cert`);
    expect(stored).toMatchObject({ issueId: "issue-001" });
    expect(deps.parts.logs).toHaveLength(0);
  });

  it("returns the existing issueId on a second denial for the SAME (agentId, ref) and does not create another issue", async () => {
    const deps = makeDeps();
    const row = makeRow({ runId: "run-FIRST" });
    const first = await raiseDeniedAlarmIfNew(deps, row);
    expect(first).toBe("issue-001");

    // Same agent + same ref, different run — collapses to the same alarm.
    const secondRow = makeRow({ runId: "run-SECOND-DENIAL" });
    const second = await raiseDeniedAlarmIfNew(deps, secondRow);

    expect(second).toBe("issue-001");
    expect(deps.createIssue).toHaveBeenCalledTimes(1);
    // setState is only called once (on creation), not on the idempotent return.
    expect(deps.setState).toHaveBeenCalledTimes(1);
  });

  it("creates SEPARATE alarm issues when EITHER agentId or secretRef differs", async () => {
    const deps = makeDeps();
    await raiseDeniedAlarmIfNew(deps, makeRow({
      agentId: "agent-A",
      secretRef: "vault://EXAMPLE/svc-secrets/a",
    }));
    await raiseDeniedAlarmIfNew(deps, makeRow({
      agentId: "agent-A",
      secretRef: "vault://EXAMPLE/svc-secrets/b",
    }));
    await raiseDeniedAlarmIfNew(deps, makeRow({
      agentId: "agent-B",
      secretRef: "vault://EXAMPLE/svc-secrets/a",
    }));
    expect(deps.parts.createdIssues).toHaveLength(3);
    expect(deps.parts.createdIssues.map((i) => i.title)).toEqual([
      expect.stringContaining("agent=agent-A"),
      expect.stringContaining("agent=agent-A"),
      expect.stringContaining("agent=agent-B"),
    ]);
  });

  it("also fires for `denied_by_allowlist` outcomes on a `list` operation", async () => {
    const deps = makeDeps();
    const row = makeRow({
      operation: "list",
      secretRef: "vault://OTHER/svc-secrets/*",
    });
    const result = await raiseDeniedAlarmIfNew(deps, row);
    expect(result).toBe("issue-001");
    expect(deps.parts.createdIssues[0]?.description).toContain("operation: list");
  });
});

describe("raiseDeniedAlarmIfNew — alarm payload", () => {
  it("the issue description carries agentId, runId, companyId, AND the requested ref", async () => {
    const deps = makeDeps();
    const row = makeRow({
      agentId: "agent-FULL-ID-1234",
      runId: "run-FULL-RUN-5678",
      companyId: "company-FULL-9012",
      secretRef: "vault://EXAMPLE/svc-secrets/tunnel-cert",
    });
    await raiseDeniedAlarmIfNew(deps, row);
    const body = deps.parts.createdIssues[0]?.description ?? "";
    expect(body).toContain("agentId: agent-FULL-ID-1234");
    expect(body).toContain("runId: run-FULL-RUN-5678");
    expect(body).toContain("companyId: company-FULL-9012");
    expect(body).toContain("secretRef: vault://EXAMPLE/svc-secrets/tunnel-cert");
  });

  it("NEVER carries a resolved value — there is no value field on AuditRow and the description is built only from safe metadata", async () => {
    const deps = makeDeps();
    // A fake "leaked token" string that, if it ever appeared in the description,
    // would prove value leakage. We never pass it (we couldn't if we wanted to
    // — AuditRow has no value field), but the assertion documents the contract.
    const SENTINEL = "ghp_LEAKED_VALUE_SENTINEL_abc123";
    const row = makeRow();
    await raiseDeniedAlarmIfNew(deps, row);

    const issue = deps.parts.createdIssues[0];
    expect(issue).toBeDefined();
    const blob = JSON.stringify(issue);
    expect(blob).not.toContain(SENTINEL);

    // Hard-pin the description shape. Adding a value-bearing line later
    // breaks this test. Every line listed is metadata the audit row carries.
    expect(issue.description).toBe(
      [
        "An agent attempted to resolve a vault ref that this adapter's allowList denies.",
        "The denial happened before any network call to Vaultwarden; no value was read.",
        "",
        `- agentId: ${row.agentId}`,
        `- runId: ${row.runId}`,
        `- companyId: ${row.companyId}`,
        `- secretRef: ${row.secretRef}`,
        `- operation: ${row.operation}`,
        "",
        "Repeated denials of the same (agentId, secretRef) collapse into this single issue.",
        "Update the adapter's `allowList` (or `companyPolicies` entry for this company) to grant access,",
        "or confirm the agent should not be reading this ref and close this issue.",
      ].join("\n"),
    );
  });

  it("truncates the ref in the title for readability but keeps it whole in the description", async () => {
    const deps = makeDeps();
    const longRef = `vault://EXAMPLE/long-collection/${"x".repeat(120)}`;
    const row = makeRow({ secretRef: longRef });
    await raiseDeniedAlarmIfNew(deps, row);
    const title = deps.parts.createdIssues[0]?.title ?? "";
    expect(title.length).toBeLessThan(160);
    // The full ref still appears in the description body.
    expect(deps.parts.createdIssues[0]?.description).toContain(longRef);
  });
});

describe("raiseDeniedAlarmIfNew — best-effort failure handling", () => {
  it("still creates the issue when state.get throws (idempotency tracking is best-effort)", async () => {
    const parts: StubParts = { state: new Map(), createdIssues: [], logs: [] };
    const deps: DeniedAlarmDeps = {
      companyId: "company-ccc",
      getState: vi.fn(async () => {
        throw new Error("state backend down");
      }),
      setState: vi.fn(async () => {}),
      createIssue: vi.fn(async (input) => {
        parts.createdIssues.push(input);
        return { id: "issue-DESPITE-STATE-FAILURE" };
      }),
      log: vi.fn((level, message, meta) => {
        parts.logs.push({ level, message, meta });
      }),
    };
    const result = await raiseDeniedAlarmIfNew(deps, makeRow());
    expect(result).toBe("issue-DESPITE-STATE-FAILURE");
    expect(parts.createdIssues).toHaveLength(1);
    expect(parts.logs.some((l) => l.message === "vault.denied_alarm_state_read_failed")).toBe(true);
  });

  it("logs and returns null (without throwing) when issue creation fails", async () => {
    const parts: StubParts = { state: new Map(), createdIssues: [], logs: [] };
    const deps: DeniedAlarmDeps = {
      companyId: "company-ccc",
      getState: vi.fn(async () => null),
      setState: vi.fn(async () => {}),
      createIssue: vi.fn(async () => {
        throw new Error("issues RPC refused");
      }),
      log: vi.fn((level, message, meta) => {
        parts.logs.push({ level, message, meta });
      }),
    };
    await expect(raiseDeniedAlarmIfNew(deps, makeRow())).resolves.toBe(null);
    expect(parts.logs.some((l) => l.message === "vault.denied_alarm_create_failed")).toBe(true);
  });

  it("still returns the issueId when state.set throws after issue creation (duplicate risk on next denial is acceptable)", async () => {
    const parts: StubParts = { state: new Map(), createdIssues: [], logs: [] };
    const deps: DeniedAlarmDeps = {
      companyId: "company-ccc",
      getState: vi.fn(async () => null),
      setState: vi.fn(async () => {
        throw new Error("state write failed");
      }),
      createIssue: vi.fn(async (input) => {
        parts.createdIssues.push(input);
        return { id: "issue-CREATED-BUT-STATE-LOST" };
      }),
      log: vi.fn((level, message, meta) => {
        parts.logs.push({ level, message, meta });
      }),
    };
    const result = await raiseDeniedAlarmIfNew(deps, makeRow());
    expect(result).toBe("issue-CREATED-BUT-STATE-LOST");
    expect(parts.logs.some((l) => l.message === "vault.denied_alarm_state_write_failed")).toBe(true);
  });
});

describe("alarmIssueTitle / alarmIssueDescription — pure helpers", () => {
  it("alarmIssueTitle starts with the documented prefix so operators can search for it", () => {
    const title = alarmIssueTitle(makeRow());
    expect(title.startsWith(ALARM_ISSUE_TITLE_PREFIX)).toBe(true);
  });

  it("alarmIssueDescription does not carry a `value:` field key or any value-bearing line", () => {
    const body = alarmIssueDescription(makeRow());
    // No `value:`-keyed field line (the shape that would actually leak a resolved
    // secret). The prose word "value" appears in "no value was read" — that is
    // fine; this assertion is about field keys, not english prose.
    expect(body).not.toMatch(/(^|\n)-\s*value:/);
    expect(body).not.toMatch(/secretValue/i);
    expect(body).not.toMatch(/plaintextToken/i);
    // The description references exactly five metadata fields, all from AuditRow.
    const fieldLines = body
      .split("\n")
      .filter((l) => /^- /.test(l))
      .map((l) => l.replace(/^- ([\w_]+):.*/, "$1"));
    expect(fieldLines.sort()).toEqual(
      ["agentId", "companyId", "operation", "runId", "secretRef"].sort(),
    );
  });
});

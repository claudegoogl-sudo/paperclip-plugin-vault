import type { AuditRow } from "./registerTools.js";

/**
 * `denied_by_allowlist` alarm — idempotent Paperclip issue per
 * (agentId, secretRef) tuple.
 *
 * When the vault tools deny a read or list call because the ref is outside
 * the allowList (or because no company policy is configured for the calling
 * company), the audit row already carries everything needed to alert on
 * (agentId, runId, companyId, secretRef). This module consumes that row and
 * raises a Paperclip issue in the dispatching company's tenant on the FIRST
 * denial for a given (agentId, secretRef) tuple. Subsequent denials of the
 * same tuple collapse into the existing issue — they do not spam.
 *
 * The alarm never carries a resolved value. {@link AuditRow} does not have a
 * value field by construction; the description built here references only the
 * row's safe metadata fields. A test asserts this end-to-end.
 *
 * Best-effort by design: if the plugin worker cannot reach `ctx.state` or
 * `ctx.issues` (capability not granted, transient host error), the alarm
 * logs loudly and returns. It must never break the caller's audit-write
 * path — the audit row is the durable record; the alarm is a UX layer on
 * top.
 */

/** Title prefix used to recognize alarm issues in `ctx.issues.list`. */
export const ALARM_ISSUE_TITLE_PREFIX = "platform.vault: denied_by_allowlist";

/**
 * Build the deterministic title for an alarm issue. Pure function so tests
 * can assert on it and operators can search for it.
 *
 * The title never carries the value; only the (agentId, secretRef) tuple.
 * The agentId is truncated to its first 8 chars to keep the title readable
 * — the full agentId is in the description body.
 */
export function alarmIssueTitle(row: AuditRow): string {
  const agentShort = row.agentId.slice(0, 8);
  const refTrunc = row.secretRef.length > 80
    ? `${row.secretRef.slice(0, 77)}…`
    : row.secretRef;
  return `${ALARM_ISSUE_TITLE_PREFIX} — agent=${agentShort}… ref=${refTrunc}`;
}

/**
 * Build the alarm issue description body. Pure function — same inputs
 * produce the same body, so a test can assert byte-for-byte and a future
 * value-leaking edit fails the test.
 *
 * The body lists exactly the four required fields (agentId, runId,
 * companyId, secretRef) plus the operation (`read` or `list`). It never
 * reads any field that could carry a value, because {@link AuditRow}
 * does not have one.
 */
export function alarmIssueDescription(row: AuditRow): string {
  return [
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
  ].join("\n");
}

/**
 * Dependency-injected surface so the logic is testable without a real
 * `PluginContext`. Production wires this to `ctx.state` + `ctx.issues`; tests
 * inject in-memory stubs.
 */
export interface DeniedAlarmDeps {
  /**
   * Read a previously-recorded alarm mapping for this key. Returns `null`
   * when no alarm has been raised yet for the tuple. Production: `ctx.state.get`.
   */
  getState: (key: string) => Promise<unknown>;
  /**
   * Record the alarm mapping after issue creation. Production: `ctx.state.set`.
   * Keyed by company-scoped state key.
   */
  setState: (key: string, value: unknown) => Promise<void>;
  /**
   * Create the alarm issue in the dispatching company's tenant. Production:
   * `ctx.issues.create`.
   */
  createIssue: (input: {
    title: string;
    description: string;
    priority: "medium";
  }) => Promise<{ id: string }>;
  /** Structured logger. Production: `ctx.logger`. */
  log: (level: "warn" | "error", message: string, meta?: Record<string, unknown>) => void;
  /** Company ID under which to scope the state key and file the issue. */
  companyId: string;
}

/**
 * Build the deterministic state key for a (agentId, secretRef) tuple. The
 * key is what `getState`/`setState` see — production prefixes it with the
 * company scope + `denied-alarms` namespace, so the raw key here is just
 * the agent + ref fingerprint.
 *
 * The agentId is a UUID (fixed shape). The secretRef is a vault ref like
 * `vault://ORG/COLLECTION/ITEM` or the list sentinel
 * `(no glob: allowList scopes)`; we keep the readable shape and only
 * escape characters that would corrupt a state key, then cap length so a
 * hostile ref can't blow up the key.
 */
export function alarmStateKey(agentId: string, secretRef: string): string {
  const safeRef = secretRef.replace(/[^\w:/.*\[\]-]/g, "_").slice(0, 120);
  return `denied:${agentId}:${safeRef}`;
}

/**
 * Raise the alarm for an audit row IF AND ONLY IF the row's outcome is
 * `denied_by_allowlist` and no alarm has been raised yet for the row's
 * (agentId, secretRef) tuple.
 *
 * Returns the issueId of the alarm issue (existing or newly created), or
 * `null` when no alarm was raised (non-deny row, state read confirmed an
 * existing alarm, or issue creation failed).
 *
 * Never throws. Failures in `getState`/`setState`/`createIssue` are caught
 * and logged; the audit-write caller is unaffected.
 */
export async function raiseDeniedAlarmIfNew(
  deps: DeniedAlarmDeps,
  row: AuditRow,
): Promise<string | null> {
  if (row.outcome !== "denied_by_allowlist") return null;
  if (row.companyId !== deps.companyId) {
    // Defensive: the audit row's companyId should always match the deps'
    // companyId (production wires them from the same runCtx). If they
    // diverge, log and proceed using deps.companyId for scoping — the
    // state key and issue must land in one consistent tenant.
    deps.log("warn", "vault.denied_alarm_company_id_mismatch", {
      rowCompanyId: row.companyId,
      depsCompanyId: deps.companyId,
    });
  }

  const key = alarmStateKey(row.agentId, row.secretRef);

  let priorIssueId: string | null = null;
  try {
    const existing = await deps.getState(key);
    if (
      existing
      && typeof existing === "object"
      && "issueId" in existing
      && typeof (existing as { issueId: unknown }).issueId === "string"
    ) {
      priorIssueId = (existing as { issueId: string }).issueId;
    }
  } catch (err) {
    deps.log("warn", "vault.denied_alarm_state_read_failed", {
      agentId: row.agentId,
      secretRef: row.secretRef,
      error: String(err instanceof Error ? err.message : err),
    });
    // Continue: try to create the issue anyway. Idempotency is best-effort;
    // a duplicate issue is recoverable, a missed alarm is not.
  }

  if (priorIssueId) return priorIssueId;

  try {
    const issue = await deps.createIssue({
      title: alarmIssueTitle(row),
      description: alarmIssueDescription(row),
      priority: "medium",
    });
    try {
      await deps.setState(key, {
        issueId: issue.id,
        firstSeenAt: new Date().toISOString(),
      });
    } catch (err) {
      // Issue was created; state-tracking failure is best-effort. The next
      // denial will file a DUPLICATE issue — preferable to silently dropping
      // the alarm. Log so the operator notices.
      deps.log("warn", "vault.denied_alarm_state_write_failed", {
        issueId: issue.id,
        agentId: row.agentId,
        secretRef: row.secretRef,
        error: String(err instanceof Error ? err.message : err),
      });
    }
    return issue.id;
  } catch (err) {
    deps.log("error", "vault.denied_alarm_create_failed", {
      agentId: row.agentId,
      secretRef: row.secretRef,
      error: String(err instanceof Error ? err.message : err),
    });
    return null;
  }
}

# Changelog

## 0.2.2

- Audit rows now store the ref under `vaultRef` (was `secretRef`). The host
  activity sanitizer redacts any metadata key whose name contains `secret`,
  so every row showed `***REDACTED***` instead of the ref. The activity
  `entityId`, the denied-alarm issue body and the alarm log fields use the
  same name. The denied-alarm state key format is unchanged, so alarms raised
  by 0.2.1 still dedupe.
- Only a ref that has the `vault://<org>/<collection>/<item>` shape and parses
  is stored in clear (list: a `vault://<org>/<collection>/*` glob). Anything
  else is stored as `(invalid)`, so caller input is never echoed into the
  audit trail.
- `vault.read` with a missing or non-string `secretRef` (for example
  `{ ref: ... }`) no longer throws (a host 500). It returns an
  `invalid_params: ...` tool error, the same client-error shape as
  `invalid_ref`, and writes an audit row with outcome `invalid_params`.

## 0.2.0

**Breaking (config semantics):** `companyPolicies` entries are the only
grant source. The instance-level `allowList` and `handleMode` are no longer
inherited — on any path.

- `companyPolicies` absent or empty now denies **every** company
  (`vault.policymap_missing`); previously the instance-level `allowList`
  became the effective grant for all companies.
- A listed entry without `allowList` now denies that company
  (`vault.policy_entry_missing_allowlist`); previously it inherited the
  instance-level `allowList`.
- `handleMode` now comes only from the `companyPolicies` entry; omitted
  means OFF. The instance-level flag is ignored.
- New boot-time drift sweep: `reportPolicyDrift` logs
  `vault.policymap_missing` / `vault.policy_entry_missing_allowlist`
  (naming the `companyId`) at worker start; the ready log reports
  `companyPolicyCount` and `misconfiguredPolicyEntries` (replacing
  `allowListSize`).
- The instance-level `allowList` remains required non-empty for worker
  activation, but grants nothing.

**Upgrading:** copy your top-level `allowList` into a `companyPolicies`
entry keyed by your companyId — see the README "Upgrading to 0.2.0"
section.

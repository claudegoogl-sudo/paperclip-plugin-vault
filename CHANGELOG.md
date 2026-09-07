# Changelog

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

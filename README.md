# paperclip-plugin-vault
Paperclip plugin: per-call secret resolution against a Vaultwarden vault (platform.vault). Internal Platform tooling. Release assets carry the bundled plugin tarball.

## Tenant scoping (0.2.0)

`companyPolicies` entries are the **only** grant source. A company may call
`vault.read` / `vault.list` if and only if it is listed there with a
non-empty `allowList`, and its grant is exactly that entry's list — an entry
**replaces** (never intersects or narrows) the instance-level list.

Fail-closed on every drift shape:

| Config shape | Result |
|---|---|
| `companyPolicies` absent or empty | **every** company denied (`vault.policymap_missing`) |
| company not listed | denied (`company_unlisted`) |
| listed entry without `allowList` | that company denied (`vault.policy_entry_missing_allowlist`) |
| `handleMode` omitted in an entry | OFF for that company — **never** inherited from the instance level |
| entry pattern fails to compile | denied (`vault.allowlist_compile_failed`) |

The top-level `allowList` is required non-empty for **worker activation
only** — since 0.2.0 it grants nothing and is never inherited. The
top-level `handleMode` has no effect; the per-entry flag is the only
switch.

Misconfiguration is surfaced loudly, never as a silent deny:

- at worker start, `reportPolicyDrift` logs `vault.policymap_missing` or
  `vault.policy_entry_missing_allowlist` (naming the `companyId`) at
  `error` level, and the ready log carries `companyPolicyCount` and
  `misconfiguredPolicyEntries`;
- on each denied call the same named error event is logged and the ordinary
  `denied_by_allowlist` audit row (and its alarm issue on first denial) is
  written.

### Upgrading to 0.2.0

Installs that relied on the legacy instance-wide grant (no
`companyPolicies`) now deny every company. Copy your top-level `allowList`
into a `companyPolicies` entry keyed by your companyId:

```json
{
  "allowList": ["vault://EXAMPLE/svc-secrets/*"],
  "companyPolicies": {
    "<your-companyId>": { "allowList": ["vault://EXAMPLE/svc-secrets/*"] }
  }
}
```

If your company needs borrowed-handle mode, set `"handleMode": true` on
that same entry (the top-level flag is ignored).

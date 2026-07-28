import type { PaperclipPluginManifestV1 } from "@paperclipai/plugin-sdk";

/**
 * paperclip-plugin-vault — manifest.
 *
 * Resolves `vault://<org>/<collection>/<item>` references per call against
 * the Platform Vaultwarden instance. Plaintext is never cached on disk and
 * never crosses the worker beyond the single tool invocation that resolved
 * it. `allowList` is enforced BEFORE any network call so unauthorized
 * resolution attempts surface as `prerequisite_missing` without touching
 * the vault.
 */
const manifest: PaperclipPluginManifestV1 = {
  id: "platform.vault",
  apiVersion: 1,
  version: __PLUGIN_VERSION__,
  displayName: "Vault",
  description:
    "Per-call secret resolution against the Platform Vaultwarden vault. " +
    "Agents call `vault.read('vault://...')` to fetch secrets without " +
    "embedding credentials in plugin config or env. Each adapter instance " +
    "declares an `allowList` of vault refs it may resolve.",
  author: "Platform",
  categories: ["connector"],
  capabilities: [
    // Outbound HTTPS to the configured Vaultwarden server (identity +
    // /api/sync + per-cipher). Worker scopes to the configured serverUrl.
    "http.outbound",
    // Vaultwarden service-account master password is itself stored in the
    // Paperclip secret provider (chicken-and-egg: one bootstrap secret to
    // unlock N downstream vault items).
    "secrets.read-ref",
    // The `vault.read` (and `vault.list`) tools.
    "agent.tools.register",
    // Per-call audit row: (agentId, runId, secretRef, outcome).
    "activity.log.write",
  ],

  entrypoints: {
    worker: "./dist/worker.js",
  },

  instanceConfigSchema: {
    type: "object",
    properties: {
      serverUrl: {
        type: "string",
        format: "uri",
        default: "https://vault.timms-gitclaw.de",
        description:
          "Vaultwarden base URL. All identity + cipher requests are scoped " +
          "to this host; the worker rejects URLs that don't match. Rejected " +
          "at worker setup (fail closed) if it is not https or its host is " +
          "not in allowedServerHosts.",
      },
      allowedServerHosts: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
        description:
          "Optional host allowlist for serverUrl. Defaults to the single " +
          "host parsed out of serverUrl itself, so most operators never " +
          "need to set this. Set explicitly to pin the plugin to a " +
          "specific host regardless of what serverUrl later resolves to.",
      },
      serviceAccountEmail: {
        type: "string",
        format: "email",
        description:
          "Email address of the dedicated Vaultwarden service-account user. " +
          "Must be invited to the target organization with read access to " +
          "every collection covered by `allowList`. See README for setup.",
      },
      masterPasswordRef: {
        type: "string",
        format: "secret-ref",
        description:
          "Paperclip secret reference for the service account's master " +
          "password. Resolved per unlock via ctx.secrets.resolve; never " +
          "logged. Plugin uses this to PBKDF2-derive the master key and " +
          "obtain an access token + the user's encryption key.",
      },
      allowList: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
        description:
          "Vault refs (or glob patterns) this adapter instance is allowed " +
          "to resolve. Patterns use `*` (one path segment) and `**` (any " +
          "depth). Example: `vault://EXAMPLE/svc-secrets/*`. Enforced before " +
          "any network call to Vaultwarden.",
      },
      sessionTtlSeconds: {
        type: "integer",
        minimum: 60,
        maximum: 86400,
        default: 3600,
        description:
          "How long the unlocked session (master key + ciphers cache) lives " +
          "in worker memory before forcing a re-unlock. Defaults to 1h. " +
          "Plaintext cipher values are NEVER cached — only the derived keys " +
          "needed to decrypt-on-demand.",
      },
      handleMode: {
        type: "boolean",
        default: false,
        description:
          "Borrowed-handle mode (Control 2). When true, `vault.read` returns " +
          "an opaque host-minted handle on both `content` and `data.value` " +
          "instead of plaintext; the value resolves only when a downstream " +
          "tool param routes it through the host egress chokepoint. " +
          "Per-binding opt-in — leave false until every consumer of this " +
          "binding's `data.value` routes through egress rather than reading " +
          "the value directly.",
      },
      companyPolicies: {
        type: "object",
        additionalProperties: {
          type: "object",
          properties: {
            allowList: {
              type: "array",
              items: { type: "string" },
              minItems: 1,
              description:
                "Vault refs/globs this company may resolve. Defaults to the " +
                "instance-level `allowList` when omitted.",
            },
            handleMode: {
              type: "boolean",
              description:
                "Override the instance-level `handleMode` for this company.",
            },
          },
          additionalProperties: false,
        },
        description:
          "Per-company tenant scoping, keyed by Paperclip companyId. " +
          "FAIL-CLOSED: when present and non-empty, ONLY listed companies " +
          "may call the vault tools; every other company is denied before " +
          "any parsing or network call. Each entry may narrow `allowList` " +
          "(e.g. `vault://OTHER/**` for a second company) and override " +
          "`handleMode`. When absent, the instance-level `allowList` and " +
          "`handleMode` apply to all companies (legacy behaviour).",
      },
    },
    required: ["serviceAccountEmail", "masterPasswordRef", "allowList"],
    additionalProperties: false,
  },

  tools: [
    {
      name: "vault.read",
      displayName: "Vault Read",
      description:
        "Resolve a `vault://<org>/<collection>/<item>` reference to the " +
        "current secret value. The ref is checked against this adapter's " +
        "allowList before any vault network call. Plaintext is returned in " +
        "the tool result for use within the calling agent's run; the " +
        "plugin never persists or re-emits it. When the binding enables " +
        "`handleMode`, `content` and `data.value` instead carry an opaque " +
        "handle that must be routed through a downstream tool param (not " +
        "read directly). Returns " +
        "`prerequisite_missing` if the ref is outside the allowList or the " +
        "adapter is unconfigured.",
      parametersSchema: {
        type: "object",
        properties: {
          secretRef: {
            type: "string",
            pattern: "^vault://[^/]+/[^/]+/[^/]+$",
            description:
              "Vault reference, e.g. `vault://EXAMPLE/svc-secrets/tunnel-cert`. " +
              "Segments are organization name, collection name, item name.",
          },
        },
        required: ["secretRef"],
        additionalProperties: false,
      },
    },
    {
      name: "vault.list",
      displayName: "Vault List",
      description:
        "List the NAMES (not values) of items the adapter is allowed to " +
        "resolve. Optionally filter to a `<org>/<collection>/*` glob. Use " +
        "for discovery; vault.read is the only way to obtain values.",
      parametersSchema: {
        type: "object",
        properties: {
          collectionGlob: {
            type: "string",
            description:
              "Optional `vault://<org>/<collection>/*` glob to filter the " +
              "listing. Defaults to the adapter's full allowList.",
          },
        },
        additionalProperties: false,
      },
    },
  ],
};

export default manifest;

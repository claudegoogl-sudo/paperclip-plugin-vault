/**
 * Strict validation for the operator-supplied `serverUrl` config value,
 * applied BEFORE the resolved service-account master password is ever
 * used against it.
 *
 * Mirrors paperclip-plugin-cad's `parseGitHubUrl` fix and
 * paperclip-klipper's `validateMoonrakerBaseUrl`: WHATWG `URL` parsing plus
 * strict `protocol`/`host` equality — never a regex or substring check on
 * the raw string. The previous check here (`/^https:\/\//.test(...)`) only
 * ever validated the scheme prefix; it never looked at `host` at all, so
 * "https, any host" was accepted. A naive follow-up that just added
 * `raw.includes(expectedHost)` would still be bypassable by an
 * attacker-controlled origin that merely mentions the expected host in its
 * *path*, e.g. `https://attacker.example/vault.timms-gitclaw.de/...` — only
 * `new URL(raw).host` reflects the actual network destination.
 */
export type VaultServerUrlValidation =
  | { ok: true; url: URL }
  | { ok: false; reason: "unparseable" | "unsupported_scheme" | "host_not_allowed"; host: string | null };

/**
 * Validate `raw` against `allowedHosts`. When `allowedHosts` is empty or
 * omitted, the allowlist defaults to the single host parsed out of `raw`
 * itself — i.e. any well-formed https URL is accepted (matching today's
 * behavior for the single-instance case) while still rejecting malformed
 * values. Operators that want to pin the plugin to a specific Vaultwarden
 * host regardless of what config value later lands can set
 * `allowedServerHosts` explicitly.
 */
export function validateVaultServerUrl(
  raw: string,
  allowedHosts?: string[],
): VaultServerUrlValidation {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "unparseable", host: null };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: "unsupported_scheme", host: url.host };
  }
  const allowlist = allowedHosts && allowedHosts.length > 0 ? allowedHosts : [url.host];
  if (!allowlist.includes(url.host)) {
    return { ok: false, reason: "host_not_allowed", host: url.host };
  }
  return { ok: true, url };
}

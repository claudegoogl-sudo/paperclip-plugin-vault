/**
 * Parse and match `vault://<org>/<collection>/<item>` references.
 *
 * Grammar:
 *   `vault://` ORG `/` COLLECTION `/` ITEM
 *   Each segment is a non-empty sequence of characters excluding `/`.
 *
 * Glob support for allowList entries:
 *   - `*`  — matches one path segment (no `/`).
 *   - `**` — matches one or more path segments.
 *   - Any other characters are matched literally (no other metacharacters).
 *
 * Examples:
 *   `vault://EXAMPLE/svc-secrets/tunnel-cert`   — exact ref
 *   `vault://EXAMPLE/svc-secrets/*`                  — any item in that collection
 *   `vault://EXAMPLE/**`                              — any item in any EXAMPLE collection
 */

export interface VaultRef {
  raw: string;
  org: string;
  collection: string;
  item: string;
}

const VAULT_REF_RE = /^vault:\/\/([^/]+)\/([^/]+)\/([^/]+)$/;

export function parseVaultRef(ref: string): VaultRef {
  const m = VAULT_REF_RE.exec(ref);
  if (!m) {
    throw new InvalidSecretRefError(ref);
  }
  return { raw: ref, org: m[1]!, collection: m[2]!, item: m[3]! };
}

export class InvalidSecretRefError extends Error {
  constructor(public readonly ref: string) {
    super(
      `invalid vault ref ${JSON.stringify(ref)}; expected vault://<org>/<collection>/<item>`,
    );
    this.name = "InvalidSecretRefError";
  }
}

/**
 * Compile a glob pattern from an allowList entry into a regex.
 *
 * Patterns must start with `vault://`. `**` matches one or more path
 * segments; `*` matches a single segment. All other characters are
 * escaped to literal. The regex anchors both ends so partial matches
 * cannot accidentally widen the grant.
 */
export function compileAllowPattern(pattern: string): RegExp {
  if (!pattern.startsWith("vault://")) {
    throw new InvalidAllowPatternError(pattern);
  }
  // Tokenize the pattern after the `vault://` prefix so glob metacharacters
  // are not re-escaped during the literal-escape pass.
  const body = pattern.slice("vault://".length);
  let regex = "^vault:\\/\\/";
  let i = 0;
  while (i < body.length) {
    const ch = body[i]!;
    if (ch === "*") {
      if (body[i + 1] === "*") {
        regex += "[^]+"; // match one or more characters including `/`
        i += 2;
      } else {
        regex += "[^/]+"; // match a single segment
        i += 1;
      }
    } else {
      // Escape regex metacharacters.
      regex += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      i += 1;
    }
  }
  regex += "$";
  return new RegExp(regex);
}

export class InvalidAllowPatternError extends Error {
  constructor(public readonly pattern: string) {
    super(
      `invalid allowList pattern ${JSON.stringify(pattern)}; must start with "vault://"`,
    );
    this.name = "InvalidAllowPatternError";
  }
}

/**
 * Check whether `ref` is permitted by any pattern in `allowList`.
 * Compiles patterns lazily; callers that match many refs against the same
 * allowList should hoist compilation via {@link compileAllowList}.
 */
export function isAllowed(ref: string, allowList: readonly string[]): boolean {
  const compiled = compileAllowList(allowList);
  return compiled.some((re) => re.test(ref));
}

export function compileAllowList(allowList: readonly string[]): RegExp[] {
  return allowList.map(compileAllowPattern);
}

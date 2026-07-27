## Thinking Path

<!--
  Required. Trace your reasoning from the top down to this specific change:
  what this plugin does, the subsystem involved, the problem, and why this PR
  exists. Blockquote style, roughly 4-6 steps.
-->

> - [What this plugin does and who consumes it]
> - [Which part of it is involved]
> - [What problem or gap exists]
> - This pull request ...
> - The benefit is ...

## What Changed

<!-- Bullet list of concrete changes. One bullet per logical unit. -->

-

## Verification

<!--
  How can a reviewer confirm this works? Real evidence: test commands and
  their output, an install probe, manual steps taken. Not an assertion.
-->

-

## Risks

<!--
  What could go wrong? Blast radius if it fails, config/schema migration
  safety, behavioral shifts, rollback path. "Low risk" is acceptable when
  genuinely minor — say why.
-->

-

## Model Used

<!--
  Required. Provider, exact model id, and capability details. Example:
  Claude Opus 4.6 (claude-opus-4-7), via Claude Code, extended thinking + tool use.
  If no AI assisted, write "None — human-authored".
-->

-

## Checklist

- [ ] Thinking Path traces from plugin context down to this change
- [ ] Model Used names the provider, exact model id, and capability details
- [ ] One PR = one logical change; no unrelated cleanups bundled in
- [ ] Verification section carries real evidence, not an assertion
- [ ] `package.json` and `src/manifest.ts` versions bumped together (or N/A — no version change)
- [ ] Internal-reference policy for this repo's visibility followed (see CONTRIBUTING.md → Repo visibility)
- [ ] Branch name describes the change and leaks no instance-local detail (public repos)
- [ ] Docs updated to match the change (or N/A)
- [ ] All CI checks green

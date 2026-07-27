# Contributing — Platform plugin repo

Internal Platform tooling. Same review bar as `paperclipai/paperclip`, minus the gates that only exist upstream.

## Repo visibility

This repo is **PUBLIC**.

Do **not** put internal, instance-local references in the PR title, branch name, description, or commit messages:

- internal ticket ids (`PLA-1234` or any `{PREFIX}-{NUMBER}` that is not a public GitHub issue number)
- instance UI links (`/PLA/issues/...`, `/PLA/agents/...`, `agent://...`)
- `localhost`, private IP, or tailnet URLs

Restate the context in plain English instead. Use a descriptive branch name scoped to the change (`fix/...`, `feat/...`, `docs/...`), never one derived from an internal ticket.

## PR template

Every PR must fill out [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md). All six sections are required: Thinking Path, What Changed, Verification, Risks, Model Used, Checklist. If you open the PR through the API or `gh pr create`, paste the template body into the description manually — the template is not applied automatically on those paths.

## Model Used (required)

Every PR states the provider, the exact model id, and relevant capability details — e.g. `Claude Opus 4.6 (claude-opus-4-7), via Claude Code, extended thinking + tool use`. If no AI assisted, write `None — human-authored`.

## Gates

- All CI checks green before merge. Red CI on a public repo is a P0 — fix or close it, never defer it.
- One PR = one logical change. No unrelated cleanups bundled in.
- When the plugin version changes, bump `package.json` **and** the version literal in `src/manifest.ts` in the same PR. The host registers by `manifest.version`; drift between the two ships a mislabelled plugin.
- The Verification section carries real evidence — command output, an install probe, a screenshot — not an assertion that it works.

## Not applicable here

This repo has no upstream parent; it is first-party, not a fork of `paperclipai/*`. So none of the following apply, and you should not escalate about them:

- **PR target** — PRs go against this repo directly. The upstream-PR freeze covers `paperclipai/*` only.
- **Greptile 5/5** — not installed here. That is a `paperclipai/paperclip` merge gate.
- **`#dev` Discord pre-agreement** and **`ROADMAP.md` check** — upstream roadmap-ownership rules. There is no `ROADMAP.md` in this repo.

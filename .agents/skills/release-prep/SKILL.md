---
name: release-prep
description: Prepare releases from this repository checkout. Use when the agent needs to inspect release readiness, compare commits since the previous release tag, summarize merged GitHub PRs, validate GitHub release/tag state, create or update a local release version branch, bump the repository version file, draft/update release changelog files, or produce safe next-step commands for opening the release PR and tagging after merge.
---

# Release Prep

## Workflow

Run the bundled script first from the repository checkout:

```bash
uv run .agents/skills/release-prep/scripts/prepare_release.py inspect
```

Use the output to confirm:

- `origin/master` has been fetched and is the intended base for normal releases.
- The worktree has no uncommitted changes before local preparation.
- The latest reachable tag and GitHub release match.
- Commits and merged PRs since the latest tag are understood.
- No existing tag, release, or remote release branch conflicts with the target version.
- Whether `include/ddwaf.h` changed since the previous tag — if so, the upgrading guide must be updated (see below).

For historical evidence and repository-specific conventions, read `references/release-findings.md`.

## Local Preparation

Prepare a release locally only after the target version is known:

```bash
uv run .agents/skills/release-prep/scripts/prepare_release.py prepare 2.0.1
```

The script creates or switches to `release/<version>` from `origin/master`, updates the top-level `version` file, and prints the PR/commit context again for reference. It deliberately does not write the changelog — write that yourself (see below) so entries are real summaries, not placeholders.

IMPORTANT: Do not push branches, push tags, publish GitHub releases, or mark draft releases as published unless the user explicitly confirms.

## Writing the changelog

The GitHub Actions release job (`.github/workflows/build.yml`) uses `docs/changelog/CHANGELOG-latest.md` verbatim as the draft release body (`body_path`). That means the symlink must always point to a file containing *only the new release's* notes — never a cumulative history. Historical entries for old releases within the same major live in a separate aggregate file (e.g. `CHANGELOG-v1.x.md` holds every `1.x.y` release; `CHANGELOG-v2.x.md` should hold every 2.x release and so on).

For every release, do all of the following:

1. Create a new single-release file `docs/changelog/CHANGELOG-v<version>.md` containing only this release's notes:

   ```markdown
   # v<version>

   <optional prose summary, only if the release is notable enough to warrant one>

   ## Release Changelog

   ### Changes

   - <PR title> ([#<number>](<PR url>))

   ### Fixes

   - <PR title> ([#<number>](<PR url>))

   ### Miscellaneous

   - <PR title> ([#<number>](<PR url>))
   ```

   Sort each PR into Changes, Fixes, or Miscellaneous by reading its title/description — don't dump everything into Changes.

2. Fold the *previous* latest file's content into the the previous version major's aggregate file, `docs/changelog/CHANGELOG-v<major>.x.md`:
   - If the aggregate doesn't exist yet, create it with `# libddwaf release` as the title, then the previous file's content demoted by one heading level and prefixed with `## v<previous version>` (`# v<version>` → `## v<version>`, `## Release Changelog` → `### Release changelog`, `### Changes`/`### Fixes`/`### Miscellaneous` → `#### Changes`/`#### Fixes`/`#### Miscellaneous`). See `docs/changelog/CHANGELOG-v1.x.md` for the target shape.
   - If it already exists, prepend the same demoted `## v<previous version>` section to the top of it.
   - Delete the now-folded standalone previous-version file — its content only lives in the aggregate from here on.

3. Repoint the symlink at the new release-only file:

   ```bash
   ln -sf CHANGELOG-v<version>.md docs/changelog/CHANGELOG-latest.md
   ```

## Writing the upgrading guide

If any merged PR in range changes the public C API or ABI (anything in `include/ddwaf.h`, or behavior it documents), describe the change in the upgrading guide, following the same latest-file/historical-aggregate split as the changelog. `docs/upgrading/` isn't read by the release automation, but `docs/upgrading/UPGRADING-latest.md` is still meant to describe only the upgrade path *into* the current release, not the full history — historical entries live in the major's aggregate file (similar to the changelog).

If this release changes the API/ABI, apply the same logic as for the changelog files, mutatis mutandis.

## Manual Checks

Expected standard release shape:

- Branch: `release/<version>` without a leading `v`.
- Base branch: `master`.
- PR title: `Release v<version>`.
- Release commit: update `version`, `docs/changelog`, and — only when the API/ABI changed — `docs/upgrading`.

Commands to open the release PR, once the changelog (and upgrading guide, if needed) are written:

```bash
git add version docs/changelog/ docs/upgrading/
git commit -m 'Release v<version>' -S
git push origin release/<version>:release/<version>
gh pr create --repo DataDog/libddwaf --base master --head release/<version> --title 'Release v<version>'
```

Use the explicit `local:remote` refspec for the push, not a bare branch name — the release branch is created from `origin/master`, so it tracks `master` as its upstream, and with `push.default=upstream` a bare `git push origin release/<version>` silently pushes to `master` instead of creating the release branch.

After the release PR merges and the user explicitly approves publishing steps, tag the merge commit with the raw version string, not `v<version>`:

```bash
git switch master
git pull --ff-only
git tag <version>
git push origin <version>
```

GitHub Actions creates a draft release named `v<tag>` from any pushed tag and uses `docs/changelog/CHANGELOG-latest.md` as the release body.

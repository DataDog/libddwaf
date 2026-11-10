# libddwaf Release Findings

Use this as repository-specific context for release preparation.

## Current release workflow

- GitHub Actions workflows `Build`, `Test`, and `Fuzz` run on pull requests, pushes to `master`, and all pushed tags.
- `.github/workflows/build.yml` has a `release` job gated by `startsWith(github.ref, 'refs/tags/')`.
- The release job downloads build artifacts, copies JSON schemas from `schema/*.json`, and uses `softprops/action-gh-release`.
- The action creates a draft GitHub release, names it `v${{ github.ref_name }}`, and uses `docs/changelog/CHANGELOG-latest.md` as the body.
- Tags are raw semver strings such as `2.0.0`, not `v2.0.0`.
- Package names come from the CMake project version, with exact tags preferred by `git describe --exact-match --tags HEAD`.
- NuGet packaging reads the `[package]` version from `Cargo.toml`.
- Publishing the GitHub release runs `.github/workflows/publish.yml`, which checks that the tag (minus any leading `v`) equals the `Cargo.toml` version and publishes the `libddwaf-src` crate to crates.io.

## Version and changelog files

- The `version` in the `[package]` table of `Cargo.toml` is the release version source of truth (since #516; the top-level `version` file no longer exists).
- `cmake/version.cmake` reads it, requiring exactly one such line; `CMakeLists.txt` strips alpha/beta suffixes for the project declaration, then restores `PROJECT_VERSION` and `CMAKE_PROJECT_VERSION`.
- `src/version.hpp` is generated from `src/version.hpp.in`; do not edit it for release prep.
- Current v2 release notes live under `docs/changelog/`.
- `docs/changelog/CHANGELOG-latest.md` is a symlink to the release body file used by the GitHub release action.

## Branch and PR naming

- Standard release branches use `release/<version>` without a leading `v`.
- Standard release PRs target `master` and use titles like `Release v2.0.0`.
- Recent examples:
  - PR #525: `release/2.2.0`, title `Release v2.2.0`, changed `Cargo.toml`, folded `CHANGELOG-v2.1.0.md` into `CHANGELOG-v2.x.md`, added `CHANGELOG-v2.2.0.md`, and did the same for `docs/upgrading/`.
  - PR #496: `release/2.0.0` into `master`, title `Release v2.0.0`, one release commit, changed `version`, `docs/changelog/CHANGELOG-v2.0.0.md`, and `docs/upgrading/UPGRADING-v2.0.md`.
  - PR #463: `release/1.29.0` into `master`, title `Release v1.29.0`, changed `version` and the old `CHANGELOG.md`.

# libddwaf Release Findings

Use this as repository-specific context for release preparation.

## Current release workflow

- GitHub Actions workflows `Build`, `Test`, and `Fuzz` run on pull requests, pushes to `master`, and all pushed tags.
- `.github/workflows/build.yml` has a `release` job gated by `startsWith(github.ref, 'refs/tags/')`.
- The release job downloads build artifacts, copies JSON schemas from `schema/*.json`, and uses `softprops/action-gh-release`.
- The action creates a draft GitHub release, names it `v${{ github.ref_name }}`, and uses `docs/changelog/CHANGELOG-latest.md` as the body.
- Tags are raw semver strings such as `2.0.0`, not `v2.0.0`.
- Package names come from the CMake project version, with exact tags preferred by `git describe --exact-match --tags HEAD`.
- NuGet packaging reads the top-level `version` file.

## Version and changelog files

- The top-level `version` file is the release version source of truth.
- `CMakeLists.txt` reads `version`, strips alpha/beta suffixes for the project declaration, then restores `PROJECT_VERSION` and `CMAKE_PROJECT_VERSION`.
- `src/version.hpp` is generated from `src/version.hpp.in`; do not edit it for release prep.
- Current v2 release notes live under `docs/changelog/`.
- `docs/changelog/CHANGELOG-latest.md` is a symlink to the release body file used by the GitHub release action.

## Branch and PR naming

- Standard release branches use `release/<version>` without a leading `v`.
- Standard release PRs target `master` and use titles like `Release v2.0.0`.
- Recent examples:
  - PR #496: `release/2.0.0` into `master`, title `Release v2.0.0`, one release commit, changed `version`, `docs/changelog/CHANGELOG-v2.0.0.md`, and `docs/upgrading/UPGRADING-v2.0.md`.
  - PR #463: `release/1.29.0` into `master`, title `Release v1.29.0`, changed `version` and the old `CHANGELOG.md`.

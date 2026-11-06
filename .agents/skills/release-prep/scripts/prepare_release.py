#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# ///

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-(?:alpha|beta)\d*)?$")
PR_RE = re.compile(r"\(#(\d+)\)")
REPO = "DataDog/libddwaf"
REQUIRED_FILES = [".git", "version", "CMakeLists.txt", ".github/workflows/build.yml"]


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args.repo.resolve(), args)
    except FileNotFoundError as exc:
        raise SystemExit(f"missing required executable: {exc.filename}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect or prepare a libddwaf release.")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="libddwaf checkout path")
    parser.add_argument("--base", default="origin/master", help="release base ref")
    parser.add_argument("--previous-tag", help="override previous release tag")
    parser.add_argument("--no-fetch", action="store_true", help="skip git fetch --tags --prune origin")
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = subcommands.add_parser("inspect", help="read-only release inspection")
    inspect_cmd.add_argument("--version", help="target version to check for conflicts")
    inspect_cmd.set_defaults(func=inspect_release)

    prepare_cmd = subcommands.add_parser("prepare", help="make local release branch and file changes")
    prepare_cmd.add_argument("version", help="target version, for example 2.0.1")
    prepare_cmd.add_argument("--branch", help="override branch name; defaults to release/<version>")
    prepare_cmd.set_defaults(func=prepare_release)
    return parser


def inspect_release(repo: Path, args: argparse.Namespace) -> None:
    require_repo(repo)
    fetch(repo, args.no_fetch)
    previous, commits, prs = release_context(repo, args)
    print(render_inspect(repo, args.base, previous, commits, prs, args.version))


def prepare_release(repo: Path, args: argparse.Namespace) -> None:
    if not SEMVER_RE.match(args.version):
        raise SystemExit("version must look like 2.0.1, 2.1.0-alpha0, or 2.1.0-beta1")

    require_repo(repo)
    fetch(repo, args.no_fetch)
    ensure_clean(repo)
    previous, commits, prs = release_context(repo, args)

    if git(repo, "rev-parse", "--verify", f"refs/tags/{args.version}", check=False).returncode == 0:
        raise SystemExit(f"tag already exists locally: {args.version}")
    if release_info(repo, args.version):
        raise SystemExit(f"GitHub release already exists for tag: {args.version}")

    branch = args.branch or f"release/{args.version}"
    create_or_switch_branch(repo, branch, args.base)
    (repo / "version").write_text(args.version, encoding="utf-8")

    print(render_inspect(repo, args.base, previous, commits, prs, args.version))
    print(f"\n## Branch: {branch}")
    print("`version` bumped. Write the changelog and next commands per SKILL.md.")


def release_context(repo: Path, args: argparse.Namespace) -> tuple[str, list[dict[str, str]], list[dict[str, Any]]]:
    previous = latest_tag(repo, args.base, args.previous_tag)
    commits = commits_since(repo, previous, args.base)
    prs = [pr_info(repo, number) for number in pr_numbers(commits)]
    return previous, commits, prs


def render_inspect(
    repo: Path,
    base: str,
    previous: str,
    commits: list[dict[str, str]],
    prs: list[dict[str, Any]],
    target_version: str | None,
) -> str:
    ahead, behind = upstream_counts(repo)
    previous_release = release_info(repo, previous)
    target_release = release_info(repo, target_version)
    branch = git(repo, "branch", "--show-current").stdout or "(detached)"
    worktree = "clean" if not git(repo, "status", "--short").stdout else "has local changes"

    lines = [
        "# libddwaf release inspection",
        "",
        f"- Repo: `{repo}`",
        f"- Branch: `{branch}`",
        f"- Base: `{base}`",
        f"- Current `version`: `{version_file(repo)}`",
        f"- Previous tag: `{previous}`",
    ]
    if ahead is not None and behind is not None:
        lines.append(f"- Upstream divergence: ahead `{ahead}`, behind `{behind}`")
    lines.append(f"- Worktree: {worktree}")

    if previous_release:
        lines.append(
            f"- GitHub release for `{previous}`: `{previous_release['name']}` "
            f"draft={previous_release['isDraft']} prerelease={previous_release['isPrerelease']} "
            f"published={previous_release['publishedAt']}"
        )
    else:
        lines.append(f"- GitHub release for `{previous}`: not found")

    if target_version:
        lines.append(f"- Target branch: `release/{target_version}`")
        lines.append(f"- Existing target GitHub release: {'yes' if target_release else 'no'}")

    api_changed = "yes (update docs/upgrading)" if api_header_changed(repo, previous, base) else "no"
    lines.append(f"- `include/ddwaf.h` changed since `{previous}`: {api_changed}")

    add_section(lines, "## Remote release/base branches", [f"- `{branch}`" for branch in release_branches(repo)])
    add_section(lines, f"## Commits since `{previous}` on `{base}`", [f"- `{c['short']}` {c['subject']}" for c in commits])
    add_section(
        lines,
        "## Merged PRs in range",
        [f"- #{pr['number']} {pr.get('title') or '(title unavailable)'} {pr.get('url') or ''}".rstrip() for pr in prs],
        "- none detected from first-parent merge commits",
    )
    return "\n".join(lines)


def require_repo(repo: Path) -> None:
    missing = [path for path in REQUIRED_FILES if not (repo / path).exists()]
    if missing:
        raise SystemExit(f"not a libddwaf checkout or missing files: {', '.join(missing)}")


def fetch(repo: Path, skip: bool) -> None:
    if not skip:
        git(repo, "fetch", "--tags", "--prune", "origin")


def ensure_clean(repo: Path) -> None:
    if git(repo, "status", "--short").stdout:
        raise SystemExit("refusing to prepare release with uncommitted changes")


def create_or_switch_branch(repo: Path, branch: str, base: str) -> None:
    if git(repo, "rev-parse", "--verify", branch, check=False).returncode == 0:
        git(repo, "switch", branch)
    else:
        git(repo, "switch", "-c", branch, base)


def version_file(repo: Path) -> str:
    return (repo / "version").read_text(encoding="utf-8").strip()


def latest_tag(repo: Path, base: str, override: str | None) -> str:
    return override or git(repo, "describe", "--tags", "--abbrev=0", base).stdout


def upstream_counts(repo: Path) -> tuple[int | None, int | None]:
    upstream = git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False)
    if upstream.returncode != 0:
        return None, None
    counts = git(repo, "rev-list", "--left-right", "--count", f"HEAD...{upstream.stdout}").stdout.split()
    return (int(counts[0]), int(counts[1])) if len(counts) == 2 else (None, None)


def commits_since(repo: Path, tag: str, base: str) -> list[dict[str, str]]:
    output = git(repo, "log", "--first-parent", "--format=%H%x09%h%x09%s", f"{tag}..{base}").stdout
    commits = []
    for line in output.splitlines():
        full, short, subject = line.split("\t", 2)
        commits.append({"sha": full, "short": short, "subject": subject})
    return commits


def pr_numbers(commits: list[dict[str, str]]) -> list[int]:
    numbers = []
    for commit in commits:
        match = PR_RE.search(commit["subject"])
        if match and int(match.group(1)) not in numbers:
            numbers.append(int(match.group(1)))
    return numbers


def pr_info(repo: Path, number: int) -> dict[str, Any]:
    data = gh_json(
        repo,
        "pr",
        "view",
        str(number),
        "--repo",
        REPO,
        "--json",
        "number,title,url,mergedAt,headRefName,baseRefName,author",
    )
    if data is None:
        return {"number": number, "title": None, "url": None}
    data["author"] = (data.get("author") or {}).get("login")
    return data


def release_info(repo: Path, tag: str | None) -> dict[str, Any] | None:
    if not tag:
        return None
    return gh_json(
        repo,
        "release",
        "view",
        tag,
        "--repo",
        REPO,
        "--json",
        "tagName,name,isDraft,isPrerelease,publishedAt,url,targetCommitish",
    )


def api_header_changed(repo: Path, previous: str, base: str) -> bool:
    return bool(git(repo, "diff", "--name-only", f"{previous}..{base}", "--", "include/ddwaf.h").stdout)


def release_branches(repo: Path) -> list[str]:
    output = git(repo, "branch", "-r", "--list", "origin/release/*", "origin/libddwaf-*").stdout
    return [line.strip() for line in output.splitlines() if line.strip()]


def add_section(lines: list[str], title: str, items: list[str], empty: str = "- none") -> None:
    lines.extend(["", title])
    lines.extend(items or [empty])


def gh_json(repo: Path, *args: str) -> dict[str, Any] | None:
    result = run(repo, ["gh", *args], check=False)
    return None if result.returncode != 0 else json.loads(result.stdout)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(repo, ["git", *args], check=check)


def run(repo: Path, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args)}\n{result.stderr.strip()}")
    result.stdout = result.stdout.strip()
    result.stderr = result.stderr.strip()
    return result


if __name__ == "__main__":
    main()
